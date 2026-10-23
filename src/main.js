// Wisp renderer.
//
// This file holds no security logic and makes no decisions. It renders whatever
// Status the Rust side reports and forwards user input back. Anything that
// looks like a rule here — which screen to show, whether a passphrase is strong
// enough — is a rule enforced in Rust and merely reflected here, so that a
// tampered renderer cannot grant itself anything.

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const screens = new Map(
  [...document.querySelectorAll("[data-screen]")].map((el) => [
    el.dataset.screen,
    el,
  ]),
);

const field = (name) => document.querySelector(`[data-field="${name}"]`);

/** Shows exactly one screen and hides the rest. */
function show(name) {
  for (const [key, el] of screens) el.hidden = key !== name;
}

function setText(name, text) {
  const el = field(name);
  if (el) el.textContent = text ?? "";
}

function setError(name, message) {
  const el = field(name);
  if (!el) return;
  el.textContent = message ?? "";
  el.hidden = !message;
}

/**
 * Renders a Status from Rust.
 *
 * The `state` tag is the only thing that decides what is on screen. There is no
 * client-side path to the unlocked view.
 */
function render(status) {
  currentState = status.state;
  resetIdleTimer();

  switch (status.state) {
    case "noDevice":
      show("noDevice");
      break;

    case "unusable":
      setText("reason", status.reason);
      setText("mountPoint", status.mountPoint);
      show("unusable");
      break;

    case "denied":
      // Nothing is populated here on purpose.
      show("denied");
      break;

    case "deniedComputer":
      show("deniedComputer");
      break;

    case "locked":
      setText("drive", driveLabel(status));
      setError("unlockError", null);
      show("locked");
      focusFirstInput("locked");
      break;

    case "idle":
      setText("idleUsername", status.username);
      setError("resumeError", null);
      // Only offered where the hardware exists; the passphrase is always there.
      document.querySelector('[data-action="hello"]').hidden =
        !status.biometricsAvailable;
      show("idle");
      focusFirstInput("idle");
      break;

    case "registrable":
      setText("registerDrive", driveLabel(status));
      showBiometricCapability();
      field("weakBinding").hidden = status.strongBinding;
      setError("registerError", null);
      show("registrable");
      focusFirstInput("registrable");
      break;

    case "unlocked":
      setText("username", status.username);
      setText("identityUsername", status.username);
      setText("fingerprint", status.fingerprint);
      publicKey = status.publicKey.toLowerCase();
      renderTrustedComputer(status);
      renderAbout(status);
      show("unlocked");
      // Always land on Messages: the drive may have been pulled and
      // reinserted, and a stale open conversation would be misleading.
      openList();
      refreshConversations();
      break;

    default:
      show("noDevice");
  }
}

function driveLabel(status) {
  return status.label
    ? `${status.label} (${status.mountPoint})`
    : status.mountPoint;
}

function focusFirstInput(screen) {
  const input = screens.get(screen)?.querySelector("input");
  // Deferred so focus lands after the screen is actually visible.
  if (input) requestAnimationFrame(() => input.focus());
}

// --- Unlock -----------------------------------------------------------------

document
  .querySelector('[data-form="unlock"]')
  .addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = event.target.elements.passphrase;

    try {
      render(await invoke("unlock", { passphrase: input.value }));
    } catch (error) {
      setError("unlockError", String(error));
    } finally {
      // Clear the field either way, so a wrong passphrase is not left sitting
      // on screen and a correct one is not left in the DOM.
      input.value = "";
    }
  });

// --- Registration -----------------------------------------------------------

const registerForm = document.querySelector('[data-form="register"]');
const registerPassphrase = registerForm.elements.passphrase;
const registerInvite = registerForm.elements.inviteCode;

// Format-checked in Rust by the same parser the relay uses, so the feedback
// here can never disagree with the answer the server would give. This catches
// typos without spending one of the relay's rate-limited redemption attempts.
let inviteTimer = null;
registerInvite.addEventListener("input", () => {
  clearTimeout(inviteTimer);
  inviteTimer = setTimeout(async () => {
    const value = registerInvite.value.trim();
    if (!value) {
      setText("inviteState", "Ask the person who invited you. Each code works once.");
      return;
    }
    const valid = await invoke("check_invite_code", { candidate: value });
    setText(
      "inviteState",
      valid ? "Code looks valid." : "That doesn't look like a complete code yet.",
    );
  }, 150);
});

// Strength is scored in Rust by the same code that enforces the policy at
// creation, so the meter can never disagree with the outcome.
let assessTimer = null;
registerPassphrase.addEventListener("input", () => {
  clearTimeout(assessTimer);
  assessTimer = setTimeout(async () => {
    const value = registerPassphrase.value;
    if (!value) {
      updateMeter(null);
      return;
    }
    updateMeter(await invoke("assess_passphrase", { candidate: value }));
  }, 120);
});

function updateMeter(report) {
  const fill = field("meterFill");

  if (!report) {
    fill.style.width = "0";
    setText(
      "strength",
      "Minimum 12 characters and 60 bits of estimated entropy.",
    );
    return;
  }

  // 100 bits is treated as a full bar; the policy floor is 60.
  const ratio = Math.min(report.estimatedBits / 100, 1);
  fill.style.width = `${ratio * 100}%`;
  fill.style.backgroundColor = report.acceptable
    ? "var(--accent)"
    : "var(--deny)";

  const kind = report.isWordPhrase ? "word phrase" : "passphrase";
  setText(
    "strength",
    report.acceptable
      ? `${report.estimatedBits} bits — strong ${kind}.`
      : report.problem,
  );
}

registerForm
  .querySelector('[data-action="generate"]')
  .addEventListener("click", async () => {
    const phrase = await invoke("generate_passphrase");
    registerPassphrase.value = phrase;
    registerPassphrase.type = "text";
    setText("generatedPhrase", phrase);
    field("generated").hidden = false;
    updateMeter(await invoke("assess_passphrase", { candidate: phrase }));
  });

registerForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const { inviteCode, username, passphrase } = event.target.elements;
  const submit = registerForm.querySelector('button[type="submit"]');

  // Registration talks to the relay, so it is the one action here that can
  // take a noticeable moment. Disable the button rather than let an impatient
  // double-click send two redemptions for the same code.
  submit.disabled = true;
  submit.textContent = "Creating identity…";

  try {
    render(
      await invoke("register", {
        inviteCode: inviteCode.value.trim(),
        username: username.value.trim(),
        passphrase: passphrase.value,
      }),
    );
    passphrase.value = "";
    inviteCode.value = "";
    field("generated").hidden = true;
    setText("generatedPhrase", "");
  } catch (error) {
    setError("registerError", String(error));
  } finally {
    submit.disabled = false;
    submit.textContent = "Create identity";
  }
});

// --- Unlocked shell ---------------------------------------------------------

document
  .querySelector('[data-action="lock"]')
  .addEventListener("click", async () => {
    openList();
    render(await invoke("lock"));
  });

// --- Conversations ----------------------------------------------------------

/** Which conversation is on screen, as a hex identity key. */
let openPeer = null;
/** Our own identity key, for the share line. */
let publicKey = "";

const tabs = [...document.querySelectorAll("[data-tab]")];

/**
 * Which tab owns each pane.
 *
 * A conversation is a sub-view of Messages rather than a tab of its own, so
 * the Messages tab stays selected while reading one.
 */
const TAB_FOR_PANE = {
  messages: "messages",
  chat: "messages",
  groupChat: "messages",
  newGroup: "messages",
  identity: "identity",
  settings: "settings",
};

for (const tab of tabs) {
  tab.addEventListener("click", () => {
    // Leaving a conversation returns to the list, so coming back to Messages
    // never lands on a chat the user has mentally left.
    if (tab.dataset.tab === "messages") openList();
    else showPane(tab.dataset.tab);
  });
}

const panes = new Map(
  [...document.querySelectorAll("[data-pane]")].map((el) => [el.dataset.pane, el]),
);

function showPane(name) {
  for (const [key, el] of panes) el.hidden = key !== name;

  const selected = TAB_FOR_PANE[name];
  for (const tab of tabs) {
    tab.setAttribute("aria-selected", String(tab.dataset.tab === selected));
  }

  if (name === "settings") refreshSettings();
}

/** Identity keys are 64 hex characters; show enough to compare at a glance. */
function shortFingerprint(hex) {
  return (
    hex
      .slice(0, 16)
      .toUpperCase()
      .match(/.{1,4}/g)
      .join(" ") + " …"
  );
}

function groupedFingerprint(hex) {
  return hex.toUpperCase().match(/.{1,4}/g).join(" ");
}

function formatTime(millis) {
  const when = new Date(millis);
  return when.toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

async function refreshConversations() {
  const [peers, groups] = await Promise.all([
    invoke("conversations"),
    invoke("groups"),
  ]);
  const list = field("conversationList");
  list.replaceChildren();

  if (peers.length === 0 && groups.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty";
    // Zero-state inbox: there is nothing to browse until someone is messaged.
    empty.textContent =
      "No conversations yet. Share your fingerprint from the Identity tab, or paste someone else's below to start one.";
    list.append(empty);
    return;
  }

  // Groups first: there are fewer of them and they are easier to recognise by
  // name than a conversation is by fingerprint.
  for (const group of groups) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "conversation group";
    button.textContent = group.name;

    const sub = document.createElement("span");
    sub.className = "sub";
    sub.textContent = `${group.members.length} members`;
    button.append(sub);

    button.addEventListener("click", () => openGroup(group));
    list.append(button);
  }

  for (const peer of peers) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "conversation";
    button.textContent = shortFingerprint(peer);
    button.addEventListener("click", () => openConversation(peer));
    list.append(button);
  }
}

function appendBubble(message) {
  const bubble = document.createElement("div");
  bubble.className = `bubble ${message.outgoing ? "mine" : "theirs"}`;
  // textContent, never innerHTML: message bodies are attacker-controlled.
  bubble.textContent = message.body;

  const stamp = document.createElement("time");
  stamp.textContent = formatTime(message.sentAt);
  bubble.append(stamp);

  const messages = field("messages");
  messages.append(bubble);
  messages.scrollTop = messages.scrollHeight;
}

async function openConversation(peer) {
  openPeer = peer;
  setText("chatPeer", groupedFingerprint(peer));
  setError("sendError", null);

  const messages = field("messages");
  messages.replaceChildren();
  for (const message of await invoke("conversation", { peer })) {
    appendBubble(message);
  }

  showPane("chat");
  requestAnimationFrame(() => panes.get("chat").querySelector("input").focus());
}

function openList() {
  openPeer = null;
  openGroupId = null;
  showPane("messages");
}

document
  .querySelector('[data-action="back"]')
  .addEventListener("click", async () => {
    openList();
    await refreshConversations();
  });

// Opening a conversation with someone new is just showing an empty one; the
// session is established lazily when the first message is actually sent.
document
  .querySelector('[data-form="newChat"]')
  .addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = event.target.elements.peer;
    const peer = input.value.replace(/\s+/g, "").toLowerCase();

    if (!/^[0-9a-f]{64}$/.test(peer)) {
      setError("newChatError", "That is not a valid identity fingerprint.");
      return;
    }
    setError("newChatError", null);
    input.value = "";
    await openConversation(peer);
  });

document
  .querySelector('[data-form="send"]')
  .addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = event.target.elements.text;
    const text = input.value;
    if (!text.trim() || !openPeer) return;

    const button = event.target.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      const sent = await invoke("send_message", {
        recipient: openPeer,
        text,
      });
      appendBubble(sent);
      input.value = "";
      setError("sendError", null);
    } catch (error) {
      setError("sendError", String(error));
    } finally {
      button.disabled = false;
      input.focus();
    }
  });

// Messages arriving while the app is open.
listen("wisp://message", async (event) => {
  const message = event.payload;
  if (message.peer === openPeer) {
    appendBubble(message);
  } else {
    // A conversation that did not exist a moment ago now does.
    await refreshConversations();
  }
});

// The user's own link to the relay. Not presence — nothing here reports on
// anyone else.
listen("wisp://connection", (event) => {
  const { connected, detail } = event.payload;
  const dot = field("connectionDot");
  dot.className = `dot ${connected ? "online" : "offline"}`;
  setText("connection", connected ? "connected" : detail || "offline");
});

/** Briefly confirms a copy on the button that triggered it. */
async function copyToClipboard(button, text, label) {
  await navigator.clipboard.writeText(text);
  button.textContent = "Copied";
  setTimeout(() => (button.textContent = label), 1200);
}

document
  .querySelector('[data-action="copy"]')
  .addEventListener("click", (event) =>
    copyToClipboard(
      event.currentTarget,
      field("fingerprint").textContent,
      "Copy fingerprint",
    ),
  );

// The share line is the raw key, which is what the other side pastes into
// "Start a conversation" — the spaced fingerprint is for reading aloud.
document
  .querySelector('[data-action="copyShare"]')
  .addEventListener("click", (event) =>
    copyToClipboard(event.currentTarget, publicKey, "Copy share line"),
  );

// --- Trusted Computer Binding -----------------------------------------------

/** Latest unlocked status, so Settings can render without re-fetching. */
let trustedComputer = { enabled: false, bindable: false };

const toggleButton = document.querySelector(
  '[data-action="toggleTrustedComputer"]',
);

async function renderTrustedComputer(status) {
  trustedComputer = {
    enabled: status.trustedComputer,
    bindable: status.canBindComputer,
  };

  const badge = field("tcState");
  badge.textContent = status.trustedComputer ? "ON" : "OFF";
  badge.className = `badge${status.trustedComputer ? " on" : ""}`;

  const { label, bindable } = await invoke("computer_info");

  if (status.trustedComputer) {
    setText(
      "tcDescription",
      `This Wisp identity can only be unlocked on ${label}. Your USB drive and this computer are both required.`,
    );
    toggleButton.textContent = "Disable";
    toggleButton.hidden = false;
  } else if (bindable) {
    setText(
      "tcDescription",
      "Your Wisp USB can be used on any authorised computer. Binding it to this one adds a third requirement.",
    );
    toggleButton.textContent = "Enable";
    toggleButton.hidden = false;
  } else {
    setText(
      "tcDescription",
      "This computer cannot be identified, so it cannot be bound to.",
    );
    toggleButton.hidden = true;
  }
}

/** Which direction the confirm screen is currently asking about. */
let pendingBinding = null;

toggleButton.addEventListener("click", async () => {
  pendingBinding = !trustedComputer.enabled;
  const { label } = await invoke("computer_info");

  setText(
    "tcConfirmTitle",
    pendingBinding
      ? "Enable Trusted Computer Binding?"
      : "Disable Trusted Computer Binding?",
  );
  setText(
    "tcConfirmBody",
    pendingBinding
      ? `This will restrict this Wisp identity to ${label}. You will need your passphrase to change this setting later.`
      : `This Wisp identity will work on any authorised computer again, not just ${label}.`,
  );
  // The lockout warning belongs on the enabling path only.
  field("tcConfirmWarning").hidden = !pendingBinding;
  field("tcConfirmSubmit").textContent = pendingBinding ? "Enable" : "Disable";
  setError("tcConfirmError", null);

  show("confirmBinding");
  focusFirstInput("confirmBinding");
});

document
  .querySelector('[data-action="cancelBinding"]')
  .addEventListener("click", async () => {
    pendingBinding = null;
    render(await invoke("gate_status"));
  });

document
  .querySelector('[data-form="confirmBinding"]')
  .addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = event.target.elements.passphrase;
    const submit = field("tcConfirmSubmit");

    submit.disabled = true;
    try {
      render(
        await invoke("set_trusted_computer", {
          enabled: pendingBinding,
          passphrase: input.value,
        }),
      );
      pendingBinding = null;
    } catch (error) {
      setError("tcConfirmError", String(error));
    } finally {
      submit.disabled = false;
      input.value = "";
    }
  });

// --- Groups -----------------------------------------------------------------

/** Which group is on screen, or null. */
let openGroupId = null;
/** Groups by id, so an incoming message can be matched to a name. */
const knownGroups = new Map();

function appendGroupBubble(message) {
  const bubble = document.createElement("div");
  bubble.className = `bubble ${message.outgoing ? "mine" : "theirs"}`;

  // Any member could have written it, so incoming messages name the sender.
  if (!message.outgoing) {
    const who = document.createElement("span");
    who.className = "who";
    who.textContent = shortFingerprint(message.sender);
    bubble.append(who);
  }

  // textContent, never innerHTML: message bodies are attacker-controlled.
  const body = document.createElement("span");
  body.textContent = message.body;
  bubble.append(body);

  const stamp = document.createElement("time");
  stamp.textContent = formatTime(message.sentAt);
  bubble.append(stamp);

  const messages = field("groupMessages");
  messages.append(bubble);
  messages.scrollTop = messages.scrollHeight;
}

async function openGroup(group) {
  openGroupId = group.id;
  openPeer = null;
  knownGroups.set(group.id, group);

  setText("groupName", group.name);
  setText("groupMembers", `${group.members.length} members`);
  setError("groupSendError", null);

  const messages = field("groupMessages");
  messages.replaceChildren();
  for (const message of await invoke("group_conversation", { group: group.id })) {
    appendGroupBubble(message);
  }

  showPane("groupChat");
  requestAnimationFrame(() =>
    panes.get("groupChat").querySelector("input").focus(),
  );
}

document
  .querySelector('[data-action="backGroup"]')
  .addEventListener("click", async () => {
    openGroupId = null;
    openList();
    await refreshConversations();
  });

document
  .querySelector('[data-action="newGroup"]')
  .addEventListener("click", () => {
    setError("createGroupError", null);
    showPane("newGroup");
    requestAnimationFrame(() =>
      panes.get("newGroup").querySelector("input").focus(),
    );
  });

document
  .querySelector('[data-action="cancelGroup"]')
  .addEventListener("click", () => openList());

document
  .querySelector('[data-form="createGroup"]')
  .addEventListener("submit", async (event) => {
    event.preventDefault();
    const { name, members } = event.target.elements;
    const submit = event.target.querySelector('button[type="submit"]');

    const parsed = members.value
      .split(/\s+/)
      .map((line) => line.replace(/\s+/g, "").toLowerCase())
      .filter(Boolean);

    const bad = parsed.find((member) => !/^[0-9a-f]{64}$/.test(member));
    if (bad) {
      setError("createGroupError", `Not a valid fingerprint: ${bad.slice(0, 12)}…`);
      return;
    }
    if (parsed.length === 0) {
      setError("createGroupError", "Add at least one member.");
      return;
    }

    // Creating a group sends a key to every member, so it can take a moment.
    submit.disabled = true;
    submit.textContent = "Creating…";
    try {
      const group = await invoke("create_group", {
        name: name.value,
        members: parsed,
      });
      name.value = "";
      members.value = "";
      setError("createGroupError", null);
      await refreshConversations();
      await openGroup(group);
    } catch (error) {
      setError("createGroupError", String(error));
    } finally {
      submit.disabled = false;
      submit.textContent = "Create group";
    }
  });

document
  .querySelector('[data-form="sendGroup"]')
  .addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = event.target.elements.text;
    const text = input.value;
    if (!text.trim() || !openGroupId) return;

    const button = event.target.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      appendGroupBubble(
        await invoke("send_group_message", { group: openGroupId, text }),
      );
      input.value = "";
      setError("groupSendError", null);
    } catch (error) {
      setError("groupSendError", String(error));
    } finally {
      button.disabled = false;
      input.focus();
    }
  });

// A group message arriving while the app is open.
listen("wisp://group-message", async (event) => {
  const message = event.payload;
  if (message.group === openGroupId) {
    appendGroupBubble(message);
  } else {
    await refreshConversations();
  }
});

// Someone shared their key, which is also how a new group first appears.
listen("wisp://group", async (event) => {
  knownGroups.set(event.payload.id, event.payload);
  if (openGroupId === event.payload.id) {
    setText("groupMembers", `${event.payload.members.length} members`);
  }
  await refreshConversations();
});

// --- Settings ---------------------------------------------------------------

function renderAbout(status) {
  setText("aboutDrive", status.mountPoint);
}

/**
 * Fills in the read-only parts of Settings.
 *
 * Re-read each time the tab is opened rather than cached: biometric hardware
 * can be disabled and enrolment removed while the app is running, and a stale
 * "available" would offer something that no longer works.
 */
async function refreshSettings() {
  const [info, biometrics, computer] = await Promise.all([
    invoke("app_info"),
    invoke("biometric_capability"),
    invoke("computer_info"),
  ]);

  setText("aboutVersion", info.version);
  setText("aboutRelay", info.relay);
  setText("aboutComputer", computer.label);

  const available = biometrics === "available";
  const badge = field("bioState");
  badge.textContent = available ? "AVAILABLE" : "UNAVAILABLE";
  badge.className = `badge${available ? " on" : ""}`;
  setText(
    "bioDescription",
    available
      ? "Windows Hello can re-open this session after it goes idle. It never replaces your USB drive or your passphrase."
      : "No biometric hardware detected. Your passphrase is the only way back in after the session goes idle.",
  );

  setText(
    "idleDescription",
    `The screen covers itself after ${info.idleAfterMinutes} minutes without input. Your key stays in memory while idle — removing the drive is what actually wipes it.`,
  );
}

// --- Idle lock --------------------------------------------------------------

/**
 * How long without input before the screen covers itself.
 *
 * This is a screen lock, not the USB gate: the key stays in memory and coming
 * back needs only a consent check. Pulling the drive is what actually wipes it.
 */
const IDLE_AFTER_MS = 5 * 60 * 1000;

let currentState = null;
let idleTimer = null;

function resetIdleTimer() {
  clearTimeout(idleTimer);
  // Only an unlocked session has anything to cover.
  if (currentState !== "unlocked") return;
  idleTimer = setTimeout(async () => {
    render(await invoke("begin_idle"));
  }, IDLE_AFTER_MS);
}

for (const activity of ["mousemove", "mousedown", "keydown", "wheel", "touchstart"]) {
  window.addEventListener(activity, resetIdleTimer, { passive: true });
}

async function showBiometricCapability() {
  // Spec: onboarding tells the user what their device supports, so an absent
  // fingerprint reader is stated rather than silently implied.
  const availability = await invoke("biometric_capability");
  const supported = availability === "available";
  setText(
    "biometricCapability",
    supported
      ? "Windows Hello is available and can be used to re-unlock this session."
      : "No biometric hardware detected. Your passphrase is the only way back in.",
  );
}

document
  .querySelector('[data-action="hello"]')
  .addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      render(await invoke("resume_biometric"));
    } catch (error) {
      setError("resumeError", String(error));
    } finally {
      button.disabled = false;
    }
  });

document
  .querySelector('[data-form="resume"]')
  .addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = event.target.elements.passphrase;
    try {
      render(await invoke("resume_passphrase", { passphrase: input.value }));
    } catch (error) {
      setError("resumeError", String(error));
    } finally {
      input.value = "";
    }
  });

// --- Wiring -----------------------------------------------------------------

// Pushed by the USB watcher. This is what makes pulling the drive lock the
// screen without the user touching anything.
listen("wisp://status", (event) => render(event.payload));

invoke("gate_status").then(render);
