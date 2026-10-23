# Project Prompt: Wisp — Private Invite-Only Desktop Chat App

## Overview
Build a desktop chat application called **Wisp** for **Windows and macOS only**
(no mobile, no web). This is a minimal, privacy-first app — the server is a dumb
relay, the client does all the work, and access is gated physically by a USB drive
plus a passphrase, with optional biometric unlock on supported hardware.

## Core Principles
- The server never sees plaintext content, and never retains message history after
  delivery. It stores public keys, invite codes, and transient encrypted blobs only.
- No feature ships unless necessary. No read receipts, no typing indicators, no
  "last seen," no analytics, no telemetry, no third-party SDKs.
- Distribution is fully private: no app store, no public download page. Installer
  shared directly with invited users.
- Physical possession of a specific USB drive is a **hard requirement** to unlock
  the app — this is the primary access control, not a convenience feature.

## Functional Requirements

### 1. Invite-only onboarding
- No public signup. Admin (owner) generates single-use, expiring invite codes via
  an admin CLI/tool.
- Redeeming a code is the only way to create an account.

### 2. USB-based identity, key storage & device binding
The identity is bound to a **specific physical USB device**, not just an
encrypted file that happens to sit on some drive. The identity is *not* bound to
the user's computer — the registered USB must work across any authorized Windows
or macOS machine.

**Registration flow (first setup):**
- User inserts the USB drive that will become their Wisp key.
- App generates the identity keypair locally.
- App reads available USB device identifiers (serial number, vendor ID, product
  ID, filesystem volume identifier, or other platform-specific identifiers).
- These raw identifiers are **not stored directly**. They are passed through a
  secure derivation/hash (established KDF/hash primitive, no custom crypto) to
  produce a **USB binding value**.
- User sets a passphrase; the private identity key is encrypted with it.
- App writes an identity file to the USB, e.g. `.wisp/identity.wisp`, containing
  (conceptually): format version, the USB binding value, the encrypted identity,
  KDF parameters, and a nonce. Exact format to be finalized securely during
  implementation, not treated as a fixed spec here.
- Public key + chosen handle are registered with the server; invite code is
  marked used.

**Unlock flow (every app start / USB insertion):**
1. Detect the removable device and locate the Wisp identity file on it.
2. Derive/identify the current USB device's binding value.
3. Compare it against the binding value stored in `identity.wisp`.
4. **Mismatch → immediate "Access Denied" screen.** No passphrase prompt, no chat
   list, no app state rendered — just a minimal denial message.
5. **Match → prompt for passphrase**, then decrypt the identity and unlock.

Checking device binding *before* prompting for a passphrase is intentional: it
gives the user (and an attacker) a clear, distinct signal — "wrong USB" vs. "wrong
passphrase" — rather than one ambiguous failure state.

- **No USB drive inserted → app shows only an "Insert USB drive" screen.** No chat
  list, no content, nothing else is accessible or rendered.
- **USB drive removed mid-session → app immediately wipes the in-memory decrypted
  key and locks back to the zero-access state.**
- Losing the registered USB drive means losing the identity by design — no
  server-side recovery path. (Optional: user may create their own encrypted
  backup of the key file at their own risk — not a built-in synced recovery
  feature.)

#### Known limitation: this is device binding, not hardware authentication
USB identifiers (serial number, VID/PID, volume ID) are **not cryptographically
trustworthy** — they can be duplicated by cheap hardware, modified, spoofed, or
simply unavailable depending on OS/hardware. Wisp should always refer to this
mechanism internally and in-app as **"USB device binding,"** never as
"cryptographic hardware authentication" or claim the physical drive itself is
unclonable.

**What this model achieves:** an attacker who copies `identity.wisp` to a
different USB drive is denied *before* even getting a passphrase prompt, because
the binding value won't match. This closes the realistic, easy attack path (file
sync, casual copying, a lost/found drive) even though the passphrase alone was
already required in that scenario too — it adds a second, independent gate.

**What it does not achieve:** it does not stop a sophisticated attacker capable of
spoofing USB device descriptors at the OS/driver level. That remains a real
limitation of any commodity USB drive, and is the correct reason to treat this as
**defense-in-depth**, not a substitute for genuine hardware-backed secrets.

**Full v1 security model (layered, not any single factor alone):**
```
Physical USB possession
        +
USB device binding (hashed identifier match)
        +
Encrypted identity key
        +
Strong passphrase
        +
Signal identity/session keys
```

**Additional v1 requirements:**
- Enforce a strong passphrase at key creation (minimum length/entropy, or a
  BIP39-style word-list passphrase for memorability + strength).
- Rate-limit / lock out repeated failed passphrase attempts, enforced **server-
  side** (tied to the account's public key, not a local counter that resets if
  the file is re-copied).
- Decrypted private identity key exists only in protected application memory
  while unlocked; securely zeroized on lock/removal — never written to disk
  unencrypted.
- No plaintext private identity key ever stored on the host computer's disk.

**v2+ path to genuine hardware-bound auth (deferred, not part of this build):**
If true device-bound cryptographic secrets become a requirement later, the
correct upgrade is a hardware security token (e.g., YubiKey/FIDO2 or a device
with a secure element), where the private key is generated inside and never
leaves the hardware chip — the app sends a challenge, the token signs it, and
returns cryptographic proof. Copying files to another device would not be
sufficient, since there's no extractable secret to copy. The `identity.wisp`
format should stay versioned so this can be added later without redesigning the
identity system. Not scoped for v1 — validate the core messaging system first.

### 3. Biometric unlock (additive, not a replacement)
- On supported hardware, offer biometric auth as a *faster re-auth* layer during an
  active session (e.g., after screen lock/inactivity) — **but the USB drive must
  still be physically present** at all times for the app to function. Biometrics
  never substitute for USB possession, only for re-entering the passphrase
  repeatedly within a session.
- **macOS**: Touch ID only (Face ID does not exist on Mac hardware). Use the
  `LocalAuthentication` framework (`LAContext`), checked via
  `canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`. Bridge from
  Tauri/Rust via a small Swift/Objective-C helper.
- **Windows**: Windows Hello (fingerprint and/or IR facial recognition, depending
  on hardware). Use `Windows.Security.Credentials.UI.UserConsentVerifier` via the
  official Rust `windows` crate; check `CheckAvailabilityAsync()` before offering it.
- Both platforms must **gracefully degrade**: if biometric hardware isn't
  available, fall back silently to USB + passphrase only, with no broken UI or
  dead ends.
- During onboarding, run a capability check and show the user what their device
  supports (e.g., "✅ Touch ID available" / "No biometric hardware detected").

### 4. End-to-end encryption
- Use the **Signal Protocol** (libsignal, Rust bindings) for 1:1 and group
  messaging — double ratchet, forward secrecy, sender-key groups. No custom
  cryptography.
- Implement **sealed sender** so the server cannot determine who sent a message,
  only its intended recipient.
- All local message storage encrypted at rest, keyed by the USB-held private key.

### 5. Zero-state inbox
- On first login (and on every login before a chat exists), the chat list is empty.
- A user only appears in someone's chat list after being messaged directly (via
  shared public key/fingerprint) or added to a group by an existing member.
- Provide an in-app way to export/share the user's own public identity (fingerprint
  string or small exportable file, since there's no camera for QR scanning on
  desktop).

### 6. Minimal UI
- No seen/unseen indicators, no typing indicators, no online status.
- Screens needed: insert-USB gate, invite code redemption, passphrase
  setup/entry, handle selection, chat list (empty by default), individual chat
  view, group chat view, identity export/sharing screen, minimal settings.

### 7. Messaging & groups
- 1:1 messaging via Signal double ratchet.
- Group messaging via Signal sender-key protocol.
- Server retains encrypted messages only until delivered, then deletes them.

## Technical Stack
- **Client framework**: Tauri (preferred over Electron) — smaller binaries, lower
  resource use, Rust core for tighter control over memory (critical for reliably
  wiping decrypted keys from RAM the instant the USB is removed).
- **Crypto**: libsignal-client (Rust bindings).
- **USB detection**: filesystem mount/unmount watching for the designated volume,
  or a Rust USB crate (e.g., `rusb`) if raw device-level detection is preferred
  over treating it as a normal removable volume.
- **Biometric bridges**: Swift/ObjC helper (macOS) and the `windows` crate
  (Windows), called from the Rust backend.
- **Backend**: Lightweight relay server (Node.js or Go), WebSocket for real-time
  delivery, no push notification dependency needed (desktop app can stay connected
  while running).
- **Database**: Postgres or SQLite — stores only public keys, hashed handles,
  invite code records, and transient encrypted message blobs pending delivery.

## Deployment Constraints
- No app store, no public listing — installer (.exe / .dmg) shared directly with
  invited users.
- No Apple Developer Program requirement for basic distribution (code signing for
  a smoother install experience is optional/nice-to-have on macOS, not a hard
  requirement the way it is for iOS).
- Backend hosted on a free/low-cost VPS (Fly.io for early dev, Oracle Cloud Free
  Tier for a permanent always-on relay), TLS via Let's Encrypt.

## Build Order
1. USB-key generation, device binding, encryption, and detection flow (core
   access gate) — build and test this first, it's the foundation everything
   else locks behind
2. 1:1 E2EE messaging (Signal protocol integration)
3. Invite code system + account creation
4. Biometric capability detection + optional unlock layer
5. Group chat (sender-key protocol)
6. Minimal UI polish
7. Deployment pipeline (installer packaging + distribution to invitees)

## Open Design Decisions (resolve before/during build)
- Passphrase required on every USB insertion vs. cached for the session until
  drive removal or app close — main security/friction trade-off in the whole flow.
- Whether to support user-initiated encrypted key backups, or enforce strict
  single-physical-copy-only key custody.
- Exact USB detection method: watch a designated removable volume/folder vs. raw
  USB device handshake.

## Resolved Decisions
- **USB security model**: v1 uses USB device binding (hashed device identifier
  check) + encrypted identity key + strong passphrase, layered together. This is
  explicitly *not* cryptographic hardware authentication — see "Known limitation"
  under section 2. True hardware-bound auth (YubiKey/FIDO2/secure element) is a
  deferred v2+ upgrade, not part of this build, though the identity file format
  is versioned to support it later without a redesign.

## Explicitly Out of Scope
- iOS, Android, or web/PWA versions
- Public signup or discoverability
- Server-side message history retention
- Analytics, crash reporting with identifying data, or third-party SDKs that
  phone home
- Read receipts, typing indicators, online/last-seen status