# Wisp

Private desktop chat for Windows and macOS with open signup: pick a username,
get a generated passphrase, and you have an account. The server is a dumb relay;
the client does all the work; access is gated by physical possession of a
specific USB drive plus a passphrase.

**Status: the core is built and working.** The USB access gate, the
open-registration relay, Signal messaging with sealed sender, Windows Hello
re-authentication, group chat, and the UI all work. **Packaging and
distribution remain.** See [Where this stands](#where-this-stands).

Wisp started as invite-only and now has open registration; see
[Open registration](#open-registration) for what that changes and what it
costs. Running a public relay is covered in [DEPLOY.md](DEPLOY.md).

**Windows is the tested platform.** macOS has never been compiled or run, and
Touch ID is deliberately unimplemented — see the notes on both below.

> **Not independently audited.** Wisp does its own key handling around
> libsignal and has had no external security review. It is a personal project,
> not a vetted messenger — do not rely on it to protect anything you cannot
> afford to lose. Vulnerabilities can be reported as described in
> [SECURITY.md](SECURITY.md).

**Prerequisites:** the Rust toolchain, [`protoc`][protoc] on `PATH` (libsignal's
build scripts need it), and on Windows the MSVC C++ build tools. See
[Building](#building).

---

## Repository layout

| Path | What it is |
| --- | --- |
| `crates/wisp-core` | Identity file format, key schedule, USB binding derivation, passphrase policy, and the wire formats shared with the relay. No platform, UI, or network dependencies. |
| `crates/wisp-usb` | Removable volume discovery, platform device identifier queries, insert/remove watching. |
| `crates/wisp-session` | The access gate state machine. Owns the only decrypted key in the process. |
| `crates/wisp-machine` | Identifies this computer, for Trusted Computer Binding. |
| `crates/wisp-biometric` | Windows Hello re-authentication. |
| `crates/wisp-messaging` | The libsignal wrapper: sessions, sealed sender, group chat, and the encrypted local vault and history. |
| `crates/wisp-server` | The relay: open account registration, throttling, and transient encrypted delivery over WebSocket. |
| `crates/wisp-admin` | Operator CLI for listing, locking, and unlocking accounts. |
| `src-tauri` | Tauri shell. Thin — it holds no security logic. |
| `src` | Frontend. Plain HTML/CSS/JS, no npm dependencies, no build step. |
| `tools/make-icons.mjs` | Generates app icons procedurally using only Node's built-in `zlib`. |
| `tools/check-ui.mjs` | Verifies every selector `main.js` uses exists in `index.html`. |
| `tools/build-installer.mjs` | Builds the installer against a relay, refusing unless that relay is online. |
| `Dockerfile`, `docker-compose.yml` | Build and run the relay in a container. |
| `DEPLOY.md` | Running a relay: Docker, Cloudflare Tunnel, building installers. |
| `SECURITY.md`, `LICENSE` | Reporting vulnerabilities; MIT license. |

The security-critical logic lives in `wisp-core`, `wisp-session`, and
`wisp-server` specifically so it can be tested exhaustively on any machine,
without hardware.

`wisp-core::protocol` holds the byte formats both the client and the relay
depend on — username hashing, the registration signature, the auth challenge.
They live there because neither side may depend on the other, and two
implementations would drift until signatures silently stopped verifying.

---

## The v1 security model

```
Physical USB possession
        +
USB device binding (hashed identifier match)
        +
Trusted computer binding          <- optional, off by default
        +
Encrypted identity key
        +
Strong passphrase
        +
Signal identity/session keys
```

These are layers, not alternatives.

| Mode | Required |
| --- | --- |
| USB only *(default)* | Registered USB + passphrase |
| USB + trusted computer | Registered USB + that computer + passphrase |
| Hardware token *(future)* | Token + passphrase |

### Unlock order

1. A removable drive is present and carries `.wisp/identity.wisp`, or the app
   renders **nothing but the insert-USB screen**.
2. The binding value is compared against the inserted drive. A mismatch is an
   immediate **Access Denied** — no passphrase prompt, no app state.
3. Only then is the passphrase requested.

Step 2 exists for the *user's* benefit: it separates "wrong drive" from "wrong
passphrase" instead of collapsing both into one ambiguous failure. It is not
what makes the drive necessary — see below.

### The device is an input to the key, not just a compared value

The obvious design — derive the key from the passphrase and store the binding
value beside it for comparison — gives the binding check no cryptographic
weight at all. The binding value sits in the file, so anyone holding a copied
`identity.wisp` simply skips the comparison and brute-forces the passphrase
offline.

Wisp folds the device fingerprint into the key schedule instead:

```
file_key = Argon2id(passphrase, kdf_salt)          # m=128 MiB, t=4, p=1
aead_key = HKDF-SHA256(ikm = file_key,
                       salt = SHA256(fingerprint), # never written to disk
                       info = "wisp.identity.v1.aead-key")
identity = XChaCha20-Poly1305(aead_key, nonce, aad = file header)
```

`SHA256(fingerprint)` never touches the disk. The value that *is* stored is a
separately salted HMAC of the same fingerprint — enough to answer "is this the
right drive?", not enough to recover the HKDF salt.

The consequence: **someone who copies the identity file but never read the
drive's descriptors cannot mount an offline passphrase attack**, because an
input to the key is missing. Someone who *did* read the real drive's
descriptors is back to passphrase-only strength.

The whole file header — version, cost parameters, salts, binding value — is
passed to the AEAD as associated data, so no field can be altered or downgraded
without the unlock failing.

### Known limitation: this is device binding, not hardware authentication

USB identifiers are **not cryptographically trustworthy**. They can be
duplicated by cheap programmable hardware, rewritten, or spoofed at the driver
level, and some drives report none at all. Wisp refers to this as **"USB device
binding"** everywhere, in code and in the UI, and never as hardware
authentication.

**What it closes:** the realistic attack path — a file copied to another stick,
a synced folder, a lost or imaged drive.

**What it does not close:** an attacker capable of spoofing USB device
descriptors. That is a limitation of every commodity USB drive and is the
correct reason to treat this as defence-in-depth.

The v2+ upgrade for genuine hardware-bound secrets is a security token
(YubiKey/FIDO2 or a secure element), where the private key never leaves the
chip. The identity file is versioned and its key material is an opaque,
type-tagged blob, so that lands without redesigning the format.

---

## Trusted Computer Binding

Optional and off by default. When on, the identity opens only on the computer
it was bound to.

```
USB ✓   Computer ✗   ->   denied, with no passphrase prompt
```

It uses the same two-part shape as the USB binding, for the same reason. A
salted HMAC of the machine identity sits in the header, so "wrong computer" can
be answered **before** the passphrase is requested; and the machine fingerprint
is folded into the key schedule, so it is cryptographically required rather than
a comparison someone could patch out:

```
combined = SHA256("wisp.binding.combined.v1" || SHA256(usb_fp) || SHA256(machine_fp))
aead_key = HKDF-SHA256(ikm = Argon2id(passphrase), salt = combined, info)
```

With binding off, `combined` is the USB hash unchanged — so a format-1 file and
an unbound format-2 file derive identical keys, and turning the feature on and
off never changes what a correct passphrase opens.

### Changing the setting requires the passphrase

Not by policy — by construction. Enabling or disabling means decrypting the
identity and re-encrypting it under a different key schedule, which cannot be
done without the passphrase. It also means **disabling only works on the bound
computer**, because disabling requires decrypting first.

The new file is staged and committed exactly like registration, so a drive
pulled mid-write leaves the old identity intact.

### What invalidates it

On Windows the identifier is `MachineGuid` from
`HKLM\SOFTWARE\Microsoft\Cryptography`.

- **Survives:** motherboard swaps, CPU/RAM/GPU changes, Windows updates.
- **Breaks:** reinstalling Windows, resetting the PC.

> **Warning.** Trusted Computer Binding may become invalid after significant
> hardware or operating-system changes. There is no server-side recovery path.
> If the identifier changes, the identity cannot be opened again.

That is consistent with the rest of Wisp — lost key means lost identity — but it
is a second way to lose one, which is why it is opt-in and warned about at the
point of enabling.

It is an *OS install* identity, not a hardware one, so someone who images the
whole system disk and boots it elsewhere carries it with them. It stops the case
it was asked to stop: a stolen USB drive in someone else's machine. The SMBIOS
system UUID would behave the opposite way — surviving an OS reinstall, breaking
on a motherboard swap, and not travelling with a disk image. Neither is strictly
better; the binding is versioned so a different source can be added.

**Not offered on macOS**, which reports no machine identity yet.

## The `identity.wisp` format (version 2)

All integers big-endian. Bytes `0..194` are the authenticated prefix — including
the trusted-computer flag, so the binding cannot be switched off by flipping a
byte on the drive.

```
off  len  field
  0    4  magic "WISP"
  4    2  format_version = 2
  6    1  kdf_id           (1 = Argon2id)
  7    1  aead_id          (1 = XChaCha20-Poly1305)
  8    1  binding_strength (0 = weak, 1 = strong)
  9    1  machine_binding  (0 = off, 1 = on)
 10    4  argon2 m_cost (KiB)
 14    4  argon2 t_cost
 18    4  argon2 p_cost
 22   16  kdf_salt
 38   32  binding_salt
 70   32  binding_value
102   32  machine_salt          (zero when off)
134   32  machine_binding_value (zero when off)
166   24  aead_nonce
190    4  ciphertext_len
194    N  ciphertext || 16-byte tag
```

**Format 1 still opens.** Its prefix is 130 bytes with byte 9 reserved and the
nonce at 102; `decode` handles both, and enabling the binding on a version-1
identity upgrades it in place. Both paths have tests.

The encrypted payload is itself versioned and carries a `key_type` tag, so
step 2 can store a serialised libsignal `IdentityKeyPair` — and a future
hardware token can store a key *handle* — without a container change.

### Binding strength

Only the device serial (strong) or the filesystem volume serial (weak)
contributes to the fingerprint, never both.

- **Strong** — device serial. Survives reformatting, identical on both
  platforms.
- **Weak** — volume serial, used only when the drive reports no device serial.
  Reformatting the drive destroys the identity. The registration UI warns
  before creating one.

Vendor and product are deliberately **excluded** from the fingerprint. Windows
reports them as strings (`"SanDisk"`, `"Cruzer Blade"`) while macOS IOKit
reports numeric USB VID/PID; including either would make a drive registered on
one OS fail to unlock on the other. They are carried for display only.

---

## Open registration

Anyone who can reach the relay can create an account. The setup screen asks for
one thing — a username — and **generates the passphrase for the user**: eight
random words from the OS CSPRNG, about 88 bits, shown once with a "I have written
this down" confirmation. The user does not choose it, so its strength is a
property of the generator and not of someone's imagination.

The USB drive is still required. Open registration changes who may *create* an
account, not what it takes to *open* one: the identity is written to a specific
drive and only unlocks with that drive plus the passphrase.

### What the registration signature proves

The client signs `(public key, username hash)` under a domain-separated tag
(`wisp.register.v2`). That proves the caller holds the private half of the key
being registered, and that neither the key nor the name can be swapped by someone
who intercepts the request. It does **not** prove anything about who the caller
is — nothing could, with no credential to present.

### What replaces the invite as the gate

Nothing stops a script from asking for accounts, so the relay limits it:

| Limit | Default | Purpose |
| --- | --- | --- |
| Accounts created per address, per hour | 5 | Caps what one machine can mint |
| Accounts created relay-wide, per hour | 500 | Stops a many-address flood from filling the database |
| Rejected registrations per address | 10, then a 15-minute lockout | Bad signatures are cheap to send and cost a verification each |
| Failed authentications per key and per address | 10, then a 15-minute lockout | Stops grinding the login challenge |

All are configurable; see [DEPLOY.md](DEPLOY.md). Only a *created* account spends
signup budget, and a taken username does not count toward a lockout, so fumbling
a name never locks a visitor out.

IPv6 addresses are throttled by their /64, because a single subscriber is
routinely handed a whole /64 and per-address limits would otherwise be
meaningless.

Be clear about what this does and does not buy:

- It makes bulk account creation slow and visible. It does **not** make it
  impossible: someone with many addresses is limited only by the relay-wide cap.
- The relay-wide cap is a trade. Hit it and real visitors are turned away until
  the window resets. That is the price of not letting the database be flooded.
- There is no CAPTCHA, email check, or proof of work. Adding one is a reasonable
  next step if the relay attracts abuse.
- A taken-username attempt is free, so usernames can be probed for availability.
  They are stored hashed, but "is `alice` taken?" is answerable.

Moderation is by public key — usernames are hashed and cannot be listed:

```bash
cargo run -q -p wisp-admin -- accounts
cargo run -q -p wisp-admin -- lock <public-key-hex> --for 24h
cargo run -q -p wisp-admin -- unlock <public-key-hex>
```

`wisp-admin` is not installed on `PATH`, so run it through cargo; the `--`
separates cargo's own flags from the tool's. Or call the built binary directly:
`./target/debug/wisp-admin accounts`. Both default to `wisp.db` in the working
directory — the same file `wisp-relay` defaults to.

### Registration ordering

Registration is sequenced so a failure never leaves a half-made account:

1. Enforce the username rules. Nothing written, nothing sent.
2. Generate and seal the identity.
3. **Stage** the file to the drive. This proves the drive is writable *before*
   the account exists; discovering a full or write-protected drive afterwards
   would leave a registered username with no identity file behind it.
4. Register with the relay.
5. Commit the staged file.

If step 4 fails, the staged file is discarded and the drive is left exactly as
it was. Unreachable-relay and rejected-by-relay are distinguished, because they
decide whether trying again could help.

One edge this does not close: if the relay creates the account but the reply is
lost, a retry generates a *new* key and finds its username taken by the first.
The user picks another name; the orphaned account is harmless but is not cleaned
up.
## Switching drives

Each drive holds one identity, so with more than one plugged in the gate cannot
know which you mean. Every gate screen has **Use a different drive**, and the
unlocked view has **Switch drive**; both open a list of the drives present, each
marked as holding an identity or blank. Choosing one makes that drive the
session's drive.

- **Switching locks.** The key belongs to the drive it was unlocked from, so
  choosing another wipes it and stops messaging first. Nothing carries over
  from one identity to the next.
- **The gate still applies.** A chosen drive goes through the same checks as any
  other: one carrying a copied identity is still denied, never offered a fresh
  setup over it.
- **The choice lasts until that drive is pulled**, after which the app goes back
  to considering every drive.
- Each identity keeps its own message history, stored under its own key, so
  moving between two accounts does not mix them.

To try two users on one machine without two USB sticks, a debug build accepts
several folders as fake drives, separated like `PATH` (`;` on Windows):

```powershell
$env:WISP_FAKE_DRIVE = "C:\tmp\usb-a;C:\tmp\usb-b"; cargo run -p wisp-desktop
```

Create the folders first. Removing a folder acts like pulling that drive. This is
compiled out of release builds.

## What the relay knows

Public keys, hashed usernames, and blobs it cannot read. Also, transiently,\nthe address each request came from, for throttling.

Usernames are stored **only as a SHA-256 digest**. Uniqueness still works — the
digest is the unique index — but the relay holds no browsable directory of who
uses Wisp, and cannot be compelled to produce one. Nothing needs the plaintext:
users find each other by fingerprint, and a display name travels
inside the encrypted payload.

Delivery and deletion happen in one transaction, so there is no window in which
a delivered message is still on disk.

`POST /v1/register`, `POST /v1/auth/challenge`, `POST /v1/auth/verify`,
`GET /v1/ws`, and `GET /v1/whoami` (tells a caller the address it will be
rate-limited on, for checking a deployment's proxy setup). There is no message-history endpoint, no user search, and no
presence — none could exist without the server holding something it may not.

WebSocket authentication happens as the first *frame*, not a query parameter,
so tokens never land in proxy logs.

## Resolved design decisions

| Decision | Choice |
| --- | --- |
| Passphrase frequency | Cached for the session, wiped on removal, lock, or exit. The passphrase itself is never retained — only the decrypted key, in protected memory. |
| Key backup | Strict single-copy. No export path. Losing the drive loses the identity, by design. |
| USB detection | Removable volume watching plus a platform device query. Not raw libusb, which on Windows would require binding a WinUSB driver to the stick and stop it working as a drive. |

---

## Building

Requires the Rust toolchain and, on Windows, the MSVC C++ build tools. No npm
dependencies — the frontend is served as static files.

```bash
cargo test --workspace

# Relay (defaults: wisp.db, 127.0.0.1:8080)
WISP_DB=wisp.db WISP_BIND=127.0.0.1:8080 cargo run -p wisp-server --bin wisp-relay

# Moderate accounts on that same database
cargo run -p wisp-admin -- --db wisp.db accounts

# Desktop app (defaults to http://127.0.0.1:8080)
WISP_RELAY_URL=http://127.0.0.1:8080 cargo run -p wisp-desktop

cargo run -p wisp-usb --example list_volumes
```

The relay's default endpoint is deliberately local. A misconfigured build
should fail to connect, never quietly register a user against someone else's
server.

TLS is not handled by the relay — it expects a terminating proxy (Caddy or
nginx with Let's Encrypt), which is less code in the security-critical path.
Behind a proxy, set `WISP_TRUST_PROXY=1` so throttling sees each visitor's real
address; leave it unset otherwise, because an untrusted `X-Forwarded-For` would
let any caller choose their own rate-limit bucket. The full recipe is in
[DEPLOY.md](DEPLOY.md).

`list_volumes` prints what Wisp can see and what it would bind to — useful for
checking a specific stick reports a device serial *before* registering an
identity on it.

For a distributable installer:

```bash
cargo tauri build               # requires: cargo install tauri-cli
```

---

## Where this stands

### Failed passphrase attempts cannot be rate-limited by the relay

It would be natural to rate-limit failed **passphrase** attempts server-side.
That is not achievable and the code does not pretend otherwise.

The passphrase decrypts `identity.wisp` locally, offline, with the relay
unreachable. The server never observes an attempt, and an attacker holding the
drive grinds away on their own machine. A client-reported failure count would
be defeated by a patched client — precisely the attacker in question.

What defends that path is on the client: Argon2id at 128 MiB per guess, an
enforced entropy floor, and the device fingerprint being a required key input.

What the relay *can* enforce, and does: account creation per address and
relay-wide, rejected registrations per address, authentication attempts per
public key and per address, and account lockout.

### Verified

- **The workspace test suite passes** (`cargo test --workspace`) across ten crates.
- The full Signal path is exercised over a real socket: register, authenticate,
  publish prekeys, fetch a bundle, establish a session, seal, deliver, unseal —
  with an assertion that the sender's key does **not** appear in what the relay
  carries.
- The Windows device query runs against real hardware in its test.
- The relay is exercised end-to-end over a real socket: HTTP registration, the
  challenge/response handshake, WebSocket delivery, offline queueing, and
  lockout enforcement.
- The app launches and correctly renders the zero-access gate; the relay serves
  and the admin CLI writes into its live database.

Relay behaviours with dedicated tests:

- Anyone can register with just a username and a key, and a leftover
  `invite_code` field from an old client is ignored and grants nothing.
- The registration signature binds key and username together, so an intercepted
  registration cannot be rebound to an attacker's key or name; a signature from
  the invite era (`wisp.register.v1`) does not verify.
- One address cannot create more than its per-hour allowance, the relay-wide cap
  holds across addresses, and a lapsed window restarts the count.
- A refused registration (taken name, bad name) spends no signup budget, and a
  username clash does **not** count toward lockout — a fumbled signup must not
  lock a user out.
- Repeated bad signatures lock the sending address out.
- `X-Forwarded-For` is ignored unless the relay was told to trust its proxy;
  when trusted, only the last entry is believed, and IPv6 collapses to a /64.- A challenge is consumed whether or not it verifies, so one nonce cannot be
  ground on.
- A token stops working the moment the account is locked.

Security behaviours with dedicated tests, driven through a mock volume
provider so they are reproducible without hardware:

- A copied identity on another drive is **denied before any passphrase prompt**,
  and the correct passphrase still cannot decrypt it even if the gate is
  bypassed entirely.
- Removing the drive **wipes the key** and drops to zero access.
- Swapping a different stick onto the same drive letter **locks the session**
  rather than going unnoticed.
- A transient enumeration failure is **never** mistaken for removal — that
  would lock the user out at random.
- Every byte of the file header is authenticated; tampering with any of them,
  including downgrading the Argon2 cost, breaks the unlock.
- Parsing never panics on arbitrary input, since it runs on bytes from an
  untrusted removable device.

### Not verified

- **macOS has never been compiled or run.** `crates/wisp-usb/src/macos_impl.rs`
  typechecks against `aarch64-apple-darwin` (`cargo check --target`), which
  covers the IOKit FFI signatures and `libc::statfs` usage, but `cargo check`
  does not link and no Mac was available. It needs a build and a hardware pass.
- **No USB drive was inserted during development**, so the full
  register → unlock → remove cycle has only been exercised against the mock
  provider, not real hardware. Plug a stick in and run `list_volumes` first.
- macOS leaves `volume_serial` unset (see the module docs for why), so a drive
  with **no** device serial cannot be used on macOS at all, and a weakly-bound
  Windows identity will not open there.

### Deliberately deferred

- Removal is detected by polling, so the key survives in memory for up to
  `DEFAULT_POLL_INTERVAL` (500 ms) after the drive is pulled. An event-driven
  upgrade (`WM_DEVICECHANGE` / DiskArbitration) should be layered *on top of*
  the poll, not replace it — both platforms coalesce and drop events, so a
  reconciling poll is needed regardless.
- Memory page locking is best-effort. It reduces incidental exposure to swap;
  it is not a defence against an attacker reading a running, unlocked process.

## Messaging

`crates/wisp-messaging` wraps libsignal, and the app is wired to it. A
sealed-sender, Signal-encrypted message travels through the real relay over a
real socket, and the recipient learns who sent it only from inside the
ciphertext.

### How the client is put together

libsignal's store traits are `#[async_trait(?Send)]`, so the futures touching
them cannot go to `tokio::spawn` on Tauri's multi-threaded runtime. Rather than
fight that, all messaging runs on one owned thread with a current-thread
runtime; the app talks to it over a channel. The `!Send` work never crosses a
thread boundary because it never leaves that thread.

Reading history is the exception — it goes through the shared `Arc<Vault>` from
whichever thread asks, because it is a plain decrypt with no protocol state
behind it.

Messaging starts on unlock and is torn down on lock **and on drive removal**: it
holds its own copy of the identity key, so it cannot be allowed to outlive the
session that authorised it.

A relay that is unreachable does not block unlocking. The user still gets in and
reads the history they already have; the UI shows the connection state instead.

**Building it requires `protoc` on `PATH`** — libsignal's build scripts compile
protobufs. Install from the [protobuf releases][protoc]; the crates are pinned
to tag `v0.99.4` because Signal does not publish them to crates.io, and bumping
that tag is a deliberate act rather than a `cargo update`.

[protoc]: https://github.com/protocolbuffers/protobuf/releases

### The vault

Session state carries the ratchet keys for every conversation, so it is as
sensitive as the identity key itself.

```text
vault_key = HKDF-SHA256(ikm = identity secret, salt = per-vault random,
                        info = "wisp.vault.v1")
record    = XChaCha20-Poly1305(vault_key, nonce, aad = namespace || key)
```

The salt sits in the clear beside the data; the identity secret never does.
Pull the drive and the vault is inert. The AAD binds each ciphertext to its own
slot, so a session blob cannot be lifted into another conversation's row.

### One identity key, not two

libsignal identity keys are Curve25519 and sign with XEdDSA; `ed25519-dalek`
cannot verify those. So an Ed25519 account key and a Signal messaging key could
not have been the same key.

**`identity.wisp` carries a single libsignal `IdentityKeyPair`
(`key_type = 2`), and the relay verifies through
`wisp_core::protocol::verify_signature`.** One key authenticates to the relay
*and* secures messages, which is what makes the fingerprint worth reading
aloud: the value users compare is the one protecting what they say. Two keys
would have meant two secrets to protect and an ambiguous answer to "what is my
fingerprint?".

Applied. Notes:

- Public keys are **32 bytes everywhere** in Wisp's own formats. libsignal
  serialises them to 33 (a `0x05` type prefix), so the prefix is added and
  stripped only at the libsignal boundary — no caller deals in two lengths.
- Verification lives in exactly one function. A second implementation is how
  the relay ends up accepting something the client would not.
- `KeyType::Ed25519Seed` is still decodable, so a pre-Signal identity opens and
  reports [`Error::LegacyKeyType`] rather than silently producing a key nothing
  can verify. Such an identity must be created again — there is no migration,
  because the key type genuinely changed.
- `wisp-core` now depends on libsignal, so building **any** crate needs
  `protoc`.

### Sealed sender

Without it the relay sees *who talks to whom* even though it reads nothing —
often the more damaging leak. Sealed sender moves the sender inside the
ciphertext, encrypted to the recipient.

```text
trust root key --signs--> server certificate --signs--> sender certificate
```

The relay issues certificates from a trust root generated on first start and
persisted, so a restart does not invalidate certificates already in the wild.

**Be precise about what this buys.** The relay could issue itself a certificate
for any identity, so sealed sender does *not* make the relay untrusted for
authenticity — the fingerprint users compare out of band does that. What it
removes is the relay's routine, passive view of the social graph.

The unsealed `WireEnvelope` path still carries the sender in the clear, because
a recipient must know which session to decrypt with. That is exactly what sealed
sender replaces, and the format is versioned so it is a new version rather than
a redesign.

## Biometric re-authentication

`crates/wisp-biometric` wraps Windows Hello via `UserConsentVerifier`. Onboarding
states plainly what the machine supports, and the app degrades to
passphrase-only when it supports nothing.

### The idle lock is a screen lock, not the USB gate

After five minutes without input the session goes **idle**: the screen is
covered, but the identity key is *still in memory*. Coming back needs a Hello
prompt or the passphrase.

That distinction matters, because Hello's `UserConsentVerifier` is a **consent
check, not a key store** — it returns "yes, this is the account owner" and no key
material whatsoever. Nothing it returns could decrypt anything, so the key has to
stay resident for a consent-only prompt to be enough to resume.

So the idle lock stops someone walking up to an unattended machine. It does
**not** stop code already running on that machine, which could read the key from
memory whether the screen is covered or not. Only `Locked` and `NoDevice` mean
the key is genuinely gone — and pulling the drive during idle wipes it, with a
test to prove it.

The cryptographic version would use `KeyCredentialManager` for a TPM-backed key,
wrap the identity key with it, and let idle wipe the plaintext. That is a larger
change than the current design needs; it is the upgrade path if the idle lock ever
needs to be more than a screen cover.

Resuming with a passphrase is throttled on the same counter as the initial
unlock, so idle is not a cheaper place to guess.

**macOS Touch ID is not implemented.** `Availability::Unsupported` is the honest
answer, and it keeps the degrade-gracefully path exercised rather than leaving it
a branch nobody runs. It needs a `LocalAuthentication` bridge and a Mac.

### Next

The access gate, open registration, messaging, biometrics, group chat, and the UI
are done. Remaining:

- **Packaging and distribution** — installers, and a relay your friends can reach.
- A real macOS build.
- A hardware pass with a real USB drive.
- The event-driven USB removal upgrade.

## License

[MIT](LICENSE).
