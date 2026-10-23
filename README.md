# Wisp

Private, invite-only desktop chat for Windows and macOS. The server is a dumb
relay; the client does all the work; access is gated by physical possession of a
specific USB drive plus a passphrase.

**Status: build order steps 1-6 are complete.** The USB access gate, the
invite-only relay, Signal messaging with sealed sender, Windows Hello
re-authentication, group chat, and the UI all work. **Packaging and
distribution (step 7) remain.** See [Where this stands](#where-this-stands).

The build order was reordered once: invite codes moved ahead of messaging,
because the relay is a shared prerequisite for both and the onboarding flow is
incoherent without them.

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
| `crates/wisp-invite` | Invite code format: generation, encoding, checksum, parsing. |
| `crates/wisp-usb` | Removable volume discovery, platform device identifier queries, insert/remove watching. |
| `crates/wisp-session` | The access gate state machine. Owns the only decrypted key in the process. |
| `crates/wisp-server` | The relay: invite redemption, accounts, throttling, and transient encrypted delivery over WebSocket. |
| `crates/wisp-admin` | Owner CLI for issuing and revoking invites and locking accounts. |
| `src-tauri` | Tauri shell. Thin — it holds no security logic. |
| `src` | Frontend. Plain HTML/CSS/JS, no npm dependencies, no build step. |
| `tools/make-icons.mjs` | Generates app icons procedurally using only Node's built-in `zlib`. |
| `tools/check-ui.mjs` | Verifies every selector `main.js` uses exists in `index.html`. |
| `wisp-project-prompt.md` | The original project brief. Where this README says "the spec", this is it. |

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

## Invite-only onboarding

Codes look like `WISP-ENG1-H8FH-9J3Q-5BAA`: 64 bits of entropy in
[Crockford base32][crockford] — so `I`/`L` decode as `1` and `O` as `0`, and the
usual transcription mistakes self-correct — plus a 15-bit checksum.

The checksum earns its place: a mistyped code is caught on the client, before
it reaches the network. Redemption is rate-limited per address, so without a
local check a user fumbling one character would burn attempts against their own
invite and lock themselves out of onboarding.

The relay stores **only `SHA-256` of the code**, never the code itself. A code
is a bearer credential — anyone holding it can create an account — so a leaked
database must yield no usable invites. `wisp-admin` prints each code once, at
generation, and cannot recover it afterwards. (Plain SHA-256 is right here,
unlike for a passphrase: the input is 64 bits of uniform CSPRNG output, so there
is no dictionary to attack and nothing a slow KDF would buy.)

`wisp-admin` is not installed on `PATH`, so run it through cargo. The `--`
separates cargo's own flags from the tool's; without it cargo tries to parse
`--expires-in` itself and fails.

```bash
cargo run -q -p wisp-admin -- new --expires-in 7d --note "for bob"
cargo run -q -p wisp-admin -- list
cargo run -q -p wisp-admin -- revoke WISP-ENG1-H8FH-9J3Q-5BAA
cargo run -q -p wisp-admin -- lock <public-key-hex> --for 24h
```

Or call the built binary directly, which needs no `--`:

```bash
./target/debug/wisp-admin new --expires-in 7d --note "for bob"
```

Both default to `wisp.db` in the working directory — the same file
`wisp-relay` defaults to, so running everything from the repository root makes
them line up with no configuration.

### Registration ordering

Registration is sequenced so a failure never spends a single-use code for
nothing:

1. Check the code's format **locally** — a typo costs no round trip.
2. Enforce the passphrase and username rules. Nothing written, nothing sent.
3. Generate and seal the identity.
4. **Stage** the file to the drive. This proves the drive is writable *before*
   the invite is spent; discovering a full or write-protected drive afterwards
   would consume the code and leave the user with no way back.
5. Redeem with the relay.
6. Commit the staged file.

If step 5 fails, the staged file is discarded and the drive is left exactly as
it was. Unreachable-relay and rejected-by-relay are distinguished, because they
decide whether the user should retry with the same code.

[crockford]: https://www.crockford.com/base32.html

## What the relay knows

Public keys, hashed usernames, invite records, and blobs it cannot read.

Usernames are stored **only as a SHA-256 digest**. Uniqueness still works — the
digest is the unique index — but the relay holds no browsable directory of who
uses Wisp, and cannot be compelled to produce one. Nothing needs the plaintext:
users find each other by fingerprint (spec §5), and a display name travels
inside the encrypted payload.

Delivery and deletion happen in one transaction, so there is no window in which
a delivered message is still on disk.

`POST /v1/register`, `POST /v1/auth/challenge`, `POST /v1/auth/verify`, and
`GET /v1/ws`. There is no message-history endpoint, no user search, and no
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

# Issue an invite against that same database
cargo run -p wisp-admin -- --db wisp.db new --expires-in 7d --note "for bob"

# Desktop app (defaults to http://127.0.0.1:8080)
WISP_RELAY_URL=http://127.0.0.1:8080 cargo run -p wisp-desktop

cargo run -p wisp-usb --example list_volumes
```

The relay's default endpoint is deliberately local. A misconfigured build
should fail to connect, never quietly register a user against someone else's
server.

TLS is not handled by the relay — it expects a terminating proxy (Caddy or
nginx with Let's Encrypt), which is less code in the security-critical path.
**Behind a proxy the throttling scope needs a trusted forwarded-header reading**
(see `ClientScope` in `routes.rs`); an untrusted `X-Forwarded-For` would let any
caller choose their own rate-limit bucket.

`list_volumes` prints what Wisp can see and what it would bind to — useful for
checking a specific stick reports a device serial *before* registering an
identity on it.

For a distributable installer:

```bash
cargo tauri build               # requires: cargo install tauri-cli
```

---

## Where this stands

### One spec requirement that cannot be met

The spec asks for failed **passphrase** attempts to be rate-limited
server-side. That is not achievable and the code does not pretend otherwise.

The passphrase decrypts `identity.wisp` locally, offline, with the relay
unreachable. The server never observes an attempt, and an attacker holding the
drive grinds away on their own machine. A client-reported failure count would
be defeated by a patched client — precisely the attacker in question.

What defends that path is on the client: Argon2id at 128 MiB per guess, an
enforced entropy floor, and the device fingerprint being a required key input.

What the relay *can* enforce, and does: invite-redemption attempts per address,
authentication attempts per public key and per address, and account lockout.

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

- An invite works **exactly once**, and redemption plus account creation happen
  in one transaction, so concurrent redemption cannot double-spend.
- A failed registration (duplicate username) **rolls the redemption back** —
  the code stays usable.
- A client cannot tell an unknown code from a spent one, so redemption is not
  an oracle for which codes exist.
- The registration signature binds invite, key, and username together, so an
  intercepted code cannot be rebound to an attacker's key.
- A username clash does **not** count toward lockout — a fumbled signup must
  not lock a user out of onboarding.
- A challenge is consumed whether or not it verifies, so one nonce cannot be
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
change than the spec called for; it is the upgrade path if the idle lock ever
needs to be more than a screen cover.

Resuming with a passphrase is throttled on the same counter as the initial
unlock, so idle is not a cheaper place to guess.

**macOS Touch ID is not implemented.** `Availability::Unsupported` is the honest
answer, and it keeps the degrade-gracefully path exercised rather than leaving it
a branch nobody runs. It needs a `LocalAuthentication` bridge and a Mac.

### Next

Steps 1–6 are complete (access gate, invites, messaging, biometrics, group
chat, UI). Remaining:

7. **Deployment** — installer packaging and distribution.

And the standing items: a real macOS build, a hardware pass with a real USB
drive, TLS/proxy configuration, and the event-driven USB removal upgrade.

## License

[MIT](LICENSE).
