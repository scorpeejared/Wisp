//! Wisp identity core: the access gate that everything else locks behind.
//!
//! This crate owns the `identity.wisp` container format, its key schedule, the
//! USB device binding derivation, and the passphrase policy. It is deliberately
//! free of platform, UI, and networking dependencies so the security-critical
//! logic can be tested exhaustively on any machine.
//!
//! # The v1 security model
//!
//! ```text
//! Physical USB possession
//!         +
//! USB device binding (hashed identifier match)
//!         +
//! Encrypted identity key
//!         +
//! Strong passphrase
//! ```
//!
//! These are layers, not alternatives. None of them is sufficient alone, and
//! the middle one in particular is **device binding, not hardware
//! authentication** — USB descriptors are forgeable by anyone willing to buy
//! programmable hardware. See [`binding`] for the full statement of what that
//! does and does not buy, and never describe it to a user as proof that a drive
//! is genuine.
//!
//! # Unlock order
//!
//! 1. A removable drive is present and carries an identity file, or the app
//!    renders nothing but "insert USB drive".
//! 2. [`identity::IdentityFile::device_matches`] — mismatch means an immediate
//!    Access Denied, with no passphrase prompt and no app state rendered.
//! 3. Passphrase entry, then [`identity::IdentityFile::unlock`].
//!
//! Step 2 exists for the user's benefit, to separate "wrong drive" from "wrong
//! passphrase". It is not what makes the drive necessary — step 3 needs the
//! device fingerprint as a key input regardless, so skipping step 2 does not
//! open a bypass.

pub mod binding;
pub mod crypto;
pub mod error;
pub mod identity;
pub mod passphrase;
pub mod protocol;
pub mod secret;

pub use binding::{BindingStrength, DeviceIdentifiers};
pub use error::{Error, Result};
pub use identity::{IdentityFile, KeyType, UnlockedIdentity, IDENTITY_DIR, IDENTITY_FILENAME};
pub use secret::SecretBytes;
