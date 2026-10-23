use thiserror::Error;

/// Errors surfaced by the identity/access-gate layer.
///
/// These are deliberately coarse where an attacker is watching. In particular
/// [`Error::Decrypt`] never distinguishes "wrong passphrase" from "corrupt
/// file" from "tampered header" — all three are one indistinguishable failure.
/// The one distinction Wisp *does* draw on purpose is wrong-USB vs.
/// wrong-passphrase, which happens a layer up in the unlock state machine.
#[derive(Debug, Error)]
pub enum Error {
    #[error("not a Wisp identity file")]
    BadMagic,

    #[error("identity file format version {found} is not supported (this build understands up to {supported})")]
    UnsupportedVersion { found: u16, supported: u16 },

    #[error("identity file is truncated or malformed")]
    Malformed,

    #[error("unsupported key derivation function id {0}")]
    UnsupportedKdf(u8),

    #[error("unsupported AEAD id {0}")]
    UnsupportedAead(u8),

    #[error("invalid Argon2 parameters")]
    BadKdfParams,

    #[error("key derivation failed")]
    KdfFailed,

    /// Covers wrong passphrase, wrong USB device, corruption, and tampering.
    /// Do not decompose this into more specific variants.
    #[error("could not decrypt identity")]
    Decrypt,

    #[error("could not encrypt identity")]
    Encrypt,

    #[error("passphrase rejected: {0}")]
    WeakPassphrase(#[from] crate::passphrase::PassphraseRejection),

    #[error("username must be 3-32 characters of a-z, 0-9, underscore or hyphen")]
    BadUsername,

    #[error("key material must be 1-1024 bytes")]
    BadKeyMaterial,

    /// A format-version-1 identity holding a raw Ed25519 seed, from before the
    /// identity key became the Signal identity key. Readable, but nothing can
    /// be done with it — such an identity has to be created again.
    #[error("this identity predates Signal messaging and must be re-created")]
    LegacyKeyType,

    #[error("device reported no usable identifiers; cannot bind an identity to it")]
    NoDeviceIdentifiers,

    /// The identity is restricted to a different computer.
    ///
    /// Distinct from [`Error::Decrypt`] on purpose: like wrong-drive, telling
    /// an honest user which factor is wrong is worth far more than the
    /// negligible information it gives an attacker who already holds the file.
    #[error("this identity is restricted to a different computer")]
    WrongComputer,
}

pub type Result<T> = std::result::Result<T, Error>;
