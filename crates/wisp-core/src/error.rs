use thiserror::Error;

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

    #[error("this identity predates Signal messaging and must be re-created")]
    LegacyKeyType,

    #[error("device reported no usable identifiers; cannot bind an identity to it")]
    NoDeviceIdentifiers,

    #[error("this identity is restricted to a different computer")]
    WrongComputer,
}

pub type Result<T> = std::result::Result<T, Error>;
