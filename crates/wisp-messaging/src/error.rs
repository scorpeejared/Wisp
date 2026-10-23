use thiserror::Error;

#[derive(Debug, Error)]
pub enum MessagingError {
    #[error("local storage error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("could not derive the vault key")]
    VaultKey,

    #[error("could not encrypt a local record")]
    VaultEncrypt,

    /// Wrong identity, corruption, or tampering — deliberately not
    /// distinguished. The common cause is opening a vault with a different
    /// identity than the one that wrote it, which is not an error condition so
    /// much as the design working.
    #[error("could not decrypt a local record")]
    VaultDecrypt,

    #[error("signal protocol error: {0}")]
    Protocol(#[from] libsignal_protocol::SignalProtocolError),

    #[error("no session with {0}")]
    NoSession(String),

    /// libsignal keeps curve/key errors in their own type rather than folding
    /// them into `SignalProtocolError`, so they need their own variant.
    #[error("key error: {0}")]
    Key(String),

    #[error("malformed stored record")]
    Malformed,
}

pub type MessagingResult<T> = Result<T, MessagingError>;
