use thiserror::Error;

#[derive(Debug, Error)]
pub enum MessagingError {
    #[error("local storage error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("could not derive the vault key")]
    VaultKey,

    #[error("could not encrypt a local record")]
    VaultEncrypt,

    #[error("could not decrypt a local record")]
    VaultDecrypt,

    #[error("signal protocol error: {0}")]
    Protocol(#[from] libsignal_protocol::SignalProtocolError),

    #[error("no session with {0}")]
    NoSession(String),

    #[error("key error: {0}")]
    Key(String),

    #[error("malformed stored record")]
    Malformed,
}

pub type MessagingResult<T> = Result<T, MessagingError>;
