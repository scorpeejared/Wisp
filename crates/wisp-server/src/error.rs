use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("this identity or username is already registered")]
    AlreadyRegistered,

    #[error("username is not acceptable")]
    BadUsername,

    #[error("malformed public key")]
    BadPublicKey,

    #[error("signature did not verify")]
    BadSignature,

    #[error("no such account")]
    UnknownAccount,

    #[error("challenge is unknown or expired")]
    BadChallenge,

    #[error("authentication required")]
    Unauthenticated,

    #[error("this account has published no prekeys")]
    NoPreKeys,

    #[error("malformed request: {0}")]
    BadRequest(String),

    #[error("too many attempts; retry in {retry_after} seconds")]
    RateLimited { retry_after: i64 },

    #[error("this account is locked; retry in {retry_after} seconds")]
    AccountLocked { retry_after: i64 },

    #[error("that recipient's mailbox is full; try again later")]
    MailboxFull,
}

pub type ServerResult<T> = Result<T, ServerError>;

impl ServerError {
    pub fn client_message(&self) -> String {
        match self {
            ServerError::Database(_) => "internal error".into(),
            other => other.to_string(),
        }
    }
    pub fn status_code(&self) -> u16 {
        match self {
            ServerError::Database(_) => 500,
            ServerError::RateLimited { .. }
            | ServerError::AccountLocked { .. }
            | ServerError::MailboxFull => 429,
            ServerError::AlreadyRegistered => 409,
            ServerError::BadSignature
            | ServerError::BadChallenge
            | ServerError::Unauthenticated => 401,
            ServerError::UnknownAccount | ServerError::NoPreKeys => 404,
            _ => 400,
        }
    }
}
