use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// No invite with that hash exists.
    ///
    /// Internal only — see [`ServerError::client_message`].
    #[error("no such invite")]
    InviteUnknown,

    /// The invite exists but is spent, revoked, or expired. Internal only.
    #[error("invite is not redeemable")]
    InviteNotRedeemable,

    #[error("that invite code is not valid")]
    InviteRejected,

    #[error("invite code is malformed: {0}")]
    InviteMalformed(#[from] wisp_invite::InviteError),

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
}

pub type ServerResult<T> = Result<T, ServerError>;

impl ServerError {
    /// What the client is told.
    ///
    /// `InviteUnknown` and `InviteNotRedeemable` both collapse to the same
    /// message. Distinguishing them would turn redemption into an oracle for
    /// which codes exist: an attacker could separate "wrong guess" from "real
    /// code, already used" and confirm hits against a stolen list. The operator
    /// still gets the precise variant in the server log.
    pub fn client_message(&self) -> String {
        match self {
            ServerError::InviteUnknown
            | ServerError::InviteNotRedeemable
            | ServerError::InviteRejected => "that invite code is not valid".into(),
            // Never leak the database's own error text to a client.
            ServerError::Database(_) => "internal error".into(),
            other => other.to_string(),
        }
    }

    /// The HTTP status this maps to.
    pub fn status_code(&self) -> u16 {
        match self {
            ServerError::Database(_) => 500,
            ServerError::RateLimited { .. } | ServerError::AccountLocked { .. } => 429,
            ServerError::AlreadyRegistered => 409,
            ServerError::BadSignature
            | ServerError::BadChallenge
            | ServerError::Unauthenticated => 401,
            ServerError::UnknownAccount | ServerError::NoPreKeys => 404,
            _ => 400,
        }
    }
}
