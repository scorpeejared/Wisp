//! The client's view of the relay.
//!
//! [`RelayClient`] is a trait rather than a concrete HTTP client so the access
//! gate can be tested without a server, and so no networking crate reaches
//! `wisp-session` — the transport lives in the Tauri layer, where it belongs.

use serde::Serialize;

/// What the client sends to redeem an invite and create an account.
#[derive(Debug, Clone, Serialize)]
pub struct RegistrationRequest {
    pub invite_code: String,
    /// Already normalised to canonical form.
    pub username: String,
    #[serde(serialize_with = "as_hex")]
    pub public_key: [u8; 32],
    #[serde(serialize_with = "as_hex_64")]
    pub signature: [u8; 64],
}

/// Why a relay call failed, and whether trying again could help.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayFailure {
    /// The request never reached the relay, or the reply never came back.
    ///
    /// Distinguished from `Rejected` because it decides what happens to the
    /// invite code: an unreachable relay has almost certainly not spent it, so
    /// the user should retry with the same code. A rejection means the relay
    /// made a decision and retrying will get the same answer.
    Unreachable,
    /// The relay answered, and the answer was no.
    Rejected,
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct RelayError {
    pub message: String,
    pub failure: RelayFailure,
}

impl RelayError {
    pub fn unreachable(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            failure: RelayFailure::Unreachable,
        }
    }

    pub fn rejected(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            failure: RelayFailure::Rejected,
        }
    }

    pub fn is_unreachable(&self) -> bool {
        self.failure == RelayFailure::Unreachable
    }
}

/// Blocking client for the relay's registration endpoint.
///
/// Blocking on purpose: registration is a single user-initiated step inside an
/// already-synchronous unlock flow, and making the whole session machine async
/// to serve one request would be a poor trade.
pub trait RelayClient: Send + Sync + 'static {
    fn register(&self, request: &RegistrationRequest) -> Result<(), RelayError>;
}

fn as_hex<S: serde::Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn as_hex_64<S: serde::Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// Test doubles.
pub mod mock {
    use std::sync::{Arc, Mutex};

    use super::{RegistrationRequest, RelayClient, RelayError};

    /// Records what it was asked and answers however it was told to.
    #[derive(Clone, Default)]
    pub struct MockRelay {
        state: Arc<Mutex<MockState>>,
    }

    #[derive(Default)]
    struct MockState {
        seen: Vec<RegistrationRequest>,
        response: Option<RelayError>,
    }

    impl MockRelay {
        pub fn accepting() -> Self {
            Self::default()
        }

        pub fn failing(error: RelayError) -> Self {
            let this = Self::default();
            this.state.lock().unwrap().response = Some(error);
            this
        }

        pub fn set_response(&self, error: Option<RelayError>) {
            self.state.lock().unwrap().response = error;
        }

        /// Every registration attempt it received.
        pub fn requests(&self) -> Vec<RegistrationRequest> {
            self.state.lock().unwrap().seen.clone()
        }
    }

    impl RelayClient for MockRelay {
        fn register(&self, request: &RegistrationRequest) -> Result<(), RelayError> {
            let mut state = self.state.lock().unwrap();
            state.seen.push(request.clone());
            match &state.response {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        }
    }
}
