use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct RegistrationRequest {
    pub username: String,
    #[serde(serialize_with = "as_hex")]
    pub public_key: [u8; 32],
    #[serde(serialize_with = "as_hex_64")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayFailure {
    Unreachable,
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

pub trait RelayClient: Send + Sync + 'static {
    fn register(&self, request: &RegistrationRequest) -> Result<(), RelayError>;
}

fn as_hex<S: serde::Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn as_hex_64<S: serde::Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

pub mod mock {
    use std::sync::{Arc, Mutex};

    use super::{RegistrationRequest, RelayClient, RelayError};

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
