//! HTTP transport for the relay.
//!
//! Lives here rather than in `wisp-session` so the access gate stays free of
//! networking code and can be tested without a server.

use wisp_session::{RegistrationRequest, RelayClient, RelayError};

/// Where the relay lives when nothing else is configured.
///
/// A local default rather than a hosted one on purpose: a misconfigured build
/// should fail to connect, never quietly register a user against somebody
/// else's server.
const DEFAULT_RELAY_URL: &str = "http://127.0.0.1:8080";

const TIMEOUT_SECS: u64 = 20;

pub struct HttpRelayClient {
    base_url: String,
}

impl HttpRelayClient {
    pub fn from_env() -> Self {
        let base_url = std::env::var("WISP_RELAY_URL")
            .unwrap_or_else(|_| DEFAULT_RELAY_URL.to_string())
            .trim_end_matches('/')
            .to_string();
        Self { base_url }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

/// What a client needs before it can send anything.
pub struct SessionCredentials {
    pub token: String,
    pub sender_certificate: Vec<u8>,
    pub trust_root: [u8; 32],
}

impl HttpRelayClient {
    /// The relay's WebSocket URL, derived from the HTTP one.
    ///
    /// Derived rather than configured separately so the two can never point at
    /// different servers — a mismatch would authenticate against one relay and
    /// deliver through another.
    pub fn websocket_url(&self) -> String {
        let base = self
            .base_url
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1);
        format!("{base}/v1/ws")
    }

    fn get(&self, path: &str, token: &str) -> Result<serde_json::Value, RelayError> {
        Self::read(
            ureq::get(&format!("{}{path}", self.base_url))
                .timeout(std::time::Duration::from_secs(TIMEOUT_SECS))
                .set("Authorization", &format!("Bearer {token}"))
                .call(),
        )
    }

    fn post(
        &self,
        path: &str,
        token: Option<&str>,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, RelayError> {
        let mut request = ureq::post(&format!("{}{path}", self.base_url))
            .timeout(std::time::Duration::from_secs(TIMEOUT_SECS));
        if let Some(token) = token {
            request = request.set("Authorization", &format!("Bearer {token}"));
        }
        Self::read(request.send_json(body))
    }

    fn read(
        outcome: Result<ureq::Response, ureq::Error>,
    ) -> Result<serde_json::Value, RelayError> {
        match outcome {
            Ok(response) => response
                .into_json()
                .map_err(|e| RelayError::rejected(format!("unreadable relay reply: {e}"))),
            Err(ureq::Error::Status(_, response)) => Err(RelayError::rejected(
                response
                    .into_json::<serde_json::Value>()
                    .ok()
                    .and_then(|body| body["error"].as_str().map(str::to_string))
                    .unwrap_or_else(|| "the relay refused the request".to_string()),
            )),
            Err(ureq::Error::Transport(t)) => {
                Err(RelayError::unreachable(format!("could not reach the relay: {t}")))
            }
        }
    }

    /// Completes the challenge/response handshake and fetches the sealed-sender
    /// material, so a caller gets everything needed to send in one step.
    pub fn authenticate(
        &self,
        public_key: &[u8; 32],
        sign: impl Fn(&[u8]) -> Result<[u8; 64], String>,
    ) -> Result<SessionCredentials, RelayError> {
        let public_hex = hex(public_key);

        let challenge = self.post(
            "/v1/auth/challenge",
            None,
            serde_json::json!({ "public_key": public_hex }),
        )?;
        let nonce: [u8; 32] = challenge["nonce"]
            .as_str()
            .and_then(unhex)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| RelayError::rejected("relay sent a malformed challenge"))?;

        let signature = sign(&wisp_core::protocol::auth_message(&nonce))
            .map_err(RelayError::rejected)?;

        let verified = self.post(
            "/v1/auth/verify",
            None,
            serde_json::json!({
                "public_key": public_hex,
                "signature": hex(&signature),
            }),
        )?;
        let token = verified["token"]
            .as_str()
            .ok_or_else(|| RelayError::rejected("relay issued no token"))?
            .to_string();

        let certificate = self.post("/v1/sender-certificate", Some(&token), serde_json::json!({}))?;
        let sender_certificate = certificate["certificate"]
            .as_str()
            .and_then(decode_base64)
            .ok_or_else(|| RelayError::rejected("relay sent a malformed certificate"))?;
        let trust_root: [u8; 32] = certificate["trust_root"]
            .as_str()
            .and_then(decode_base64)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| RelayError::rejected("relay sent a malformed trust root"))?;

        Ok(SessionCredentials {
            token,
            sender_certificate,
            trust_root,
        })
    }

    /// Publishes our prekeys so others can start sessions while we are offline.
    pub fn publish_prekeys(
        &self,
        token: &str,
        published: &wisp_messaging::PublishedPreKeys,
    ) -> Result<(), RelayError> {
        self.post(
            "/v1/prekeys",
            Some(token),
            serde_json::json!({
                "registration_id": published.registration_id,
                "identity_key": encode_base64(&published.identity_key),
                "signed_prekey_id": published.signed_prekey_id,
                "signed_prekey_public": encode_base64(&published.signed_prekey_public),
                "signed_prekey_signature": encode_base64(&published.signed_prekey_signature),
                "kyber_prekey_id": published.kyber_prekey_id,
                "kyber_prekey_public": encode_base64(&published.kyber_prekey_public),
                "kyber_prekey_signature": encode_base64(&published.kyber_prekey_signature),
                "one_time_prekeys": published
                    .one_time_prekeys
                    .iter()
                    .map(|(id, key)| serde_json::json!({ "id": id, "public": encode_base64(key) }))
                    .collect::<Vec<_>>(),
            }),
        )?;
        Ok(())
    }

    /// Fetches someone's bundle, consuming one of their one-time prekeys.
    pub fn fetch_prekeys(
        &self,
        token: &str,
        target: &[u8; 32],
    ) -> Result<(wisp_messaging::PublishedPreKeys, Option<(u32, Vec<u8>)>), RelayError> {
        let body = self.get(&format!("/v1/prekeys/{}", hex(target)), token)?;

        let field = |name: &str| -> Result<Vec<u8>, RelayError> {
            body[name]
                .as_str()
                .and_then(decode_base64)
                .ok_or_else(|| RelayError::rejected(format!("bundle is missing {name}")))
        };
        let number = |name: &str| -> Result<u32, RelayError> {
            body[name]
                .as_u64()
                .map(|v| v as u32)
                .ok_or_else(|| RelayError::rejected(format!("bundle is missing {name}")))
        };

        let published = wisp_messaging::PublishedPreKeys {
            registration_id: number("registration_id")?,
            identity_key: field("identity_key")?,
            signed_prekey_id: number("signed_prekey_id")?,
            signed_prekey_public: field("signed_prekey_public")?,
            signed_prekey_signature: field("signed_prekey_signature")?,
            kyber_prekey_id: number("kyber_prekey_id")?,
            kyber_prekey_public: field("kyber_prekey_public")?,
            kyber_prekey_signature: field("kyber_prekey_signature")?,
            one_time_prekeys: Vec::new(),
        };

        // Absent when the pool is exhausted; X3DH proceeds without it.
        let one_time = body["one_time_prekey"].as_object().and_then(|prekey| {
            Some((
                prekey["id"].as_u64()? as u32,
                prekey["public"].as_str().and_then(decode_base64)?,
            ))
        });

        Ok((published, one_time))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect()
}

fn encode_base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

impl RelayClient for HttpRelayClient {
    fn register(&self, request: &RegistrationRequest) -> Result<(), RelayError> {
        let response = ureq::post(&format!("{}/v1/register", self.base_url))
            .timeout(std::time::Duration::from_secs(TIMEOUT_SECS))
            .send_json(request);

        match response {
            Ok(_) => Ok(()),

            // The relay answered and said no. Surface its message — it is
            // already the sanitised, client-safe one.
            Err(ureq::Error::Status(_, response)) => Err(RelayError::rejected(
                response
                    .into_json::<serde_json::Value>()
                    .ok()
                    .and_then(|body| body["error"].as_str().map(str::to_string))
                    .unwrap_or_else(|| "the relay rejected the registration".to_string()),
            )),

            // Never reached the relay, so the invite code is almost certainly
            // still unspent and the user can retry with it.
            Err(ureq::Error::Transport(transport)) => Err(RelayError::unreachable(format!(
                "could not reach the relay: {transport}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_slashes_are_trimmed() {
        // Otherwise the request URL would contain a double slash.
        std::env::set_var("WISP_RELAY_URL", "https://relay.example.com/");
        assert_eq!(
            HttpRelayClient::from_env().base_url(),
            "https://relay.example.com"
        );
        std::env::remove_var("WISP_RELAY_URL");
    }

    #[test]
    fn falls_back_to_the_local_default() {
        std::env::remove_var("WISP_RELAY_URL");
        assert_eq!(HttpRelayClient::from_env().base_url(), DEFAULT_RELAY_URL);
    }

    /// An unreachable relay must be reported as retryable, so the caller keeps
    /// the invite code rather than discarding it as spent.
    #[test]
    fn an_unreachable_relay_is_reported_as_retryable() {
        let client = HttpRelayClient {
            // Reserved by RFC 5737 for documentation; never routable.
            base_url: "http://192.0.2.1:1".to_string(),
        };
        let error = client
            .register(&RegistrationRequest {
                invite_code: "WISP-A1B2-C3D4-E5F6-G7H8".into(),
                username: "alice".into(),
                public_key: [0u8; 32],
                signature: [0u8; 64],
            })
            .unwrap_err();

        assert!(error.is_unreachable(), "got {error:?}");
    }
}
