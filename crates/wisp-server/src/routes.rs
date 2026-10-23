//! HTTP and WebSocket surface.
//!
//! Four endpoints and a socket. There is no message history endpoint, no user
//! search, no presence — none of those can exist without the server holding
//! something it is not allowed to hold.
//!
//! ```text
//! GET  /health
//! POST /v1/register        invite code -> account
//! POST /v1/auth/challenge  public key  -> nonce
//! POST /v1/auth/verify     signature   -> session token
//! GET  /v1/ws              authenticated envelope stream
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::hub::Hub;
use crate::{PublicKey, ServerError};

pub type AppState = Arc<Hub>;

pub fn router(hub: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/register", post(register))
        .route("/v1/auth/challenge", post(auth_challenge))
        .route("/v1/auth/verify", post(auth_verify))
        .route("/v1/prekeys", post(publish_prekeys).get(prekey_status))
        .route("/v1/prekeys/{public_key}", get(fetch_prekeys))
        .route("/v1/sender-certificate", post(sender_certificate))
        .route("/v1/ws", get(websocket))
        .with_state(hub)
}

// --- Error rendering --------------------------------------------------------

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        // Log the precise variant, return the sanitised one. The two differ
        // deliberately for invite errors — see `ServerError::client_message`.
        if self.status_code() >= 500 {
            eprintln!("[wisp] internal error: {self}");
        }
        let status =
            StatusCode::from_u16(self.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (
            status,
            Json(ErrorBody {
                error: self.client_message(),
            }),
        )
            .into_response()
    }
}

// --- Client identity for throttling ----------------------------------------

/// The address used as a throttling scope.
///
/// Falls back to `"unknown"` when the connection info is absent, which happens
/// in tests. Behind a reverse proxy this must be replaced with a trusted
/// forwarded-header reading — an untrusted `X-Forwarded-For` would let any
/// caller pick their own rate-limit bucket, so it is deliberately not read here.
struct ClientScope(String);

impl<S: Send + Sync> FromRequestParts<S> for ClientScope {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(ClientScope(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0.ip().to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        ))
    }
}

// --- Endpoints --------------------------------------------------------------

async fn health() -> &'static str {
    "ok"
}

#[derive(Deserialize)]
struct RegisterRequest {
    invite_code: String,
    username: String,
    /// 64 hex characters.
    public_key: String,
    /// 128 hex characters.
    signature: String,
}

async fn register(
    State(hub): State<AppState>,
    ClientScope(scope): ClientScope,
    Json(body): Json<RegisterRequest>,
) -> Result<StatusCode, ServerError> {
    let public_key = parse_public_key(&body.public_key)?;
    let signature = parse_hex(&body.signature).ok_or(ServerError::BadSignature)?;

    hub.relay.register(
        &scope,
        &body.invite_code,
        &body.username,
        &public_key,
        &signature,
    )?;
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
struct ChallengeRequest {
    public_key: String,
}

#[derive(Serialize)]
struct ChallengeResponse {
    nonce: String,
}

async fn auth_challenge(
    State(hub): State<AppState>,
    Json(body): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, ServerError> {
    let public_key = parse_public_key(&body.public_key)?;
    let nonce = hub.relay.issue_challenge(&public_key)?;
    Ok(Json(ChallengeResponse { nonce: hex(&nonce) }))
}

#[derive(Deserialize)]
struct VerifyRequest {
    public_key: String,
    signature: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    token: String,
    expires_in: u64,
}

async fn auth_verify(
    State(hub): State<AppState>,
    ClientScope(scope): ClientScope,
    Json(body): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ServerError> {
    let public_key = parse_public_key(&body.public_key)?;
    let signature = parse_hex(&body.signature).ok_or(ServerError::BadSignature)?;

    let token = hub.authenticate(&scope, &public_key, &signature)?;
    Ok(Json(VerifyResponse {
        token,
        expires_in: crate::hub::TOKEN_TTL.as_secs(),
    }))
}

// --- Prekeys ----------------------------------------------------------------

/// Proof that the caller holds a valid session token.
///
/// Prekey publication has to be authenticated or anyone could overwrite anyone
/// else's prekeys and make them unreachable. *Fetching* is authenticated too —
/// not because bundles are secret, but so that an anonymous caller cannot drain
/// a user's one-time prekey pool, which would silently degrade the forward
/// secrecy of everyone who messages them next.
struct Authenticated(PublicKey);

impl FromRequestParts<AppState> for Authenticated {
    type Rejection = ServerError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or(ServerError::Unauthenticated)?;

        let public_key = state
            .resolve_token(token)
            .ok_or(ServerError::Unauthenticated)?;
        // A token issued before the account was locked must stop working.
        state.ensure_active(&public_key)?;
        Ok(Authenticated(public_key))
    }
}

/// Key material on the wire, base64 rather than JSON number arrays.
///
/// A Kyber public key is 1568 bytes; as a JSON array that is roughly 6 KB of
/// digits and commas per publish.
#[derive(Debug, Deserialize, Serialize)]
struct WireBundle {
    registration_id: i64,
    identity_key: String,
    signed_prekey_id: i64,
    signed_prekey_public: String,
    signed_prekey_signature: String,
    kyber_prekey_id: Option<i64>,
    kyber_prekey_public: Option<String>,
    kyber_prekey_signature: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct WireOneTimePreKey {
    id: i64,
    public: String,
}

#[derive(Debug, Deserialize)]
struct PublishPreKeysRequest {
    #[serde(flatten)]
    bundle: WireBundle,
    #[serde(default)]
    one_time_prekeys: Vec<WireOneTimePreKey>,
}

#[derive(Debug, Serialize)]
struct PublishPreKeysResponse {
    one_time_prekeys_stored: usize,
    one_time_prekeys_available: i64,
}

#[derive(Debug, Serialize)]
struct FetchedBundleResponse {
    #[serde(flatten)]
    bundle: WireBundle,
    one_time_prekey: Option<WireOneTimePreKey>,
}

#[derive(Debug, Serialize)]
struct PreKeyStatusResponse {
    one_time_prekeys_available: i64,
}

impl WireBundle {
    fn decode(self) -> Result<crate::store::PreKeyBundle, ServerError> {
        let required = |field: &str, value: &str| -> Result<Vec<u8>, ServerError> {
            BASE64
                .decode(value)
                .map_err(|_| ServerError::BadRequest(format!("{field} is not valid base64")))
        };
        let optional = |field: &'static str,
                        value: Option<String>|
         -> Result<Option<Vec<u8>>, ServerError> {
            value.map(|v| required(field, &v)).transpose()
        };

        Ok(crate::store::PreKeyBundle {
            identity_key: required("identity_key", &self.identity_key)?,
            registration_id: self.registration_id,
            signed_prekey_id: self.signed_prekey_id,
            signed_prekey_public: required("signed_prekey_public", &self.signed_prekey_public)?,
            signed_prekey_signature: required(
                "signed_prekey_signature",
                &self.signed_prekey_signature,
            )?,
            kyber_prekey_id: self.kyber_prekey_id,
            kyber_prekey_public: optional("kyber_prekey_public", self.kyber_prekey_public)?,
            kyber_prekey_signature: optional(
                "kyber_prekey_signature",
                self.kyber_prekey_signature,
            )?,
        })
    }

    fn encode(bundle: crate::store::PreKeyBundle) -> Self {
        Self {
            registration_id: bundle.registration_id,
            identity_key: BASE64.encode(&bundle.identity_key),
            signed_prekey_id: bundle.signed_prekey_id,
            signed_prekey_public: BASE64.encode(&bundle.signed_prekey_public),
            signed_prekey_signature: BASE64.encode(&bundle.signed_prekey_signature),
            kyber_prekey_id: bundle.kyber_prekey_id,
            kyber_prekey_public: bundle.kyber_prekey_public.map(|v| BASE64.encode(v)),
            kyber_prekey_signature: bundle.kyber_prekey_signature.map(|v| BASE64.encode(v)),
        }
    }
}

/// Publishes (or rotates) the caller's own prekeys.
///
/// Scoped to the authenticated account, never to a key in the request body —
/// otherwise the endpoint would let anyone replace anyone's prekeys.
async fn publish_prekeys(
    State(hub): State<AppState>,
    Authenticated(owner): Authenticated,
    Json(body): Json<PublishPreKeysRequest>,
) -> Result<Json<PublishPreKeysResponse>, ServerError> {
    let bundle = body.bundle.decode()?;

    let mut one_time = Vec::with_capacity(body.one_time_prekeys.len());
    for prekey in body.one_time_prekeys {
        one_time.push(crate::store::OneTimePreKey {
            id: prekey.id,
            public: BASE64
                .decode(&prekey.public)
                .map_err(|_| ServerError::BadRequest("one-time prekey is not valid base64".into()))?,
        });
    }

    let (stored, available) = hub.relay.with_store(|store| -> Result<_, ServerError> {
        store.put_prekey_bundle(&owner, &bundle)?;
        let stored = store.add_one_time_prekeys(&owner, &one_time)?;
        let available = store.one_time_prekey_count(&owner)?;
        Ok((stored, available))
    })?;

    Ok(Json(PublishPreKeysResponse {
        one_time_prekeys_stored: stored,
        one_time_prekeys_available: available,
    }))
}

/// How many one-time prekeys the caller has left, so a client can top up before
/// running dry.
async fn prekey_status(
    State(hub): State<AppState>,
    Authenticated(owner): Authenticated,
) -> Result<Json<PreKeyStatusResponse>, ServerError> {
    let available = hub
        .relay
        .with_store(|store| store.one_time_prekey_count(&owner))?;
    Ok(Json(PreKeyStatusResponse {
        one_time_prekeys_available: available,
    }))
}

/// Fetches someone's bundle to start a session, consuming one one-time prekey.
async fn fetch_prekeys(
    State(hub): State<AppState>,
    _auth: Authenticated,
    axum::extract::Path(public_key): axum::extract::Path<String>,
) -> Result<Json<FetchedBundleResponse>, ServerError> {
    let target = parse_public_key(&public_key)?;

    let fetched = hub
        .relay
        .with_store(|store| store.take_prekey_bundle(&target))?
        .ok_or(ServerError::NoPreKeys)?;

    Ok(Json(FetchedBundleResponse {
        bundle: WireBundle::encode(fetched.bundle),
        one_time_prekey: fetched.one_time.map(|prekey| WireOneTimePreKey {
            id: prekey.id,
            public: BASE64.encode(&prekey.public),
        }),
    }))
}

// --- Sealed sender ----------------------------------------------------------

#[derive(Debug, Serialize)]
struct SenderCertificateResponse {
    /// Base64 libsignal `SenderCertificate`.
    certificate: String,
    /// Base64 trust root public key, for validating certificates from others.
    trust_root: String,
    expires_in: u64,
}

/// Issues the caller a certificate binding their own identity key to itself.
///
/// Issued for the **authenticated** account, never for a key named in the
/// request — otherwise the endpoint would mint a certificate impersonating
/// anyone who asked.
///
/// The trust root is returned alongside so a client learns it from the same
/// relay it is already talking to. That is worth being honest about: it is
/// trust-on-first-use against the relay, and a hostile relay could hand out its
/// own root and issue itself certificates for any identity. Sealed sender
/// removes the relay's *passive* view of who talks to whom; it does not make
/// the relay untrusted for authenticity. The fingerprint users compare out of
/// band is what does that.
async fn sender_certificate(
    State(hub): State<AppState>,
    Authenticated(owner): Authenticated,
) -> Result<Json<SenderCertificateResponse>, ServerError> {
    let authority = hub.authority();

    let certificate = authority
        .issue(&owner, wisp_messaging::CERTIFICATE_VALIDITY)
        .map_err(|e| ServerError::BadRequest(e.to_string()))?;
    let trust_root = authority
        .trust_root_public()
        .map_err(|e| ServerError::BadRequest(e.to_string()))?;

    Ok(Json(SenderCertificateResponse {
        certificate: BASE64.encode(&certificate),
        trust_root: BASE64.encode(trust_root),
        expires_in: wisp_messaging::CERTIFICATE_VALIDITY.as_secs(),
    }))
}

// --- WebSocket --------------------------------------------------------------

/// Frames the client may send.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientFrame {
    /// Must be the first frame on the socket.
    Auth { token: String },
    Send {
        /// Recipient public key, 64 hex characters.
        recipient: String,
        /// Base64 sealed envelope.
        envelope: String,
    },
}

/// Frames the server sends.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerFrame {
    Ready,
    Envelope { data: String },
    Accepted,
    Error { message: String },
}

async fn websocket(ws: WebSocketUpgrade, State(hub): State<AppState>) -> Response {
    ws.on_upgrade(move |socket| serve_socket(socket, hub))
}

/// Authentication happens as the first *frame*, not as a query parameter.
///
/// A token in the URL ends up in proxy logs and browser history; a token in the
/// opening frame does not. The socket is closed if the first frame is anything
/// else, so an unauthenticated peer can never reach the message loop.
async fn serve_socket(mut socket: WebSocket, hub: AppState) {
    let Some(public_key) = authenticate_socket(&mut socket, &hub).await else {
        let _ = socket.send(close_frame("authentication required")).await;
        return;
    };

    let (wake_tx, mut wake_rx) = mpsc::unbounded_channel();
    hub.connect(&public_key, wake_tx);

    // Anything queued while the client was away is delivered immediately.
    if drain(&mut socket, &hub, &public_key).await.is_err() {
        hub.disconnect(&public_key);
        return;
    }
    let _ = socket.send(json_frame(&ServerFrame::Ready)).await;

    loop {
        tokio::select! {
            woken = wake_rx.recv() => {
                if woken.is_none() { break; }
                if drain(&mut socket, &hub, &public_key).await.is_err() {
                    break;
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        if handle_frame(&mut socket, &hub, &text).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {} // ping/pong/binary: ignored
                    Some(Err(_)) => break,
                }
            }
        }
    }

    hub.disconnect(&public_key);
}

async fn authenticate_socket(socket: &mut WebSocket, hub: &AppState) -> Option<PublicKey> {
    let Some(Ok(Message::Text(text))) = socket.recv().await else {
        return None;
    };
    let Ok(ClientFrame::Auth { token }) = serde_json::from_str::<ClientFrame>(&text) else {
        return None;
    };

    let public_key = hub.resolve_token(&token)?;
    // A token issued before the account was locked must stop working.
    hub.ensure_active(&public_key).ok()?;
    Some(public_key)
}

async fn handle_frame(socket: &mut WebSocket, hub: &AppState, text: &str) -> Result<(), ()> {
    let frame = match serde_json::from_str::<ClientFrame>(text) {
        Ok(frame) => frame,
        Err(_) => {
            return send(socket, &ServerFrame::Error {
                message: "malformed frame".into(),
            })
            .await
        }
    };

    match frame {
        // Re-authenticating mid-stream is not a thing; ignore rather than
        // allowing an identity switch on a live socket.
        ClientFrame::Auth { .. } => Ok(()),

        ClientFrame::Send {
            recipient,
            envelope,
        } => {
            let Ok(recipient) = parse_public_key(&recipient) else {
                return send(socket, &ServerFrame::Error {
                    message: "malformed recipient".into(),
                })
                .await;
            };
            let Ok(envelope) = BASE64.decode(envelope) else {
                return send(socket, &ServerFrame::Error {
                    message: "malformed envelope".into(),
                })
                .await;
            };

            match hub.deliver(&recipient, &envelope) {
                Ok(()) => send(socket, &ServerFrame::Accepted).await,
                Err(e) => {
                    send(socket, &ServerFrame::Error {
                        message: e.client_message(),
                    })
                    .await
                }
            }
        }
    }
}

/// Delivers everything queued, deleting as it goes.
async fn drain(socket: &mut WebSocket, hub: &AppState, recipient: &PublicKey) -> Result<(), ()> {
    let envelopes = hub.relay.collect(recipient).map_err(|_| ())?;
    for envelope in envelopes {
        send(
            socket,
            &ServerFrame::Envelope {
                data: BASE64.encode(&envelope),
            },
        )
        .await?;
    }
    Ok(())
}

async fn send(socket: &mut WebSocket, frame: &ServerFrame) -> Result<(), ()> {
    socket.send(json_frame(frame)).await.map_err(|_| ())
}

fn json_frame(frame: &ServerFrame) -> Message {
    Message::Text(serde_json::to_string(frame).unwrap_or_default().into())
}

fn close_frame(reason: &str) -> Message {
    Message::Text(
        serde_json::to_string(&ServerFrame::Error {
            message: reason.into(),
        })
        .unwrap_or_default()
        .into(),
    )
}

// --- Hex helpers ------------------------------------------------------------

fn parse_public_key(text: &str) -> Result<PublicKey, ServerError> {
    parse_hex(text)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or(ServerError::BadPublicKey)
}

fn parse_hex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{now, Relay, Store};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use wisp_invite::InviteCode;

    struct Harness {
        hub: AppState,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                hub: Arc::new(Hub::new(Relay::new(
                    Store::in_memory().unwrap(),
                    Default::default(),
                ))),
            }
        }

        fn invite(&self) -> InviteCode {
            let code = InviteCode::generate();
            self.hub
                .relay
                .with_store(|s| s.create_invite(&code.redemption_hash(), now() + 3600, None))
                .unwrap();
            code
        }

        async fn post(&self, path: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
            let request = Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();

            let response = router(Arc::clone(&self.hub))
                .oneshot(request)
                .await
                .unwrap();
            let status = response.status();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
            (status, json)
        }
    }

    fn client() -> wisp_core::UnlockedIdentity {
        wisp_core::UnlockedIdentity::generate("tester").unwrap()
    }

    fn register_body(
        key: &wisp_core::UnlockedIdentity,
        code: &InviteCode,
        username: &str,
    ) -> serde_json::Value {
        let public = key.public_key().unwrap();
        let canonical = wisp_core::identity::normalise_username(username);
        let message = Relay::registration_challenge(code, &public, &crate::username_hash(&canonical));
        serde_json::json!({
            "invite_code": code.to_string(),
            "username": username,
            "public_key": hex(&public),
            "signature": hex(&key.sign(&message).unwrap()),
        })
    }

    #[tokio::test]
    async fn health_responds() {
        let harness = Harness::new();
        let response = router(Arc::clone(&harness.hub))
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn registration_succeeds_with_a_valid_invite() {
        let harness = Harness::new();
        let code = harness.invite();
        let alice = client();

        let (status, _) = harness
            .post("/v1/register", register_body(&alice, &code, "alice"))
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn registration_without_an_invite_is_refused() {
        let harness = Harness::new();
        let alice = client();
        let (status, body) = harness
            .post(
                "/v1/register",
                register_body(&alice, &InviteCode::generate(), "alice"),
            )
            .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "that invite code is not valid");
    }

    /// The client must not be able to tell a spent code from a nonexistent one.
    #[tokio::test]
    async fn a_spent_code_is_indistinguishable_from_an_unknown_one() {
        let harness = Harness::new();
        let code = harness.invite();
        harness
            .post("/v1/register", register_body(&client(), &code, "alice"))
            .await;

        let (spent_status, spent_body) = harness
            .post("/v1/register", register_body(&client(), &code, "bob"))
            .await;
        let (unknown_status, unknown_body) = harness
            .post(
                "/v1/register",
                register_body(&client(), &InviteCode::generate(), "bob"),
            )
            .await;

        assert_eq!(spent_status, unknown_status);
        assert_eq!(spent_body["error"], unknown_body["error"]);
    }

    #[tokio::test]
    async fn a_forged_signature_is_refused() {
        let harness = Harness::new();
        let code = harness.invite();
        let mut body = register_body(&client(), &code, "alice");
        body["public_key"] = serde_json::json!(hex(&client().public_key().unwrap()));

        let (status, _) = harness.post("/v1/register", body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_duplicate_username_conflicts() {
        let harness = Harness::new();
        let first = harness.invite();
        harness
            .post("/v1/register", register_body(&client(), &first, "alice"))
            .await;

        let second = harness.invite();
        let (status, _) = harness
            .post("/v1/register", register_body(&client(), &second, "alice"))
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn the_full_auth_handshake_issues_a_token() {
        let harness = Harness::new();
        let code = harness.invite();
        let alice = client();
        let public = alice.public_key().unwrap();
        harness
            .post("/v1/register", register_body(&alice, &code, "alice"))
            .await;

        let (status, challenge) = harness
            .post(
                "/v1/auth/challenge",
                serde_json::json!({ "public_key": hex(&public) }),
            )
            .await;
        assert_eq!(status, StatusCode::OK);

        let nonce: [u8; 32] = parse_hex(challenge["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let signature = alice.sign(&Relay::auth_message(&nonce)).unwrap();

        let (status, verified) = harness
            .post(
                "/v1/auth/verify",
                serde_json::json!({
                    "public_key": hex(&public),
                    "signature": hex(&signature),
                }),
            )
            .await;

        assert_eq!(status, StatusCode::OK);
        let token = verified["token"].as_str().unwrap();
        assert_eq!(harness.hub.resolve_token(token), Some(public));
    }

    #[tokio::test]
    async fn an_unregistered_key_gets_no_challenge() {
        let harness = Harness::new();
        let (status, _) = harness
            .post(
                "/v1/auth/challenge",
                serde_json::json!({
                    "public_key": hex(&client().public_key().unwrap())
                }),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_wrong_signature_does_not_authenticate() {
        let harness = Harness::new();
        let code = harness.invite();
        let alice = client();
        let public = alice.public_key().unwrap();
        harness
            .post("/v1/register", register_body(&alice, &code, "alice"))
            .await;
        harness
            .post(
                "/v1/auth/challenge",
                serde_json::json!({ "public_key": hex(&public) }),
            )
            .await;

        let (status, _) = harness
            .post(
                "/v1/auth/verify",
                serde_json::json!({
                    "public_key": hex(&public),
                    "signature": hex(&[0u8; 64]),
                }),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn malformed_keys_are_rejected() {
        let harness = Harness::new();
        let (status, _) = harness
            .post("/v1/auth/challenge", serde_json::json!({ "public_key": "abc" }))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn hex_round_trips_and_rejects_junk() {
        assert_eq!(parse_hex("00ff").unwrap(), vec![0x00, 0xFF]);
        assert_eq!(hex(&[0x00, 0xFF]), "00ff");
        assert!(parse_hex("abc").is_none(), "odd length");
        assert!(parse_hex("zz").is_none(), "not hex");
    }
}
