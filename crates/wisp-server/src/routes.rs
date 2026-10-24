use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

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
        .route("/v1/whoami", get(whoami))
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

struct ClientScope(String);

impl FromRequestParts<AppState> for ClientScope {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip());
        let forwarded = state
            .client_ip_header()
            .and_then(|name| header_address(&parts.headers, name));

        Ok(ClientScope(
            forwarded
                .or(peer)
                .map(throttle_key)
                .unwrap_or_else(|| "unknown".to_string()),
        ))
    }
}

fn header_address(headers: &axum::http::HeaderMap, name: &str) -> Option<IpAddr> {
    headers
        .get(name)?
        .to_str()
        .ok()?
        .rsplit(',')
        .next()?
        .trim()
        .parse()
        .ok()
}

fn throttle_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

// --- Endpoints --------------------------------------------------------------

async fn health() -> &'static str {
    "ok"
}

#[derive(Serialize)]
struct WhoAmI {
    address: String,
}

async fn whoami(ClientScope(address): ClientScope) -> Json<WhoAmI> {
    Json(WhoAmI { address })
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    public_key: String,
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
        state.ensure_active(&public_key)?;
        Ok(Authenticated(public_key))
    }
}

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
    certificate: String,
    trust_root: String,
    expires_in: u64,
}

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

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientFrame {
    Auth { token: String },
    Send {
        recipient: String,
        envelope: String,
    },
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerFrame {
    Ready,
    Envelope { data: String },
    Accepted,
    Error { message: String },
}

const MAX_WS_MESSAGE_BYTES: usize = 512 * 1024;
const AUTH_FRAME_TIMEOUT: Duration = Duration::from_secs(10);
const PING_INTERVAL: Duration = Duration::from_secs(30);

async fn websocket(ws: WebSocketUpgrade, State(hub): State<AppState>) -> Response {
    ws.max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| serve_socket(socket, hub))
}

async fn serve_socket(mut socket: WebSocket, hub: AppState) {
    let authenticated = tokio::time::timeout(AUTH_FRAME_TIMEOUT, authenticate_socket(&mut socket, &hub))
        .await
        .ok()
        .flatten();
    let Some(public_key) = authenticated else {
        let _ = socket.send(close_frame("authentication required")).await;
        return;
    };

    let (wake_tx, mut wake_rx) = mpsc::unbounded_channel();
    hub.connect(&public_key, wake_tx);

    if drain(&mut socket, &hub, &public_key).await.is_err() {
        hub.disconnect(&public_key);
        return;
    }
    let _ = socket.send(json_frame(&ServerFrame::Ready)).await;

    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.tick().await;

    loop {
        tokio::select! {
            _ = ping.tick() => {
                if socket.send(Message::Ping(axum::body::Bytes::new())).await.is_err() {
                    break;
                }
            }
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
                    Some(Ok(_)) => {}
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
    use crate::{Relay, Store};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

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

    fn register_body(key: &wisp_core::UnlockedIdentity, username: &str) -> serde_json::Value {
        let public = key.public_key().unwrap();
        let canonical = wisp_core::identity::normalise_username(username);
        let message = Relay::registration_challenge(&public, &crate::username_hash(&canonical));
        serde_json::json!({
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
    async fn anyone_can_register_with_just_a_username_and_a_key() {
        let harness = Harness::new();
        let alice = client();

        let (status, _) = harness
            .post("/v1/register", register_body(&alice, "alice"))
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn a_leftover_invite_field_is_ignored() {
        let harness = Harness::new();
        let mut body = register_body(&client(), "alice");
        body["invite_code"] = serde_json::json!("WISP-AAAA-AAAA-AAAA-AAAA");

        let (status, _) = harness.post("/v1/register", body).await;
        assert_eq!(status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn a_forged_signature_is_refused() {
        let harness = Harness::new();
        let mut body = register_body(&client(), "alice");
        body["public_key"] = serde_json::json!(hex(&client().public_key().unwrap()));

        let (status, _) = harness.post("/v1/register", body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_duplicate_username_conflicts() {
        let harness = Harness::new();
        harness
            .post("/v1/register", register_body(&client(), "alice"))
            .await;

        let (status, _) = harness
            .post("/v1/register", register_body(&client(), "alice"))
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn signup_flooding_is_answered_with_429() {
        let harness = Harness::new();
        let limit = crate::RelayConfig::default().signups_per_address;

        for i in 0..limit {
            let (status, _) = harness
                .post("/v1/register", register_body(&client(), &format!("user-{i}")))
                .await;
            assert_eq!(status, StatusCode::CREATED);
        }
        let (status, _) = harness
            .post("/v1/register", register_body(&client(), "one-too-many"))
            .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }

    // --- Throttling scope -------------------------------------------------

    async fn scope_of_headers(hub: &AppState, headers: &[(&str, &str)]) -> String {
        let mut builder = Request::builder().uri("/");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let (mut parts, _) = builder.body(()).unwrap().into_parts();
        parts
            .extensions
            .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 1], 4000))));
        let ClientScope(scope) = ClientScope::from_request_parts(&mut parts, hub)
            .await
            .unwrap();
        scope
    }

    async fn scope_of(hub: &AppState, forwarded: Option<&str>) -> String {
        match forwarded {
            Some(value) => scope_of_headers(hub, &[("x-forwarded-for", value)]).await,
            None => scope_of_headers(hub, &[]).await,
        }
    }

    fn hub_with_header(header: &str) -> AppState {
        Arc::new(
            Hub::new(Relay::new(Store::in_memory().unwrap(), Default::default()))
                .with_client_ip_header(Some(header.to_string())),
        )
    }
    fn hub(trust_proxy: bool) -> AppState {
        Arc::new(
            Hub::new(Relay::new(Store::in_memory().unwrap(), Default::default()))
                .with_trusted_proxy(trust_proxy),
        )
    }

    #[tokio::test]
    async fn forwarded_for_is_ignored_unless_the_proxy_is_trusted() {
        let scope = scope_of(&hub(false), Some("198.51.100.9")).await;
        assert_eq!(scope, "10.0.0.1");
    }

    #[tokio::test]
    async fn a_trusted_proxy_supplies_the_caller_address() {
        let scope = scope_of(&hub(true), Some("198.51.100.9")).await;
        assert_eq!(scope, "198.51.100.9");
    }

    #[tokio::test]
    async fn only_the_last_forwarded_entry_is_believed() {
        let scope = scope_of(&hub(true), Some("1.2.3.4, 5.6.7.8, 198.51.100.9")).await;
        assert_eq!(scope, "198.51.100.9");
    }

    #[tokio::test]
    async fn a_missing_or_junk_header_falls_back_to_the_peer() {
        assert_eq!(scope_of(&hub(true), None).await, "10.0.0.1");
        assert_eq!(scope_of(&hub(true), Some("not-an-ip")).await, "10.0.0.1");
    }

    #[tokio::test]
    async fn a_configured_header_supplies_the_caller_address() {
        let hub = hub_with_header("X-Real-IP");
        let scope = scope_of_headers(&hub, &[("x-real-ip", "198.51.100.9")]).await;
        assert_eq!(scope, "198.51.100.9");
    }

    #[tokio::test]
    async fn the_configured_header_wins_over_forwarded_for() {
        let hub = hub_with_header("x-real-ip");
        let scope = scope_of_headers(
            &hub,
            &[("x-real-ip", "198.51.100.9"), ("x-forwarded-for", "203.0.113.5")],
        )
        .await;
        assert_eq!(scope, "198.51.100.9");
    }

    #[tokio::test]
    async fn a_configured_header_that_is_absent_or_junk_falls_back_to_the_peer() {
        let hub = hub_with_header("x-real-ip");
        assert_eq!(scope_of_headers(&hub, &[]).await, "10.0.0.1");
        assert_eq!(
            scope_of_headers(&hub, &[("x-real-ip", "not-an-ip")]).await,
            "10.0.0.1"
        );
    }

    #[tokio::test]
    async fn a_header_nobody_configured_is_ignored() {
        let scope = scope_of_headers(&hub(false), &[("x-real-ip", "198.51.100.9")]).await;
        assert_eq!(scope, "10.0.0.1");
    }

    #[tokio::test]
    async fn whoami_reports_the_address_the_relay_throttles_on() {
        let harness = Harness::new();
        let request = Request::builder()
            .uri("/v1/whoami")
            .extension(ConnectInfo(SocketAddr::from(([203, 0, 113, 7], 5000))))
            .body(Body::empty())
            .unwrap();

        let response = router(Arc::clone(&harness.hub))
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["address"], "203.0.113.7");
    }
    #[test]
    fn ipv6_addresses_share_a_bucket_per_64() {
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(throttle_key(a), throttle_key(b));
        assert_ne!(throttle_key(a), throttle_key(other));
    }
    #[tokio::test]
    async fn the_full_auth_handshake_issues_a_token() {
        let harness = Harness::new();
        let alice = client();
        let public = alice.public_key().unwrap();
        harness
            .post("/v1/register", register_body(&alice, "alice"))
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
        let alice = client();
        let public = alice.public_key().unwrap();
        harness
            .post("/v1/register", register_body(&alice, "alice"))
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
