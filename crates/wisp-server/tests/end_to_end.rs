use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use wisp_server::{now, router, Hub, PublicKey, Relay, RelayConfig, Store};

struct TestServer {
    base: String,
    hub: Arc<Hub>,
}

impl TestServer {
    async fn start() -> Self {
        let hub = Arc::new(Hub::new(Relay::new(
            Store::in_memory().unwrap(),
            RelayConfig::default(),
        )));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let app = router(Arc::clone(&hub));
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        Self {
            base: format!("http://{address}"),
            hub,
        }
    }

    fn external(url: &str) -> Self {
        let hub = Arc::new(Hub::new(Relay::new(
            Store::in_memory().unwrap(),
            RelayConfig::default(),
        )));
        Self {
            base: url.trim_end_matches('/').to_string(),
            hub,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn ws_url(&self) -> String {
        let base = self
            .base
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1);
        format!("{base}/v1/ws")
    }
}

struct TestClient {
    identity: wisp_core::UnlockedIdentity,
}

impl TestClient {
    fn new() -> Self {
        Self {
            identity: wisp_core::UnlockedIdentity::generate("tester").unwrap(),
        }
    }

    fn public_key(&self) -> PublicKey {
        self.identity.public_key().unwrap()
    }

    fn public_hex(&self) -> String {
        hex(&self.public_key())
    }

    async fn register(&self, server: &TestServer, username: &str) {
        let canonical = wisp_core::identity::normalise_username(username);
        let message = Relay::registration_challenge(
            &self.public_key(),
            &wisp_server::username_hash(&canonical),
        );

        let response = reqwest::Client::new()
            .post(server.url("/v1/register"))
            .json(&serde_json::json!({
                "username": username,
                "public_key": self.public_hex(),
                "signature": hex(&self.identity.sign(&message).unwrap()),
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 201, "registration failed for {username}");
    }

    async fn authenticate(&self, server: &TestServer) -> String {
        let http = reqwest::Client::new();

        let challenge: serde_json::Value = http
            .post(server.url("/v1/auth/challenge"))
            .json(&serde_json::json!({ "public_key": self.public_hex() }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let nonce: [u8; 32] = unhex(challenge["nonce"].as_str().unwrap())
            .try_into()
            .unwrap();
        let signature = self.identity.sign(&Relay::auth_message(&nonce)).unwrap();

        let verified: serde_json::Value = http
            .post(server.url("/v1/auth/verify"))
            .json(&serde_json::json!({
                "public_key": self.public_hex(),
                "signature": hex(&signature),
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        verified["token"]
            .as_str()
            .unwrap_or_else(|| panic!("no token in {verified}"))
            .to_string()
    }
}

type Socket = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

async fn connect(server: &TestServer, token: &str) -> Socket {
    let (mut socket, _) = tokio_tungstenite::connect_async(server.ws_url())
        .await
        .expect("websocket upgrade");

    socket
        .send(Message::Text(
            serde_json::json!({ "type": "auth", "token": token }).to_string(),
        ))
        .await
        .unwrap();
    socket
}

async fn expect_frame(socket: &mut Socket, wanted: &str) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let next = tokio::time::timeout_at(deadline, socket.next())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for a {wanted:?} frame"));

        let Some(Ok(Message::Text(text))) = next else {
            panic!("socket closed while waiting for {wanted:?}");
        };
        let frame: serde_json::Value = serde_json::from_str(&text).unwrap();
        if frame["type"] == wanted {
            return frame;
        }
    }
}

#[tokio::test]
async fn a_message_travels_from_one_account_to_another() {
    let server = TestServer::start().await;

    let alice = TestClient::new();
    let bob = TestClient::new();
    alice.register(&server, "alice").await;
    bob.register(&server, "bob").await;

    let mut alice_socket = connect(&server, &alice.authenticate(&server).await).await;
    expect_frame(&mut alice_socket, "ready").await;

    let mut bob_socket = connect(&server, &bob.authenticate(&server).await).await;
    expect_frame(&mut bob_socket, "ready").await;

    let envelope = b"a sealed sender ciphertext";
    bob_socket
        .send(Message::Text(
            serde_json::json!({
                "type": "send",
                "recipient": alice.public_hex(),
                "envelope": base64(envelope),
            })
            .to_string(),
        ))
        .await
        .unwrap();

    expect_frame(&mut bob_socket, "accepted").await;

    let delivered = expect_frame(&mut alice_socket, "envelope").await;
    assert_eq!(
        unbase64(delivered["data"].as_str().unwrap()),
        envelope.to_vec()
    );
}

#[tokio::test]
async fn messages_queued_while_offline_arrive_on_reconnect() {
    let server = TestServer::start().await;

    let alice = TestClient::new();
    let bob = TestClient::new();
    alice.register(&server, "alice").await;
    bob.register(&server, "bob").await;

    let mut bob_socket = connect(&server, &bob.authenticate(&server).await).await;
    expect_frame(&mut bob_socket, "ready").await;

    bob_socket
        .send(Message::Text(
            serde_json::json!({
                "type": "send",
                "recipient": alice.public_hex(),
                "envelope": base64(b"while you were out"),
            })
            .to_string(),
        ))
        .await
        .unwrap();
    expect_frame(&mut bob_socket, "accepted").await;

    let mut alice_socket = connect(&server, &alice.authenticate(&server).await).await;
    let delivered = expect_frame(&mut alice_socket, "envelope").await;
    assert_eq!(
        unbase64(delivered["data"].as_str().unwrap()),
        b"while you were out".to_vec()
    );

    assert_eq!(
        server
            .hub
            .relay
            .with_store(|s| s.pending_count(&alice.public_key()))
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn a_socket_without_a_valid_token_is_refused() {
    let server = TestServer::start().await;
    let mut socket = connect(&server, "not-a-real-token").await;

    let mut sent_ready = false;
    while let Some(Ok(message)) = socket.next().await {
        if let Message::Text(text) = message {
            let frame: serde_json::Value = serde_json::from_str(&text).unwrap();
            if frame["type"] == "ready" {
                sent_ready = true;
            }
        }
    }
    assert!(!sent_ready, "an unauthenticated socket reached the stream");
}

#[tokio::test]
async fn a_token_stops_working_once_the_account_is_locked() {
    let server = TestServer::start().await;
    let alice = TestClient::new();
    alice.register(&server, "alice").await;

    let token = alice.authenticate(&server).await;
    server
        .hub
        .relay
        .with_store(|s| s.lock_account(&alice.public_key(), now() + 600))
        .unwrap();

    let mut socket = connect(&server, &token).await;
    let mut sent_ready = false;
    while let Some(Ok(message)) = socket.next().await {
        if let Message::Text(text) = message {
            let frame: serde_json::Value = serde_json::from_str(&text).unwrap();
            if frame["type"] == "ready" {
                sent_ready = true;
            }
        }
    }
    assert!(!sent_ready, "a locked account was served");
}

#[tokio::test]
async fn sending_to_an_unknown_account_is_rejected() {
    let server = TestServer::start().await;
    let bob = TestClient::new();
    bob.register(&server, "bob").await;

    let mut socket = connect(&server, &bob.authenticate(&server).await).await;
    expect_frame(&mut socket, "ready").await;

    socket
        .send(Message::Text(
            serde_json::json!({
                "type": "send",
                "recipient": hex(&TestClient::new().public_key()),
                "envelope": base64(b"nobody home"),
            })
            .to_string(),
        ))
        .await
        .unwrap();

    let frame = expect_frame(&mut socket, "error").await;
    assert_eq!(frame["message"], "no such account");
}

#[tokio::test]
async fn a_malformed_frame_does_not_kill_the_socket() {
    let server = TestServer::start().await;
    let bob = TestClient::new();
    bob.register(&server, "bob").await;

    let mut socket = connect(&server, &bob.authenticate(&server).await).await;
    expect_frame(&mut socket, "ready").await;

    socket
        .send(Message::Text("{not json at all".into()))
        .await
        .unwrap();
    expect_frame(&mut socket, "error").await;

    socket
        .send(Message::Text(
            serde_json::json!({
                "type": "send",
                "recipient": bob.public_hex(),
                "envelope": base64(b"to myself"),
            })
            .to_string(),
        ))
        .await
        .unwrap();
    expect_frame(&mut socket, "accepted").await;
}

// --- Prekey distribution ---------------------------------------------------

fn wire_bundle(tag: u8) -> serde_json::Value {
    serde_json::json!({
        "registration_id": 4242,
        "identity_key": base64(&[tag; 33]),
        "signed_prekey_id": 7,
        "signed_prekey_public": base64(&[tag.wrapping_add(1); 33]),
        "signed_prekey_signature": base64(&[tag.wrapping_add(2); 64]),
        "kyber_prekey_id": 3,
        "kyber_prekey_public": base64(&[tag.wrapping_add(3); 1568]),
        "kyber_prekey_signature": base64(&[tag.wrapping_add(4); 64]),
    })
}

async fn publish(
    server: &TestServer,
    token: &str,
    bundle: serde_json::Value,
    one_time: &[i64],
) -> reqwest::Response {
    let mut body = bundle;
    body["one_time_prekeys"] = serde_json::json!(one_time
        .iter()
        .map(|id| serde_json::json!({ "id": id, "public": base64(&[*id as u8; 33]) }))
        .collect::<Vec<_>>());

    reqwest::Client::new()
        .post(server.url("/v1/prekeys"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap()
}

async fn fetch(server: &TestServer, token: &str, target: &str) -> reqwest::Response {
    reqwest::Client::new()
        .get(server.url(&format!("/v1/prekeys/{target}")))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn prekeys_can_be_published_and_fetched() {
    let server = TestServer::start().await;
    let alice = TestClient::new();
    let bob = TestClient::new();
    alice.register(&server, "alice").await;
    bob.register(&server, "bob").await;

    let bob_token = bob.authenticate(&server).await;
    let response = publish(&server, &bob_token, wire_bundle(0xAA), &[1, 2, 3]).await;
    assert_eq!(response.status(), 200);
    let published: serde_json::Value = response.json().await.unwrap();
    assert_eq!(published["one_time_prekeys_stored"], 3);
    assert_eq!(published["one_time_prekeys_available"], 3);

    let alice_token = alice.authenticate(&server).await;
    let response = fetch(&server, &alice_token, &bob.public_hex()).await;
    assert_eq!(response.status(), 200);

    let fetched: serde_json::Value = response.json().await.unwrap();
    assert_eq!(fetched["registration_id"], 4242);
    assert_eq!(fetched["identity_key"], base64(&[0xAA; 33]));
    assert!(
        fetched["one_time_prekey"].is_object(),
        "a one-time prekey should have been handed out"
    );
}

#[tokio::test]
async fn one_time_prekeys_are_handed_out_once_each_over_http() {
    let server = TestServer::start().await;
    let alice = TestClient::new();
    let bob = TestClient::new();
    alice.register(&server, "alice").await;
    bob.register(&server, "bob").await;

    let bob_token = bob.authenticate(&server).await;
    publish(&server, &bob_token, wire_bundle(0xAA), &[1, 2]).await;

    let alice_token = alice.authenticate(&server).await;
    let mut issued = Vec::new();
    for _ in 0..2 {
        let fetched: serde_json::Value = fetch(&server, &alice_token, &bob.public_hex())
            .await
            .json()
            .await
            .unwrap();
        issued.push(fetched["one_time_prekey"]["id"].as_i64().unwrap());
    }
    issued.sort_unstable();
    assert_eq!(issued, vec![1, 2], "each key must be issued exactly once");

    let fetched: serde_json::Value = fetch(&server, &alice_token, &bob.public_hex())
        .await
        .json()
        .await
        .unwrap();
    assert!(fetched["one_time_prekey"].is_null());
    assert_eq!(fetched["identity_key"], base64(&[0xAA; 33]));

    let status: serde_json::Value = reqwest::Client::new()
        .get(server.url("/v1/prekeys"))
        .bearer_auth(&bob_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["one_time_prekeys_available"], 0);
}

#[tokio::test]
async fn publishing_requires_authentication() {
    let server = TestServer::start().await;
    let bob = TestClient::new();
    bob.register(&server, "bob").await;

    let response = reqwest::Client::new()
        .post(server.url("/v1/prekeys"))
        .json(&wire_bundle(0xAA))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);

    let response = publish(&server, "not-a-real-token", wire_bundle(0xAA), &[]).await;
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn fetching_requires_authentication() {
    let server = TestServer::start().await;
    let bob = TestClient::new();
    bob.register(&server, "bob").await;
    publish(
        &server,
        &bob.authenticate(&server).await,
        wire_bundle(0xAA),
        &[1],
    )
    .await;

    let response = reqwest::Client::new()
        .get(server.url(&format!("/v1/prekeys/{}", bob.public_hex())))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn fetching_an_account_with_no_prekeys_is_a_clean_404() {
    let server = TestServer::start().await;
    let alice = TestClient::new();
    let bob = TestClient::new();
    alice.register(&server, "alice").await;
    bob.register(&server, "bob").await;

    let response = fetch(
        &server,
        &alice.authenticate(&server).await,
        &bob.public_hex(),
    )
    .await;
    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn republishing_rotates_the_bundle() {
    let server = TestServer::start().await;
    let alice = TestClient::new();
    let bob = TestClient::new();
    alice.register(&server, "alice").await;
    bob.register(&server, "bob").await;

    let bob_token = bob.authenticate(&server).await;
    publish(&server, &bob_token, wire_bundle(0xAA), &[]).await;
    publish(&server, &bob_token, wire_bundle(0xBB), &[]).await;

    let fetched: serde_json::Value = fetch(
        &server,
        &alice.authenticate(&server).await,
        &bob.public_hex(),
    )
    .await
    .json()
    .await
    .unwrap();
    assert_eq!(fetched["identity_key"], base64(&[0xBB; 33]));
}

#[tokio::test]
async fn malformed_key_material_is_rejected() {
    let server = TestServer::start().await;
    let bob = TestClient::new();
    bob.register(&server, "bob").await;

    let mut bundle = wire_bundle(0xAA);
    bundle["identity_key"] = serde_json::json!("not base64!!!");

    let response = publish(&server, &bob.authenticate(&server).await, bundle, &[]).await;
    assert_eq!(response.status(), 400);
}

// --- Full Signal round trip -------------------------------------------------

use wisp_messaging::{
    address_for, bundle_from_published, identity_from_private_key, Messenger, ProtocolAddress,
    Vault, WireEnvelope, WispProtocolStore,
};

impl TestClient {
    fn messenger(&self, registration_id: u32) -> Messenger {
        let identity =
            identity_from_private_key(self.identity.key_material().as_slice()).unwrap();
        let vault = Vault::in_memory(self.identity.key_material().as_slice()).unwrap();
        Messenger::new(WispProtocolStore::new(vault, identity, registration_id))
    }

    fn address(&self) -> ProtocolAddress {
        address_for(&self.public_key())
    }

    async fn publish_prekeys(&self, server: &TestServer, token: &str, messenger: &mut Messenger) {
        let published = messenger.generate_prekeys(1, 1, 100, 5).await.unwrap();

        let body = serde_json::json!({
            "registration_id": published.registration_id,
            "identity_key": base64(&published.identity_key),
            "signed_prekey_id": published.signed_prekey_id,
            "signed_prekey_public": base64(&published.signed_prekey_public),
            "signed_prekey_signature": base64(&published.signed_prekey_signature),
            "kyber_prekey_id": published.kyber_prekey_id,
            "kyber_prekey_public": base64(&published.kyber_prekey_public),
            "kyber_prekey_signature": base64(&published.kyber_prekey_signature),
            "one_time_prekeys": published.one_time_prekeys.iter().map(|(id, key)| {
                serde_json::json!({ "id": id, "public": base64(key) })
            }).collect::<Vec<_>>(),
        });

        let response = reqwest::Client::new()
            .post(server.url("/v1/prekeys"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    async fn sender_certificate(&self, server: &TestServer, token: &str) -> (Vec<u8>, [u8; 32]) {
        let body: serde_json::Value = reqwest::Client::new()
            .post(server.url("/v1/sender-certificate"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let certificate = unbase64(body["certificate"].as_str().unwrap());
        let trust_root: [u8; 32] = unbase64(body["trust_root"].as_str().unwrap())
            .try_into()
            .unwrap();
        (certificate, trust_root)
    }
}

async fn start_session(
    server: &TestServer,
    token: &str,
    messenger: &mut Messenger,
    target: &TestClient,
) {
    let fetched: serde_json::Value = fetch(server, token, &target.public_hex())
        .await
        .json()
        .await
        .unwrap();

    let published = wisp_messaging::PublishedPreKeys {
        registration_id: fetched["registration_id"].as_u64().unwrap() as u32,
        identity_key: unbase64(fetched["identity_key"].as_str().unwrap()),
        signed_prekey_id: fetched["signed_prekey_id"].as_u64().unwrap() as u32,
        signed_prekey_public: unbase64(fetched["signed_prekey_public"].as_str().unwrap()),
        signed_prekey_signature: unbase64(fetched["signed_prekey_signature"].as_str().unwrap()),
        kyber_prekey_id: fetched["kyber_prekey_id"].as_u64().unwrap() as u32,
        kyber_prekey_public: unbase64(fetched["kyber_prekey_public"].as_str().unwrap()),
        kyber_prekey_signature: unbase64(fetched["kyber_prekey_signature"].as_str().unwrap()),
        one_time_prekeys: vec![],
    };

    let one_time = fetched["one_time_prekey"].as_object().map(|prekey| {
        (
            prekey["id"].as_u64().unwrap() as u32,
            unbase64(prekey["public"].as_str().unwrap()),
        )
    });

    let bundle = bundle_from_published(
        &published,
        one_time.as_ref().map(|(id, key)| (*id, key.as_slice())),
    )
    .unwrap();

    messenger.start_session(&target.address(), &bundle).await.unwrap();
}

#[tokio::test]
async fn a_sealed_message_travels_end_to_end_through_the_relay() {
    let server = TestServer::start().await;

    let alice = TestClient::new();
    let bob = TestClient::new();
    alice.register(&server, "alice").await;
    bob.register(&server, "bob").await;

    let alice_token = alice.authenticate(&server).await;
    let bob_token = bob.authenticate(&server).await;

    let mut alice_messenger = alice.messenger(1001);
    let mut bob_messenger = bob.messenger(2002);

    bob.publish_prekeys(&server, &bob_token, &mut bob_messenger).await;

    start_session(&server, &alice_token, &mut alice_messenger, &bob).await;

    let (certificate, _) = alice.sender_certificate(&server, &alice_token).await;
    let sealed = alice_messenger
        .seal(&bob.address(), &certificate, b"the eagle lands at dawn")
        .await
        .unwrap();

    assert!(
        !sealed.windows(32).any(|w| w == alice.public_key()),
        "the sender's key is visible in what the relay carries"
    );

    let mut alice_socket = connect(&server, &alice_token).await;
    expect_frame(&mut alice_socket, "ready").await;
    alice_socket
        .send(Message::Text(
            serde_json::json!({
                "type": "send",
                "recipient": bob.public_hex(),
                "envelope": base64(&sealed),
            })
            .to_string(),
        ))
        .await
        .unwrap();
    expect_frame(&mut alice_socket, "accepted").await;

    let mut bob_socket = connect(&server, &bob_token).await;
    let delivered = expect_frame(&mut bob_socket, "envelope").await;
    let received = unbase64(delivered["data"].as_str().unwrap());

    let (_, trust_root) = bob.sender_certificate(&server, &bob_token).await;
    let (sender, plaintext) = bob_messenger.unseal(&trust_root, &received).await.unwrap();

    assert_eq!(sender, alice.public_key(), "Bob learns who sent it");
    assert_eq!(plaintext, b"the eagle lands at dawn");
}

#[tokio::test]
async fn an_unsealed_conversation_works_over_the_relay() {
    let server = TestServer::start().await;

    let alice = TestClient::new();
    let bob = TestClient::new();
    alice.register(&server, "alice").await;
    bob.register(&server, "bob").await;

    let alice_token = alice.authenticate(&server).await;
    let bob_token = bob.authenticate(&server).await;

    let mut alice_messenger = alice.messenger(1001);
    let mut bob_messenger = bob.messenger(2002);

    bob.publish_prekeys(&server, &bob_token, &mut bob_messenger).await;
    start_session(&server, &alice_token, &mut alice_messenger, &bob).await;

    let envelope = alice_messenger
        .encrypt(&bob.address(), b"hello over the wire")
        .await
        .unwrap();
    let wire = WireEnvelope::new(alice.public_key(), envelope).to_bytes();

    let mut alice_socket = connect(&server, &alice_token).await;
    expect_frame(&mut alice_socket, "ready").await;
    alice_socket
        .send(Message::Text(
            serde_json::json!({
                "type": "send",
                "recipient": bob.public_hex(),
                "envelope": base64(&wire),
            })
            .to_string(),
        ))
        .await
        .unwrap();
    expect_frame(&mut alice_socket, "accepted").await;

    let mut bob_socket = connect(&server, &bob_token).await;
    let delivered = expect_frame(&mut bob_socket, "envelope").await;

    let parsed = WireEnvelope::from_bytes(&unbase64(delivered["data"].as_str().unwrap())).unwrap();
    assert_eq!(parsed.sender, alice.public_key());

    let plaintext = bob_messenger
        .decrypt(&alice.address(), &parsed.envelope)
        .await
        .unwrap();
    assert_eq!(plaintext, b"hello over the wire");
}

#[tokio::test]
async fn a_sender_certificate_requires_authentication() {
    let server = TestServer::start().await;
    let response = reqwest::Client::new()
        .post(server.url("/v1/sender-certificate"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn the_trust_root_is_stable_across_requests() {
    let server = TestServer::start().await;
    let alice = TestClient::new();
    alice.register(&server, "alice").await;
    let token = alice.authenticate(&server).await;

    let (_, first) = alice.sender_certificate(&server, &token).await;
    let (_, second) = alice.sender_certificate(&server, &token).await;
    assert_eq!(first, second);
}

// --- Deployed relay ---------------------------------------------------------

#[tokio::test]
#[ignore = "needs WISP_TEST_RELAY_URL pointing at a deployed relay"]
async fn a_deployed_relay_carries_messages_and_keeps_idle_sockets_open() {
    let url = std::env::var("WISP_TEST_RELAY_URL").expect("set WISP_TEST_RELAY_URL");
    let idle_secs: u64 = std::env::var("WISP_TEST_IDLE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let server = TestServer::external(&url);

    let tag = hex(&rand_tag());
    let alice = TestClient::new();
    let bob = TestClient::new();
    alice.register(&server, &format!("smoke-a-{tag}")).await;
    bob.register(&server, &format!("smoke-b-{tag}")).await;

    let mut alice_socket = connect(&server, &alice.authenticate(&server).await).await;
    expect_frame(&mut alice_socket, "ready").await;
    let mut bob_socket = connect(&server, &bob.authenticate(&server).await).await;
    expect_frame(&mut bob_socket, "ready").await;

    send_envelope(&mut bob_socket, &alice, b"first, straight away").await;
    let first = expect_frame(&mut alice_socket, "envelope").await;
    assert_eq!(
        unbase64(first["data"].as_str().unwrap()),
        b"first, straight away".to_vec()
    );
    println!("first message delivered");

    if idle_secs > 0 {
        println!("holding both sockets idle for {idle_secs}s");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(idle_secs);
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break,
                frame = alice_socket.next() => {
                    assert!(matches!(frame, Some(Ok(_))), "alice's socket ended while idle: {frame:?}");
                }
                frame = bob_socket.next() => {
                    assert!(matches!(frame, Some(Ok(_))), "bob's socket ended while idle: {frame:?}");
                }
            }
        }
        println!("both sockets survived the idle wait");
    }

    send_envelope(&mut alice_socket, &bob, b"second, after the wait").await;
    let second = expect_frame(&mut bob_socket, "envelope").await;
    assert_eq!(
        unbase64(second["data"].as_str().unwrap()),
        b"second, after the wait".to_vec()
    );
    println!("second message delivered");
}

async fn send_envelope(socket: &mut Socket, to: &TestClient, bytes: &[u8]) {
    socket
        .send(Message::Text(
            serde_json::json!({
                "type": "send",
                "recipient": to.public_hex(),
                "envelope": base64(bytes),
            })
            .to_string(),
        ))
        .await
        .unwrap();
    expect_frame(socket, "accepted").await;
}

fn rand_tag() -> [u8; 4] {
    let mut bytes = [0u8; 4];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
    bytes
}
// --- helpers ---------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

fn base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unbase64(text: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(text).unwrap()
}
