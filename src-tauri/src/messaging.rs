//! The app's messaging session.
//!
//! Owns the [`Messenger`], the relay WebSocket, and the encrypted history for
//! one unlocked identity. Created on unlock, destroyed on lock — the messaging
//! key material must not outlive the USB drive that protects it.
//!
//! # Why a dedicated thread
//!
//! libsignal's store traits are declared `#[async_trait(?Send)]`, so the futures
//! that touch them are not `Send` and cannot be handed to `tokio::spawn` on
//! Tauri's multi-threaded runtime. Rather than fight that, all messaging runs on
//! one owned thread with a current-thread runtime, and the rest of the app talks
//! to it over a channel. The `!Send` work never has to cross a thread boundary
//! because it never leaves this one.
//!
//! Reading history is the exception: it goes through the `Arc<Vault>` directly
//! from whichever thread asks, because it is a plain decrypt with no protocol
//! state behind it.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use wisp_messaging::{
    address_for, bundle_from_published, identity_from_private_key, Content, Group, GroupMessage,
    Groups, History, Message, Messenger, Vault, WispProtocolStore,
};

use crate::relay_client::{HttpRelayClient, SessionCredentials};

/// Event name for messages arriving while the app is open.
pub const MESSAGE_EVENT: &str = "wisp://message";
/// Event name for connection state changes.
pub const CONNECTION_EVENT: &str = "wisp://connection";
/// Event name for a group message arriving.
pub const GROUP_MESSAGE_EVENT: &str = "wisp://group-message";
/// Event name for learning about a group, or a member re-sharing their key.
pub const GROUP_EVENT: &str = "wisp://group";

/// How many one-time prekeys to publish per session.
const PREKEY_BATCH: u32 = 20;
const PREKEY_COUNTER_KEY: &[u8] = b"prekey_counter";
const NS_META: &str = "meta";

/// What the UI is told about a message.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageView {
    /// Hex identity key of the other party.
    pub peer: String,
    pub outgoing: bool,
    pub sent_at: u64,
    pub body: String,
}

impl From<&Message> for MessageView {
    fn from(message: &Message) -> Self {
        Self {
            peer: hex(&message.peer),
            outgoing: message.outgoing,
            sent_at: message.sent_at,
            body: message.body.clone(),
        }
    }
}

/// What the UI is told about a group.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupView {
    pub id: String,
    pub name: String,
    /// Hex identity keys, ours included.
    pub members: Vec<String>,
    pub created_at: u64,
}

impl From<&Group> for GroupView {
    fn from(group: &Group) -> Self {
        Self {
            id: group.id.to_string(),
            name: group.name.clone(),
            members: group.members.iter().map(|m| hex(m)).collect(),
            created_at: group.created_at,
        }
    }
}

/// A group message, with the sender named — unlike a one-to-one message, where
/// the peer *is* the other party.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMessageView {
    pub group: String,
    pub sender: String,
    pub outgoing: bool,
    pub sent_at: u64,
    pub body: String,
}

impl From<&GroupMessage> for GroupMessageView {
    fn from(message: &GroupMessage) -> Self {
        Self {
            group: message.group.to_string(),
            sender: hex(&message.sender),
            outgoing: message.outgoing,
            sent_at: message.sent_at,
            body: message.body.clone(),
        }
    }
}

enum Command {
    Send {
        recipient: [u8; 32],
        text: String,
        reply: oneshot::Sender<Result<MessageView, String>>,
    },
    CreateGroup {
        name: String,
        members: Vec<[u8; 32]>,
        reply: oneshot::Sender<Result<GroupView, String>>,
    },
    SendGroup {
        group: uuid::Uuid,
        text: String,
        reply: oneshot::Sender<Result<GroupMessageView, String>>,
    },
    Shutdown,
}

struct Active {
    vault: Arc<Vault>,
    commands: mpsc::UnboundedSender<Command>,
    worker: Option<std::thread::JoinHandle<()>>,
}

/// Tauri-managed messaging state. Empty until an identity is unlocked.
#[derive(Default)]
pub struct Messaging {
    active: Mutex<Option<Active>>,
}

impl Messaging {
    /// Brings messaging up for a freshly unlocked identity.
    ///
    /// Failure here is deliberately **not** fatal to the unlock: if the relay is
    /// unreachable the user should still get into the app and read the history
    /// they already have, rather than being locked out by someone else's
    /// downtime.
    pub fn start(
        &self,
        app: AppHandle,
        vault_dir: &Path,
        identity_private_key: &[u8],
        public_key: [u8; 32],
        relay: HttpRelayClient,
    ) -> Result<(), String> {
        self.stop();

        std::fs::create_dir_all(vault_dir).map_err(|e| format!("vault directory: {e}"))?;
        let vault_path = vault_dir.join(format!("{}.vault", hex(&public_key)));

        // Keyed by the identity private key: without the drive, this file is
        // noise.
        let vault = Arc::new(
            Vault::open(&vault_path, identity_private_key).map_err(|e| e.to_string())?,
        );

        let identity =
            identity_from_private_key(identity_private_key).map_err(|e| e.to_string())?;
        let registration_id = registration_id_from(&public_key);

        // A second vault handle for the worker: the store needs ownership, the
        // app needs history reads.
        let worker_vault =
            Vault::open(&vault_path, identity_private_key).map_err(|e| e.to_string())?;
        let messenger = Messenger::new(WispProtocolStore::new(
            worker_vault,
            identity,
            registration_id,
        ));

        let (commands, receiver) = mpsc::unbounded_channel();
        let read_vault = Arc::clone(&vault);

        let worker = std::thread::Builder::new()
            .name("wisp-messaging".into())
            .spawn(move || run_worker(app, messenger, relay, public_key, read_vault, receiver))
            .map_err(|e| format!("could not start the messaging thread: {e}"))?;

        *self.active.lock().unwrap() = Some(Active {
            vault,
            commands,
            worker: Some(worker),
        });
        Ok(())
    }

    /// Tears messaging down. Safe to call when nothing is running.
    pub fn stop(&self) {
        let Some(mut active) = self.active.lock().unwrap().take() else {
            return;
        };
        let _ = active.commands.send(Command::Shutdown);
        if let Some(worker) = active.worker.take() {
            let _ = worker.join();
        }
    }

    pub fn is_active(&self) -> bool {
        self.active.lock().unwrap().is_some()
    }

    /// Every peer we have history with, newest conversation first.
    pub fn conversations(&self) -> Result<Vec<String>, String> {
        let guard = self.active.lock().unwrap();
        let Some(active) = guard.as_ref() else {
            return Ok(Vec::new());
        };
        History::new(&active.vault)
            .peers()
            .map(|peers| peers.iter().map(|peer| hex(peer)).collect())
            .map_err(|e| e.to_string())
    }

    pub fn conversation(&self, peer: &[u8; 32]) -> Result<Vec<MessageView>, String> {
        let guard = self.active.lock().unwrap();
        let Some(active) = guard.as_ref() else {
            return Ok(Vec::new());
        };
        History::new(&active.vault)
            .conversation(peer)
            .map(|messages| messages.iter().map(MessageView::from).collect())
            .map_err(|e| e.to_string())
    }

    /// Sends a message, returning it as stored.
    pub fn send(&self, recipient: [u8; 32], text: String) -> Result<MessageView, String> {
        let commands = {
            let guard = self.active.lock().unwrap();
            guard
                .as_ref()
                .ok_or("messaging is not running")?
                .commands
                .clone()
        };

        let (reply, wait) = oneshot::channel();
        commands
            .send(Command::Send {
                recipient,
                text,
                reply,
            })
            .map_err(|_| "the messaging thread has stopped".to_string())?;

        // Blocking is fine: Tauri runs commands on a pool, and the caller is a
        // user waiting for their own message to send.
        wait.blocking_recv()
            .map_err(|_| "the messaging thread stopped before replying".to_string())?
    }
}

impl Messaging {
    /// Every group we know about.
    pub fn groups(&self) -> Result<Vec<GroupView>, String> {
        let guard = self.active.lock().unwrap();
        let Some(active) = guard.as_ref() else {
            return Ok(Vec::new());
        };
        Groups::new(&active.vault)
            .list()
            .map(|groups| groups.iter().map(GroupView::from).collect())
            .map_err(|e| e.to_string())
    }

    pub fn group_conversation(&self, group: &uuid::Uuid) -> Result<Vec<GroupMessageView>, String> {
        let guard = self.active.lock().unwrap();
        let Some(active) = guard.as_ref() else {
            return Ok(Vec::new());
        };
        History::new(&active.vault)
            .group_conversation(group)
            .map(|messages| messages.iter().map(GroupMessageView::from).collect())
            .map_err(|e| e.to_string())
    }

    /// Creates a group and hands every member the key to read it.
    pub fn create_group(
        &self,
        name: String,
        members: Vec<[u8; 32]>,
    ) -> Result<GroupView, String> {
        let (reply, wait) = oneshot::channel();
        self.dispatch(Command::CreateGroup {
            name,
            members,
            reply,
        })?;
        wait.blocking_recv()
            .map_err(|_| "the messaging thread stopped before replying".to_string())?
    }

    pub fn send_group(
        &self,
        group: uuid::Uuid,
        text: String,
    ) -> Result<GroupMessageView, String> {
        let (reply, wait) = oneshot::channel();
        self.dispatch(Command::SendGroup { group, text, reply })?;
        wait.blocking_recv()
            .map_err(|_| "the messaging thread stopped before replying".to_string())?
    }

    fn dispatch(&self, command: Command) -> Result<(), String> {
        let guard = self.active.lock().unwrap();
        guard
            .as_ref()
            .ok_or("messaging is not running")?
            .commands
            .send(command)
            .map_err(|_| "the messaging thread has stopped".to_string())
    }
}

impl Drop for Messaging {
    fn drop(&mut self) {
        self.stop();
    }
}

/// libsignal wants a registration id per install; Wisp has one identity per
/// device, so it is derived from the identity key rather than stored. Stable
/// across restarts, which is what the protocol requires.
fn registration_id_from(public_key: &[u8; 32]) -> u32 {
    let raw = u32::from_be_bytes([public_key[0], public_key[1], public_key[2], public_key[3]]);
    // libsignal reserves the top bit.
    raw & 0x3FFF
}

// --- the worker thread ------------------------------------------------------

fn run_worker(
    app: AppHandle,
    messenger: Messenger,
    relay: HttpRelayClient,
    public_key: [u8; 32],
    vault: Arc<Vault>,
    commands: mpsc::UnboundedReceiver<Command>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            report(&app, false, &format!("messaging runtime failed: {e}"));
            return;
        }
    };

    runtime.block_on(async move {
        if let Err(e) = worker_loop(&app, messenger, relay, public_key, vault, commands).await {
            report(&app, false, &e);
        }
    });
}

async fn worker_loop(
    app: &AppHandle,
    mut messenger: Messenger,
    relay: HttpRelayClient,
    public_key: [u8; 32],
    vault: Arc<Vault>,
    mut commands: mpsc::UnboundedReceiver<Command>,
) -> Result<(), String> {
    // Authenticate. The signature proves we hold the identity key.
    let credentials: SessionCredentials = relay
        .authenticate(&public_key, |message| {
            messenger.sign(message).map_err(|e| e.to_string())
        })
        .map_err(|e| e.to_string())?;

    // Publish a fresh batch of prekeys so others can reach us while offline.
    let base = next_prekey_base(&vault)?;
    let published = messenger
        .generate_prekeys(base, base, base + 1, PREKEY_BATCH)
        .await
        .map_err(|e| e.to_string())?;
    relay
        .publish_prekeys(&credentials.token, &published)
        .map_err(|e| e.to_string())?;

    let (mut socket, _) = tokio_tungstenite::connect_async(relay.websocket_url())
        .await
        .map_err(|e| format!("could not open the relay socket: {e}"))?;

    socket
        .send(WsMessage::Text(
            serde_json::json!({ "type": "auth", "token": credentials.token }).to_string(),
        ))
        .await
        .map_err(|e| e.to_string())?;

    report(app, true, "connected");

    loop {
        tokio::select! {
            incoming = socket.next() => {
                match incoming {
                    Some(Ok(WsMessage::Text(text))) => {
                        if let Err(e) = handle_frame(
                            app, &mut messenger, &vault, &credentials, &text,
                        ).await {
                            // One bad message must not take the socket down;
                            // a hostile relay could otherwise disconnect us at
                            // will by sending garbage.
                            eprintln!("[wisp] dropped an unreadable message: {e}");
                        }
                    }
                    Some(Ok(WsMessage::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        report(app, false, &format!("relay socket closed: {e}"));
                        break;
                    }
                }
            }

            command = commands.recv() => {
                match command {
                    Some(Command::Send { recipient, text, reply }) => {
                        let outcome = send_message(
                            &mut messenger, &relay, &vault, &credentials,
                            &mut socket, recipient, &text,
                        ).await;
                        let _ = reply.send(outcome);
                    }
                    Some(Command::CreateGroup { name, members, reply }) => {
                        let outcome = create_group(
                            &mut messenger, &relay, &credentials, &mut socket, &name, members,
                        ).await;
                        let _ = reply.send(outcome);
                    }
                    Some(Command::SendGroup { group, text, reply }) => {
                        let outcome = send_group_message(
                            &mut messenger, &relay, &vault, &credentials,
                            &mut socket, group, &text,
                        ).await;
                        let _ = reply.send(outcome);
                    }
                    Some(Command::Shutdown) | None => break,
                }
            }
        }
    }

    let _ = socket.close(None).await;
    report(app, false, "disconnected");
    Ok(())
}

/// Decrypts an inbound envelope and files it.
async fn handle_frame(
    app: &AppHandle,
    messenger: &mut Messenger,
    vault: &Vault,
    credentials: &SessionCredentials,
    text: &str,
) -> Result<(), String> {
    let frame: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    if frame["type"] != "envelope" {
        return Ok(());
    }

    let sealed = frame["data"]
        .as_str()
        .and_then(decode_base64)
        .ok_or("envelope was not valid base64")?;

    // Sealed sender: who sent it is inside the ciphertext, and the certificate
    // is validated against the trust root before we believe it.
    let (sender, plaintext) = messenger
        .unseal(&credentials.trust_root, &sealed)
        .await
        .map_err(|e| e.to_string())?;

    // What kind of thing it is only becomes readable after decryption — the
    // relay never sees this layer.
    match Content::from_bytes(&plaintext).map_err(|e| e.to_string())? {
        Content::Direct { body } => {
            let message = Message {
                peer: sender,
                outgoing: false,
                sent_at: now_millis(),
                body,
            };
            History::new(vault)
                .append(&message)
                .map_err(|e| e.to_string())?;
            let _ = app.emit(MESSAGE_EVENT, MessageView::from(&message));
        }

        distribution @ Content::Distribution { .. } => {
            // Someone has given us the key to read their group messages. This
            // also teaches us the group if we had not heard of it.
            let group = messenger
                .accept_distribution(&sender, &distribution)
                .await
                .map_err(|e| e.to_string())?;
            let _ = app.emit(GROUP_EVENT, GroupView::from(&group));
        }

        Content::Group { group, ciphertext } => {
            let body = messenger
                .decrypt_group(&sender, &ciphertext)
                .await
                .map_err(|e| e.to_string())?;
            let body = String::from_utf8(body).map_err(|_| "group message was not text")?;

            let message = GroupMessage {
                group,
                sender,
                outgoing: false,
                sent_at: now_millis(),
                body,
            };
            History::new(vault)
                .append_group(&message)
                .map_err(|e| e.to_string())?;
            let _ = app.emit(GROUP_MESSAGE_EVENT, GroupMessageView::from(&message));
        }
    }
    Ok(())
}

/// Makes sure we can seal to `recipient`, fetching their prekeys if needed.
async fn ensure_session(
    messenger: &mut Messenger,
    relay: &HttpRelayClient,
    credentials: &SessionCredentials,
    recipient: &[u8; 32],
) -> Result<(), String> {
    let address = address_for(recipient);
    if messenger
        .has_session(&address)
        .await
        .map_err(|e| e.to_string())?
    {
        return Ok(());
    }

    let (published, one_time) = relay
        .fetch_prekeys(&credentials.token, recipient)
        .map_err(|e| e.to_string())?;
    let bundle = bundle_from_published(
        &published,
        one_time.as_ref().map(|(id, key)| (*id, key.as_slice())),
    )
    .map_err(|e| e.to_string())?;

    messenger
        .start_session(&address, &bundle)
        .await
        .map_err(|e| e.to_string())
}

/// Seals one piece of content to one recipient and hands it to the relay.
async fn deliver(
    messenger: &mut Messenger,
    relay: &HttpRelayClient,
    credentials: &SessionCredentials,
    socket: &mut Socket,
    recipient: &[u8; 32],
    content: &Content,
) -> Result<(), String> {
    ensure_session(messenger, relay, credentials, recipient).await?;

    let sealed = messenger
        .seal(
            &address_for(recipient),
            &credentials.sender_certificate,
            &content.to_bytes(),
        )
        .await
        .map_err(|e| e.to_string())?;

    socket
        .send(WsMessage::Text(
            serde_json::json!({
                "type": "send",
                "recipient": hex(recipient),
                "envelope": encode_base64(&sealed),
            })
            .to_string(),
        ))
        .await
        .map_err(|e| format!("could not reach the relay: {e}"))
}

/// Creates a group and distributes our sender key to every other member.
///
/// A member we cannot reach — no account, no prekeys — is reported rather than
/// silently dropped, because they will never see anything sent to the group and
/// the creator should know that now rather than wonder later.
async fn create_group(
    messenger: &mut Messenger,
    relay: &HttpRelayClient,
    credentials: &SessionCredentials,
    socket: &mut Socket,
    name: &str,
    members: Vec<[u8; 32]>,
) -> Result<GroupView, String> {
    let group = messenger
        .create_group(name, members)
        .map_err(|e| e.to_string())?;
    let distribution = messenger
        .sender_key_distribution(&group)
        .await
        .map_err(|e| e.to_string())?;

    let me = messenger.public_key().map_err(|e| e.to_string())?;
    let mut unreachable = Vec::new();
    for member in group.others(&me) {
        if deliver(messenger, relay, credentials, socket, &member, &distribution)
            .await
            .is_err()
        {
            unreachable.push(hex(&member)[..8].to_string());
        }
    }

    if !unreachable.is_empty() {
        return Err(format!(
            "group created, but these members could not be reached: {}",
            unreachable.join(", ")
        ));
    }
    Ok(GroupView::from(&group))
}

/// Encrypts once for the group, then delivers that same ciphertext to each
/// member.
async fn send_group_message(
    messenger: &mut Messenger,
    relay: &HttpRelayClient,
    vault: &Vault,
    credentials: &SessionCredentials,
    socket: &mut Socket,
    group_id: uuid::Uuid,
    text: &str,
) -> Result<GroupMessageView, String> {
    let group = messenger
        .group(&group_id)
        .map_err(|e| e.to_string())?
        .ok_or("no such group")?;

    let content = messenger
        .encrypt_group(&group, text.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    let me = messenger.public_key().map_err(|e| e.to_string())?;
    let mut delivered = 0usize;
    let recipients = group.others(&me);
    for member in &recipients {
        if deliver(messenger, relay, credentials, socket, member, &content)
            .await
            .is_ok()
        {
            delivered += 1;
        }
    }

    // Recorded locally regardless: the message was written and encrypted, and
    // hiding it because one member is unreachable would lose it.
    let message = GroupMessage {
        group: group_id,
        sender: me,
        outgoing: true,
        sent_at: now_millis(),
        body: text.to_string(),
    };
    History::new(vault)
        .append_group(&message)
        .map_err(|e| e.to_string())?;

    if delivered < recipients.len() {
        eprintln!(
            "[wisp] group message reached {delivered} of {} members",
            recipients.len()
        );
    }
    Ok(GroupMessageView::from(&message))
}

/// Establishes a session if needed, seals, sends, and records.
async fn send_message(
    messenger: &mut Messenger,
    relay: &HttpRelayClient,
    vault: &Vault,
    credentials: &SessionCredentials,
    socket: &mut Socket,
    recipient: [u8; 32],
    text: &str,
) -> Result<MessageView, String> {
    let address = address_for(&recipient);

    // First message to someone: fetch their bundle and run X3DH.
    if !messenger
        .has_session(&address)
        .await
        .map_err(|e| e.to_string())?
    {
        let (published, one_time) = relay
            .fetch_prekeys(&credentials.token, &recipient)
            .map_err(|e| e.to_string())?;
        let bundle = bundle_from_published(
            &published,
            one_time.as_ref().map(|(id, key)| (*id, key.as_slice())),
        )
        .map_err(|e| e.to_string())?;

        messenger
            .start_session(&address, &bundle)
            .await
            .map_err(|e| e.to_string())?;
    }

    let sealed = messenger
        .seal(
            &address,
            &credentials.sender_certificate,
            // Wrapped so the recipient can tell a message from a group
            // distribution; before groups existed the plaintext was the text.
            &Content::Direct {
                body: text.to_string(),
            }
            .to_bytes(),
        )
        .await
        .map_err(|e| e.to_string())?;

    socket
        .send(WsMessage::Text(
            serde_json::json!({
                "type": "send",
                "recipient": hex(&recipient),
                "envelope": encode_base64(&sealed),
            })
            .to_string(),
        ))
        .await
        .map_err(|e| format!("could not reach the relay: {e}"))?;

    let message = Message {
        peer: recipient,
        outgoing: true,
        sent_at: now_millis(),
        body: text.to_string(),
    };
    History::new(vault)
        .append(&message)
        .map_err(|e| e.to_string())?;

    Ok(MessageView::from(&message))
}

type Socket = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

/// Prekey ids must never be reused, or a fresh key would overwrite one still in
/// flight. The counter lives in the vault so it survives restarts.
fn next_prekey_base(vault: &Vault) -> Result<u32, String> {
    let current = vault
        .get(NS_META, PREKEY_COUNTER_KEY)
        .map_err(|e| e.to_string())?
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .unwrap_or(1);

    let next = current.saturating_add(PREKEY_BATCH + 2);
    vault
        .put(NS_META, PREKEY_COUNTER_KEY, &next.to_be_bytes())
        .map_err(|e| e.to_string())?;
    Ok(current)
}

fn report(app: &AppHandle, connected: bool, detail: &str) {
    let _ = app.emit(
        CONNECTION_EVENT,
        serde_json::json!({ "connected": connected, "detail": detail }),
    );
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_identity(text: &str) -> Option<[u8; 32]> {
    let text = text.trim();
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn encode_base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

/// Where per-identity vaults live.
pub fn vault_dir(app: &AppHandle) -> PathBuf {
    use tauri::Manager;
    app.path()
        .app_data_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("vaults")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_hex_round_trips() {
        let key = [0xABu8; 32];
        assert_eq!(parse_identity(&hex(&key)), Some(key));
    }

    #[test]
    fn malformed_identities_are_rejected() {
        assert!(parse_identity("").is_none());
        assert!(parse_identity("abc").is_none());
        assert!(parse_identity(&"z".repeat(64)).is_none());
    }

    #[test]
    fn registration_ids_are_stable_and_in_range() {
        let key = [0xFFu8; 32];
        assert_eq!(registration_id_from(&key), registration_id_from(&key));
        assert!(registration_id_from(&key) <= 0x3FFF);
    }

    /// Reusing a prekey id would overwrite a key that may still be in flight.
    #[test]
    fn prekey_ids_never_repeat_across_sessions() {
        let vault = Vault::in_memory(b"secret").unwrap();
        let first = next_prekey_base(&vault).unwrap();
        let second = next_prekey_base(&vault).unwrap();
        assert!(
            second >= first + PREKEY_BATCH,
            "{second} overlaps the batch starting at {first}"
        );
    }

    #[test]
    fn messaging_starts_inactive() {
        let messaging = Messaging::default();
        assert!(!messaging.is_active());
        assert!(messaging.conversations().unwrap().is_empty());
        assert!(messaging.send([0u8; 32], "hi".into()).is_err());
    }
}
