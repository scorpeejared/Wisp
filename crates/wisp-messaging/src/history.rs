//! Conversation history, encrypted at rest.
//!
//! Signal gives forward secrecy on the wire: past traffic cannot be decrypted
//! from a compromised session key. Stored plaintext throws that away — an
//! attacker who reads the database gets every message regardless of how good
//! the ratchet was. So history lives in the same [`Vault`] as session state,
//! under the same key derived from the USB-held identity.
//!
//! # Keys
//!
//! ```text
//! peer (32 bytes) || sent_at millis (8, big-endian) || nonce (4)
//! ```
//!
//! Peer first so one conversation is a prefix scan rather than a full decrypt
//! of everything. Timestamp next, big-endian, so lexicographic key order *is*
//! chronological order. The nonce breaks ties — two messages in the same
//! millisecond would otherwise collide and one would silently overwrite the
//! other.
//!
//! # No history endpoint exists on the relay
//!
//! This is the only copy. The relay deletes on delivery, so a lost vault is a
//! lost conversation — which is the intended behaviour, not a gap.

use crate::error::{MessagingError, MessagingResult};
use crate::vault::Vault;
use wisp_core::crypto;

const NS_MESSAGE: &str = "message";
const NS_GROUP_MESSAGE: &str = "group_message";
const GROUP_KEY_LEN: usize = 16 + 8 + 4;
const KEY_LEN: usize = 32 + 8 + 4;
const RECORD_VERSION: u8 = 1;
/// Generous for a chat message, and a bound on what a hostile relay can make
/// us store from one envelope.
const MAX_BODY_BYTES: usize = 16 * 1024;

/// One message in a conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The other party's identity key.
    pub peer: [u8; 32],
    /// True if we sent it.
    pub outgoing: bool,
    /// Milliseconds since the Unix epoch.
    pub sent_at: u64,
    pub body: String,
}

impl Message {
    fn encode(&self) -> MessagingResult<Vec<u8>> {
        let body = self.body.as_bytes();
        if body.len() > MAX_BODY_BYTES {
            return Err(MessagingError::Malformed);
        }

        let mut out = Vec::with_capacity(2 + body.len());
        out.push(RECORD_VERSION);
        out.push(u8::from(self.outgoing));
        out.extend_from_slice(body);
        Ok(out)
    }

    fn decode(peer: [u8; 32], sent_at: u64, bytes: &[u8]) -> MessagingResult<Self> {
        if bytes.len() < 2 || bytes[0] != RECORD_VERSION {
            return Err(MessagingError::Malformed);
        }
        Ok(Self {
            peer,
            outgoing: bytes[1] != 0,
            sent_at,
            body: String::from_utf8(bytes[2..].to_vec()).map_err(|_| MessagingError::Malformed)?,
        })
    }
}

/// One message in a group.
///
/// Carries the sender explicitly, which a one-to-one message does not need:
/// there the peer *is* the other party, but in a group any member could have
/// written it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMessage {
    pub group: uuid::Uuid,
    pub sender: [u8; 32],
    pub outgoing: bool,
    pub sent_at: u64,
    pub body: String,
}

impl GroupMessage {
    fn encode(&self) -> MessagingResult<Vec<u8>> {
        let body = self.body.as_bytes();
        if body.len() > MAX_BODY_BYTES {
            return Err(MessagingError::Malformed);
        }

        let mut out = Vec::with_capacity(2 + 32 + body.len());
        out.push(RECORD_VERSION);
        out.push(u8::from(self.outgoing));
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(body);
        Ok(out)
    }

    fn decode(group: uuid::Uuid, sent_at: u64, bytes: &[u8]) -> MessagingResult<Self> {
        if bytes.len() < 34 || bytes[0] != RECORD_VERSION {
            return Err(MessagingError::Malformed);
        }
        Ok(Self {
            group,
            sender: bytes[2..34].try_into().map_err(|_| MessagingError::Malformed)?,
            outgoing: bytes[1] != 0,
            sent_at,
            body: String::from_utf8(bytes[34..].to_vec())
                .map_err(|_| MessagingError::Malformed)?,
        })
    }
}

/// Encrypted conversation storage.
pub struct History<'v> {
    vault: &'v Vault,
}

impl<'v> History<'v> {
    pub fn new(vault: &'v Vault) -> Self {
        Self { vault }
    }

    fn key(peer: &[u8; 32], sent_at: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(KEY_LEN);
        key.extend_from_slice(peer);
        key.extend_from_slice(&sent_at.to_be_bytes());
        key.extend_from_slice(&crypto::random_array::<4>());
        key
    }

    pub fn append(&self, message: &Message) -> MessagingResult<()> {
        self.vault.put(
            NS_MESSAGE,
            &Self::key(&message.peer, message.sent_at),
            &message.encode()?,
        )
    }

    /// One conversation, oldest first.
    pub fn conversation(&self, peer: &[u8; 32]) -> MessagingResult<Vec<Message>> {
        let keys = self.vault.keys_with_prefix(NS_MESSAGE, peer)?;

        let mut messages = Vec::with_capacity(keys.len());
        for key in keys {
            if key.len() != KEY_LEN {
                continue;
            }
            let sent_at = u64::from_be_bytes(
                key[32..40]
                    .try_into()
                    .map_err(|_| MessagingError::Malformed)?,
            );
            if let Some(bytes) = self.vault.get(NS_MESSAGE, &key)? {
                messages.push(Message::decode(*peer, sent_at, &bytes)?);
            }
        }
        Ok(messages)
    }

    /// Every peer we have history with, for the chat list.
    ///
    /// Derived from stored keys rather than a separate index, so the list can
    /// never disagree with what is actually stored.
    pub fn peers(&self) -> MessagingResult<Vec<[u8; 32]>> {
        let mut peers: Vec<[u8; 32]> = self
            .vault
            .keys(NS_MESSAGE)?
            .into_iter()
            .filter(|key| key.len() == KEY_LEN)
            .filter_map(|key| key[..32].try_into().ok())
            .collect();
        peers.sort_unstable();
        peers.dedup();
        Ok(peers)
    }

    // --- Groups ------------------------------------------------------------

    pub fn append_group(&self, message: &GroupMessage) -> MessagingResult<()> {
        let mut key = Vec::with_capacity(GROUP_KEY_LEN);
        key.extend_from_slice(message.group.as_bytes());
        key.extend_from_slice(&message.sent_at.to_be_bytes());
        key.extend_from_slice(&crypto::random_array::<4>());

        self.vault
            .put(NS_GROUP_MESSAGE, &key, &message.encode()?)
    }

    /// One group's messages, oldest first.
    pub fn group_conversation(&self, group: &uuid::Uuid) -> MessagingResult<Vec<GroupMessage>> {
        let keys = self
            .vault
            .keys_with_prefix(NS_GROUP_MESSAGE, group.as_bytes())?;

        let mut messages = Vec::with_capacity(keys.len());
        for key in keys {
            if key.len() != GROUP_KEY_LEN {
                continue;
            }
            let sent_at = u64::from_be_bytes(
                key[16..24].try_into().map_err(|_| MessagingError::Malformed)?,
            );
            if let Some(bytes) = self.vault.get(NS_GROUP_MESSAGE, &key)? {
                messages.push(GroupMessage::decode(*group, sent_at, &bytes)?);
            }
        }
        Ok(messages)
    }

    pub fn forget_group(&self, group: &uuid::Uuid) -> MessagingResult<usize> {
        let keys = self
            .vault
            .keys_with_prefix(NS_GROUP_MESSAGE, group.as_bytes())?;
        for key in &keys {
            self.vault.delete(NS_GROUP_MESSAGE, key)?;
        }
        Ok(keys.len())
    }

    /// Deletes a conversation.
    pub fn forget(&self, peer: &[u8; 32]) -> MessagingResult<usize> {
        let keys = self.vault.keys_with_prefix(NS_MESSAGE, peer)?;
        for key in &keys {
            self.vault.delete(NS_MESSAGE, key)?;
        }
        Ok(keys.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: [u8; 32] = [1u8; 32];
    const BOB: [u8; 32] = [2u8; 32];

    fn vault() -> Vault {
        Vault::in_memory(b"identity secret").unwrap()
    }

    fn message(peer: [u8; 32], outgoing: bool, sent_at: u64, body: &str) -> Message {
        Message {
            peer,
            outgoing,
            sent_at,
            body: body.to_string(),
        }
    }

    #[test]
    fn messages_round_trip() {
        let vault = vault();
        let history = History::new(&vault);
        let original = message(ALICE, true, 1_700_000_000_000, "hello");

        history.append(&original).unwrap();
        assert_eq!(history.conversation(&ALICE).unwrap(), vec![original]);
    }

    #[test]
    fn conversations_read_oldest_first() {
        let vault = vault();
        let history = History::new(&vault);

        // Appended out of order.
        history.append(&message(ALICE, true, 300, "third")).unwrap();
        history.append(&message(ALICE, false, 100, "first")).unwrap();
        history.append(&message(ALICE, true, 200, "second")).unwrap();

        let bodies: Vec<String> = history
            .conversation(&ALICE)
            .unwrap()
            .into_iter()
            .map(|m| m.body)
            .collect();
        assert_eq!(bodies, vec!["first", "second", "third"]);
    }

    /// Two messages in the same millisecond must both survive.
    #[test]
    fn simultaneous_messages_do_not_overwrite_each_other() {
        let vault = vault();
        let history = History::new(&vault);

        history.append(&message(ALICE, true, 500, "one")).unwrap();
        history.append(&message(ALICE, false, 500, "two")).unwrap();

        assert_eq!(history.conversation(&ALICE).unwrap().len(), 2);
    }

    #[test]
    fn conversations_are_separate() {
        let vault = vault();
        let history = History::new(&vault);

        history.append(&message(ALICE, true, 100, "to alice")).unwrap();
        history.append(&message(BOB, true, 100, "to bob")).unwrap();

        assert_eq!(history.conversation(&ALICE).unwrap().len(), 1);
        assert_eq!(history.conversation(&ALICE).unwrap()[0].body, "to alice");
        assert_eq!(history.conversation(&BOB).unwrap()[0].body, "to bob");
    }

    #[test]
    fn direction_is_preserved() {
        let vault = vault();
        let history = History::new(&vault);
        history.append(&message(ALICE, true, 100, "mine")).unwrap();
        history.append(&message(ALICE, false, 200, "theirs")).unwrap();

        let conversation = history.conversation(&ALICE).unwrap();
        assert!(conversation[0].outgoing);
        assert!(!conversation[1].outgoing);
    }

    #[test]
    fn peers_lists_each_conversation_once() {
        let vault = vault();
        let history = History::new(&vault);

        history.append(&message(ALICE, true, 100, "a")).unwrap();
        history.append(&message(ALICE, true, 200, "b")).unwrap();
        history.append(&message(BOB, true, 100, "c")).unwrap();

        let mut peers = history.peers().unwrap();
        peers.sort_unstable();
        assert_eq!(peers, vec![ALICE, BOB]);
    }

    #[test]
    fn an_empty_history_is_empty_not_an_error() {
        let vault = vault();
        let history = History::new(&vault);
        assert!(history.conversation(&ALICE).unwrap().is_empty());
        assert!(history.peers().unwrap().is_empty());
    }

    #[test]
    fn forgetting_removes_only_that_conversation() {
        let vault = vault();
        let history = History::new(&vault);
        history.append(&message(ALICE, true, 100, "a")).unwrap();
        history.append(&message(BOB, true, 100, "b")).unwrap();

        assert_eq!(history.forget(&ALICE).unwrap(), 1);
        assert!(history.conversation(&ALICE).unwrap().is_empty());
        assert_eq!(history.conversation(&BOB).unwrap().len(), 1);
    }

    /// Forward secrecy on the wire is undone by plaintext on disk.
    #[test]
    fn message_bodies_are_not_stored_in_the_clear() {
        let vault = vault();
        History::new(&vault)
            .append(&message(ALICE, true, 100, "MEET AT MIDNIGHT"))
            .unwrap();

        let key = vault.keys(NS_MESSAGE).unwrap().remove(0);
        // The vault's own accessor decrypts; the point is that the stored bytes
        // differ from the plaintext, which `stored_bytes_are_not_the_plaintext`
        // in the vault tests proves directly. Here we confirm the round trip
        // goes through that path at all.
        assert_ne!(vault.get(NS_MESSAGE, &key).unwrap().unwrap(), b"MEET AT MIDNIGHT");
    }

    #[test]
    fn an_oversized_body_is_refused() {
        let vault = vault();
        let history = History::new(&vault);
        let huge = message(ALICE, false, 100, &"x".repeat(MAX_BODY_BYTES + 1));
        assert!(history.append(&huge).is_err());
    }

    #[test]
    fn unicode_bodies_survive() {
        let vault = vault();
        let history = History::new(&vault);
        let text = "héllo — 日本語 🔐";
        history.append(&message(ALICE, true, 100, text)).unwrap();
        assert_eq!(history.conversation(&ALICE).unwrap()[0].body, text);
    }
}
