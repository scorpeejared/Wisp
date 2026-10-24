use std::time::SystemTime;

pub use libsignal_protocol::ProtocolAddress;

use libsignal_protocol::{
    message_decrypt, message_encrypt, process_prekey_bundle, CiphertextMessage,
    CiphertextMessageType, DeviceId, GenericSignedPreKey, IdentityKeyPair, KyberPreKeyRecord,
    PreKeyBundle, PreKeyRecord, PreKeySignalMessage, SignalMessage,
    SignedPreKeyRecord, Timestamp,
};
use rand::TryRngCore;

pub mod content;
pub mod error;
pub mod group;
pub mod history;
pub mod sealed;
pub mod store;
pub mod vault;
pub mod wire;

pub use content::Content;
pub use error::{MessagingError, MessagingResult};
pub use group::{Group, Groups};
pub use history::{GroupMessage, History, Message};
pub use sealed::{CertificateAuthority, CERTIFICATE_VALIDITY};
pub use store::{identity_from_private_key, WispProtocolStore};
pub use vault::Vault;
pub use wire::WireEnvelope;

pub fn address_for(identity: &[u8; 32]) -> ProtocolAddress {
    ProtocolAddress::new(sealed::identity_string(identity), device_id())
}

pub const DEVICE_ID: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPreKeys {
    pub registration_id: u32,
    pub identity_key: Vec<u8>,
    pub signed_prekey_id: u32,
    pub signed_prekey_public: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    pub kyber_prekey_id: u32,
    pub kyber_prekey_public: Vec<u8>,
    pub kyber_prekey_signature: Vec<u8>,
    pub one_time_prekeys: Vec<(u32, Vec<u8>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub is_prekey: bool,
    pub ciphertext: Vec<u8>,
}

pub struct Messenger {
    pub(crate) store: WispProtocolStore,
}

impl Messenger {
    pub fn new(store: WispProtocolStore) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &WispProtocolStore {
        &self.store
    }

    pub fn identity_key_pair(&self) -> &IdentityKeyPair {
        self.store.identity_key_pair()
    }

    pub fn sign(&self, message: &[u8]) -> MessagingResult<[u8; 64]> {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let signature = self
            .identity_key_pair()
            .private_key()
            .calculate_signature(message, &mut rng)
            .map_err(|e| MessagingError::Key(e.to_string()))?;
        signature
            .as_ref()
            .try_into()
            .map_err(|_| MessagingError::Malformed)
    }

    pub async fn generate_prekeys(
        &mut self,
        signed_prekey_id: u32,
        kyber_prekey_id: u32,
        one_time_start_id: u32,
        one_time_count: u32,
    ) -> MessagingResult<PublishedPreKeys> {
        use libsignal_protocol::{KeyPair, PreKeyStore, SignedPreKeyStore, KyberPreKeyStore};

        let mut rng = rand::rngs::OsRng.unwrap_err();
        let identity = *self.store.identity_key_pair();
        let now = Timestamp::from_epoch_millis(now_millis());

        let signed_pair = KeyPair::generate(&mut rng);
        let signed_signature = identity
            .private_key()
            .calculate_signature(&signed_pair.public_key.serialize(), &mut rng)
            .map_err(|e| MessagingError::Key(e.to_string()))?;
        let signed_record = SignedPreKeyRecord::new(
            signed_prekey_id.into(),
            now,
            &signed_pair,
            &signed_signature,
        );
        self.store
            .signed_pre_key_store
            .save_signed_pre_key(signed_prekey_id.into(), &signed_record)
            .await?;

        let kyber_record = KyberPreKeyRecord::generate(
            libsignal_protocol::kem::KeyType::Kyber1024,
            kyber_prekey_id.into(),
            identity.private_key(),
        )?;
        self.store
            .kyber_pre_key_store
            .save_kyber_pre_key(kyber_prekey_id.into(), &kyber_record)
            .await?;

        let mut one_time_prekeys = Vec::with_capacity(one_time_count as usize);
        for offset in 0..one_time_count {
            let id = one_time_start_id + offset;
            let pair = KeyPair::generate(&mut rng);
            let record = PreKeyRecord::new(id.into(), &pair);
            self.store
                .pre_key_store
                .save_pre_key(id.into(), &record)
                .await?;
            one_time_prekeys.push((id, pair.public_key.serialize().to_vec()));
        }

        Ok(PublishedPreKeys {
            registration_id: self.store.registration_id(),
            identity_key: identity.identity_key().serialize().to_vec(),
            signed_prekey_id,
            signed_prekey_public: signed_pair.public_key.serialize().to_vec(),
            signed_prekey_signature: signed_signature.to_vec(),
            kyber_prekey_id,
            kyber_prekey_public: kyber_record.public_key()?.serialize().to_vec(),
            kyber_prekey_signature: kyber_record.signature()?.to_vec(),
            one_time_prekeys,
        })
    }

    pub async fn start_session(
        &mut self,
        remote: &ProtocolAddress,
        bundle: &PreKeyBundle,
    ) -> MessagingResult<()> {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        process_prekey_bundle(
            remote,
            &self.local_address(),
            &mut self.store.session_store,
            &mut self.store.identity_store,
            bundle,
            SystemTime::now(),
            &mut rng,
        )
        .await?;
        Ok(())
    }

    pub async fn has_session(&self, remote: &ProtocolAddress) -> MessagingResult<bool> {
        use libsignal_protocol::SessionStore;
        Ok(self.store.session_store.load_session(remote).await?.is_some())
    }

    pub async fn encrypt(
        &mut self,
        remote: &ProtocolAddress,
        plaintext: &[u8],
    ) -> MessagingResult<Envelope> {
        if !self.has_session(remote).await? {
            return Err(MessagingError::NoSession(remote.name().to_string()));
        }

        let mut rng = rand::rngs::OsRng.unwrap_err();
        let message = message_encrypt(
            plaintext,
            remote,
            &self.local_address(),
            &mut self.store.session_store,
            &mut self.store.identity_store,
            SystemTime::now(),
            &mut rng,
        )
        .await?;

        Ok(Envelope {
            is_prekey: message.message_type() == CiphertextMessageType::PreKey,
            ciphertext: message.serialize().to_vec(),
        })
    }

    pub async fn decrypt(
        &mut self,
        remote: &ProtocolAddress,
        envelope: &Envelope,
    ) -> MessagingResult<Vec<u8>> {
        let message = if envelope.is_prekey {
            CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
                envelope.ciphertext.as_slice(),
            )?)
        } else {
            CiphertextMessage::SignalMessage(SignalMessage::try_from(
                envelope.ciphertext.as_slice(),
            )?)
        };

        let mut rng = rand::rngs::OsRng.unwrap_err();
        let plaintext = message_decrypt(
            &message,
            remote,
            &self.local_address(),
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &mut self.store.pre_key_store,
            &self.store.signed_pre_key_store,
            &mut self.store.kyber_pre_key_store,
            &mut rng,
        )
        .await?;

        Ok(plaintext)
    }

    // --- Groups ------------------------------------------------------------

    pub fn create_group(
        &mut self,
        name: &str,
        members: Vec<[u8; 32]>,
    ) -> MessagingResult<group::Group> {
        let me = self.public_key()?;
        let mut members = members;
        if !members.contains(&me) {
            members.push(me);
        }
        members.sort_unstable();
        members.dedup();

        let created = group::Group {
            id: uuid::Uuid::new_v4(),
            name: name.trim().to_string(),
            members,
            created_at: now_millis(),
        };
        group::Groups::new(&self.store.vault).put(&created)?;
        Ok(created)
    }

    pub fn public_key(&self) -> MessagingResult<[u8; 32]> {
        self.identity_key_pair()
            .public_key()
            .public_key_bytes()
            .try_into()
            .map_err(|_| MessagingError::Malformed)
    }

    pub fn groups(&self) -> MessagingResult<Vec<group::Group>> {
        group::Groups::new(&self.store.vault).list()
    }

    pub fn group(&self, id: &uuid::Uuid) -> MessagingResult<Option<group::Group>> {
        group::Groups::new(&self.store.vault).get(id)
    }

    pub async fn sender_key_distribution(
        &mut self,
        group: &group::Group,
    ) -> MessagingResult<Content> {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let sender = self.local_address();
        let distribution = libsignal_protocol::create_sender_key_distribution_message(
            &sender,
            group.id,
            &mut self.store.sender_key_store,
            &mut rng,
        )
        .await?;

        Ok(Content::Distribution {
            group: group.id,
            name: group.name.clone(),
            members: group.members.clone(),
            distribution: distribution.serialized().to_vec(),
        })
    }

    pub async fn accept_distribution(
        &mut self,
        sender: &[u8; 32],
        content: &Content,
    ) -> MessagingResult<group::Group> {
        let Content::Distribution {
            group: id,
            name,
            members,
            distribution,
        } = content
        else {
            return Err(MessagingError::Malformed);
        };

        let skdm = libsignal_protocol::SenderKeyDistributionMessage::try_from(
            distribution.as_slice(),
        )?;
        libsignal_protocol::process_sender_key_distribution_message(
            &address_for(sender),
            &skdm,
            &mut self.store.sender_key_store,
        )
        .await?;

        let groups = group::Groups::new(&self.store.vault);
        let record = group::Group {
            id: *id,
            name: name.clone(),
            members: members.clone(),
            created_at: groups
                .get(id)?
                .map(|existing| existing.created_at)
                .unwrap_or_else(now_millis),
        };
        groups.put(&record)?;
        Ok(record)
    }

    pub async fn encrypt_group(
        &mut self,
        group: &group::Group,
        plaintext: &[u8],
    ) -> MessagingResult<Content> {
        self.ensure_sender_key(group).await?;

        let mut rng = rand::rngs::OsRng.unwrap_err();
        let sender = self.local_address();
        let message = libsignal_protocol::group_encrypt(
            &mut self.store.sender_key_store,
            &sender,
            group.id,
            plaintext,
            &mut rng,
        )
        .await?;

        Ok(Content::Group {
            group: group.id,
            ciphertext: message.serialized().to_vec(),
        })
    }

    async fn ensure_sender_key(&mut self, group: &group::Group) -> MessagingResult<()> {
        use libsignal_protocol::SenderKeyStore;

        let sender = self.local_address();
        if self
            .store
            .sender_key_store
            .load_sender_key(&sender, group.id)
            .await?
            .is_none()
        {
            let mut rng = rand::rngs::OsRng.unwrap_err();
            libsignal_protocol::create_sender_key_distribution_message(
                &sender,
                group.id,
                &mut self.store.sender_key_store,
                &mut rng,
            )
            .await?;
        }
        Ok(())
    }

    pub async fn decrypt_group(
        &mut self,
        sender: &[u8; 32],
        ciphertext: &[u8],
    ) -> MessagingResult<Vec<u8>> {
        Ok(libsignal_protocol::group_decrypt(
            ciphertext,
            &mut self.store.sender_key_store,
            &address_for(sender),
        )
        .await?)
    }

    fn local_address(&self) -> ProtocolAddress {
        match self.public_key() {
            Ok(key) => address_for(&key),
            Err(_) => ProtocolAddress::new("self".to_string(), device_id()),
        }
    }
}

pub fn device_id() -> DeviceId {
    DeviceId::new(DEVICE_ID).expect("DEVICE_ID is a valid device id")
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn bundle_from_published(
    published: &PublishedPreKeys,
    one_time: Option<(u32, &[u8])>,
) -> MessagingResult<PreKeyBundle> {
    use libsignal_protocol::{IdentityKey, PublicKey};

    let identity_key = IdentityKey::decode(&published.identity_key)?;
    let signed_public = PublicKey::deserialize(&published.signed_prekey_public)
        .map_err(|e| MessagingError::Key(e.to_string()))?;
    let kyber_public =
        libsignal_protocol::kem::PublicKey::deserialize(&published.kyber_prekey_public)?;

    let bundle = PreKeyBundle::new(
        published.registration_id,
        device_id(),
        match one_time {
            Some((id, public)) => Some((
                id.into(),
                PublicKey::deserialize(public).map_err(|e| MessagingError::Key(e.to_string()))?,
            )),
            None => None,
        },
        published.signed_prekey_id.into(),
        signed_public,
        published.signed_prekey_signature.clone(),
        published.kyber_prekey_id.into(),
        kyber_public,
        published.kyber_prekey_signature.clone(),
        identity_key,
    )?;

    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_protocol::KeyPair;

    fn messenger(registration_id: u32) -> Messenger {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let identity = IdentityKeyPair::generate(&mut rng);
        let vault = Vault::in_memory(&identity.private_key().serialize()).unwrap();
        Messenger::new(WispProtocolStore::new(vault, identity, registration_id))
    }

    fn address(name: &str) -> ProtocolAddress {
        ProtocolAddress::new(name.to_string(), device_id())
    }

    #[tokio::test]
    async fn two_parties_can_hold_a_conversation() {
        let mut alice = messenger(1001);
        let mut bob = messenger(2002);

        let published = bob.generate_prekeys(1, 1, 100, 5).await.unwrap();
        let one_time = published.one_time_prekeys[0].clone();
        let bundle = bundle_from_published(&published, Some((one_time.0, &one_time.1))).unwrap();

        alice.start_session(&address("bob"), &bundle).await.unwrap();
        assert!(alice.has_session(&address("bob")).await.unwrap());

        let first = alice.encrypt(&address("bob"), b"hello bob").await.unwrap();
        assert!(first.is_prekey, "the opening message must set up the session");

        let received = bob.decrypt(&address("alice"), &first).await.unwrap();
        assert_eq!(received, b"hello bob");

        let reply = bob.encrypt(&address("alice"), b"hello alice").await.unwrap();
        assert!(!reply.is_prekey);
        assert_eq!(
            alice.decrypt(&address("bob"), &reply).await.unwrap(),
            b"hello alice"
        );
    }

    #[tokio::test]
    async fn repeated_plaintexts_produce_different_ciphertexts() {
        let mut alice = messenger(1001);
        let mut bob = messenger(2002);

        let published = bob.generate_prekeys(1, 1, 100, 5).await.unwrap();
        let one_time = published.one_time_prekeys[0].clone();
        let bundle = bundle_from_published(&published, Some((one_time.0, &one_time.1))).unwrap();
        alice.start_session(&address("bob"), &bundle).await.unwrap();

        let a = alice.encrypt(&address("bob"), b"same text").await.unwrap();
        let b = alice.encrypt(&address("bob"), b"same text").await.unwrap();
        assert_ne!(a.ciphertext, b.ciphertext, "the ratchet must advance");

        assert_eq!(bob.decrypt(&address("alice"), &b).await.unwrap(), b"same text");
        assert_eq!(bob.decrypt(&address("alice"), &a).await.unwrap(), b"same text");
    }

    #[tokio::test]
    async fn encrypting_without_a_session_is_refused() {
        let mut alice = messenger(1001);
        assert!(matches!(
            alice.encrypt(&address("stranger"), b"hi").await,
            Err(MessagingError::NoSession(_))
        ));
    }

    #[tokio::test]
    async fn a_session_works_without_a_one_time_prekey() {
        let mut alice = messenger(1001);
        let mut bob = messenger(2002);

        let published = bob.generate_prekeys(1, 1, 100, 0).await.unwrap();
        assert!(published.one_time_prekeys.is_empty());

        let bundle = bundle_from_published(&published, None).unwrap();
        alice.start_session(&address("bob"), &bundle).await.unwrap();

        let message = alice.encrypt(&address("bob"), b"no one-time key").await.unwrap();
        assert_eq!(
            bob.decrypt(&address("alice"), &message).await.unwrap(),
            b"no one-time key"
        );
    }

    #[tokio::test]
    async fn a_tampered_message_is_rejected() {
        let mut alice = messenger(1001);
        let mut bob = messenger(2002);

        let published = bob.generate_prekeys(1, 1, 100, 5).await.unwrap();
        let one_time = published.one_time_prekeys[0].clone();
        let bundle = bundle_from_published(&published, Some((one_time.0, &one_time.1))).unwrap();
        alice.start_session(&address("bob"), &bundle).await.unwrap();

        let mut message = alice.encrypt(&address("bob"), b"hello bob").await.unwrap();
        let last = message.ciphertext.len() - 1;
        message.ciphertext[last] ^= 0x01;

        assert!(bob.decrypt(&address("alice"), &message).await.is_err());
    }

    #[tokio::test]
    async fn a_one_time_prekey_is_consumed_on_first_use() {
        use libsignal_protocol::PreKeyStore;

        let mut alice = messenger(1001);
        let mut bob = messenger(2002);

        let published = bob.generate_prekeys(1, 1, 100, 5).await.unwrap();
        let (one_time_id, one_time_public) = published.one_time_prekeys[0].clone();
        let bundle =
            bundle_from_published(&published, Some((one_time_id, &one_time_public))).unwrap();
        alice.start_session(&address("bob"), &bundle).await.unwrap();

        let opening = alice.encrypt(&address("bob"), b"hello").await.unwrap();
        bob.decrypt(&address("alice"), &opening).await.unwrap();

        assert!(
            bob.store
                .pre_key_store
                .get_pre_key(one_time_id.into())
                .await
                .is_err(),
            "the one-time prekey should have been deleted after use"
        );
    }

    #[tokio::test]
    async fn published_prekeys_contain_no_private_keys() {
        let mut bob = messenger(2002);
        let identity = *bob.identity_key_pair();
        let published = bob.generate_prekeys(1, 1, 100, 3).await.unwrap();

        let private = identity.private_key().serialize().to_vec();
        let haystack: Vec<u8> = published
            .identity_key
            .iter()
            .chain(published.signed_prekey_public.iter())
            .chain(published.kyber_prekey_public.iter())
            .chain(published.one_time_prekeys.iter().flat_map(|(_, k)| k.iter()))
            .copied()
            .collect();

        assert!(
            !haystack
                .windows(private.len())
                .any(|window| window == private.as_slice()),
            "a private key was published"
        );
    }

    #[tokio::test]
    async fn identity_can_be_rebuilt_from_its_private_key() {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let original = IdentityKeyPair::generate(&mut rng);

        let rebuilt = identity_from_private_key(&original.private_key().serialize()).unwrap();
        assert_eq!(
            rebuilt.identity_key().serialize(),
            original.identity_key().serialize()
        );
    }

    #[tokio::test]
    async fn sessions_survive_being_reloaded_from_the_vault() {
        let mut alice = messenger(1001);
        let mut bob = messenger(2002);

        let published = bob.generate_prekeys(1, 1, 100, 5).await.unwrap();
        let one_time = published.one_time_prekeys[0].clone();
        let bundle = bundle_from_published(&published, Some((one_time.0, &one_time.1))).unwrap();
        alice.start_session(&address("bob"), &bundle).await.unwrap();

        assert!(alice.has_session(&address("bob")).await.unwrap());
        let message = alice.encrypt(&address("bob"), b"round trip").await.unwrap();
        assert_eq!(
            bob.decrypt(&address("alice"), &message).await.unwrap(),
            b"round trip"
        );
    }

    // --- Groups ------------------------------------------------------------

    fn identity_of(m: &Messenger) -> [u8; 32] {
        m.public_key().unwrap()
    }

    #[tokio::test]
    async fn a_group_message_reaches_every_member() {
        let mut alice = messenger(1001);
        let mut bob = messenger(2002);
        let mut carol = messenger(3003);

        let members = vec![
            identity_of(&alice),
            identity_of(&bob),
            identity_of(&carol),
        ];
        let group = alice.create_group("the group", members).unwrap();
        assert_eq!(group.members.len(), 3);

        let distribution = alice.sender_key_distribution(&group).await.unwrap();
        let alice_id = identity_of(&alice);
        bob.accept_distribution(&alice_id, &distribution).await.unwrap();
        carol.accept_distribution(&alice_id, &distribution).await.unwrap();

        let content = alice
            .encrypt_group(&group, b"meeting at six")
            .await
            .unwrap();
        let Content::Group { ciphertext, .. } = &content else {
            panic!("expected a group message, got {content:?}");
        };

        assert_eq!(
            bob.decrypt_group(&alice_id, ciphertext).await.unwrap(),
            b"meeting at six"
        );
        assert_eq!(
            carol.decrypt_group(&alice_id, ciphertext).await.unwrap(),
            b"meeting at six"
        );
    }

    #[tokio::test]
    async fn accepting_a_distribution_creates_the_group_locally() {
        let mut alice = messenger(1001);
        let mut bob = messenger(2002);

        let group = alice
            .create_group("book club", vec![identity_of(&alice), identity_of(&bob)])
            .unwrap();
        assert!(bob.groups().unwrap().is_empty());

        let distribution = alice.sender_key_distribution(&group).await.unwrap();
        bob.accept_distribution(&identity_of(&alice), &distribution)
            .await
            .unwrap();

        let known = bob.groups().unwrap();
        assert_eq!(known.len(), 1);
        assert_eq!(known[0].id, group.id);
        assert_eq!(known[0].name, "book club");
        assert!(known[0].contains(&identity_of(&alice)));
    }

    #[tokio::test]
    async fn a_member_without_the_sender_key_cannot_read() {
        let mut alice = messenger(1001);
        let mut stranger = messenger(4004);

        let group = alice
            .create_group("private", vec![identity_of(&alice)])
            .unwrap();
        let content = alice.encrypt_group(&group, b"secret").await.unwrap();
        let Content::Group { ciphertext, .. } = &content else {
            unreachable!()
        };

        assert!(stranger
            .decrypt_group(&identity_of(&alice), ciphertext)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn both_directions_work_in_a_group() {
        let mut alice = messenger(1001);
        let mut bob = messenger(2002);
        let members = vec![identity_of(&alice), identity_of(&bob)];

        let group = alice.create_group("duo", members).unwrap();
        let alice_id = identity_of(&alice);
        let bob_id = identity_of(&bob);

        let from_alice = alice.sender_key_distribution(&group).await.unwrap();
        bob.accept_distribution(&alice_id, &from_alice).await.unwrap();

        let bob_group = bob.group(&group.id).unwrap().unwrap();
        let from_bob = bob.sender_key_distribution(&bob_group).await.unwrap();
        alice.accept_distribution(&bob_id, &from_bob).await.unwrap();

        let a = alice.encrypt_group(&group, b"from alice").await.unwrap();
        let b = bob.encrypt_group(&bob_group, b"from bob").await.unwrap();
        let (Content::Group { ciphertext: ca, .. }, Content::Group { ciphertext: cb, .. }) =
            (&a, &b)
        else {
            unreachable!()
        };

        assert_eq!(bob.decrypt_group(&alice_id, ca).await.unwrap(), b"from alice");
        assert_eq!(alice.decrypt_group(&bob_id, cb).await.unwrap(), b"from bob");
    }

    #[tokio::test]
    async fn the_group_ratchet_advances() {
        let mut alice = messenger(1001);
        let mut bob = messenger(2002);
        let group = alice
            .create_group("g", vec![identity_of(&alice), identity_of(&bob)])
            .unwrap();

        let distribution = alice.sender_key_distribution(&group).await.unwrap();
        bob.accept_distribution(&identity_of(&alice), &distribution)
            .await
            .unwrap();

        let first = alice.encrypt_group(&group, b"same").await.unwrap();
        let second = alice.encrypt_group(&group, b"same").await.unwrap();
        assert_ne!(first, second);

        let (Content::Group { ciphertext: c1, .. }, Content::Group { ciphertext: c2, .. }) =
            (&first, &second)
        else {
            unreachable!()
        };
        assert_eq!(bob.decrypt_group(&identity_of(&alice), c2).await.unwrap(), b"same");
        assert_eq!(bob.decrypt_group(&identity_of(&alice), c1).await.unwrap(), b"same");
    }

    #[tokio::test]
    async fn a_tampered_group_message_is_rejected() {
        let mut alice = messenger(1001);
        let mut bob = messenger(2002);
        let group = alice
            .create_group("g", vec![identity_of(&alice), identity_of(&bob)])
            .unwrap();
        let distribution = alice.sender_key_distribution(&group).await.unwrap();
        bob.accept_distribution(&identity_of(&alice), &distribution)
            .await
            .unwrap();

        let content = alice.encrypt_group(&group, b"hello").await.unwrap();
        let Content::Group { ciphertext, .. } = content else {
            unreachable!()
        };
        let mut tampered = ciphertext.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;

        assert!(bob
            .decrypt_group(&identity_of(&alice), &tampered)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn the_creator_is_always_a_member() {
        let mut alice = messenger(1001);
        let bob = messenger(2002);
        let group = alice.create_group("g", vec![identity_of(&bob)]).unwrap();
        assert!(group.contains(&identity_of(&alice)));
    }

    #[tokio::test]
    async fn duplicate_members_are_collapsed() {
        let mut alice = messenger(1001);
        let bob = identity_of(&messenger(2002));
        let group = alice
            .create_group("g", vec![bob, bob, identity_of(&alice), bob])
            .unwrap();
        assert_eq!(group.members.len(), 2);
    }

    #[tokio::test]
    async fn fan_out_excludes_the_sender() {
        let mut alice = messenger(1001);
        let bob = identity_of(&messenger(2002));
        let carol = identity_of(&messenger(3003));
        let group = alice.create_group("g", vec![bob, carol]).unwrap();

        let others = group.others(&identity_of(&alice));
        assert_eq!(others.len(), 2);
        assert!(!others.contains(&identity_of(&alice)));
    }

    #[test]
    fn keypairs_are_distinct() {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let a = KeyPair::generate(&mut rng);
        let b = KeyPair::generate(&mut rng);
        assert_ne!(a.public_key.serialize(), b.public_key.serialize());
    }
}
