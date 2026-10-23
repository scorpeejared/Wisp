//! libsignal's protocol stores, backed by the encrypted [`Vault`].
//!
//! Every record libsignal hands us is serialised with its own
//! `serialize()`/`deserialize()` and then encrypted before it touches disk, so
//! the on-disk format stays libsignal's problem and the confidentiality stays
//! ours.
//!
//! # Why six structs and not one
//!
//! libsignal's session functions take each store as a separate `&mut` argument
//! — `&mut store.session_store, &mut store.identity_store` — so a single type
//! implementing every trait could not be passed to them at all: it would be two
//! mutable borrows of the same value. The stores are therefore separate types
//! sharing one `Arc<Vault>`, which is also how libsignal's own in-memory store
//! is shaped.
//!
//! The identity key pair is *not* in the vault. It comes from `identity.wisp`
//! on the USB drive and is passed in at construction — the vault holds session
//! and prekey material, never the root secret that protects it.

use std::sync::Arc;

use async_trait::async_trait;
use libsignal_protocol::{
    Direction, GenericSignedPreKey, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore,
    KyberPreKeyId,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore, PrivateKey,
    ProtocolAddress, PublicKey, SenderKeyRecord, SenderKeyStore, SessionRecord, SessionStore,
    SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};
use uuid::Uuid;

use crate::vault::Vault;

const NS_SESSION: &str = "session";
const NS_IDENTITY: &str = "identity";
const NS_PREKEY: &str = "prekey";
const NS_SIGNED_PREKEY: &str = "signed_prekey";
const NS_KYBER_PREKEY: &str = "kyber_prekey";
const NS_KYBER_USED: &str = "kyber_used";
const NS_SENDER_KEY: &str = "sender_key";

/// Addresses key their records by name and device, so the same person on two
/// devices gets two sessions rather than one that fights itself.
fn address_key(address: &ProtocolAddress) -> Vec<u8> {
    format!("{}.{}", address.name(), address.device_id()).into_bytes()
}

/// Vault failures become `InvalidState` rather than propagating a storage type
/// into libsignal's error space, which has no room for it.
fn storage_error(context: &'static str, error: crate::MessagingError) -> SignalProtocolError {
    SignalProtocolError::InvalidState(context, error.to_string())
}

fn load(
    vault: &Vault,
    namespace: &str,
    key: &[u8],
    context: &'static str,
) -> Result<Option<Vec<u8>>, SignalProtocolError> {
    vault
        .get(namespace, key)
        .map_err(|e| storage_error(context, e))
}

fn save(
    vault: &Vault,
    namespace: &str,
    key: &[u8],
    value: &[u8],
    context: &'static str,
) -> Result<(), SignalProtocolError> {
    vault
        .put(namespace, key, value)
        .map_err(|e| storage_error(context, e))
}

// --- Identity ---------------------------------------------------------------

pub struct WispIdentityStore {
    vault: Arc<Vault>,
    identity: IdentityKeyPair,
    registration_id: u32,
}

#[async_trait(?Send)]
impl IdentityKeyStore for WispIdentityStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        Ok(self.identity)
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        let key = address_key(address);
        let serialised = identity.serialize().to_vec();
        let previous = load(&self.vault, NS_IDENTITY, &key, "save_identity")?;
        save(&self.vault, NS_IDENTITY, &key, &serialised, "save_identity")?;

        Ok(match previous {
            Some(existing) if existing != serialised => IdentityChange::ReplacedExisting,
            _ => IdentityChange::NewOrUnchanged,
        })
    }

    /// Trust on first use.
    ///
    /// An unknown identity is accepted; a *changed* one is refused. Refusing the
    /// change is what turns a relay swapping in its own key into a visible
    /// failure rather than silent interception — the user has to re-verify the
    /// fingerprint before traffic resumes.
    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        match load(&self.vault, NS_IDENTITY, &address_key(address), "is_trusted_identity")? {
            None => Ok(true),
            Some(known) => Ok(known == identity.serialize().to_vec()),
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        match load(&self.vault, NS_IDENTITY, &address_key(address), "get_identity")? {
            Some(bytes) => Ok(Some(IdentityKey::decode(&bytes)?)),
            None => Ok(None),
        }
    }
}

// --- Sessions ---------------------------------------------------------------

pub struct WispSessionStore {
    vault: Arc<Vault>,
}

#[async_trait(?Send)]
impl SessionStore for WispSessionStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        match load(&self.vault, NS_SESSION, &address_key(address), "load_session")? {
            Some(bytes) => Ok(Some(SessionRecord::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        save(
            &self.vault,
            NS_SESSION,
            &address_key(address),
            &record.serialize()?,
            "store_session",
        )
    }
}

// --- One-time prekeys -------------------------------------------------------

pub struct WispPreKeyStore {
    vault: Arc<Vault>,
}

#[async_trait(?Send)]
impl PreKeyStore for WispPreKeyStore {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        match load(
            &self.vault,
            NS_PREKEY,
            &u32::from(prekey_id).to_be_bytes(),
            "get_pre_key",
        )? {
            Some(bytes) => PreKeyRecord::deserialize(&bytes),
            None => Err(SignalProtocolError::InvalidPreKeyId),
        }
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        save(
            &self.vault,
            NS_PREKEY,
            &u32::from(prekey_id).to_be_bytes(),
            &record.serialize()?,
            "save_pre_key",
        )
    }

    /// Deleting a used one-time prekey is what makes it one-time.
    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        self.vault
            .delete(NS_PREKEY, &u32::from(prekey_id).to_be_bytes())
            .map_err(|e| storage_error("remove_pre_key", e))
    }
}

// --- Signed prekeys ---------------------------------------------------------

pub struct WispSignedPreKeyStore {
    vault: Arc<Vault>,
}

#[async_trait(?Send)]
impl SignedPreKeyStore for WispSignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        match load(
            &self.vault,
            NS_SIGNED_PREKEY,
            &u32::from(signed_prekey_id).to_be_bytes(),
            "get_signed_pre_key",
        )? {
            Some(bytes) => SignedPreKeyRecord::deserialize(&bytes),
            None => Err(SignalProtocolError::InvalidSignedPreKeyId),
        }
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        save(
            &self.vault,
            NS_SIGNED_PREKEY,
            &u32::from(signed_prekey_id).to_be_bytes(),
            &record.serialize()?,
            "save_signed_pre_key",
        )
    }
}

// --- Kyber prekeys ----------------------------------------------------------

pub struct WispKyberPreKeyStore {
    vault: Arc<Vault>,
}

#[async_trait(?Send)]
impl KyberPreKeyStore for WispKyberPreKeyStore {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        match load(
            &self.vault,
            NS_KYBER_PREKEY,
            &u32::from(kyber_prekey_id).to_be_bytes(),
            "get_kyber_pre_key",
        )? {
            Some(bytes) => KyberPreKeyRecord::deserialize(&bytes),
            None => Err(SignalProtocolError::InvalidKyberPreKeyId),
        }
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        save(
            &self.vault,
            NS_KYBER_PREKEY,
            &u32::from(kyber_prekey_id).to_be_bytes(),
            &record.serialize()?,
            "save_kyber_pre_key",
        )
    }

    /// Records that a (kyber, ec, base key) triple has been used.
    ///
    /// Recording the triple rather than deleting the prekey is what lets a
    /// last-resort key stay usable while still catching a replay of the same
    /// combination.
    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        let mut key = Vec::with_capacity(8 + 33);
        key.extend_from_slice(&u32::from(kyber_prekey_id).to_be_bytes());
        key.extend_from_slice(&u32::from(ec_prekey_id).to_be_bytes());
        key.extend_from_slice(&base_key.serialize());

        if self
            .vault
            .contains(NS_KYBER_USED, &key)
            .map_err(|e| storage_error("mark_kyber_pre_key_used", e))?
        {
            return Err(SignalProtocolError::InvalidState(
                "mark_kyber_pre_key_used",
                "this prekey combination has already been used".into(),
            ));
        }

        save(&self.vault, NS_KYBER_USED, &key, &[1], "mark_kyber_pre_key_used")
    }
}

// --- Sender keys (groups, later) --------------------------------------------

pub struct WispSenderKeyStore {
    vault: Arc<Vault>,
}

fn sender_key_key(sender: &ProtocolAddress, distribution_id: Uuid) -> Vec<u8> {
    let mut key = address_key(sender);
    key.push(0x00);
    key.extend_from_slice(distribution_id.as_bytes());
    key
}

#[async_trait(?Send)]
impl SenderKeyStore for WispSenderKeyStore {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        save(
            &self.vault,
            NS_SENDER_KEY,
            &sender_key_key(sender, distribution_id),
            &record.serialize()?,
            "store_sender_key",
        )
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        match load(
            &self.vault,
            NS_SENDER_KEY,
            &sender_key_key(sender, distribution_id),
            "load_sender_key",
        )? {
            Some(bytes) => Ok(Some(SenderKeyRecord::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }
}

// --- The bundle of stores ---------------------------------------------------

/// All of libsignal's stores over one encrypted vault.
///
/// Fields are public because that is how libsignal wants them passed.
pub struct WispProtocolStore {
    pub vault: Arc<Vault>,
    pub identity_store: WispIdentityStore,
    pub session_store: WispSessionStore,
    pub pre_key_store: WispPreKeyStore,
    pub signed_pre_key_store: WispSignedPreKeyStore,
    pub kyber_pre_key_store: WispKyberPreKeyStore,
    pub sender_key_store: WispSenderKeyStore,
}

impl WispProtocolStore {
    pub fn new(vault: Vault, identity: IdentityKeyPair, registration_id: u32) -> Self {
        let vault = Arc::new(vault);
        Self {
            identity_store: WispIdentityStore {
                vault: Arc::clone(&vault),
                identity,
                registration_id,
            },
            session_store: WispSessionStore {
                vault: Arc::clone(&vault),
            },
            pre_key_store: WispPreKeyStore {
                vault: Arc::clone(&vault),
            },
            signed_pre_key_store: WispSignedPreKeyStore {
                vault: Arc::clone(&vault),
            },
            kyber_pre_key_store: WispKyberPreKeyStore {
                vault: Arc::clone(&vault),
            },
            sender_key_store: WispSenderKeyStore {
                vault: Arc::clone(&vault),
            },
            vault,
        }
    }

    pub fn identity_key_pair(&self) -> &IdentityKeyPair {
        &self.identity_store.identity
    }

    pub fn registration_id(&self) -> u32 {
        self.identity_store.registration_id
    }
}

/// Rebuilds an identity key pair from the 32-byte private key held on the USB
/// drive.
pub fn identity_from_private_key(
    private_key: &[u8],
) -> Result<IdentityKeyPair, SignalProtocolError> {
    let private = PrivateKey::deserialize(private_key)?;
    let public = private.public_key()?;
    Ok(IdentityKeyPair::new(IdentityKey::new(public), private))
}
