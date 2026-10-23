//! Sealed sender.
//!
//! Without it the relay sees *who is talking to whom* even though it cannot
//! read a word — and that social graph is often the more damaging leak. Sealed
//! sender moves the originator inside the ciphertext, encrypted to the
//! recipient, so the relay sees only a destination.
//!
//! # How the recipient still knows who sent it
//!
//! A sender attaches a **sender certificate** issued by the relay, which the
//! recipient validates against a **trust root** public key. The chain is:
//!
//! ```text
//! trust root key  --signs-->  server certificate  --signs-->  sender certificate
//! ```
//!
//! The relay therefore vouches that a public key belongs to an account, but the
//! *message* it carries is sealed against it. This is worth being precise
//! about: the relay could issue itself a certificate for any identity, so
//! sealed sender does not make the relay untrusted for authenticity — that job
//! belongs to the identity fingerprint users compare out of band. What it does
//! remove is the relay's routine, passive view of who messages whom.
//!
//! # Identity strings
//!
//! libsignal addresses accounts by UUID because Signal does. Wisp has no
//! UUIDs, so the lowercase hex identity key is used as the identifier
//! throughout — one canonical form, derived from the key itself, so it cannot
//! disagree with the key it names.

use std::time::{Duration, SystemTime};

use libsignal_protocol::{
    sealed_sender_decrypt, sealed_sender_encrypt, KeyPair, PrivateKey, ProtocolAddress, PublicKey,
    SenderCertificate, ServerCertificate, Timestamp,
};
use rand::TryRngCore;

use crate::error::{MessagingError, MessagingResult};
use crate::{device_id, Messenger};

/// How long an issued sender certificate stays valid.
///
/// Short enough that a leaked certificate stops being useful quickly, long
/// enough that a client is not fetching one per message.
pub const CERTIFICATE_VALIDITY: Duration = Duration::from_secs(24 * 3600);

/// Renders an identity key as the string libsignal will carry as the sender id.
pub fn identity_string(public_key: &[u8; 32]) -> String {
    public_key.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses an identity string back into a key.
pub fn identity_from_string(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The relay's certificate issuer.
///
/// Holds two private keys: the trust root, which clients pin, and a server key
/// that the trust root signs. They are separate so the signing key can be
/// rotated without every client having to learn a new trust root.
pub struct CertificateAuthority {
    trust_root: PrivateKey,
    server_key: KeyPair,
    server_certificate: ServerCertificate,
}

impl CertificateAuthority {
    /// Mints a fresh authority. The caller must persist both private keys.
    pub fn generate() -> MessagingResult<Self> {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let trust_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);
        Self::assemble(trust_root.private_key, server_key)
    }

    /// Rebuilds an authority from persisted keys.
    pub fn restore(trust_root: &[u8], server_private: &[u8]) -> MessagingResult<Self> {
        let trust_root =
            PrivateKey::deserialize(trust_root).map_err(|e| MessagingError::Key(e.to_string()))?;
        let server_private = PrivateKey::deserialize(server_private)
            .map_err(|e| MessagingError::Key(e.to_string()))?;
        let server_public = server_private
            .public_key()
            .map_err(|e| MessagingError::Key(e.to_string()))?;

        Self::assemble(
            trust_root,
            KeyPair::new(server_public, server_private),
        )
    }

    fn assemble(trust_root: PrivateKey, server_key: KeyPair) -> MessagingResult<Self> {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let server_certificate =
            ServerCertificate::new(1, server_key.public_key, &trust_root, &mut rng)?;
        Ok(Self {
            trust_root,
            server_key,
            server_certificate,
        })
    }

    /// The value clients pin to validate certificates.
    pub fn trust_root_public(&self) -> MessagingResult<[u8; 32]> {
        self.trust_root
            .public_key()
            .map_err(|e| MessagingError::Key(e.to_string()))?
            .public_key_bytes()
            .try_into()
            .map_err(|_| MessagingError::Malformed)
    }

    pub fn trust_root_private_bytes(&self) -> Vec<u8> {
        self.trust_root.serialize()
    }

    pub fn server_private_bytes(&self) -> Vec<u8> {
        self.server_key.private_key.serialize()
    }

    /// Issues a certificate binding an identity key to its own name.
    pub fn issue(
        &self,
        sender_identity: &[u8; 32],
        valid_for: Duration,
    ) -> MessagingResult<Vec<u8>> {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let sender_public = PublicKey::from_djb_public_key_bytes(sender_identity)
            .map_err(|e| MessagingError::Key(e.to_string()))?;

        let expires = SystemTime::now()
            .checked_add(valid_for)
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64)
            .ok_or(MessagingError::Malformed)?;

        let certificate = SenderCertificate::new(
            identity_string(sender_identity),
            None,
            sender_public,
            device_id(),
            Timestamp::from_epoch_millis(expires),
            self.server_certificate.clone(),
            &self.server_key.private_key,
            &mut rng,
        )?;

        Ok(certificate.serialized()?.to_vec())
    }
}

impl Messenger {
    /// Encrypts so the relay cannot tell who sent it.
    ///
    /// Requires a live session, same as an ordinary message — sealed sender
    /// hides the sender, it does not replace the ratchet.
    pub async fn seal(
        &mut self,
        remote: &ProtocolAddress,
        sender_certificate: &[u8],
        plaintext: &[u8],
    ) -> MessagingResult<Vec<u8>> {
        if !self.has_session(remote).await? {
            return Err(MessagingError::NoSession(remote.name().to_string()));
        }

        let certificate = SenderCertificate::deserialize(sender_certificate)?;
        let mut rng = rand::rngs::OsRng.unwrap_err();

        Ok(sealed_sender_encrypt(
            remote,
            &certificate,
            plaintext,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            SystemTime::now(),
            &mut rng,
        )
        .await?)
    }

    /// Decrypts a sealed message, returning the sender's identity key.
    ///
    /// The sender is discovered here rather than supplied: the whole point is
    /// that nothing outside the ciphertext said who it was from. The
    /// certificate is validated against `trust_root`, so an unsigned or expired
    /// claim is rejected before the plaintext is returned.
    pub async fn unseal(
        &mut self,
        trust_root: &[u8; 32],
        ciphertext: &[u8],
    ) -> MessagingResult<([u8; 32], Vec<u8>)> {
        let trust_root_key = PublicKey::from_djb_public_key_bytes(trust_root)
            .map_err(|e| MessagingError::Key(e.to_string()))?;

        let local_identity = self
            .identity_key_pair()
            .public_key()
            .public_key_bytes()
            .try_into()
            .map_err(|_| MessagingError::Malformed)?;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let result = sealed_sender_decrypt(
            ciphertext,
            &trust_root_key,
            Timestamp::from_epoch_millis(now),
            None,
            identity_string(&local_identity),
            device_id(),
            &mut self.store.identity_store,
            &mut self.store.session_store,
            &mut self.store.pre_key_store,
            &self.store.signed_pre_key_store,
            &mut self.store.kyber_pre_key_store,
        )
        .await?;

        let sender = identity_from_string(&result.sender_uuid).ok_or(MessagingError::Malformed)?;
        Ok((sender, result.message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bundle_from_published, WispProtocolStore};
    use libsignal_protocol::IdentityKeyPair;

    fn messenger(registration_id: u32) -> Messenger {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let identity = IdentityKeyPair::generate(&mut rng);
        let vault = crate::Vault::in_memory(&identity.private_key().serialize()).unwrap();
        Messenger::new(WispProtocolStore::new(vault, identity, registration_id))
    }

    fn identity_of(m: &Messenger) -> [u8; 32] {
        m.identity_key_pair()
            .public_key()
            .public_key_bytes()
            .try_into()
            .unwrap()
    }

    fn address(key: &[u8; 32]) -> ProtocolAddress {
        ProtocolAddress::new(identity_string(key), device_id())
    }

    /// Sets up a live session from Alice to Bob.
    async fn linked() -> (Messenger, Messenger) {
        let mut alice = messenger(1001);
        let mut bob = messenger(2002);

        let published = bob.generate_prekeys(1, 1, 100, 5).await.unwrap();
        let one_time = published.one_time_prekeys[0].clone();
        let bundle = bundle_from_published(&published, Some((one_time.0, &one_time.1))).unwrap();

        let bob_address = address(&identity_of(&bob));
        alice.start_session(&bob_address, &bundle).await.unwrap();
        (alice, bob)
    }

    #[test]
    fn identity_strings_round_trip() {
        let key = [0xABu8; 32];
        assert_eq!(identity_from_string(&identity_string(&key)), Some(key));
        assert_eq!(identity_from_string("short"), None);
        assert_eq!(identity_from_string(&"z".repeat(64)), None);
    }

    /// The headline property: the recipient learns who sent it, from inside the
    /// ciphertext, with nothing on the outside saying so.
    #[tokio::test]
    async fn a_sealed_message_carries_its_sender_inside() {
        let authority = CertificateAuthority::generate().unwrap();
        let trust_root = authority.trust_root_public().unwrap();

        let (mut alice, mut bob) = linked().await;
        let alice_identity = identity_of(&alice);
        let certificate = authority
            .issue(&alice_identity, CERTIFICATE_VALIDITY)
            .unwrap();

        let sealed = alice
            .seal(&address(&identity_of(&bob)), &certificate, b"hello bob")
            .await
            .unwrap();

        let (sender, plaintext) = bob.unseal(&trust_root, &sealed).await.unwrap();
        assert_eq!(sender, alice_identity);
        assert_eq!(plaintext, b"hello bob");
    }

    /// The sender's identity must not be recoverable from the ciphertext by
    /// anyone without the recipient's key — the relay included.
    #[tokio::test]
    async fn the_sender_identity_is_not_visible_in_the_ciphertext() {
        let authority = CertificateAuthority::generate().unwrap();
        let (mut alice, bob) = linked().await;
        let alice_identity = identity_of(&alice);
        let certificate = authority
            .issue(&alice_identity, CERTIFICATE_VALIDITY)
            .unwrap();

        let sealed = alice
            .seal(&address(&identity_of(&bob)), &certificate, b"hello bob")
            .await
            .unwrap();

        assert!(
            !sealed
                .windows(alice_identity.len())
                .any(|w| w == alice_identity),
            "the sender's key appears in the sealed ciphertext"
        );
        let as_text = identity_string(&alice_identity);
        assert!(
            !sealed.windows(as_text.len()).any(|w| w == as_text.as_bytes()),
            "the sender's identity string appears in the sealed ciphertext"
        );
    }

    /// A certificate from an authority the recipient does not trust must be
    /// refused, or anyone could claim to be anyone.
    #[tokio::test]
    async fn a_certificate_from_an_untrusted_authority_is_refused() {
        let real = CertificateAuthority::generate().unwrap();
        let impostor = CertificateAuthority::generate().unwrap();

        let (mut alice, mut bob) = linked().await;
        let certificate = impostor
            .issue(&identity_of(&alice), CERTIFICATE_VALIDITY)
            .unwrap();

        let sealed = alice
            .seal(&address(&identity_of(&bob)), &certificate, b"trust me")
            .await
            .unwrap();

        assert!(
            bob.unseal(&real.trust_root_public().unwrap(), &sealed)
                .await
                .is_err(),
            "a certificate signed by an unknown authority was accepted"
        );
    }

    #[tokio::test]
    async fn an_expired_certificate_is_refused() {
        let authority = CertificateAuthority::generate().unwrap();
        let trust_root = authority.trust_root_public().unwrap();

        let (mut alice, mut bob) = linked().await;
        // Already expired when issued.
        let certificate = authority
            .issue(&identity_of(&alice), Duration::from_secs(0))
            .unwrap();

        let sealed = alice
            .seal(&address(&identity_of(&bob)), &certificate, b"stale")
            .await
            .unwrap();

        assert!(bob.unseal(&trust_root, &sealed).await.is_err());
    }

    #[tokio::test]
    async fn a_tampered_sealed_message_is_rejected() {
        let authority = CertificateAuthority::generate().unwrap();
        let trust_root = authority.trust_root_public().unwrap();

        let (mut alice, mut bob) = linked().await;
        let certificate = authority
            .issue(&identity_of(&alice), CERTIFICATE_VALIDITY)
            .unwrap();

        let mut sealed = alice
            .seal(&address(&identity_of(&bob)), &certificate, b"hello")
            .await
            .unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;

        assert!(bob.unseal(&trust_root, &sealed).await.is_err());
    }

    #[tokio::test]
    async fn sealing_without_a_session_is_refused() {
        let authority = CertificateAuthority::generate().unwrap();
        let mut alice = messenger(1001);
        let certificate = authority
            .issue(&identity_of(&alice), CERTIFICATE_VALIDITY)
            .unwrap();

        assert!(matches!(
            alice.seal(&address(&[9u8; 32]), &certificate, b"hi").await,
            Err(MessagingError::NoSession(_))
        ));
    }

    /// An authority restored from persisted keys must issue certificates the
    /// same clients still trust — otherwise a relay restart breaks everyone.
    #[tokio::test]
    async fn a_restored_authority_keeps_its_trust_root() {
        let original = CertificateAuthority::generate().unwrap();
        let restored = CertificateAuthority::restore(
            &original.trust_root_private_bytes(),
            &original.server_private_bytes(),
        )
        .unwrap();

        assert_eq!(
            restored.trust_root_public().unwrap(),
            original.trust_root_public().unwrap()
        );

        let (mut alice, mut bob) = linked().await;
        let certificate = restored
            .issue(&identity_of(&alice), CERTIFICATE_VALIDITY)
            .unwrap();
        let sealed = alice
            .seal(&address(&identity_of(&bob)), &certificate, b"after restart")
            .await
            .unwrap();

        let (_, plaintext) = bob
            .unseal(&original.trust_root_public().unwrap(), &sealed)
            .await
            .unwrap();
        assert_eq!(plaintext, b"after restart");
    }
}
