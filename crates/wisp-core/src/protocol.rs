use sha2::{Digest, Sha256};

const USERNAME_DOMAIN: &[u8] = b"wisp.username.v1";
const REGISTER_DOMAIN: &[u8] = b"wisp.register.v2";
const AUTH_DOMAIN: &[u8] = b"wisp.auth.v1";

pub fn username_hash(canonical_username: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(USERNAME_DOMAIN);
    hasher.update(canonical_username.as_bytes());
    hasher.finalize().into()
}

pub fn registration_challenge(public_key: &[u8; 32], username_hash: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(REGISTER_DOMAIN.len() + 64);
    message.extend_from_slice(REGISTER_DOMAIN);
    message.extend_from_slice(public_key);
    message.extend_from_slice(username_hash);
    message
}

pub fn auth_message(nonce: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(AUTH_DOMAIN.len() + 32);
    message.extend_from_slice(AUTH_DOMAIN);
    message.extend_from_slice(nonce);
    message
}

pub fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    if signature.len() != 64 {
        return false;
    }
    match libsignal_protocol::PublicKey::from_djb_public_key_bytes(public_key) {
        Ok(key) => key.verify_signature(message, signature),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_hashing_is_stable_and_distinct() {
        assert_eq!(username_hash("alice"), username_hash("alice"));
        assert_ne!(username_hash("alice"), username_hash("bob"));
    }

    #[test]
    fn the_hash_does_not_contain_the_username() {
        let hash = username_hash("alice");
        assert!(!hash.windows(5).any(|w| w == b"alice"));
    }

    #[test]
    fn registration_challenge_binds_every_input() {
        let base = registration_challenge(&[2; 32], &[3; 32]);
        assert_ne!(base, registration_challenge(&[9; 32], &[3; 32]));
        assert_ne!(base, registration_challenge(&[2; 32], &[9; 32]));
    }

    #[test]
    fn a_genuine_signature_verifies() {
        let identity = crate::UnlockedIdentity::generate("alice").unwrap();
        let public = identity.public_key().unwrap();
        let message = b"prove you hold this key";

        assert!(verify_signature(
            &public,
            message,
            &identity.sign(message).unwrap()
        ));
    }

    #[test]
    fn a_signature_from_another_key_does_not_verify() {
        let alice = crate::UnlockedIdentity::generate("alice").unwrap();
        let mallory = crate::UnlockedIdentity::generate("mallory").unwrap();
        let message = b"prove you hold this key";

        assert!(!verify_signature(
            &alice.public_key().unwrap(),
            message,
            &mallory.sign(message).unwrap()
        ));
    }

    #[test]
    fn a_signature_over_a_different_message_does_not_verify() {
        let identity = crate::UnlockedIdentity::generate("alice").unwrap();
        assert!(!verify_signature(
            &identity.public_key().unwrap(),
            b"a different message",
            &identity.sign(b"the original message").unwrap()
        ));
    }

    #[test]
    fn malformed_signatures_are_rejected_cleanly() {
        let identity = crate::UnlockedIdentity::generate("alice").unwrap();
        let public = identity.public_key().unwrap();

        assert!(!verify_signature(&public, b"msg", &[]));
        assert!(!verify_signature(&public, b"msg", &[0u8; 63]));
        assert!(!verify_signature(&public, b"msg", &[0u8; 65]));
        assert!(!verify_signature(&public, b"msg", &[0xFF; 64]));
        assert!(!verify_signature(&[0u8; 32], b"msg", &[0u8; 64]));
    }

    #[test]
    fn domains_are_separated() {
        let registration = registration_challenge(&[0; 32], &[0; 32]);
        let auth = auth_message(&[0; 32]);
        assert!(!registration.starts_with(AUTH_DOMAIN));
        assert!(!auth.starts_with(REGISTER_DOMAIN));
        assert_ne!(registration, auth);
    }
}
