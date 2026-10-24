use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::secret::SecretBytes;

pub const KDF_ID_ARGON2ID: u8 = 1;
pub const AEAD_ID_XCHACHA20POLY1305: u8 = 1;

pub const KDF_SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

const HKDF_INFO: &[u8] = b"wisp.identity.v1.aead-key";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    pub const RECOMMENDED: Self = Self {
        m_cost: 128 * 1024,
        t_cost: 4,
        p_cost: 1,
    };

    pub const INSECURE_FOR_TESTS: Self = Self {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    };

    fn to_argon2(self) -> Result<Argon2<'static>> {
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|_| Error::BadKdfParams)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::RECOMMENDED
    }
}

pub fn fill_random(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    fill_random(&mut out);
    out
}

pub fn derive_file_key(
    passphrase: &[u8],
    kdf_salt: &[u8; KDF_SALT_LEN],
    params: KdfParams,
) -> Result<SecretBytes> {
    let mut key = SecretBytes::zeroed(KEY_LEN);
    params
        .to_argon2()?
        .hash_password_into(passphrase, kdf_salt, key.as_mut_slice())
        .map_err(|_| Error::KdfFailed)?;
    Ok(key)
}

pub fn derive_aead_key(file_key: &SecretBytes, fingerprint_hash: &[u8; 32]) -> Result<SecretBytes> {
    let hk = Hkdf::<Sha256>::new(Some(fingerprint_hash), file_key.as_slice());
    let mut key = SecretBytes::zeroed(KEY_LEN);
    hk.expand(HKDF_INFO, key.as_mut_slice())
        .map_err(|_| Error::KdfFailed)?;
    Ok(key)
}

pub fn aead_encrypt(
    key: &SecretBytes,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| Error::Encrypt)?;
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::Encrypt)
}

pub fn aead_decrypt(
    key: &SecretBytes,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<SecretBytes> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| Error::Decrypt)?;
    let mut plaintext = cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| Error::Decrypt)?;
    Ok(SecretBytes::from_slice_mut(&mut plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: KdfParams = KdfParams::INSECURE_FOR_TESTS;

    fn key_for(pass: &[u8], salt: &[u8; KDF_SALT_LEN], fp: &[u8; 32]) -> SecretBytes {
        let fk = derive_file_key(pass, salt, P).unwrap();
        derive_aead_key(&fk, fp).unwrap()
    }

    #[test]
    fn derivation_is_deterministic() {
        let salt = [7u8; KDF_SALT_LEN];
        let a = derive_file_key(b"passphrase", &salt, P).unwrap();
        let b = derive_file_key(b"passphrase", &salt, P).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn different_salt_gives_different_key() {
        let a = derive_file_key(b"passphrase", &[1u8; KDF_SALT_LEN], P).unwrap();
        let b = derive_file_key(b"passphrase", &[2u8; KDF_SALT_LEN], P).unwrap();
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn round_trip_recovers_plaintext() {
        let key = key_for(b"pw", &[0u8; KDF_SALT_LEN], &[9u8; 32]);
        let nonce = [3u8; NONCE_LEN];
        let ct = aead_encrypt(&key, &nonce, b"header", b"secret payload").unwrap();
        let pt = aead_decrypt(&key, &nonce, b"header", &ct).unwrap();
        assert_eq!(pt.as_slice(), b"secret payload");
    }

    #[test]
    fn ciphertext_carries_an_authentication_tag() {
        let key = key_for(b"pw", &[0u8; KDF_SALT_LEN], &[9u8; 32]);
        let ct = aead_encrypt(&key, &[0u8; NONCE_LEN], b"", b"12345").unwrap();
        assert_eq!(ct.len(), 5 + TAG_LEN);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let salt = [0u8; KDF_SALT_LEN];
        let fp = [9u8; 32];
        let ct = aead_encrypt(&key_for(b"right", &salt, &fp), &[0u8; NONCE_LEN], b"", b"x").unwrap();
        let attempt = aead_decrypt(&key_for(b"wrong", &salt, &fp), &[0u8; NONCE_LEN], b"", &ct);
        assert!(matches!(attempt, Err(Error::Decrypt)));
    }

    #[test]
    fn right_passphrase_wrong_device_fails() {
        let salt = [0u8; KDF_SALT_LEN];
        let ct = aead_encrypt(
            &key_for(b"pw", &salt, &[1u8; 32]),
            &[0u8; NONCE_LEN],
            b"",
            b"identity",
        )
        .unwrap();
        let attempt = aead_decrypt(
            &key_for(b"pw", &salt, &[2u8; 32]),
            &[0u8; NONCE_LEN],
            b"",
            &ct,
        );
        assert!(matches!(attempt, Err(Error::Decrypt)));
    }

    #[test]
    fn tampering_with_aad_fails() {
        let key = key_for(b"pw", &[0u8; KDF_SALT_LEN], &[9u8; 32]);
        let ct = aead_encrypt(&key, &[0u8; NONCE_LEN], b"v1-header", b"x").unwrap();
        let attempt = aead_decrypt(&key, &[0u8; NONCE_LEN], b"v2-header", &ct);
        assert!(matches!(attempt, Err(Error::Decrypt)));
    }

    #[test]
    fn tampering_with_ciphertext_fails() {
        let key = key_for(b"pw", &[0u8; KDF_SALT_LEN], &[9u8; 32]);
        let mut ct = aead_encrypt(&key, &[0u8; NONCE_LEN], b"", b"x").unwrap();
        ct[0] ^= 0x01;
        assert!(aead_decrypt(&key, &[0u8; NONCE_LEN], b"", &ct).is_err());
    }

    #[test]
    fn random_bytes_are_not_constant() {
        assert_ne!(random_array::<32>(), random_array::<32>());
    }
}
