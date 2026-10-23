//! Encrypted-at-rest local storage.
//!
//! Signal's stores hold material that is as sensitive as the identity key
//! itself: session states carry the ratchet keys for every conversation, and
//! anyone who reads them can decrypt traffic. The spec requires local storage
//! to be encrypted with a key held on the USB drive, and this is where that
//! happens.
//!
//! # Key schedule
//!
//! ```text
//! vault_key = HKDF-SHA256(ikm = identity secret, salt = per-vault random,
//!                         info = "wisp.vault.v1")
//! record    = XChaCha20-Poly1305(vault_key, nonce, aad = namespace || key)
//! ```
//!
//! The salt is stored in the clear beside the data; the identity secret never
//! is. Pull the drive and the vault is inert — which is the point. The AAD
//! binds every ciphertext to its own slot, so a stored record cannot be lifted
//! and replayed into a different one: swapping one conversation's session blob
//! into another's would otherwise be undetectable.
//!
//! Each write uses a fresh random nonce. XChaCha20's 192-bit nonce makes random
//! generation safe without tracking a counter across restarts, which a 96-bit
//! nonce would not.

use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::Sha256;
use wisp_core::crypto;
use wisp_core::SecretBytes;

use crate::error::{MessagingError, MessagingResult};

const HKDF_INFO: &[u8] = b"wisp.vault.v1";
const SALT_KEY: &str = "vault_salt";
const NONCE_LEN: usize = 24;

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS records (
    namespace  TEXT NOT NULL,
    key        BLOB NOT NULL,
    nonce      BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    PRIMARY KEY (namespace, key)
);
"#;

/// A local database whose every value is encrypted under a key derived from the
/// USB-held identity secret.
///
/// The connection sits behind a `Mutex` so the vault is `Sync`. libsignal wants
/// each of its stores as a separate `&mut` field, so they all share one
/// `Arc<Vault>`; without the mutex that sharing could not cross a thread, and
/// the Tauri layer needs the whole thing to be `Send + Sync`.
pub struct Vault {
    conn: std::sync::Mutex<Connection>,
    key: SecretBytes,
}

impl Vault {
    /// Opens (or creates) a vault at `path`, deriving its key from
    /// `identity_secret`.
    ///
    /// A vault created under one identity cannot be opened by another: the
    /// derived key differs, so every record fails authentication.
    pub fn open(
        path: impl AsRef<std::path::Path>,
        identity_secret: &[u8],
    ) -> MessagingResult<Self> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn, identity_secret)
    }

    pub fn in_memory(identity_secret: &[u8]) -> MessagingResult<Self> {
        Self::from_connection(Connection::open_in_memory()?, identity_secret)
    }

    fn from_connection(conn: Connection, identity_secret: &[u8]) -> MessagingResult<Self> {
        conn.execute_batch(SCHEMA)?;

        // Reuse the existing salt, or mint one on first open. Regenerating it
        // would silently orphan every record already written.
        let salt: Vec<u8> = match conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                params![SALT_KEY],
                |row| row.get(0),
            )
            .optional()?
        {
            Some(existing) => existing,
            None => {
                let fresh = crypto::random_array::<32>().to_vec();
                conn.execute(
                    "INSERT INTO meta (key, value) VALUES (?1, ?2)",
                    params![SALT_KEY, &fresh],
                )?;
                fresh
            }
        };

        let hk = Hkdf::<Sha256>::new(Some(&salt), identity_secret);
        let mut key = SecretBytes::zeroed(32);
        hk.expand(HKDF_INFO, key.as_mut_slice())
            .map_err(|_| MessagingError::VaultKey)?;

        Ok(Self {
            conn: std::sync::Mutex::new(conn),
            key,
        })
    }

    /// Binds a ciphertext to its slot, so records cannot be moved between keys.
    fn aad(namespace: &str, key: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(namespace.len() + key.len() + 1);
        aad.extend_from_slice(namespace.as_bytes());
        aad.push(0x00);
        aad.extend_from_slice(key);
        aad
    }

    fn cipher(&self) -> MessagingResult<XChaCha20Poly1305> {
        XChaCha20Poly1305::new_from_slice(self.key.as_slice())
            .map_err(|_| MessagingError::VaultKey)
    }

    pub fn put(&self, namespace: &str, key: &[u8], plaintext: &[u8]) -> MessagingResult<()> {
        let nonce = crypto::random_array::<NONCE_LEN>();
        let ciphertext = self
            .cipher()?
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &Self::aad(namespace, key),
                },
            )
            .map_err(|_| MessagingError::VaultEncrypt)?;

        self.conn.lock().unwrap().execute(
            "INSERT INTO records (namespace, key, nonce, ciphertext) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(namespace, key) DO UPDATE SET
                 nonce = excluded.nonce, ciphertext = excluded.ciphertext",
            params![namespace, key, &nonce[..], &ciphertext],
        )?;
        Ok(())
    }

    pub fn get(&self, namespace: &str, key: &[u8]) -> MessagingResult<Option<Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        let row: Option<(Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT nonce, ciphertext FROM records WHERE namespace = ?1 AND key = ?2",
                params![namespace, key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let Some((nonce, ciphertext)) = row else {
            return Ok(None);
        };
        let nonce: [u8; NONCE_LEN] = nonce
            .try_into()
            .map_err(|_| MessagingError::VaultDecrypt)?;

        let plaintext = self
            .cipher()?
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &Self::aad(namespace, key),
                },
            )
            .map_err(|_| MessagingError::VaultDecrypt)?;
        Ok(Some(plaintext))
    }

    pub fn delete(&self, namespace: &str, key: &[u8]) -> MessagingResult<()> {
        self.conn.lock().unwrap().execute(
            "DELETE FROM records WHERE namespace = ?1 AND key = ?2",
            params![namespace, key],
        )?;
        Ok(())
    }

    pub fn contains(&self, namespace: &str, key: &[u8]) -> MessagingResult<bool> {
        Ok(self
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT 1 FROM records WHERE namespace = ?1 AND key = ?2",
                params![namespace, key],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Keys in a namespace beginning with `prefix`, in order.
    ///
    /// Conversation history is keyed by peer-then-timestamp, so a prefix scan
    /// is how one conversation is read without decrypting every other.
    pub fn keys_with_prefix(&self, namespace: &str, prefix: &[u8]) -> MessagingResult<Vec<Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT key FROM records
             WHERE namespace = ?1 AND substr(key, 1, ?2) = ?3
             ORDER BY key",
        )?;
        let rows = stmt.query_map(
            params![namespace, prefix.len() as i64, prefix],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Every key in a namespace. Values stay encrypted until asked for.
    pub fn keys(&self, namespace: &str) -> MessagingResult<Vec<Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT key FROM records WHERE namespace = ?1 ORDER BY key")?;
        let rows = stmt.query_map(params![namespace], |row| row.get::<_, Vec<u8>>(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"an identity secret from the usb drive";

    fn vault() -> Vault {
        Vault::in_memory(SECRET).unwrap()
    }

    #[test]
    fn values_round_trip() {
        let v = vault();
        v.put("session", b"alice", b"ratchet state").unwrap();
        assert_eq!(
            v.get("session", b"alice").unwrap().unwrap(),
            b"ratchet state"
        );
    }

    #[test]
    fn a_missing_record_is_none_not_an_error() {
        assert!(vault().get("session", b"nobody").unwrap().is_none());
    }

    #[test]
    fn writes_overwrite_in_place() {
        let v = vault();
        v.put("session", b"alice", b"first").unwrap();
        v.put("session", b"alice", b"second").unwrap();
        assert_eq!(v.get("session", b"alice").unwrap().unwrap(), b"second");
    }

    #[test]
    fn namespaces_are_separate() {
        let v = vault();
        v.put("session", b"alice", b"session data").unwrap();
        v.put("prekey", b"alice", b"prekey data").unwrap();
        assert_eq!(v.get("session", b"alice").unwrap().unwrap(), b"session data");
        assert_eq!(v.get("prekey", b"alice").unwrap().unwrap(), b"prekey data");
    }

    #[test]
    fn deletion_removes_the_record() {
        let v = vault();
        v.put("prekey", b"7", b"one-time").unwrap();
        assert!(v.contains("prekey", b"7").unwrap());
        v.delete("prekey", b"7").unwrap();
        assert!(!v.contains("prekey", b"7").unwrap());
        assert!(v.get("prekey", b"7").unwrap().is_none());
    }

    #[test]
    fn keys_are_listed_per_namespace() {
        let v = vault();
        v.put("prekey", b"1", b"a").unwrap();
        v.put("prekey", b"2", b"b").unwrap();
        v.put("session", b"3", b"c").unwrap();
        assert_eq!(v.keys("prekey").unwrap(), vec![b"1".to_vec(), b"2".to_vec()]);
        assert_eq!(v.keys("session").unwrap(), vec![b"3".to_vec()]);
    }

    /// Nothing readable may reach the disk.
    #[test]
    fn stored_bytes_are_not_the_plaintext() {
        let v = vault();
        v.put("session", b"alice", b"SUPER SECRET RATCHET").unwrap();

        let stored: Vec<u8> = v
            .conn.lock().unwrap()
            .query_row("SELECT ciphertext FROM records", [], |row| row.get(0))
            .unwrap();
        assert!(
            !stored.windows(5).any(|w| w == b"SUPER"),
            "plaintext reached the database"
        );
    }

    /// Pull the drive, and the vault is inert.
    #[test]
    fn a_different_identity_cannot_read_the_vault() {
        // Same connection would be needed to share the salt, so this is tested
        // through a file the two opens share.
        let dir = std::env::temp_dir().join(format!("wisp-vault-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.db");

        Vault::open(&path, SECRET)
            .unwrap()
            .put("session", b"alice", b"ratchet state")
            .unwrap();

        let impostor = Vault::open(&path, b"a different identity secret").unwrap();
        assert!(
            matches!(
                impostor.get("session", b"alice"),
                Err(MessagingError::VaultDecrypt)
            ),
            "the wrong identity must not be able to read the vault"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Reopening with the right secret must still work — the salt has to be
    /// reused, not regenerated.
    #[test]
    fn the_vault_survives_being_reopened() {
        let dir = std::env::temp_dir().join(format!("wisp-vault-reopen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.db");

        Vault::open(&path, SECRET)
            .unwrap()
            .put("session", b"alice", b"ratchet state")
            .unwrap();

        let reopened = Vault::open(&path, SECRET).unwrap();
        assert_eq!(
            reopened.get("session", b"alice").unwrap().unwrap(),
            b"ratchet state"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A record lifted into another slot must not decrypt there.
    #[test]
    fn ciphertexts_cannot_be_moved_between_slots() {
        let v = vault();
        v.put("session", b"alice", b"alice session").unwrap();

        let (nonce, ciphertext): (Vec<u8>, Vec<u8>) = v
            .conn.lock().unwrap()
            .query_row(
                "SELECT nonce, ciphertext FROM records WHERE key = ?1",
                params![b"alice".as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        // Same namespace, different key.
        v.conn.lock().unwrap()
            .execute(
                "INSERT INTO records (namespace, key, nonce, ciphertext) VALUES (?1, ?2, ?3, ?4)",
                params!["session", b"bob".as_slice(), &nonce, &ciphertext],
            )
            .unwrap();

        assert!(matches!(
            v.get("session", b"bob"),
            Err(MessagingError::VaultDecrypt)
        ));
    }

    #[test]
    fn tampering_with_a_record_is_detected() {
        let v = vault();
        v.put("session", b"alice", b"ratchet state").unwrap();
        v.conn.lock().unwrap()
            .execute(
                "UPDATE records SET ciphertext = ?1 WHERE key = ?2",
                params![vec![0xFFu8; 40], b"alice".as_slice()],
            )
            .unwrap();

        assert!(matches!(
            v.get("session", b"alice"),
            Err(MessagingError::VaultDecrypt)
        ));
    }
}
