//! SQLite storage for the relay.
//!
//! # What the server is allowed to know
//!
//! Public keys, *hashed* usernames, invite records, and encrypted blobs it
//! cannot read. That is the whole list.
//!
//! Usernames are stored only as a SHA-256 digest. Uniqueness still works — the
//! digest is the unique index — but the server holds no browsable directory of
//! who uses Wisp. Nothing needs the plaintext: users find each other by
//! fingerprint (spec §5), and a display name travels inside the end-to-end
//! encrypted payload, never from here. A server that cannot enumerate its users
//! cannot be compelled to hand that list over.
//!
//! Message blobs are transient. [`Store::take_pending`] deletes as it reads, so
//! a delivered message is gone from the server in the same transaction that
//! delivers it.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

use wisp_invite::RedemptionHash;

use crate::error::{ServerError, ServerResult};

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS accounts (
    public_key    BLOB PRIMARY KEY NOT NULL,
    username_hash BLOB NOT NULL UNIQUE,
    created_at    INTEGER NOT NULL,
    locked_until  INTEGER
);

CREATE TABLE IF NOT EXISTS invites (
    redemption_hash BLOB PRIMARY KEY NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    note            TEXT,
    revoked_at      INTEGER,
    used_at         INTEGER,
    used_by         BLOB
);

CREATE TABLE IF NOT EXISTS attempts (
    scope        TEXT PRIMARY KEY NOT NULL,
    count        INTEGER NOT NULL,
    first_at     INTEGER NOT NULL,
    locked_until INTEGER
);

CREATE TABLE IF NOT EXISTS pending_messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient  BLOB NOT NULL,
    envelope   BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pending_recipient ON pending_messages(recipient);

-- Prekey material is all *public* keys. The relay stores it so a sender can
-- start a session with someone who is offline, which is the whole point of
-- X3DH. It never sees a private key and cannot derive a session from these.
CREATE TABLE IF NOT EXISTS prekey_bundles (
    owner                   BLOB PRIMARY KEY NOT NULL,
    identity_key            BLOB NOT NULL,
    registration_id         INTEGER NOT NULL,
    signed_prekey_id        INTEGER NOT NULL,
    signed_prekey_public    BLOB NOT NULL,
    signed_prekey_signature BLOB NOT NULL,
    kyber_prekey_id         INTEGER,
    kyber_prekey_public     BLOB,
    kyber_prekey_signature  BLOB,
    updated_at              INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS one_time_prekeys (
    rowid_alias INTEGER PRIMARY KEY AUTOINCREMENT,
    owner       BLOB NOT NULL,
    prekey_id   INTEGER NOT NULL,
    public      BLOB NOT NULL,
    UNIQUE(owner, prekey_id)
);

CREATE INDEX IF NOT EXISTS idx_one_time_owner ON one_time_prekeys(owner);

-- Long-lived relay keys: the sealed-sender trust root and the certificate
-- signing key it vouches for. Generated once, on first start.
CREATE TABLE IF NOT EXISTS server_meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value BLOB NOT NULL
);
"#;

/// A 32-byte Ed25519 public identity key.
pub type PublicKey = [u8; 32];

/// SHA-256 of a canonical username. The server never sees the plaintext.
///
/// Delegates to `wisp-core` so client and relay hash identically; a divergence
/// here would make every registration fail its signature check.
pub use wisp_core::protocol::username_hash;

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// An account's long-lived prekey material.
///
/// Every field is a public key or a signature over one. The relay stores these
/// verbatim and never interprets them — validating the signatures is the
/// *recipient's* job, and a relay that could vouch for them would be a relay
/// you had to trust.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PreKeyBundle {
    pub identity_key: Vec<u8>,
    pub registration_id: i64,
    pub signed_prekey_id: i64,
    pub signed_prekey_public: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    /// Post-quantum prekey. Optional so the format survives a client that
    /// predates it.
    pub kyber_prekey_id: Option<i64>,
    pub kyber_prekey_public: Option<Vec<u8>>,
    pub kyber_prekey_signature: Option<Vec<u8>>,
}

/// A single-use prekey, handed out at most once.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OneTimePreKey {
    pub id: i64,
    pub public: Vec<u8>,
}

/// What a sender receives to start a session.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FetchedBundle {
    #[serde(flatten)]
    pub bundle: PreKeyBundle,
    /// Absent when the recipient's pool is exhausted; X3DH proceeds without it.
    pub one_time: Option<OneTimePreKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRecord {
    pub created_at: i64,
    pub expires_at: i64,
    pub note: Option<String>,
    pub revoked_at: Option<i64>,
    pub used_at: Option<i64>,
    pub used_by: Option<PublicKey>,
}

impl InviteRecord {
    pub fn is_redeemable(&self, at: i64) -> bool {
        self.used_at.is_none() && self.revoked_at.is_none() && self.expires_at > at
    }
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> ServerResult<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn in_memory() -> ServerResult<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    // --- Invites ----------------------------------------------------------

    /// Records a new invite. Only the hash is stored, never the code.
    pub fn create_invite(
        &self,
        hash: &RedemptionHash,
        expires_at: i64,
        note: Option<&str>,
    ) -> ServerResult<()> {
        self.conn.execute(
            "INSERT INTO invites (redemption_hash, created_at, expires_at, note)
             VALUES (?1, ?2, ?3, ?4)",
            params![&hash.0[..], now(), expires_at, note],
        )?;
        Ok(())
    }

    pub fn get_invite(&self, hash: &RedemptionHash) -> ServerResult<Option<InviteRecord>> {
        let record = self
            .conn
            .query_row(
                "SELECT created_at, expires_at, note, revoked_at, used_at, used_by
                 FROM invites WHERE redemption_hash = ?1",
                params![&hash.0[..]],
                |row| {
                    Ok(InviteRecord {
                        created_at: row.get(0)?,
                        expires_at: row.get(1)?,
                        note: row.get(2)?,
                        revoked_at: row.get(3)?,
                        used_at: row.get(4)?,
                        used_by: row
                            .get::<_, Option<Vec<u8>>>(5)?
                            .and_then(|v| v.try_into().ok()),
                    })
                },
            )
            .optional()?;
        Ok(record)
    }

    pub fn revoke_invite(&self, hash: &RedemptionHash) -> ServerResult<bool> {
        let changed = self.conn.execute(
            "UPDATE invites SET revoked_at = ?1
             WHERE redemption_hash = ?2 AND used_at IS NULL AND revoked_at IS NULL",
            params![now(), &hash.0[..]],
        )?;
        Ok(changed > 0)
    }

    pub fn list_invites(&self) -> ServerResult<Vec<(RedemptionHash, InviteRecord)>> {
        let mut stmt = self.conn.prepare(
            "SELECT redemption_hash, created_at, expires_at, note, revoked_at, used_at, used_by
             FROM invites ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let raw: Vec<u8> = row.get(0)?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&raw);
            Ok((
                RedemptionHash(hash),
                InviteRecord {
                    created_at: row.get(1)?,
                    expires_at: row.get(2)?,
                    note: row.get(3)?,
                    revoked_at: row.get(4)?,
                    used_at: row.get(5)?,
                    used_by: row
                        .get::<_, Option<Vec<u8>>>(6)?
                        .and_then(|v| v.try_into().ok()),
                },
            ))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // --- Accounts ---------------------------------------------------------

    /// Redeems an invite and creates the account, atomically.
    ///
    /// Both halves happen in one transaction. Splitting them would allow two
    /// concurrent redemptions of the same code to both pass their checks before
    /// either wrote — the classic double-spend — and the `used_at IS NULL`
    /// guard in the `UPDATE` means the loser of that race changes zero rows and
    /// is rejected.
    pub fn redeem_and_register(
        &mut self,
        hash: &RedemptionHash,
        public_key: &PublicKey,
        username_hash: &[u8; 32],
    ) -> ServerResult<()> {
        let at = now();
        let tx = self.conn.transaction()?;

        let claimed = tx.execute(
            "UPDATE invites SET used_at = ?1, used_by = ?2
             WHERE redemption_hash = ?3
               AND used_at IS NULL
               AND revoked_at IS NULL
               AND expires_at > ?1",
            params![at, &public_key[..], &hash.0[..]],
        )?;

        if claimed == 0 {
            // Distinguish "no such code" from "code exists but is spent or
            // expired" for the operator's logs — but see `routes.rs`: the
            // client is told the same thing either way, so that redemption
            // cannot be used to probe which codes exist.
            let exists = tx
                .query_row(
                    "SELECT 1 FROM invites WHERE redemption_hash = ?1",
                    params![&hash.0[..]],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            return Err(if exists {
                ServerError::InviteNotRedeemable
            } else {
                ServerError::InviteUnknown
            });
        }

        tx.execute(
            "INSERT INTO accounts (public_key, username_hash, created_at)
             VALUES (?1, ?2, ?3)",
            params![&public_key[..], &username_hash[..], at],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                ServerError::AlreadyRegistered
            }
            other => ServerError::Database(other),
        })?;

        tx.commit()?;
        Ok(())
    }

    pub fn account_exists(&self, public_key: &PublicKey) -> ServerResult<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM accounts WHERE public_key = ?1",
                params![&public_key[..]],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn username_taken(&self, username_hash: &[u8; 32]) -> ServerResult<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM accounts WHERE username_hash = ?1",
                params![&username_hash[..]],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Every account, newest first.
    ///
    /// Returns public keys and timestamps only — there is no plaintext
    /// username to return, by design.
    pub fn list_accounts(&self) -> ServerResult<Vec<(PublicKey, i64, Option<i64>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT public_key, created_at, locked_until FROM accounts ORDER BY created_at DESC")?;
        let rows = stmt.query_map([], |row| {
            let raw: Vec<u8> = row.get(0)?;
            let mut key = [0u8; 32];
            key.copy_from_slice(&raw);
            Ok((key, row.get(1)?, row.get(2)?))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Locks an account until `until`, refusing relay service.
    pub fn lock_account(&self, public_key: &PublicKey, until: i64) -> ServerResult<()> {
        self.conn.execute(
            "UPDATE accounts SET locked_until = ?1 WHERE public_key = ?2",
            params![until, &public_key[..]],
        )?;
        Ok(())
    }

    pub fn account_locked_until(&self, public_key: &PublicKey) -> ServerResult<Option<i64>> {
        Ok(self
            .conn
            .query_row(
                "SELECT locked_until FROM accounts WHERE public_key = ?1",
                params![&public_key[..]],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten()
            .filter(|until| *until > now()))
    }

    // --- Attempt throttling ----------------------------------------------

    /// Records a failure against `scope` and returns the new count.
    pub fn record_failure(&self, scope: &str) -> ServerResult<u32> {
        let at = now();
        self.conn.execute(
            "INSERT INTO attempts (scope, count, first_at) VALUES (?1, 1, ?2)
             ON CONFLICT(scope) DO UPDATE SET count = count + 1",
            params![scope, at],
        )?;
        Ok(self
            .conn
            .query_row(
                "SELECT count FROM attempts WHERE scope = ?1",
                params![scope],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0))
    }

    pub fn set_lockout(&self, scope: &str, until: i64) -> ServerResult<()> {
        self.conn.execute(
            "UPDATE attempts SET locked_until = ?1 WHERE scope = ?2",
            params![until, scope],
        )?;
        Ok(())
    }

    /// Remaining lockout in seconds, if `scope` is currently locked out.
    pub fn lockout_remaining(&self, scope: &str) -> ServerResult<Option<i64>> {
        let until: Option<i64> = self
            .conn
            .query_row(
                "SELECT locked_until FROM attempts WHERE scope = ?1",
                params![scope],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        Ok(until.map(|u| u - now()).filter(|remaining| *remaining > 0))
    }

    pub fn clear_failures(&self, scope: &str) -> ServerResult<()> {
        self.conn
            .execute("DELETE FROM attempts WHERE scope = ?1", params![scope])?;
        Ok(())
    }

    // --- Server keys ------------------------------------------------------

    pub fn get_meta(&self, key: &str) -> ServerResult<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row(
                "SELECT value FROM server_meta WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Stores a value only if absent, returning what is now stored.
    ///
    /// Insert-if-absent rather than upsert: these are the relay's long-lived
    /// signing keys, and quietly replacing one would invalidate every
    /// certificate already issued under it.
    pub fn put_meta_if_absent(&self, key: &str, value: &[u8]) -> ServerResult<Vec<u8>> {
        self.conn.execute(
            "INSERT OR IGNORE INTO server_meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(self.get_meta(key)?.unwrap_or_else(|| value.to_vec()))
    }

    // --- Prekey distribution ----------------------------------------------

    /// Replaces an account's long-lived prekey material.
    ///
    /// Upsert rather than insert: clients rotate their signed prekey
    /// periodically, and the old one is simply superseded.
    pub fn put_prekey_bundle(
        &self,
        owner: &PublicKey,
        bundle: &PreKeyBundle,
    ) -> ServerResult<()> {
        self.conn.execute(
            "INSERT INTO prekey_bundles (
                 owner, identity_key, registration_id,
                 signed_prekey_id, signed_prekey_public, signed_prekey_signature,
                 kyber_prekey_id, kyber_prekey_public, kyber_prekey_signature,
                 updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(owner) DO UPDATE SET
                 identity_key = excluded.identity_key,
                 registration_id = excluded.registration_id,
                 signed_prekey_id = excluded.signed_prekey_id,
                 signed_prekey_public = excluded.signed_prekey_public,
                 signed_prekey_signature = excluded.signed_prekey_signature,
                 kyber_prekey_id = excluded.kyber_prekey_id,
                 kyber_prekey_public = excluded.kyber_prekey_public,
                 kyber_prekey_signature = excluded.kyber_prekey_signature,
                 updated_at = excluded.updated_at",
            params![
                &owner[..],
                &bundle.identity_key,
                bundle.registration_id,
                bundle.signed_prekey_id,
                &bundle.signed_prekey_public,
                &bundle.signed_prekey_signature,
                bundle.kyber_prekey_id,
                bundle.kyber_prekey_public.as_deref(),
                bundle.kyber_prekey_signature.as_deref(),
                now(),
            ],
        )?;
        Ok(())
    }

    /// Adds one-time prekeys to an account's pool.
    ///
    /// Ignores ids already present, so a client that retries an upload after a
    /// dropped connection does not fail outright.
    pub fn add_one_time_prekeys(
        &mut self,
        owner: &PublicKey,
        prekeys: &[OneTimePreKey],
    ) -> ServerResult<usize> {
        let tx = self.conn.transaction()?;
        let mut added = 0;
        for prekey in prekeys {
            added += tx.execute(
                "INSERT OR IGNORE INTO one_time_prekeys (owner, prekey_id, public)
                 VALUES (?1, ?2, ?3)",
                params![&owner[..], prekey.id, &prekey.public],
            )?;
        }
        tx.commit()?;
        Ok(added)
    }

    pub fn one_time_prekey_count(&self, owner: &PublicKey) -> ServerResult<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM one_time_prekeys WHERE owner = ?1",
            params![&owner[..]],
            |row| row.get(0),
        )?)
    }

    /// Hands out a bundle for starting a session, consuming one one-time prekey.
    ///
    /// The read and the delete are one transaction. A one-time prekey handed to
    /// two different senders would let both derive the same initial root key,
    /// destroying the forward secrecy of the first message — so "at most once"
    /// is not a nicety, it is the property the one-time prekey exists for.
    ///
    /// Running out is not an error. X3DH is defined to proceed without a
    /// one-time prekey, at the cost of that first-message forward secrecy;
    /// refusing to serve a bundle instead would let an attacker deny messaging
    /// to a user simply by draining their pool.
    pub fn take_prekey_bundle(&mut self, owner: &PublicKey) -> ServerResult<Option<FetchedBundle>> {
        let tx = self.conn.transaction()?;

        let bundle = tx
            .query_row(
                "SELECT identity_key, registration_id,
                        signed_prekey_id, signed_prekey_public, signed_prekey_signature,
                        kyber_prekey_id, kyber_prekey_public, kyber_prekey_signature
                 FROM prekey_bundles WHERE owner = ?1",
                params![&owner[..]],
                |row| {
                    Ok(PreKeyBundle {
                        identity_key: row.get(0)?,
                        registration_id: row.get(1)?,
                        signed_prekey_id: row.get(2)?,
                        signed_prekey_public: row.get(3)?,
                        signed_prekey_signature: row.get(4)?,
                        kyber_prekey_id: row.get(5)?,
                        kyber_prekey_public: row.get(6)?,
                        kyber_prekey_signature: row.get(7)?,
                    })
                },
            )
            .optional()?;

        let Some(bundle) = bundle else {
            return Ok(None);
        };

        let one_time = tx
            .query_row(
                "SELECT rowid_alias, prekey_id, public FROM one_time_prekeys
                 WHERE owner = ?1 ORDER BY rowid_alias LIMIT 1",
                params![&owner[..]],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        OneTimePreKey {
                            id: row.get(1)?,
                            public: row.get(2)?,
                        },
                    ))
                },
            )
            .optional()?;

        if let Some((rowid, _)) = &one_time {
            tx.execute(
                "DELETE FROM one_time_prekeys WHERE rowid_alias = ?1",
                params![rowid],
            )?;
        }

        tx.commit()?;
        Ok(Some(FetchedBundle {
            bundle,
            one_time: one_time.map(|(_, prekey)| prekey),
        }))
    }

    // --- Message relay ----------------------------------------------------

    /// Queues an encrypted envelope for a recipient.
    ///
    /// The server cannot read `envelope` and does not know who sent it — under
    /// sealed sender the originator is inside the ciphertext.
    pub fn queue_message(&self, recipient: &PublicKey, envelope: &[u8]) -> ServerResult<i64> {
        self.conn.execute(
            "INSERT INTO pending_messages (recipient, envelope, created_at)
             VALUES (?1, ?2, ?3)",
            params![&recipient[..], envelope, now()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Reads and deletes everything queued for a recipient, in one transaction.
    ///
    /// Delivery and deletion must be atomic: the spec forbids retaining message
    /// history after delivery, so there must be no window in which a delivered
    /// message is still on disk.
    pub fn take_pending(&mut self, recipient: &PublicKey) -> ServerResult<Vec<Vec<u8>>> {
        let tx = self.conn.transaction()?;
        let envelopes = {
            let mut stmt = tx.prepare(
                "SELECT envelope FROM pending_messages WHERE recipient = ?1 ORDER BY id",
            )?;
            let rows = stmt.query_map(params![&recipient[..]], |row| row.get::<_, Vec<u8>>(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        tx.execute(
            "DELETE FROM pending_messages WHERE recipient = ?1",
            params![&recipient[..]],
        )?;
        tx.commit()?;
        Ok(envelopes)
    }

    pub fn pending_count(&self, recipient: &PublicKey) -> ServerResult<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM pending_messages WHERE recipient = ?1",
            params![&recipient[..]],
            |row| row.get(0),
        )?)
    }

    /// Drops undelivered messages older than `max_age_secs`.
    ///
    /// A recipient who never comes back must not leave blobs on the relay
    /// forever.
    pub fn expire_messages(&self, max_age_secs: i64) -> ServerResult<usize> {
        Ok(self.conn.execute(
            "DELETE FROM pending_messages WHERE created_at < ?1",
            params![now() - max_age_secs],
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wisp_invite::InviteCode;

    const ALICE: PublicKey = [1u8; 32];
    const BOB: PublicKey = [2u8; 32];

    fn store() -> Store {
        Store::in_memory().unwrap()
    }

    fn valid_invite(store: &Store) -> (InviteCode, RedemptionHash) {
        let code = InviteCode::generate();
        let hash = code.redemption_hash();
        store.create_invite(&hash, now() + 3600, Some("test")).unwrap();
        (code, hash)
    }

    #[test]
    fn invite_round_trips() {
        let s = store();
        let (_, hash) = valid_invite(&s);
        let record = s.get_invite(&hash).unwrap().unwrap();
        assert!(record.is_redeemable(now()));
        assert_eq!(record.note.as_deref(), Some("test"));
    }

    #[test]
    fn unknown_invite_is_not_found() {
        let s = store();
        let hash = InviteCode::generate().redemption_hash();
        assert!(s.get_invite(&hash).unwrap().is_none());
    }

    #[test]
    fn redemption_creates_the_account_and_spends_the_code() {
        let mut s = store();
        let (_, hash) = valid_invite(&s);

        s.redeem_and_register(&hash, &ALICE, &username_hash("alice"))
            .unwrap();

        assert!(s.account_exists(&ALICE).unwrap());
        assert!(s.username_taken(&username_hash("alice")).unwrap());

        let record = s.get_invite(&hash).unwrap().unwrap();
        assert!(!record.is_redeemable(now()));
        assert_eq!(record.used_by, Some(ALICE));
    }

    /// Single-use is the entire point of an invite.
    #[test]
    fn an_invite_cannot_be_redeemed_twice() {
        let mut s = store();
        let (_, hash) = valid_invite(&s);
        s.redeem_and_register(&hash, &ALICE, &username_hash("alice"))
            .unwrap();

        let second = s.redeem_and_register(&hash, &BOB, &username_hash("bob"));
        assert!(matches!(second, Err(ServerError::InviteNotRedeemable)));
        assert!(!s.account_exists(&BOB).unwrap());
    }

    #[test]
    fn an_expired_invite_is_refused() {
        let mut s = store();
        let code = InviteCode::generate();
        let hash = code.redemption_hash();
        s.create_invite(&hash, now() - 1, None).unwrap();

        assert!(matches!(
            s.redeem_and_register(&hash, &ALICE, &username_hash("alice")),
            Err(ServerError::InviteNotRedeemable)
        ));
        assert!(!s.account_exists(&ALICE).unwrap());
    }

    #[test]
    fn a_revoked_invite_is_refused() {
        let mut s = store();
        let (_, hash) = valid_invite(&s);
        assert!(s.revoke_invite(&hash).unwrap());

        assert!(matches!(
            s.redeem_and_register(&hash, &ALICE, &username_hash("alice")),
            Err(ServerError::InviteNotRedeemable)
        ));
    }

    #[test]
    fn a_spent_invite_cannot_be_revoked() {
        let mut s = store();
        let (_, hash) = valid_invite(&s);
        s.redeem_and_register(&hash, &ALICE, &username_hash("alice"))
            .unwrap();
        assert!(!s.revoke_invite(&hash).unwrap());
    }

    #[test]
    fn an_unknown_invite_is_distinguished_internally() {
        let mut s = store();
        let hash = InviteCode::generate().redemption_hash();
        assert!(matches!(
            s.redeem_and_register(&hash, &ALICE, &username_hash("alice")),
            Err(ServerError::InviteUnknown)
        ));
    }

    /// A failed registration must not silently consume the invite.
    #[test]
    fn a_duplicate_username_rolls_the_whole_redemption_back() {
        let mut s = store();
        let (_, first) = valid_invite(&s);
        s.redeem_and_register(&first, &ALICE, &username_hash("alice"))
            .unwrap();

        let (_, second) = valid_invite(&s);
        let clash = s.redeem_and_register(&second, &BOB, &username_hash("alice"));
        assert!(matches!(clash, Err(ServerError::AlreadyRegistered)));

        // The second invite must still be usable.
        let record = s.get_invite(&second).unwrap().unwrap();
        assert!(
            record.is_redeemable(now()),
            "a rejected registration consumed the invite anyway"
        );
        assert!(!s.account_exists(&BOB).unwrap());
    }

    #[test]
    fn a_duplicate_public_key_is_rejected() {
        let mut s = store();
        let (_, first) = valid_invite(&s);
        s.redeem_and_register(&first, &ALICE, &username_hash("alice"))
            .unwrap();

        let (_, second) = valid_invite(&s);
        assert!(matches!(
            s.redeem_and_register(&second, &ALICE, &username_hash("alice2")),
            Err(ServerError::AlreadyRegistered)
        ));
    }

    #[test]
    fn usernames_are_stored_only_as_a_hash() {
        let mut s = store();
        let (_, hash) = valid_invite(&s);
        s.redeem_and_register(&hash, &ALICE, &username_hash("alice"))
            .unwrap();

        // Nothing in the accounts table should contain the plaintext.
        let mut stmt = s
            .conn
            .prepare("SELECT username_hash FROM accounts")
            .unwrap();
        let stored: Vec<Vec<u8>> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0], username_hash("alice").to_vec());
        assert!(!stored[0].windows(5).any(|w| w == b"alice"));
    }

    #[test]
    fn failures_accumulate_and_clear() {
        let s = store();
        assert_eq!(s.record_failure("pk:alice").unwrap(), 1);
        assert_eq!(s.record_failure("pk:alice").unwrap(), 2);
        assert_eq!(s.record_failure("pk:bob").unwrap(), 1, "scopes are separate");

        s.clear_failures("pk:alice").unwrap();
        assert_eq!(s.record_failure("pk:alice").unwrap(), 1);
    }

    #[test]
    fn lockouts_expire() {
        let s = store();
        s.record_failure("ip:127.0.0.1").unwrap();

        s.set_lockout("ip:127.0.0.1", now() + 60).unwrap();
        assert!(s.lockout_remaining("ip:127.0.0.1").unwrap().unwrap() > 0);

        s.set_lockout("ip:127.0.0.1", now() - 1).unwrap();
        assert!(s.lockout_remaining("ip:127.0.0.1").unwrap().is_none());
    }

    #[test]
    fn account_lock_expires() {
        let mut s = store();
        let (_, hash) = valid_invite(&s);
        s.redeem_and_register(&hash, &ALICE, &username_hash("alice"))
            .unwrap();

        assert!(s.account_locked_until(&ALICE).unwrap().is_none());
        s.lock_account(&ALICE, now() + 300).unwrap();
        assert!(s.account_locked_until(&ALICE).unwrap().is_some());
        s.lock_account(&ALICE, now() - 1).unwrap();
        assert!(s.account_locked_until(&ALICE).unwrap().is_none());
    }

    /// Delivery must remove the message in the same breath.
    #[test]
    fn delivered_messages_are_deleted() {
        let mut s = store();
        s.queue_message(&ALICE, b"sealed-envelope-1").unwrap();
        s.queue_message(&ALICE, b"sealed-envelope-2").unwrap();
        s.queue_message(&BOB, b"for-bob").unwrap();

        let delivered = s.take_pending(&ALICE).unwrap();
        assert_eq!(delivered, vec![b"sealed-envelope-1".to_vec(), b"sealed-envelope-2".to_vec()]);
        assert_eq!(s.pending_count(&ALICE).unwrap(), 0);
        assert_eq!(s.pending_count(&BOB).unwrap(), 1, "other queues untouched");

        assert!(s.take_pending(&ALICE).unwrap().is_empty());
    }

    #[test]
    fn messages_preserve_order() {
        let mut s = store();
        for i in 0..20u8 {
            s.queue_message(&ALICE, &[i]).unwrap();
        }
        let delivered = s.take_pending(&ALICE).unwrap();
        assert_eq!(delivered, (0..20u8).map(|i| vec![i]).collect::<Vec<_>>());
    }

    #[test]
    fn undelivered_messages_expire() {
        let s = store();
        s.queue_message(&ALICE, b"old").unwrap();
        s.conn
            .execute(
                "UPDATE pending_messages SET created_at = ?1",
                params![now() - 100_000],
            )
            .unwrap();

        assert_eq!(s.expire_messages(86_400).unwrap(), 1);
        assert_eq!(s.pending_count(&ALICE).unwrap(), 0);
    }

    fn bundle() -> PreKeyBundle {
        PreKeyBundle {
            identity_key: vec![0xAA; 33],
            registration_id: 4242,
            signed_prekey_id: 7,
            signed_prekey_public: vec![0xBB; 33],
            signed_prekey_signature: vec![0xCC; 64],
            kyber_prekey_id: Some(3),
            kyber_prekey_public: Some(vec![0xDD; 1568]),
            kyber_prekey_signature: Some(vec![0xEE; 64]),
        }
    }

    fn one_time(id: i64) -> OneTimePreKey {
        OneTimePreKey {
            id,
            public: vec![id as u8; 33],
        }
    }

    #[test]
    fn a_prekey_bundle_round_trips() {
        let mut s = store();
        s.put_prekey_bundle(&ALICE, &bundle()).unwrap();

        let fetched = s.take_prekey_bundle(&ALICE).unwrap().unwrap();
        assert_eq!(fetched.bundle, bundle());
        assert!(fetched.one_time.is_none(), "no one-time keys were uploaded");
    }

    #[test]
    fn an_unknown_account_has_no_bundle() {
        let mut s = store();
        assert!(s.take_prekey_bundle(&ALICE).unwrap().is_none());
    }

    #[test]
    fn rotating_the_signed_prekey_replaces_it() {
        let mut s = store();
        s.put_prekey_bundle(&ALICE, &bundle()).unwrap();

        let rotated = PreKeyBundle {
            signed_prekey_id: 8,
            signed_prekey_public: vec![0x11; 33],
            ..bundle()
        };
        s.put_prekey_bundle(&ALICE, &rotated).unwrap();

        assert_eq!(s.take_prekey_bundle(&ALICE).unwrap().unwrap().bundle, rotated);
    }

    /// The property one-time prekeys exist for: handing the same one to two
    /// senders would let both derive the same initial root key.
    #[test]
    fn a_one_time_prekey_is_handed_out_at_most_once() {
        let mut s = store();
        s.put_prekey_bundle(&ALICE, &bundle()).unwrap();
        s.add_one_time_prekeys(&ALICE, &[one_time(1), one_time(2), one_time(3)])
            .unwrap();
        assert_eq!(s.one_time_prekey_count(&ALICE).unwrap(), 3);

        let mut seen = Vec::new();
        for _ in 0..3 {
            let fetched = s.take_prekey_bundle(&ALICE).unwrap().unwrap();
            seen.push(fetched.one_time.expect("pool is not empty yet").id);
        }
        seen.sort_unstable();
        assert_eq!(seen, vec![1, 2, 3], "each key must be issued exactly once");
        assert_eq!(s.one_time_prekey_count(&ALICE).unwrap(), 0);
    }

    /// Running out must degrade, not fail — otherwise draining someone's pool
    /// would be a denial of service against them.
    #[test]
    fn an_exhausted_pool_still_yields_a_usable_bundle() {
        let mut s = store();
        s.put_prekey_bundle(&ALICE, &bundle()).unwrap();
        s.add_one_time_prekeys(&ALICE, &[one_time(1)]).unwrap();

        assert!(s.take_prekey_bundle(&ALICE).unwrap().unwrap().one_time.is_some());

        let fetched = s.take_prekey_bundle(&ALICE).unwrap().unwrap();
        assert!(fetched.one_time.is_none());
        assert_eq!(fetched.bundle, bundle(), "the bundle itself still works");
    }

    #[test]
    fn re_uploading_the_same_prekey_ids_is_harmless() {
        let mut s = store();
        assert_eq!(
            s.add_one_time_prekeys(&ALICE, &[one_time(1), one_time(2)])
                .unwrap(),
            2
        );
        // A retry after a dropped connection must not fail outright.
        assert_eq!(
            s.add_one_time_prekeys(&ALICE, &[one_time(2), one_time(3)])
                .unwrap(),
            1
        );
        assert_eq!(s.one_time_prekey_count(&ALICE).unwrap(), 3);
    }

    #[test]
    fn prekey_pools_are_per_account() {
        let mut s = store();
        s.put_prekey_bundle(&ALICE, &bundle()).unwrap();
        s.put_prekey_bundle(&BOB, &bundle()).unwrap();
        s.add_one_time_prekeys(&ALICE, &[one_time(1)]).unwrap();

        assert_eq!(s.one_time_prekey_count(&ALICE).unwrap(), 1);
        assert_eq!(s.one_time_prekey_count(&BOB).unwrap(), 0);

        s.take_prekey_bundle(&BOB).unwrap();
        assert_eq!(
            s.one_time_prekey_count(&ALICE).unwrap(),
            1,
            "Bob's fetch must not consume Alice's keys"
        );
    }

    #[test]
    fn a_bundle_without_kyber_material_is_accepted() {
        let mut s = store();
        let classic = PreKeyBundle {
            kyber_prekey_id: None,
            kyber_prekey_public: None,
            kyber_prekey_signature: None,
            ..bundle()
        };
        s.put_prekey_bundle(&ALICE, &classic).unwrap();
        assert_eq!(s.take_prekey_bundle(&ALICE).unwrap().unwrap().bundle, classic);
    }

    #[test]
    fn fresh_messages_survive_expiry_sweeps() {
        let s = store();
        s.queue_message(&ALICE, b"new").unwrap();
        assert_eq!(s.expire_messages(86_400).unwrap(), 0);
        assert_eq!(s.pending_count(&ALICE).unwrap(), 1);
    }
}
