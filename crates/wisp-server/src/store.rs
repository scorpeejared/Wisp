use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

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

-- Failure counters, lockouts, and fixed-window signup counters, keyed by scope.
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

pub type PublicKey = [u8; 32];

pub use wisp_core::protocol::username_hash;

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PreKeyBundle {
    pub identity_key: Vec<u8>,
    pub registration_id: i64,
    pub signed_prekey_id: i64,
    pub signed_prekey_public: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    pub kyber_prekey_id: Option<i64>,
    pub kyber_prekey_public: Option<Vec<u8>>,
    pub kyber_prekey_signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OneTimePreKey {
    pub id: i64,
    pub public: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FetchedBundle {
    #[serde(flatten)]
    pub bundle: PreKeyBundle,
    pub one_time: Option<OneTimePreKey>,
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

    // --- Accounts ---------------------------------------------------------

    pub fn create_account(
        &self,
        public_key: &PublicKey,
        username_hash: &[u8; 32],
    ) -> ServerResult<()> {
        self.conn
            .execute(
                "INSERT INTO accounts (public_key, username_hash, created_at)
                 VALUES (?1, ?2, ?3)",
                params![&public_key[..], &username_hash[..], now()],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(err, _)
                    if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    ServerError::AlreadyRegistered
                }
                other => ServerError::Database(other),
            })?;
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

    #[cfg(test)]
    pub(crate) fn age_signup_windows_for_test(&self, secs: i64) {
        self.conn
            .execute("UPDATE attempts SET first_at = first_at - ?1", params![secs])
            .unwrap();
    }
    pub fn clear_failures(&self, scope: &str) -> ServerResult<()> {
        self.conn
            .execute("DELETE FROM attempts WHERE scope = ?1", params![scope])?;
        Ok(())
    }

    pub fn window_usage(&self, scope: &str, window_secs: i64) -> ServerResult<(u32, i64)> {
        let row: Option<(u32, i64)> = self
            .conn
            .query_row(
                "SELECT count, first_at FROM attempts WHERE scope = ?1",
                params![scope],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let at = now();
        Ok(match row {
            Some((count, first_at)) if first_at + window_secs > at => {
                (count, first_at + window_secs - at)
            }
            _ => (0, 0),
        })
    }

    pub fn bump_window(&self, scope: &str, window_secs: i64) -> ServerResult<()> {
        self.conn.execute(
            "INSERT INTO attempts (scope, count, first_at) VALUES (?1, 1, ?2)
             ON CONFLICT(scope) DO UPDATE SET
                 count    = CASE WHEN first_at + ?3 <= ?2 THEN 1 ELSE count + 1 END,
                 first_at = CASE WHEN first_at + ?3 <= ?2 THEN ?2 ELSE first_at END",
            params![scope, now(), window_secs],
        )?;
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

    pub fn put_meta_if_absent(&self, key: &str, value: &[u8]) -> ServerResult<Vec<u8>> {
        self.conn.execute(
            "INSERT OR IGNORE INTO server_meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(self.get_meta(key)?.unwrap_or_else(|| value.to_vec()))
    }

    // --- Prekey distribution ----------------------------------------------

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

    pub fn queue_message(&self, recipient: &PublicKey, envelope: &[u8]) -> ServerResult<i64> {
        self.conn.execute(
            "INSERT INTO pending_messages (recipient, envelope, created_at)
             VALUES (?1, ?2, ?3)",
            params![&recipient[..], envelope, now()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

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

    const ALICE: PublicKey = [1u8; 32];
    const BOB: PublicKey = [2u8; 32];

    fn store() -> Store {
        Store::in_memory().unwrap()
    }
    fn register(s: &Store, key: &PublicKey, name: &str) -> ServerResult<()> {
        s.create_account(key, &username_hash(name))
    }

    #[test]
    fn creating_an_account_records_the_key_and_the_name() {
        let s = store();
        register(&s, &ALICE, "alice").unwrap();

        assert!(s.account_exists(&ALICE).unwrap());
        assert!(s.username_taken(&username_hash("alice")).unwrap());
        assert!(!s.account_exists(&BOB).unwrap());
    }

    #[test]
    fn a_duplicate_username_is_rejected() {
        let s = store();
        register(&s, &ALICE, "alice").unwrap();

        assert!(matches!(
            register(&s, &BOB, "alice"),
            Err(ServerError::AlreadyRegistered)
        ));
        assert!(!s.account_exists(&BOB).unwrap());
    }

    #[test]
    fn a_duplicate_public_key_is_rejected() {
        let s = store();
        register(&s, &ALICE, "alice").unwrap();

        assert!(matches!(
            register(&s, &ALICE, "alice2"),
            Err(ServerError::AlreadyRegistered)
        ));
    }

    #[test]
    fn usernames_are_stored_only_as_a_hash() {
        let s = store();
        register(&s, &ALICE, "alice").unwrap();

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
    fn window_counts_events_and_reports_time_to_reset() {
        let s = store();
        assert_eq!(s.window_usage("signup:a", 3600).unwrap(), (0, 0));

        s.bump_window("signup:a", 3600).unwrap();
        s.bump_window("signup:a", 3600).unwrap();
        s.bump_window("signup:b", 3600).unwrap();

        let (count, resets_in) = s.window_usage("signup:a", 3600).unwrap();
        assert_eq!(count, 2);
        assert!(resets_in > 3590 && resets_in <= 3600);
        assert_eq!(s.window_usage("signup:b", 3600).unwrap().0, 1, "scopes are separate");
    }

    #[test]
    fn an_elapsed_window_reads_as_empty_and_restarts() {
        let s = store();
        s.bump_window("signup:a", 3600).unwrap();
        s.bump_window("signup:a", 3600).unwrap();
        s.conn
            .execute(
                "UPDATE attempts SET first_at = ?1 WHERE scope = 'signup:a'",
                params![now() - 7200],
            )
            .unwrap();

        assert_eq!(s.window_usage("signup:a", 3600).unwrap(), (0, 0));

        s.bump_window("signup:a", 3600).unwrap();
        assert_eq!(s.window_usage("signup:a", 3600).unwrap().0, 1);
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
        let s = store();
        register(&s, &ALICE, "alice").unwrap();

        assert!(s.account_locked_until(&ALICE).unwrap().is_none());
        s.lock_account(&ALICE, now() + 300).unwrap();
        assert!(s.account_locked_until(&ALICE).unwrap().is_some());
        s.lock_account(&ALICE, now() - 1).unwrap();
        assert!(s.account_locked_until(&ALICE).unwrap().is_none());
    }

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
