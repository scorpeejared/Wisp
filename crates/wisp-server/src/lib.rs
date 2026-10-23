//! The Wisp relay.
//!
//! A dumb pipe with a guest list. It knows public keys, hashed usernames,
//! invite records, and encrypted blobs it cannot read — and it forgets each
//! blob the moment it is delivered.
//!
//! # What the relay can and cannot enforce
//!
//! The spec asks for failed *passphrase* attempts to be rate-limited
//! server-side. That is not achievable, and this crate does not pretend
//! otherwise: the passphrase decrypts `identity.wisp` locally, offline, with
//! the relay unreachable. The server never observes an attempt and no
//! server-side control can stop an attacker who holds the drive from grinding
//! away on their own machine.
//!
//! What actually defends that path lives on the client: Argon2id at 128 MiB
//! per guess, an enforced entropy floor, and the device fingerprint being a
//! required input to the key.
//!
//! What the relay *can* enforce, and does:
//!
//! - **Invite redemption attempts**, per IP — the only defence against grinding
//!   invite codes, and entirely the server's to make.
//! - **Authentication attempts**, per public key and per IP.
//! - **Account lockout** — refusing to relay for an account at all.
//!
//! Treating these three as real and the fourth as impossible is the honest
//! split. A "server-side passphrase lockout" that relied on the client
//! self-reporting failures would be defeated by a patched client, which is
//! precisely the attacker in question.

use std::collections::HashMap;
use std::sync::Mutex;

use rand_core::{OsRng, RngCore};
use wisp_invite::InviteCode;

pub mod error;
pub mod hub;
pub mod routes;
pub mod store;

pub use error::{ServerError, ServerResult};
pub use hub::Hub;
pub use routes::router;
pub use store::{now, username_hash, InviteRecord, PublicKey, Store};


/// Tunables for the throttling policy.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Failed redemptions from one address before it is locked out.
    pub redeem_attempts: u32,
    pub redeem_lockout_secs: i64,
    /// Failed authentications against one key before it is locked out.
    pub auth_attempts: u32,
    pub auth_lockout_secs: i64,
    /// How long an issued challenge stays valid.
    pub challenge_ttl_secs: i64,
    /// How long an undelivered message is kept before being dropped.
    pub message_ttl_secs: i64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            // Deliberately tight. A legitimate user types one code, once; ten
            // failures from an address is already a script, not a person.
            redeem_attempts: 10,
            redeem_lockout_secs: 15 * 60,
            auth_attempts: 10,
            auth_lockout_secs: 15 * 60,
            challenge_ttl_secs: 60,
            message_ttl_secs: 30 * 24 * 3600,
        }
    }
}

/// An outstanding authentication challenge.
struct Challenge {
    nonce: [u8; 32],
    expires_at: i64,
}

pub struct Relay {
    store: Mutex<Store>,
    config: RelayConfig,
    /// Challenges are deliberately in memory: they are single-use and live for
    /// a minute, so persisting them across restarts buys nothing and would only
    /// add a table to clean up.
    challenges: Mutex<HashMap<PublicKey, Challenge>>,
}

impl Relay {
    pub fn new(store: Store, config: RelayConfig) -> Self {
        Self {
            store: Mutex::new(store),
            config,
            challenges: Mutex::new(HashMap::new()),
        }
    }

    pub fn in_memory() -> ServerResult<Self> {
        Ok(Self::new(Store::in_memory()?, RelayConfig::default()))
    }

    pub fn with_store<T>(&self, f: impl FnOnce(&mut Store) -> T) -> T {
        f(&mut self.store.lock().unwrap())
    }

    // --- Registration -----------------------------------------------------

    /// The bytes a client signs to prove it controls the identity it is
    /// registering. See [`wisp_core::protocol::registration_challenge`].
    pub fn registration_challenge(
        invite: &InviteCode,
        public_key: &PublicKey,
        username_hash: &[u8; 32],
    ) -> Vec<u8> {
        wisp_core::protocol::registration_challenge(
            &invite.redemption_hash().0,
            public_key,
            username_hash,
        )
    }

    /// Redeems an invite and creates an account.
    ///
    /// `client_scope` identifies the caller for throttling — an IP address in
    /// production.
    pub fn register(
        &self,
        client_scope: &str,
        code: &str,
        username: &str,
        public_key: &PublicKey,
        signature: &[u8],
    ) -> ServerResult<()> {
        let scope = format!("redeem:{client_scope}");
        self.check_lockout(&scope)?;

        // Parsing failures are throttled too. Without that, the checksum turns
        // into a free filter an attacker can use to enumerate well-formed codes
        // without ever touching the rate limit.
        let outcome = self.register_inner(code, username, public_key, signature);

        match &outcome {
            Ok(()) => {
                self.store.lock().unwrap().clear_failures(&scope)?;
            }
            // A username clash is the user's own mistake, not an attack; it
            // must not count toward a lockout or a fumbled signup would lock
            // the user out of onboarding entirely.
            Err(ServerError::AlreadyRegistered) | Err(ServerError::BadUsername) => {}
            Err(_) => self.register_failure(&scope)?,
        }

        outcome
    }

    fn register_inner(
        &self,
        code: &str,
        username: &str,
        public_key: &PublicKey,
        signature: &[u8],
    ) -> ServerResult<()> {
        let invite = InviteCode::parse(code)?;

        let canonical = wisp_core::identity::normalise_username(username);
        wisp_core::identity::check_username(&canonical).map_err(|_| ServerError::BadUsername)?;
        let uname_hash = username_hash(&canonical);

        let message = Self::registration_challenge(&invite, public_key, &uname_hash);
        verify_signature(public_key, &message, signature)?;

        let mut store = self.store.lock().unwrap();
        store.redeem_and_register(&invite.redemption_hash(), public_key, &uname_hash)
    }

    fn register_failure(&self, scope: &str) -> ServerResult<()> {
        let store = self.store.lock().unwrap();
        let count = store.record_failure(scope)?;
        if count >= self.config.redeem_attempts {
            store.set_lockout(scope, now() + self.config.redeem_lockout_secs)?;
        }
        Ok(())
    }

    // --- Authentication ---------------------------------------------------

    /// Issues a fresh challenge for an account to sign.
    pub fn issue_challenge(&self, public_key: &PublicKey) -> ServerResult<[u8; 32]> {
        if !self.store.lock().unwrap().account_exists(public_key)? {
            return Err(ServerError::UnknownAccount);
        }

        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        self.challenges.lock().unwrap().insert(
            *public_key,
            Challenge {
                nonce,
                expires_at: now() + self.config.challenge_ttl_secs,
            },
        );
        Ok(nonce)
    }

    /// The bytes a client signs to answer a challenge.
    pub fn auth_message(nonce: &[u8; 32]) -> Vec<u8> {
        wisp_core::protocol::auth_message(nonce)
    }

    /// Verifies a challenge response.
    ///
    /// The challenge is consumed whether or not verification succeeds, so a
    /// single nonce can never be attacked more than once.
    pub fn verify_challenge(
        &self,
        client_scope: &str,
        public_key: &PublicKey,
        signature: &[u8],
    ) -> ServerResult<()> {
        let key_scope = format!("auth:{}", hex(public_key));
        let addr_scope = format!("auth-ip:{client_scope}");
        self.check_lockout(&key_scope)?;
        self.check_lockout(&addr_scope)?;

        if let Some(remaining) = self
            .store
            .lock()
            .unwrap()
            .account_locked_until(public_key)?
            .map(|until| until - now())
        {
            return Err(ServerError::AccountLocked {
                retry_after: remaining,
            });
        }

        let challenge = self.challenges.lock().unwrap().remove(public_key);
        let Some(challenge) = challenge.filter(|c| c.expires_at > now()) else {
            return Err(ServerError::BadChallenge);
        };

        match verify_signature(public_key, &Self::auth_message(&challenge.nonce), signature) {
            Ok(()) => {
                let store = self.store.lock().unwrap();
                store.clear_failures(&key_scope)?;
                store.clear_failures(&addr_scope)?;
                Ok(())
            }
            Err(e) => {
                for scope in [&key_scope, &addr_scope] {
                    let store = self.store.lock().unwrap();
                    let count = store.record_failure(scope)?;
                    if count >= self.config.auth_attempts {
                        store.set_lockout(scope, now() + self.config.auth_lockout_secs)?;
                    }
                }
                Err(e)
            }
        }
    }

    fn check_lockout(&self, scope: &str) -> ServerResult<()> {
        if let Some(retry_after) = self.store.lock().unwrap().lockout_remaining(scope)? {
            return Err(ServerError::RateLimited { retry_after });
        }
        Ok(())
    }

    // --- Relay ------------------------------------------------------------

    /// Queues an encrypted envelope. The recipient must be a known account.
    pub fn submit(&self, recipient: &PublicKey, envelope: &[u8]) -> ServerResult<()> {
        let store = self.store.lock().unwrap();
        if !store.account_exists(recipient)? {
            return Err(ServerError::UnknownAccount);
        }
        store.queue_message(recipient, envelope)?;
        Ok(())
    }

    /// Delivers and forgets everything queued for a recipient.
    pub fn collect(&self, recipient: &PublicKey) -> ServerResult<Vec<Vec<u8>>> {
        self.store.lock().unwrap().take_pending(recipient)
    }

    /// Drops undelivered messages past their TTL. Call periodically.
    pub fn sweep(&self) -> ServerResult<usize> {
        self.store
            .lock()
            .unwrap()
            .expire_messages(self.config.message_ttl_secs)
    }
}

/// Verifies a client signature.
///
/// Delegates to `wisp-core` rather than verifying here: identity keys are
/// Curve25519 signing with XEdDSA, and a second implementation of that check
/// is exactly the kind of divergence that ends with the relay accepting
/// something the client would not, or vice versa.
fn verify_signature(
    public_key: &PublicKey,
    message: &[u8],
    signature: &[u8],
) -> ServerResult<()> {
    if wisp_core::protocol::verify_signature(public_key, message, signature) {
        Ok(())
    } else {
        Err(ServerError::BadSignature)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: &str = "203.0.113.7";

    /// Drives the same identity code the real client does, so these tests
    /// break if the signature format ever diverges from what ships.
    struct Client {
        identity: wisp_core::UnlockedIdentity,
    }

    impl Client {
        fn new() -> Self {
            Self {
                identity: wisp_core::UnlockedIdentity::generate("tester").unwrap(),
            }
        }

        fn public_key(&self) -> PublicKey {
            self.identity.public_key().unwrap()
        }

        fn sign(&self, message: &[u8]) -> [u8; 64] {
            self.identity.sign(message).unwrap()
        }

        fn register_signature(&self, code: &InviteCode, username: &str) -> [u8; 64] {
            let uname = wisp_core::identity::normalise_username(username);
            let message =
                Relay::registration_challenge(code, &self.public_key(), &username_hash(&uname));
            self.sign(&message)
        }
    }

    fn relay() -> Relay {
        Relay::in_memory().unwrap()
    }

    fn fresh_invite(relay: &Relay) -> InviteCode {
        let code = InviteCode::generate();
        relay.with_store(|s| s.create_invite(&code.redemption_hash(), now() + 3600, None))
            .unwrap();
        code
    }

    fn register(relay: &Relay, client: &Client, code: &InviteCode, username: &str) -> ServerResult<()> {
        relay.register(
            IP,
            &code.to_string(),
            username,
            &client.public_key(),
            &client.register_signature(code, username),
        )
    }

    #[test]
    fn a_valid_invite_creates_an_account() {
        let relay = relay();
        let code = fresh_invite(&relay);
        let alice = Client::new();

        register(&relay, &alice, &code, "alice").unwrap();
        assert!(relay
            .with_store(|s| s.account_exists(&alice.public_key()))
            .unwrap());
    }

    #[test]
    fn registration_without_an_invite_is_impossible() {
        let relay = relay();
        // A well-formed code that was never issued.
        let code = InviteCode::generate();
        let alice = Client::new();

        assert!(matches!(
            register(&relay, &alice, &code, "alice"),
            Err(ServerError::InviteUnknown)
        ));
        assert!(!relay
            .with_store(|s| s.account_exists(&alice.public_key()))
            .unwrap());
    }

    #[test]
    fn an_invite_works_exactly_once() {
        let relay = relay();
        let code = fresh_invite(&relay);

        register(&relay, &Client::new(), &code, "alice").unwrap();
        assert!(matches!(
            register(&relay, &Client::new(), &code, "bob"),
            Err(ServerError::InviteNotRedeemable)
        ));
    }

    /// The signature must bind to the key being registered, or an intercepted
    /// code could be bound to an attacker's key.
    #[test]
    fn a_signature_from_another_key_is_rejected() {
        let relay = relay();
        let code = fresh_invite(&relay);
        let alice = Client::new();
        let mallory = Client::new();

        let outcome = relay.register(
            IP,
            &code.to_string(),
            "alice",
            &alice.public_key(),
            &mallory.register_signature(&code, "alice"),
        );
        assert!(matches!(outcome, Err(ServerError::BadSignature)));
    }

    #[test]
    fn a_signature_for_a_different_username_is_rejected() {
        let relay = relay();
        let code = fresh_invite(&relay);
        let alice = Client::new();

        let outcome = relay.register(
            IP,
            &code.to_string(),
            "alice",
            &alice.public_key(),
            &alice.register_signature(&code, "someone-else"),
        );
        assert!(matches!(outcome, Err(ServerError::BadSignature)));
    }

    #[test]
    fn usernames_are_normalised_before_registration() {
        let relay = relay();
        let alice = Client::new();
        let code = fresh_invite(&relay);

        // The client signs the canonical form; the server accepts the messy one.
        relay
            .register(
                IP,
                &code.to_string(),
                "  Alice  ",
                &alice.public_key(),
                &alice.register_signature(&code, "  Alice  "),
            )
            .unwrap();

        assert!(relay
            .with_store(|s| s.username_taken(&username_hash("alice")))
            .unwrap());
    }

    #[test]
    fn an_invalid_username_is_refused() {
        let relay = relay();
        let code = fresh_invite(&relay);
        let alice = Client::new();
        assert!(matches!(
            register(&relay, &alice, &code, "no"),
            Err(ServerError::BadUsername)
        ));
    }

    #[test]
    fn a_malformed_code_is_rejected() {
        let relay = relay();
        let alice = Client::new();
        let outcome = relay.register(IP, "WISP-NOPE", "alice", &alice.public_key(), &[0u8; 64]);
        assert!(matches!(outcome, Err(ServerError::InviteMalformed(_))));
    }

    /// Grinding invite codes is the attack the relay actually has to stop.
    #[test]
    fn repeated_bad_redemptions_lock_the_address_out() {
        let relay = relay();
        let alice = Client::new();

        for _ in 0..RelayConfig::default().redeem_attempts {
            let _ = register(&relay, &alice, &InviteCode::generate(), "alice");
        }

        // Even a genuine code is now refused from this address.
        let real = fresh_invite(&relay);
        assert!(matches!(
            register(&relay, &alice, &real, "alice"),
            Err(ServerError::RateLimited { .. })
        ));
    }

    /// A user fumbling their own signup must not lock themselves out.
    #[test]
    fn a_username_clash_does_not_count_toward_lockout() {
        let relay = relay();
        register(&relay, &Client::new(), &fresh_invite(&relay), "alice").unwrap();

        let bob = Client::new();
        for _ in 0..RelayConfig::default().redeem_attempts + 5 {
            let code = fresh_invite(&relay);
            assert!(matches!(
                register(&relay, &bob, &code, "alice"),
                Err(ServerError::AlreadyRegistered)
            ));
        }

        // Still able to register under a free name.
        let code = fresh_invite(&relay);
        register(&relay, &bob, &code, "bob").unwrap();
    }

    #[test]
    fn a_successful_registration_clears_the_failure_count() {
        let relay = relay();
        let alice = Client::new();
        for _ in 0..5 {
            let _ = register(&relay, &alice, &InviteCode::generate(), "alice");
        }
        register(&relay, &alice, &fresh_invite(&relay), "alice").unwrap();

        let bob = Client::new();
        for _ in 0..5 {
            let _ = register(&relay, &bob, &InviteCode::generate(), "bob");
        }
        // Would have tripped the limit had the count not been reset.
        register(&relay, &bob, &fresh_invite(&relay), "bob").unwrap();
    }

    #[test]
    fn the_client_cannot_tell_an_unknown_code_from_a_spent_one() {
        let relay = relay();
        let spent = fresh_invite(&relay);
        register(&relay, &Client::new(), &spent, "alice").unwrap();

        let unknown = ServerError::InviteUnknown.client_message();
        let used = ServerError::InviteNotRedeemable.client_message();
        assert_eq!(unknown, used);
    }

    // --- Authentication ---------------------------------------------------

    fn registered(relay: &Relay, username: &str) -> Client {
        let client = Client::new();
        let code = fresh_invite(relay);
        register(relay, &client, &code, username).unwrap();
        client
    }

    #[test]
    fn a_registered_account_can_authenticate() {
        let relay = relay();
        let alice = registered(&relay, "alice");

        let nonce = relay.issue_challenge(&alice.public_key()).unwrap();
        let signature = alice.sign(&Relay::auth_message(&nonce));
        relay
            .verify_challenge(IP, &alice.public_key(), &signature)
            .unwrap();
    }

    #[test]
    fn an_unknown_account_gets_no_challenge() {
        let relay = relay();
        assert!(matches!(
            relay.issue_challenge(&Client::new().public_key()),
            Err(ServerError::UnknownAccount)
        ));
    }

    #[test]
    fn a_challenge_cannot_be_replayed() {
        let relay = relay();
        let alice = registered(&relay, "alice");

        let nonce = relay.issue_challenge(&alice.public_key()).unwrap();
        let signature = alice.sign(&Relay::auth_message(&nonce));

        relay
            .verify_challenge(IP, &alice.public_key(), &signature)
            .unwrap();
        assert!(matches!(
            relay.verify_challenge(IP, &alice.public_key(), &signature),
            Err(ServerError::BadChallenge)
        ));
    }

    /// A wrong answer burns the challenge, so one nonce cannot be ground on.
    #[test]
    fn a_failed_attempt_consumes_the_challenge() {
        let relay = relay();
        let alice = registered(&relay, "alice");
        relay.issue_challenge(&alice.public_key()).unwrap();

        assert!(matches!(
            relay.verify_challenge(IP, &alice.public_key(), &[0u8; 64]),
            Err(ServerError::BadSignature)
        ));
        assert!(matches!(
            relay.verify_challenge(IP, &alice.public_key(), &[0u8; 64]),
            Err(ServerError::BadChallenge)
        ));
    }

    #[test]
    fn another_key_cannot_answer_your_challenge() {
        let relay = relay();
        let alice = registered(&relay, "alice");
        let mallory = Client::new();

        let nonce = relay.issue_challenge(&alice.public_key()).unwrap();
        let signature = mallory.sign(&Relay::auth_message(&nonce));
        assert!(matches!(
            relay.verify_challenge(IP, &alice.public_key(), &signature),
            Err(ServerError::BadSignature)
        ));
    }

    #[test]
    fn repeated_auth_failures_lock_the_key_out() {
        let relay = relay();
        let alice = registered(&relay, "alice");

        for _ in 0..RelayConfig::default().auth_attempts {
            relay.issue_challenge(&alice.public_key()).unwrap();
            let _ = relay.verify_challenge(IP, &alice.public_key(), &[0u8; 64]);
        }

        let nonce = relay.issue_challenge(&alice.public_key()).unwrap();
        let good = alice.sign(&Relay::auth_message(&nonce));
        assert!(matches!(
            relay.verify_challenge(IP, &alice.public_key(), &good),
            Err(ServerError::RateLimited { .. })
        ));
    }

    #[test]
    fn a_locked_account_cannot_authenticate() {
        let relay = relay();
        let alice = registered(&relay, "alice");
        relay
            .with_store(|s| s.lock_account(&alice.public_key(), now() + 300))
            .unwrap();

        let nonce = relay.issue_challenge(&alice.public_key()).unwrap();
        let signature = alice.sign(&Relay::auth_message(&nonce));
        assert!(matches!(
            relay.verify_challenge(IP, &alice.public_key(), &signature),
            Err(ServerError::AccountLocked { .. })
        ));
    }

    // --- Relay ------------------------------------------------------------

    #[test]
    fn messages_are_delivered_once_then_forgotten() {
        let relay = relay();
        let alice = registered(&relay, "alice");

        relay.submit(&alice.public_key(), b"sealed").unwrap();
        assert_eq!(relay.collect(&alice.public_key()).unwrap(), vec![b"sealed".to_vec()]);
        assert!(relay.collect(&alice.public_key()).unwrap().is_empty());
    }

    #[test]
    fn messages_to_unknown_accounts_are_refused() {
        let relay = relay();
        assert!(matches!(
            relay.submit(&Client::new().public_key(), b"sealed"),
            Err(ServerError::UnknownAccount)
        ));
    }

    #[test]
    fn the_relay_cannot_read_what_it_carries() {
        // Not a property a test can prove, but it can prove the relay never
        // inspects the bytes: an envelope of pure noise round-trips unchanged.
        let relay = relay();
        let alice = registered(&relay, "alice");
        let mut noise = vec![0u8; 4096];
        OsRng.fill_bytes(&mut noise);

        relay.submit(&alice.public_key(), &noise).unwrap();
        assert_eq!(relay.collect(&alice.public_key()).unwrap(), vec![noise]);
    }
}
