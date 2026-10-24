use std::collections::HashMap;
use std::sync::Mutex;

use rand_core::{OsRng, RngCore};

pub mod error;
pub mod hub;
pub mod routes;
pub mod store;

pub use error::{ServerError, ServerResult};
pub use hub::Hub;
pub use routes::router;
pub use store::{now, username_hash, PublicKey, Store};

const GLOBAL_SIGNUP_SCOPE: &str = "signup:*";

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub signups_per_address: u32,
    pub signups_global: u32,
    pub signup_window_secs: i64,
    pub register_failures: u32,
    pub register_lockout_secs: i64,
    pub auth_attempts: u32,
    pub auth_lockout_secs: i64,
    pub challenge_ttl_secs: i64,
    pub message_ttl_secs: i64,
    pub max_envelope_bytes: usize,
    pub max_pending_per_recipient: i64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            signups_per_address: 5,
            signups_global: 500,
            signup_window_secs: 3600,
            register_failures: 10,
            register_lockout_secs: 15 * 60,
            auth_attempts: 10,
            auth_lockout_secs: 15 * 60,
            challenge_ttl_secs: 60,
            message_ttl_secs: 30 * 24 * 3600,
            max_envelope_bytes: 256 * 1024,
            max_pending_per_recipient: 1000,
        }
    }
}

struct Challenge {
    nonce: [u8; 32],
    expires_at: i64,
}

pub struct Relay {
    store: Mutex<Store>,
    config: RelayConfig,
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

    pub fn registration_challenge(public_key: &PublicKey, username_hash: &[u8; 32]) -> Vec<u8> {
        wisp_core::protocol::registration_challenge(public_key, username_hash)
    }

    pub fn register(
        &self,
        client_scope: &str,
        username: &str,
        public_key: &PublicKey,
        signature: &[u8],
    ) -> ServerResult<()> {
        let fail_scope = format!("register-fail:{client_scope}");
        self.check_lockout(&fail_scope)?;

        let outcome = self.register_inner(client_scope, username, public_key, signature);

        match &outcome {
            Ok(()) => self.store.lock().unwrap().clear_failures(&fail_scope)?,
            Err(ServerError::AlreadyRegistered)
            | Err(ServerError::BadUsername)
            | Err(ServerError::RateLimited { .. }) => {}
            Err(_) => self.register_failure(&fail_scope)?,
        }

        outcome
    }

    fn register_inner(
        &self,
        client_scope: &str,
        username: &str,
        public_key: &PublicKey,
        signature: &[u8],
    ) -> ServerResult<()> {
        let canonical = wisp_core::identity::normalise_username(username);
        wisp_core::identity::check_username(&canonical).map_err(|_| ServerError::BadUsername)?;
        let uname_hash = username_hash(&canonical);

        let message = Self::registration_challenge(public_key, &uname_hash);
        verify_signature(public_key, &message, signature)?;

        let store = self.store.lock().unwrap();
        let window = self.config.signup_window_secs;
        let address_scope = format!("signup:{client_scope}");

        for (scope, limit) in [
            (address_scope.as_str(), self.config.signups_per_address),
            (GLOBAL_SIGNUP_SCOPE, self.config.signups_global),
        ] {
            let (used, resets_in) = store.window_usage(scope, window)?;
            if used >= limit {
                return Err(ServerError::RateLimited {
                    retry_after: resets_in,
                });
            }
        }

        store.create_account(public_key, &uname_hash)?;

        store.bump_window(&address_scope, window)?;
        store.bump_window(GLOBAL_SIGNUP_SCOPE, window)?;
        Ok(())
    }

    fn register_failure(&self, scope: &str) -> ServerResult<()> {
        let store = self.store.lock().unwrap();
        let count = store.record_failure(scope)?;
        if count >= self.config.register_failures {
            store.set_lockout(scope, now() + self.config.register_lockout_secs)?;
        }
        Ok(())
    }

    // --- Authentication ---------------------------------------------------

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

    pub fn auth_message(nonce: &[u8; 32]) -> Vec<u8> {
        wisp_core::protocol::auth_message(nonce)
    }

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

    pub fn submit(&self, recipient: &PublicKey, envelope: &[u8]) -> ServerResult<()> {
        if envelope.len() > self.config.max_envelope_bytes {
            return Err(ServerError::BadRequest("envelope is too large".into()));
        }

        let store = self.store.lock().unwrap();
        if !store.account_exists(recipient)? {
            return Err(ServerError::UnknownAccount);
        }
        if store.pending_count(recipient)? >= self.config.max_pending_per_recipient {
            return Err(ServerError::MailboxFull);
        }
        store.queue_message(recipient, envelope)?;
        Ok(())
    }

    pub fn collect(&self, recipient: &PublicKey) -> ServerResult<Vec<Vec<u8>>> {
        self.store.lock().unwrap().take_pending(recipient)
    }

    pub fn sweep(&self) -> ServerResult<usize> {
        self.store
            .lock()
            .unwrap()
            .expire_messages(self.config.message_ttl_secs)
    }
}

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

        fn register_signature(&self, username: &str) -> [u8; 64] {
            let uname = wisp_core::identity::normalise_username(username);
            let message = Relay::registration_challenge(&self.public_key(), &username_hash(&uname));
            self.sign(&message)
        }
    }

    fn relay() -> Relay {
        Relay::in_memory().unwrap()
    }

    fn relay_with(config: RelayConfig) -> Relay {
        Relay::new(Store::in_memory().unwrap(), config)
    }

    fn register_from(
        relay: &Relay,
        ip: &str,
        client: &Client,
        username: &str,
    ) -> ServerResult<()> {
        relay.register(
            ip,
            username,
            &client.public_key(),
            &client.register_signature(username),
        )
    }

    fn register(relay: &Relay, client: &Client, username: &str) -> ServerResult<()> {
        register_from(relay, IP, client, username)
    }

    #[test]
    fn anyone_can_create_an_account() {
        let relay = relay();
        let alice = Client::new();

        register(&relay, &alice, "alice").unwrap();
        assert!(relay
            .with_store(|s| s.account_exists(&alice.public_key()))
            .unwrap());
    }

    #[test]
    fn a_signature_from_another_key_is_rejected() {
        let relay = relay();
        let alice = Client::new();
        let mallory = Client::new();

        let outcome = relay.register(
            IP,
            "alice",
            &alice.public_key(),
            &mallory.register_signature("alice"),
        );
        assert!(matches!(outcome, Err(ServerError::BadSignature)));
        assert!(!relay
            .with_store(|s| s.account_exists(&alice.public_key()))
            .unwrap());
    }

    #[test]
    fn a_signature_for_a_different_username_is_rejected() {
        let relay = relay();
        let alice = Client::new();

        let outcome = relay.register(
            IP,
            "alice",
            &alice.public_key(),
            &alice.register_signature("someone-else"),
        );
        assert!(matches!(outcome, Err(ServerError::BadSignature)));
    }

    #[test]
    fn an_invite_era_signature_is_rejected() {
        let relay = relay();
        let alice = Client::new();
        let uname = username_hash("alice");

        let mut old = b"wisp.register.v1".to_vec();
        old.extend_from_slice(&[7u8; 32]);
        old.extend_from_slice(&alice.public_key());
        old.extend_from_slice(&uname);

        let outcome = relay.register(IP, "alice", &alice.public_key(), &alice.sign(&old));
        assert!(matches!(outcome, Err(ServerError::BadSignature)));
    }

    #[test]
    fn usernames_are_normalised_before_registration() {
        let relay = relay();
        let alice = Client::new();

        register(&relay, &alice, "  Alice  ").unwrap();

        assert!(relay
            .with_store(|s| s.username_taken(&username_hash("alice")))
            .unwrap());
    }

    #[test]
    fn an_invalid_username_is_refused() {
        let relay = relay();
        let alice = Client::new();
        assert!(matches!(
            register(&relay, &alice, "no"),
            Err(ServerError::BadUsername)
        ));
    }

    #[test]
    fn a_taken_username_conflicts() {
        let relay = relay();
        register(&relay, &Client::new(), "alice").unwrap();

        assert!(matches!(
            register(&relay, &Client::new(), "alice"),
            Err(ServerError::AlreadyRegistered)
        ));
    }

    // --- Signup limits ----------------------------------------------------

    fn tight(per_address: u32, global: u32) -> RelayConfig {
        RelayConfig {
            signups_per_address: per_address,
            signups_global: global,
            ..RelayConfig::default()
        }
    }

    #[test]
    fn one_address_cannot_mint_unlimited_accounts() {
        let relay = relay_with(tight(3, 1000));

        for i in 0..3 {
            register(&relay, &Client::new(), &format!("user-{i}")).unwrap();
        }

        let outcome = register(&relay, &Client::new(), "one-too-many");
        match outcome {
            Err(ServerError::RateLimited { retry_after }) => {
                assert!(retry_after > 0 && retry_after <= 3600)
            }
            other => panic!("expected a rate limit, got {other:?}"),
        }
    }

    #[test]
    fn the_per_address_limit_is_per_address() {
        let relay = relay_with(tight(1, 1000));

        register_from(&relay, "203.0.113.1", &Client::new(), "alice").unwrap();
        register_from(&relay, "203.0.113.2", &Client::new(), "bob").unwrap();

        assert!(matches!(
            register_from(&relay, "203.0.113.1", &Client::new(), "carol"),
            Err(ServerError::RateLimited { .. })
        ));
    }

    #[test]
    fn the_global_cap_applies_across_addresses() {
        let relay = relay_with(tight(10, 2));

        register_from(&relay, "203.0.113.1", &Client::new(), "alice").unwrap();
        register_from(&relay, "203.0.113.2", &Client::new(), "bob").unwrap();

        assert!(matches!(
            register_from(&relay, "203.0.113.3", &Client::new(), "carol"),
            Err(ServerError::RateLimited { .. })
        ));
    }

    #[test]
    fn the_limit_lapses_when_the_window_does() {
        let relay = relay_with(tight(1, 1000));
        register(&relay, &Client::new(), "alice").unwrap();
        assert!(matches!(
            register(&relay, &Client::new(), "bob"),
            Err(ServerError::RateLimited { .. })
        ));

        relay.with_store(|s| {
            s.age_signup_windows_for_test(7200);
        });
        register(&relay, &Client::new(), "bob").unwrap();
    }

    #[test]
    fn refused_registrations_do_not_spend_signup_budget() {
        let relay = relay_with(tight(2, 1000));
        register(&relay, &Client::new(), "alice").unwrap();

        for _ in 0..5 {
            let _ = register(&relay, &Client::new(), "alice");
            let _ = register(&relay, &Client::new(), "x");
        }
        register(&relay, &Client::new(), "bob").unwrap();
    }

    #[test]
    fn a_username_clash_does_not_count_toward_lockout() {
        let relay = relay_with(tight(1000, 100_000));
        register(&relay, &Client::new(), "alice").unwrap();

        let bob = Client::new();
        for _ in 0..RelayConfig::default().register_failures + 5 {
            assert!(matches!(
                register(&relay, &bob, "alice"),
                Err(ServerError::AlreadyRegistered)
            ));
        }

        register(&relay, &bob, "bob").unwrap();
    }

    #[test]
    fn repeated_bad_registrations_lock_the_address_out() {
        let relay = relay_with(tight(1000, 100_000));
        let alice = Client::new();
        let forged = Client::new();

        for _ in 0..RelayConfig::default().register_failures {
            let _ = relay.register(
                IP,
                "alice",
                &alice.public_key(),
                &forged.register_signature("alice"),
            );
        }

        assert!(matches!(
            register(&relay, &alice, "alice"),
            Err(ServerError::RateLimited { .. })
        ));
    }

    #[test]
    fn a_few_bad_registrations_do_not_block_a_genuine_one() {
        let relay = relay_with(tight(1000, 100_000));
        let alice = Client::new();
        let forged = Client::new();

        for _ in 0..5 {
            let _ = relay.register(
                IP,
                "alice",
                &alice.public_key(),
                &forged.register_signature("alice"),
            );
        }
        register(&relay, &alice, "alice").unwrap();
    }

    // --- Authentication ---------------------------------------------------

    fn registered(relay: &Relay, username: &str) -> Client {
        let client = Client::new();
        register(relay, &client, username).unwrap();
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
    fn an_oversized_envelope_is_refused() {
        let relay = relay_with(RelayConfig {
            max_envelope_bytes: 1024,
            ..RelayConfig::default()
        });
        let alice = registered(&relay, "alice");

        relay.submit(&alice.public_key(), &[0u8; 1024]).unwrap();
        assert!(matches!(
            relay.submit(&alice.public_key(), &[0u8; 1025]),
            Err(ServerError::BadRequest(_))
        ));
        assert_eq!(relay.collect(&alice.public_key()).unwrap().len(), 1);
    }

    #[test]
    fn a_full_mailbox_refuses_more_until_it_is_collected() {
        let relay = relay_with(RelayConfig {
            max_pending_per_recipient: 3,
            ..RelayConfig::default()
        });
        let alice = registered(&relay, "alice");

        for _ in 0..3 {
            relay.submit(&alice.public_key(), b"sealed").unwrap();
        }
        assert!(matches!(
            relay.submit(&alice.public_key(), b"sealed"),
            Err(ServerError::MailboxFull)
        ));

        assert_eq!(relay.collect(&alice.public_key()).unwrap().len(), 3);
        relay.submit(&alice.public_key(), b"sealed").unwrap();
    }

    #[test]
    fn one_full_mailbox_does_not_block_other_recipients() {
        let relay = relay_with(RelayConfig {
            max_pending_per_recipient: 1,
            ..RelayConfig::default()
        });
        let alice = registered(&relay, "alice");
        let bob = registered(&relay, "bob");

        relay.submit(&alice.public_key(), b"sealed").unwrap();
        assert!(relay.submit(&alice.public_key(), b"sealed").is_err());
        relay.submit(&bob.public_key(), b"sealed").unwrap();
    }
    #[test]
    fn the_relay_cannot_read_what_it_carries() {
        let relay = relay();
        let alice = registered(&relay, "alice");
        let mut noise = vec![0u8; 4096];
        OsRng.fill_bytes(&mut noise);

        relay.submit(&alice.public_key(), &noise).unwrap();
        assert_eq!(relay.collect(&alice.public_key()).unwrap(), vec![noise]);
    }
}
