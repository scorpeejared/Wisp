use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use tokio::sync::mpsc;
use wisp_messaging::CertificateAuthority;

use crate::{now, PublicKey, Relay, ServerError, ServerResult};

pub const TOKEN_TTL: Duration = Duration::from_secs(12 * 3600);

pub type Token = String;

struct SessionEntry {
    public_key: PublicKey,
    expires_at: Instant,
}

pub type Wake = mpsc::UnboundedSender<()>;

const TRUST_ROOT_KEY: &str = "sealed_sender.trust_root";
const SERVER_SIGNING_KEY: &str = "sealed_sender.server_key";

pub struct Hub {
    pub relay: Relay,
    authority: CertificateAuthority,
    sessions: Mutex<HashMap<Token, SessionEntry>>,
    connected: Mutex<HashMap<PublicKey, Wake>>,
    client_ip_header: Option<String>,
}

impl Hub {
    pub fn new(relay: Relay) -> Self {
        let authority =
            Self::load_or_create_authority(&relay).expect("sealed-sender keys unavailable");
        Self {
            relay,
            authority,
            sessions: Mutex::new(HashMap::new()),
            connected: Mutex::new(HashMap::new()),
            client_ip_header: None,
        }
    }

    pub fn with_client_ip_header(mut self, header: Option<String>) -> Self {
        self.client_ip_header = header.map(|h| h.trim().to_ascii_lowercase());
        self
    }

    pub fn with_trusted_proxy(self, trusted: bool) -> Self {
        self.with_client_ip_header(trusted.then(|| "x-forwarded-for".to_string()))
    }

    pub fn client_ip_header(&self) -> Option<&str> {
        self.client_ip_header.as_deref()
    }

    fn load_or_create_authority(relay: &Relay) -> ServerResult<CertificateAuthority> {
        let existing = relay.with_store(|store| -> ServerResult<_> {
            Ok((
                store.get_meta(TRUST_ROOT_KEY)?,
                store.get_meta(SERVER_SIGNING_KEY)?,
            ))
        })?;

        if let (Some(trust_root), Some(server_key)) = existing {
            if let Ok(authority) = CertificateAuthority::restore(&trust_root, &server_key) {
                return Ok(authority);
            }
        }

        let fresh = CertificateAuthority::generate()
            .map_err(|e| ServerError::BadRequest(e.to_string()))?;

        let (trust_root, server_key) = relay.with_store(|store| -> ServerResult<_> {
            Ok((
                store.put_meta_if_absent(TRUST_ROOT_KEY, &fresh.trust_root_private_bytes())?,
                store.put_meta_if_absent(SERVER_SIGNING_KEY, &fresh.server_private_bytes())?,
            ))
        })?;

        CertificateAuthority::restore(&trust_root, &server_key)
            .map_err(|e| ServerError::BadRequest(e.to_string()))
    }

    pub fn authority(&self) -> &CertificateAuthority {
        &self.authority
    }

    pub fn issue_token(&self, public_key: &PublicKey) -> Token {
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        let token: Token = raw.iter().map(|b| format!("{b:02x}")).collect();

        let mut sessions = self.sessions.lock().unwrap();
        let cutoff = Instant::now();
        sessions.retain(|_, entry| entry.expires_at > cutoff);

        sessions.insert(
            token.clone(),
            SessionEntry {
                public_key: *public_key,
                expires_at: Instant::now() + TOKEN_TTL,
            },
        );
        token
    }

    pub fn resolve_token(&self, token: &str) -> Option<PublicKey> {
        let sessions = self.sessions.lock().unwrap();
        sessions
            .get(token)
            .filter(|entry| entry.expires_at > Instant::now())
            .map(|entry| entry.public_key)
    }

    pub fn revoke_token(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }

    pub fn connect(&self, public_key: &PublicKey, wake: Wake) {
        self.connected.lock().unwrap().insert(*public_key, wake);
    }

    pub fn disconnect(&self, public_key: &PublicKey) {
        self.connected.lock().unwrap().remove(public_key);
    }

    pub fn is_connected(&self, public_key: &PublicKey) -> bool {
        self.connected.lock().unwrap().contains_key(public_key)
    }

    pub fn deliver(&self, recipient: &PublicKey, envelope: &[u8]) -> ServerResult<()> {
        self.relay.submit(recipient, envelope)?;

        let connected = self.connected.lock().unwrap();
        if let Some(wake) = connected.get(recipient) {
            let _ = wake.send(());
        }
        Ok(())
    }

    pub fn authenticate(
        &self,
        client_scope: &str,
        public_key: &PublicKey,
        signature: &[u8],
    ) -> ServerResult<Token> {
        self.relay
            .verify_challenge(client_scope, public_key, signature)?;
        Ok(self.issue_token(public_key))
    }

    pub fn ensure_active(&self, public_key: &PublicKey) -> ServerResult<()> {
        if let Some(until) = self
            .relay
            .with_store(|s| s.account_locked_until(public_key))?
        {
            return Err(ServerError::AccountLocked {
                retry_after: until - now(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: PublicKey = [1u8; 32];
    const BOB: PublicKey = [2u8; 32];

    fn hub() -> Hub {
        Hub::new(Relay::in_memory().unwrap())
    }

    #[test]
    fn a_token_resolves_to_its_account() {
        let hub = hub();
        let token = hub.issue_token(&ALICE);
        assert_eq!(hub.resolve_token(&token), Some(ALICE));
    }

    #[test]
    fn an_unknown_token_resolves_to_nothing() {
        let hub = hub();
        hub.issue_token(&ALICE);
        assert_eq!(hub.resolve_token("not-a-real-token"), None);
    }

    #[test]
    fn tokens_are_distinct_per_issue() {
        let hub = hub();
        assert_ne!(hub.issue_token(&ALICE), hub.issue_token(&ALICE));
    }

    #[test]
    fn a_revoked_token_stops_working() {
        let hub = hub();
        let token = hub.issue_token(&ALICE);
        hub.revoke_token(&token);
        assert_eq!(hub.resolve_token(&token), None);
    }

    #[test]
    fn an_expired_token_is_refused() {
        let hub = hub();
        let token = hub.issue_token(&ALICE);
        hub.sessions
            .lock()
            .unwrap()
            .get_mut(&token)
            .unwrap()
            .expires_at = Instant::now() - Duration::from_secs(1);
        assert_eq!(hub.resolve_token(&token), None);
    }

    #[test]
    fn expired_sessions_are_swept_on_issue() {
        let hub = hub();
        let stale = hub.issue_token(&ALICE);
        hub.sessions
            .lock()
            .unwrap()
            .get_mut(&stale)
            .unwrap()
            .expires_at = Instant::now() - Duration::from_secs(1);

        hub.issue_token(&BOB);
        assert!(!hub.sessions.lock().unwrap().contains_key(&stale));
    }

    #[test]
    fn a_second_connection_displaces_the_first() {
        let hub = hub();
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let (tx2, _rx2) = mpsc::unbounded_channel();

        hub.connect(&ALICE, tx1);
        hub.connect(&ALICE, tx2);
        assert!(hub.is_connected(&ALICE));

        drop(hub);
        assert!(rx1.try_recv().is_err());
    }

    #[test]
    fn disconnecting_clears_the_registration() {
        let hub = hub();
        let (tx, _rx) = mpsc::unbounded_channel();
        hub.connect(&ALICE, tx);
        hub.disconnect(&ALICE);
        assert!(!hub.is_connected(&ALICE));
    }
}
