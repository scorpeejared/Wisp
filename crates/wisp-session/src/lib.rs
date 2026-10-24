use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

use wisp_core::crypto::KdfParams;
use wisp_core::{BindingStrength, IdentityFile, UnlockedIdentity};
use wisp_usb::{RemovableVolume, VolumeProvider};

pub mod gate;
pub mod relay;

pub use gate::Gate;
pub use relay::{RegistrationRequest, RelayClient, RelayError, RelayFailure};

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("no identity is waiting to be unlocked")]
    NotLocked,

    #[error("no drive is available to register an identity on")]
    NotRegistrable,

    #[error("the session is not idle")]
    NotIdle,

    #[error("that drive is not available")]
    UnknownDrive,

    #[error("this computer cannot be identified, so it cannot be bound to")]
    MachineUnidentifiable,

    #[error("trusted-computer binding is already in that state")]
    BindingUnchanged,

    #[error("could not unlock the identity")]
    UnlockFailed,

    #[error("too many failed attempts; wait {} seconds", .retry_after.as_secs().max(1))]
    Throttled { retry_after: Duration },

    #[error(transparent)]
    Identity(#[from] wisp_core::Error),

    #[error("{0}")]
    Relay(#[from] RelayError),

    #[error("could not write the identity to the drive: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DriveInfo {
    pub mount_point: String,
    pub label: Option<String>,
    pub has_identity: bool,
    pub current: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum Status {
    NoDevice,

    #[serde(rename_all = "camelCase")]
    Unusable { mount_point: String, reason: String },

    #[serde(rename_all = "camelCase")]
    Registrable {
        mount_point: String,
        label: Option<String>,
        strong_binding: bool,
    },

    #[serde(rename_all = "camelCase")]
    Denied { mount_point: String },

    #[serde(rename_all = "camelCase")]
    DeniedComputer { mount_point: String },

    #[serde(rename_all = "camelCase")]
    Locked {
        mount_point: String,
        label: Option<String>,
    },

    #[serde(rename_all = "camelCase")]
    Idle {
        username: String,
        biometrics_available: bool,
    },

    #[serde(rename_all = "camelCase")]
    Unlocked {
        username: String,
        public_key: String,
        fingerprint: String,
        mount_point: String,
        trusted_computer: bool,
        can_bind_computer: bool,
    },
}

impl Status {
    pub fn permits_app_content(&self) -> bool {
        matches!(self, Status::Unlocked { .. })
    }
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub kdf_params: KdfParams,
    pub throttle_base: Duration,
    pub throttle_max: Duration,
    pub machine_id: Option<String>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            kdf_params: KdfParams::RECOMMENDED,
            throttle_base: Duration::from_millis(500),
            throttle_max: Duration::from_secs(30),
            machine_id: wisp_machine::identify().machine_id,
        }
    }
}

pub struct Session<P: VolumeProvider> {
    provider: Arc<P>,
    relay: Arc<dyn RelayClient>,
    config: SessionConfig,
    inner: Mutex<Inner>,
}

struct Inner {
    gate: Gate,
    identity: Option<UnlockedIdentity>,
    bound: Option<RemovableVolume>,
    idle: bool,
    biometrics_available: bool,
    machine_id: Option<String>,
    failed_attempts: u32,
    last_failure: Option<Instant>,
    selected: Option<std::path::PathBuf>,
}

impl Inner {
    fn wipe(&mut self) {
        if let Some(identity) = &mut self.identity {
            identity.lock();
        }
        self.identity = None;
        self.bound = None;
        self.idle = false;
    }

    fn throttle_remaining(&self, config: &SessionConfig) -> Option<Duration> {
        let attempts = self.failed_attempts;
        if attempts == 0 {
            return None;
        }
        let last = self.last_failure?;
        let delay = config
            .throttle_base
            .saturating_mul(1u32 << attempts.min(16))
            .min(config.throttle_max);
        let elapsed = last.elapsed();
        (elapsed < delay).then(|| delay - elapsed)
    }
}

impl<P: VolumeProvider> Session<P> {
    pub fn new(provider: Arc<P>, relay: Arc<dyn RelayClient>) -> Self {
        Self::with_config(provider, relay, SessionConfig::default())
    }

    pub fn with_config(
        provider: Arc<P>,
        relay: Arc<dyn RelayClient>,
        config: SessionConfig,
    ) -> Self {
        let config_machine_id = config.machine_id.clone();
        let session = Self {
            provider,
            relay,
            config,
            inner: Mutex::new(Inner {
                gate: Gate::NoDevice,
                identity: None,
                bound: None,
                idle: false,
                biometrics_available: false,
                machine_id: config_machine_id,
                failed_attempts: 0,
                last_failure: None,
                selected: None,
            }),
        };
        session.refresh();
        session
    }

    pub fn refresh(&self) -> Status {
        let Ok(volumes) = self.provider.list_removable() else {
            return self.status();
        };

        let mut inner = self.inner.lock().unwrap();

        if let Some(bound) = inner.bound.clone() {
            let still_present = volumes
                .iter()
                .any(|volume| *volume == bound && volume.has_identity());
            if still_present {
                return status_of(&inner);
            }
            inner.wipe();
        }

        let candidates = narrow(&volumes, &mut inner.selected);
        inner.gate = gate::evaluate(&candidates, self.config.machine_id.as_deref());
        status_of(&inner)
    }

    pub fn drives(&self) -> Vec<DriveInfo> {
        let Ok(mut volumes) = self.provider.list_removable() else {
            return Vec::new();
        };
        volumes.sort_by(|a, b| a.mount_point.cmp(&b.mount_point));

        let inner = self.inner.lock().unwrap();
        let current = match (&inner.identity, &inner.bound) {
            (Some(_), Some(bound)) => Some(bound.mount_point.as_path()),
            _ => inner.gate.mount_point(),
        };

        volumes
            .iter()
            .map(|volume| DriveInfo {
                mount_point: display(&volume.mount_point),
                label: volume.label.clone(),
                has_identity: volume.has_identity(),
                current: current == Some(volume.mount_point.as_path()),
            })
            .collect()
    }

    pub fn select_drive(&self, mount_point: &str) -> Result<Status, SessionError> {
        let volumes = self
            .provider
            .list_removable()
            .map_err(|_| SessionError::UnknownDrive)?;
        let target = volumes
            .into_iter()
            .find(|volume| display(&volume.mount_point) == mount_point)
            .ok_or(SessionError::UnknownDrive)?;

        let mut inner = self.inner.lock().unwrap();
        inner.wipe();
        inner.selected = Some(target.mount_point.clone());
        inner.gate = gate::evaluate(&[target], self.config.machine_id.as_deref());
        Ok(status_of(&inner))
    }

    pub fn status(&self) -> Status {
        status_of(&self.inner.lock().unwrap())
    }

    pub fn is_unlocked(&self) -> bool {
        self.inner.lock().unwrap().identity.is_some()
    }

    pub fn unlock(&self, passphrase: &str) -> Result<Status, SessionError> {
        let mut inner = self.inner.lock().unwrap();

        if let Some(retry_after) = inner.throttle_remaining(&self.config) {
            return Err(SessionError::Throttled { retry_after });
        }

        let Gate::Locked { volume, file } = inner.gate.clone() else {
            return Err(SessionError::NotLocked);
        };

        match file.unlock(passphrase, &volume.identifiers, self.config.machine_id.as_deref()) {
            Ok(identity) => {
                inner.identity = Some(identity);
                inner.bound = Some(volume);
                inner.failed_attempts = 0;
                inner.last_failure = None;
                Ok(status_of(&inner))
            }
            Err(_) => {
                inner.failed_attempts = inner.failed_attempts.saturating_add(1);
                inner.last_failure = Some(Instant::now());
                Err(SessionError::UnlockFailed)
            }
        }
    }

    pub fn register(&self, username: &str, passphrase: &str) -> Result<Status, SessionError> {
        let mut inner = self.inner.lock().unwrap();
        let Gate::Registrable { volume, .. } = inner.gate.clone() else {
            return Err(SessionError::NotRegistrable);
        };

        let username = wisp_core::identity::normalise_username(username);
        wisp_core::identity::check_username(&username)?;
        wisp_core::passphrase::enforce(passphrase).map_err(wisp_core::Error::WeakPassphrase)?;

        let identity = UnlockedIdentity::generate(&username)?;
        let file = IdentityFile::create(
            &identity,
            passphrase,
            &volume.identifiers,
            None,
            self.config.kdf_params,
        )?;

        volume.stage_identity(&file.encode())?;

        let public_key = identity.public_key()?;
        let username_hash = wisp_core::protocol::username_hash(&username);
        let signature = identity.sign(&wisp_core::protocol::registration_challenge(
            &public_key,
            &username_hash,
        ))?;

        if let Err(e) = self.relay.register(&RegistrationRequest {
            username: username.clone(),
            public_key,
            signature,
        }) {
            volume.discard_staged_identity();
            return Err(e.into());
        }

        volume.commit_identity()?;

        inner.gate = Gate::Locked {
            volume: volume.clone(),
            file: Box::new(file),
        };
        inner.identity = Some(identity);
        inner.bound = Some(volume);
        Ok(status_of(&inner))
    }

    pub fn set_biometrics_available(&self, available: bool) {
        self.inner.lock().unwrap().biometrics_available = available;
    }

    pub fn begin_idle(&self) -> Status {
        let mut inner = self.inner.lock().unwrap();
        if inner.identity.is_some() {
            inner.idle = true;
        }
        status_of(&inner)
    }

    pub fn is_idle(&self) -> bool {
        self.inner.lock().unwrap().idle
    }

    pub fn resume_verified(&self) -> Result<Status, SessionError> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.idle || inner.identity.is_none() {
            return Err(SessionError::NotIdle);
        }
        inner.idle = false;
        Ok(status_of(&inner))
    }

    pub fn resume_with_passphrase(&self, passphrase: &str) -> Result<Status, SessionError> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.idle || inner.identity.is_none() {
            return Err(SessionError::NotIdle);
        }
        if let Some(retry_after) = inner.throttle_remaining(&self.config) {
            return Err(SessionError::Throttled { retry_after });
        }

        let Gate::Locked { volume, file } = inner.gate.clone() else {
            return Err(SessionError::NotLocked);
        };

        match file.unlock(passphrase, &volume.identifiers, self.config.machine_id.as_deref()) {
            Ok(identity) => {
                inner.identity = Some(identity);
                inner.idle = false;
                inner.failed_attempts = 0;
                inner.last_failure = None;
                Ok(status_of(&inner))
            }
            Err(_) => {
                inner.failed_attempts = inner.failed_attempts.saturating_add(1);
                inner.last_failure = Some(Instant::now());
                Err(SessionError::UnlockFailed)
            }
        }
    }

    pub fn is_trusted_computer_bound(&self) -> bool {
        matches!(
            &self.inner.lock().unwrap().gate,
            Gate::Locked { file, .. } if file.machine_binding
        )
    }

    pub fn set_trusted_computer(
        &self,
        enabled: bool,
        passphrase: &str,
    ) -> Result<Status, SessionError> {
        let mut inner = self.inner.lock().unwrap();

        let Gate::Locked { volume, file } = inner.gate.clone() else {
            return Err(SessionError::NotLocked);
        };
        if file.machine_binding == enabled {
            return Err(SessionError::BindingUnchanged);
        }

        let machine_id = self.config.machine_id.as_deref();
        if enabled && machine_id.is_none() {
            return Err(SessionError::MachineUnidentifiable);
        }

        let current = file.machine_binding.then_some(machine_id).flatten();
        let next = enabled.then_some(machine_id).flatten();

        let rebound = file.rebind(passphrase, &volume.identifiers, current, next)?;
        volume.stage_identity(&rebound.encode())?;
        volume.commit_identity()?;

        inner.gate = Gate::Locked {
            volume,
            file: Box::new(rebound),
        };
        Ok(status_of(&inner))
    }

    pub fn lock(&self) -> Status {
        let mut inner = self.inner.lock().unwrap();
        inner.wipe();
        drop(inner);
        self.refresh()
    }

    pub fn with_identity<T>(&self, f: impl FnOnce(&UnlockedIdentity) -> T) -> Option<T> {
        self.inner.lock().unwrap().identity.as_ref().map(f)
    }

    pub fn public_key(&self) -> Option<[u8; 32]> {
        self.inner
            .lock()
            .unwrap()
            .identity
            .as_ref()
            .and_then(|identity| identity.public_key().ok())
    }
}

fn status_of(inner: &Inner) -> Status {
    if let (Some(identity), Some(volume)) = (&inner.identity, &inner.bound) {
        if inner.idle {
            return Status::Idle {
                username: identity.username.clone(),
                biometrics_available: inner.biometrics_available,
            };
        }
        if let Ok(public) = identity.public_key() {
            return Status::Unlocked {
                username: identity.username.clone(),
                public_key: to_hex(&public),
                fingerprint: fingerprint(&public),
                mount_point: display(&volume.mount_point),
                trusted_computer: matches!(
                    &inner.gate,
                    Gate::Locked { file, .. } if file.machine_binding
                ),
                can_bind_computer: inner.machine_id.is_some(),
            };
        }
    }

    match &inner.gate {
        Gate::NoDevice => Status::NoDevice,
        Gate::Unusable {
            mount_point,
            reason,
        } => Status::Unusable {
            mount_point: display(mount_point),
            reason: reason.clone(),
        },
        Gate::Registrable { volume, strength } => Status::Registrable {
            mount_point: display(&volume.mount_point),
            label: volume.label.clone(),
            strong_binding: *strength == BindingStrength::Strong,
        },
        Gate::Denied { mount_point } => Status::Denied {
            mount_point: display(mount_point),
        },
        Gate::WrongComputer { mount_point } => Status::DeniedComputer {
            mount_point: display(mount_point),
        },
        Gate::Locked { volume, .. } => Status::Locked {
            mount_point: display(&volume.mount_point),
            label: volume.label.clone(),
        },
    }
}

fn narrow(
    volumes: &[RemovableVolume],
    selected: &mut Option<std::path::PathBuf>,
) -> Vec<RemovableVolume> {
    if let Some(path) = selected.as_ref() {
        if let Some(volume) = volumes.iter().find(|v| &v.mount_point == path) {
            return vec![volume.clone()];
        }
        *selected = None;
    }
    volumes.to_vec()
}

fn display(path: &std::path::Path) -> String {
    path.display().to_string()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn fingerprint(public: &[u8; 32]) -> String {
    to_hex(public)
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use wisp_core::DeviceIdentifiers;
    use wisp_usb::mock::MockVolumeProvider;

    const PASS: &str = "Tr0ub4dor&3xK!ncq9Zvw";
    const THIS_MACHINE: &str = "2a48fb29-1111-2222-3333-444455556666";
    const OTHER_MACHINE: &str = "9f86d081-884c-4d65-9a2d-1f7a2b3c4d5e";
    const OTHER_PASS: &str = "Zx9!qWeRtY&asdfGH42";

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    struct FakeDrive {
        path: PathBuf,
        serial: String,
    }

    impl FakeDrive {
        fn new(serial: &str) -> Self {
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "wisp-session-{}-{}-{}",
                std::process::id(),
                unique,
                serial
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self {
                path,
                serial: serial.to_string(),
            }
        }

        fn volume(&self) -> RemovableVolume {
            RemovableVolume {
                mount_point: self.path.clone(),
                label: Some("WISP".into()),
                identifiers: DeviceIdentifiers {
                    device_serial: Some(self.serial.clone()),
                    volume_serial: Some("1A2B-3C4D".into()),
                    vendor: Some("SanDisk".into()),
                    product: Some("Cruzer".into()),
                },
            }
        }

        fn volume_with_serial(&self, serial: &str) -> RemovableVolume {
            let mut volume = self.volume();
            volume.identifiers.device_serial = Some(serial.into());
            volume
        }

        fn identity_bytes(&self) -> Vec<u8> {
            std::fs::read(self.volume().identity_path()).unwrap()
        }
    }

    impl Drop for FakeDrive {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.path).ok();
        }
    }

    fn session(mock: &Arc<MockVolumeProvider>) -> Session<MockVolumeProvider> {
        session_with_relay(mock, Arc::new(relay::mock::MockRelay::accepting()))
    }

    fn session_with_relay(
        mock: &Arc<MockVolumeProvider>,
        relay: Arc<dyn RelayClient>,
    ) -> Session<MockVolumeProvider> {
        Session::with_config(
            Arc::clone(mock),
            relay,
            SessionConfig {
                kdf_params: KdfParams::INSECURE_FOR_TESTS,
                throttle_base: Duration::ZERO,
                throttle_max: Duration::ZERO,
                machine_id: Some(THIS_MACHINE.to_string()),
            },
        )
    }

    #[test]
    fn nothing_inserted_means_no_device() {
        let mock = Arc::new(MockVolumeProvider::new());
        assert_eq!(session(&mock).status(), Status::NoDevice);
    }

    #[test]
    fn no_status_but_unlocked_permits_app_content() {
        for status in [
            Status::NoDevice,
            Status::Denied {
                mount_point: "E:\\".into(),
            },
            Status::Locked {
                mount_point: "E:\\".into(),
                label: None,
            },
            Status::Registrable {
                mount_point: "E:\\".into(),
                label: None,
                strong_binding: true,
            },
            Status::Unusable {
                mount_point: "E:\\".into(),
                reason: "x".into(),
            },
        ] {
            assert!(!status.permits_app_content(), "{status:?}");
        }
    }

    #[test]
    fn blank_drive_offers_registration() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        assert!(matches!(
            session(&mock).status(),
            Status::Registrable {
                strong_binding: true,
                ..
            }
        ));
    }

    #[test]
    fn drive_without_a_serial_binds_weakly() {
        let drive = FakeDrive::new("AAA1");
        let mut volume = drive.volume();
        volume.identifiers.device_serial = None;
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![volume]));
        assert!(matches!(
            session(&mock).status(),
            Status::Registrable {
                strong_binding: false,
                ..
            }
        ));
    }

    #[test]
    fn unbindable_drive_is_reported_as_unusable() {
        let drive = FakeDrive::new("AAA1");
        let mut volume = drive.volume();
        volume.identifiers.device_serial = None;
        volume.identifiers.volume_serial = None;
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![volume]));
        assert!(matches!(session(&mock).status(), Status::Unusable { .. }));
    }

    #[test]
    fn registration_writes_an_identity_and_unlocks() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);

        let status = session.register("alice", PASS).unwrap();
        assert!(matches!(status, Status::Unlocked { ref username, .. } if username == "alice"));
        assert!(status.permits_app_content());
        assert!(drive.volume().has_identity());
        assert!(session.public_key().is_some());
    }

    #[test]
    fn registration_refuses_a_weak_passphrase_without_touching_the_drive() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);

        assert!(session.register("alice", "short").is_err());
        assert!(
            !drive.volume().has_identity(),
            "a rejected passphrase must leave the drive untouched"
        );
    }

    #[test]
    fn a_rejected_registration_leaves_the_drive_exactly_as_it_was() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let relay = Arc::new(relay::mock::MockRelay::failing(RelayError::rejected(
            "this identity or username is already registered",
        )));
        let session = session_with_relay(&mock, relay);

        assert!(matches!(
            session.register("alice", PASS),
            Err(SessionError::Relay(_))
        ));
        assert!(!drive.volume().has_identity());
        assert!(!session.is_unlocked());
        assert!(!drive.path.join(".wisp").join("identity.wisp.tmp").exists());
    }

    #[test]
    fn an_unreachable_relay_allows_a_retry() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let relay = Arc::new(relay::mock::MockRelay::failing(RelayError::unreachable(
            "connection refused",
        )));
        let session = session_with_relay(&mock, relay.clone());

        let failure = session.register("alice", PASS).unwrap_err();
        let SessionError::Relay(e) = &failure else {
            panic!("expected a relay error, got {failure:?}");
        };
        assert!(e.is_unreachable());
        assert!(!drive.volume().has_identity());

        relay.set_response(None);
        session.refresh();
        session.register("alice", PASS).unwrap();
        assert!(drive.volume().has_identity());
        assert!(session.is_unlocked());
    }

    #[test]
    fn the_relay_receives_a_canonical_username_and_a_verifiable_signature() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let relay = Arc::new(relay::mock::MockRelay::accepting());
        let session = session_with_relay(&mock, relay.clone());

        session.register("  Alice  ", PASS).unwrap();

        let requests = relay.requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];

        assert_eq!(request.username, "alice", "username must be canonical");
        assert_eq!(request.public_key, session.public_key().unwrap());

        let message = wisp_core::protocol::registration_challenge(
            &request.public_key,
            &wisp_core::protocol::username_hash(&request.username),
        );
        assert!(
            wisp_core::protocol::verify_signature(
                &request.public_key,
                &message,
                &request.signature
            ),
            "the relay must be able to verify this signature"
        );
    }

    #[test]
    fn an_invalid_username_is_refused_before_the_relay_is_called() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let relay = Arc::new(relay::mock::MockRelay::accepting());
        let session = session_with_relay(&mock, relay.clone());

        assert!(session.register("no", PASS).is_err());
        assert!(relay.requests().is_empty());
        assert!(!drive.volume().has_identity());
    }

    #[test]
    fn removing_the_drive_wipes_the_key_and_locks_out() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);
        session.register("alice", PASS).unwrap();
        assert!(session.is_unlocked());

        mock.remove_all();
        let status = session.refresh();

        assert_eq!(status, Status::NoDevice);
        assert!(!session.is_unlocked(), "the key must be gone");
        assert!(session.public_key().is_none());
        assert!(!status.permits_app_content());
    }

    #[test]
    fn reinserting_requires_the_passphrase_again() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);
        session.register("alice", PASS).unwrap();

        mock.remove_all();
        session.refresh();
        mock.set_volumes(vec![drive.volume()]);

        assert!(matches!(session.refresh(), Status::Locked { .. }));
        assert!(!session.is_unlocked());

        let status = session.unlock(PASS).unwrap();
        assert!(matches!(status, Status::Unlocked { ref username, .. } if username == "alice"));
    }

    #[test]
    fn wrong_passphrase_is_rejected_and_the_session_stays_locked() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);
        session.register("alice", PASS).unwrap();
        session.lock();

        assert!(matches!(
            session.unlock(OTHER_PASS),
            Err(SessionError::UnlockFailed)
        ));
        assert!(!session.is_unlocked());
        assert!(matches!(session.status(), Status::Locked { .. }));
    }

    #[test]
    fn copied_identity_on_another_drive_is_denied_before_any_prompt() {
        let original = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![original.volume()]));
        let session = session(&mock);
        session.register("alice", PASS).unwrap();

        let thief = FakeDrive::new("BBB2");
        thief.volume().write_identity(&original.identity_bytes()).unwrap();

        mock.set_volumes(vec![thief.volume()]);
        let status = session.refresh();

        assert!(
            matches!(status, Status::Denied { .. }),
            "expected denial, got {status:?}"
        );
        assert!(!session.is_unlocked());

        assert!(matches!(
            session.unlock(PASS),
            Err(SessionError::NotLocked)
        ));
    }

    #[test]
    fn copied_identity_cannot_be_decrypted_even_bypassing_the_gate() {
        let original = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![original.volume()]));
        session(&mock).register("alice", PASS).unwrap();

        let thief = FakeDrive::new("BBB2");
        let file = IdentityFile::decode(&original.identity_bytes()).unwrap();

        assert!(file
            .unlock(PASS, &thief.volume().identifiers, Some(THIS_MACHINE))
            .is_err());
    }

    #[test]
    fn swapping_drives_mid_session_locks_immediately() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);
        session.register("alice", PASS).unwrap();
        assert!(session.is_unlocked());

        mock.set_volumes(vec![drive.volume_with_serial("CCC3")]);
        session.refresh();

        assert!(!session.is_unlocked(), "a swapped drive must lock the session");
    }

    #[test]
    fn deleting_the_identity_file_locks_the_session() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);
        session.register("alice", PASS).unwrap();

        std::fs::remove_file(drive.volume().identity_path()).unwrap();
        session.refresh();

        assert!(!session.is_unlocked());
    }

    #[test]
    fn enumeration_failure_does_not_lock_the_session() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);
        session.register("alice", PASS).unwrap();

        mock.fail_with("simulated platform error");
        let status = session.refresh();

        assert!(session.is_unlocked(), "a flaky API call must not lock the user out");
        assert!(matches!(status, Status::Unlocked { .. }));
    }

    #[test]
    fn corrupt_identity_file_is_reported_as_unusable() {
        let drive = FakeDrive::new("AAA1");
        drive.volume().write_identity(b"this is not an identity file").unwrap();
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));

        assert!(matches!(session(&mock).status(), Status::Unusable { .. }));
    }

    #[test]
    fn the_correct_drive_wins_over_a_mismatched_one() {
        let original = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![original.volume()]));
        let session = session(&mock);
        session.register("alice", PASS).unwrap();

        let thief = FakeDrive::new("BBB2");
        thief.volume().write_identity(&original.identity_bytes()).unwrap();

        mock.set_volumes(vec![thief.volume(), original.volume()]);
        session.lock();

        assert!(
            matches!(session.status(), Status::Locked { .. }),
            "the genuine drive should still be offered"
        );
    }

    #[test]
    fn repeated_failures_are_throttled() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = Session::with_config(
            Arc::clone(&mock),
            Arc::new(relay::mock::MockRelay::accepting()),
            SessionConfig {
                kdf_params: KdfParams::INSECURE_FOR_TESTS,
                throttle_base: Duration::from_secs(10),
                throttle_max: Duration::from_secs(30),
                machine_id: Some(THIS_MACHINE.to_string()),
            },
        );
        session.register("alice", PASS).unwrap();
        session.lock();

        assert!(matches!(
            session.unlock(OTHER_PASS),
            Err(SessionError::UnlockFailed)
        ));
        assert!(matches!(
            session.unlock(PASS),
            Err(SessionError::Throttled { .. })
        ));
    }

    #[test]
    fn status_serialises_without_leaking_secrets() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);
        let status = session.register("alice", PASS).unwrap();

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"state\":\"unlocked\""));
        assert!(json.contains("alice"));
        assert!(!json.contains(PASS), "the passphrase must never be serialised");
    }

    // --- Trusted computer binding ------------------------------------------

    fn session_on_machine(
        mock: &Arc<MockVolumeProvider>,
        machine_id: Option<&str>,
    ) -> Session<MockVolumeProvider> {
        Session::with_config(
            Arc::clone(mock),
            Arc::new(relay::mock::MockRelay::accepting()),
            SessionConfig {
                kdf_params: KdfParams::INSECURE_FOR_TESTS,
                throttle_base: Duration::ZERO,
                throttle_max: Duration::ZERO,
                machine_id: machine_id.map(str::to_string),
            },
        )
    }

    #[test]
    fn a_new_identity_is_not_machine_bound() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);
        let status = session.register("alice", PASS).unwrap();

        assert!(matches!(
            status,
            Status::Unlocked {
                trusted_computer: false,
                can_bind_computer: true,
                ..
            }
        ));
        assert!(!session.is_trusted_computer_bound());
    }

    #[test]
    fn binding_can_be_enabled_and_is_reported() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);
        session.register("alice", PASS).unwrap();

        let status = session.set_trusted_computer(true, PASS).unwrap();
        assert!(matches!(
            status,
            Status::Unlocked {
                trusted_computer: true,
                ..
            }
        ));
        assert!(session.is_trusted_computer_bound());
        assert!(session.is_unlocked());
    }

    #[test]
    fn changing_the_setting_needs_the_passphrase() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);
        session.register("alice", PASS).unwrap();

        assert!(session.set_trusted_computer(true, OTHER_PASS).is_err());
        assert!(!session.is_trusted_computer_bound());

        session.set_trusted_computer(true, PASS).unwrap();
        assert!(session.set_trusted_computer(false, OTHER_PASS).is_err());
        assert!(session.is_trusted_computer_bound());
    }

    #[test]
    fn a_bound_identity_is_denied_on_another_computer() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));

        let session = session_on_machine(&mock, Some(THIS_MACHINE));
        session.register("alice", PASS).unwrap();
        session.set_trusted_computer(true, PASS).unwrap();

        let elsewhere = session_on_machine(&mock, Some(OTHER_MACHINE));
        let status = elsewhere.status();

        assert!(
            matches!(status, Status::DeniedComputer { .. }),
            "expected a computer denial, got {status:?}"
        );
        assert!(!status.permits_app_content());
        assert!(matches!(
            elsewhere.unlock(PASS),
            Err(SessionError::NotLocked)
        ));
    }

    #[test]
    fn a_bound_identity_is_denied_on_an_unidentifiable_computer() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));

        let session = session_on_machine(&mock, Some(THIS_MACHINE));
        session.register("alice", PASS).unwrap();
        session.set_trusted_computer(true, PASS).unwrap();

        let nameless = session_on_machine(&mock, None);
        assert!(matches!(nameless.status(), Status::DeniedComputer { .. }));
    }

    #[test]
    fn disabling_restores_use_on_other_computers() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));

        let session = session_on_machine(&mock, Some(THIS_MACHINE));
        session.register("alice", PASS).unwrap();
        session.set_trusted_computer(true, PASS).unwrap();
        session.set_trusted_computer(false, PASS).unwrap();

        let elsewhere = session_on_machine(&mock, Some(OTHER_MACHINE));
        assert!(matches!(elsewhere.status(), Status::Locked { .. }));
        assert!(elsewhere.unlock(PASS).is_ok());
    }

    #[test]
    fn the_setting_is_written_to_the_drive() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));

        let session = session_on_machine(&mock, Some(THIS_MACHINE));
        session.register("alice", PASS).unwrap();
        session.set_trusted_computer(true, PASS).unwrap();

        let file = IdentityFile::decode(&drive.identity_bytes()).unwrap();
        assert!(file.machine_binding, "the drive still holds an unbound identity");
    }

    #[test]
    fn a_computer_that_cannot_be_identified_cannot_be_bound_to() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session_on_machine(&mock, None);

        let status = session.register("alice", PASS).unwrap();
        assert!(matches!(
            status,
            Status::Unlocked {
                can_bind_computer: false,
                ..
            }
        ));
        assert!(matches!(
            session.set_trusted_computer(true, PASS),
            Err(SessionError::MachineUnidentifiable)
        ));
    }

    #[test]
    fn setting_it_to_its_current_value_is_refused() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);
        session.register("alice", PASS).unwrap();

        assert!(matches!(
            session.set_trusted_computer(false, PASS),
            Err(SessionError::BindingUnchanged)
        ));
    }

    #[test]
    fn a_bound_identity_still_unlocks_on_its_own_computer() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session_on_machine(&mock, Some(THIS_MACHINE));
        session.register("alice", PASS).unwrap();
        session.set_trusted_computer(true, PASS).unwrap();
        session.lock();

        assert!(matches!(session.status(), Status::Locked { .. }));
        let status = session.unlock(PASS).unwrap();
        assert!(matches!(
            status,
            Status::Unlocked {
                trusted_computer: true,
                ..
            }
        ));
    }

    // --- Idle lock ---------------------------------------------------------

    fn unlocked_session(
        drive: &FakeDrive,
    ) -> (Arc<MockVolumeProvider>, Session<MockVolumeProvider>) {
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);
        session.register("alice", PASS).unwrap();
        (mock, session)
    }

    #[test]
    fn going_idle_keeps_the_key_but_hides_the_app() {
        let drive = FakeDrive::new("AAA1");
        let (_mock, session) = unlocked_session(&drive);

        let status = session.begin_idle();
        assert!(matches!(status, Status::Idle { .. }));
        assert!(!status.permits_app_content(), "idle must render no app content");
        assert!(session.is_idle());
        assert!(session.is_unlocked());
    }

    #[test]
    fn idle_reports_whether_biometrics_can_be_offered() {
        let drive = FakeDrive::new("AAA1");
        let (_mock, session) = unlocked_session(&drive);

        session.set_biometrics_available(true);
        assert!(matches!(
            session.begin_idle(),
            Status::Idle {
                biometrics_available: true,
                ..
            }
        ));

        session.resume_verified().unwrap();
        session.set_biometrics_available(false);
        assert!(matches!(
            session.begin_idle(),
            Status::Idle {
                biometrics_available: false,
                ..
            }
        ));
    }

    #[test]
    fn a_verified_user_resumes() {
        let drive = FakeDrive::new("AAA1");
        let (_mock, session) = unlocked_session(&drive);
        session.begin_idle();

        let status = session.resume_verified().unwrap();
        assert!(status.permits_app_content());
        assert!(!session.is_idle());
    }

    #[test]
    fn the_passphrase_resumes_without_any_biometrics() {
        let drive = FakeDrive::new("AAA1");
        let (_mock, session) = unlocked_session(&drive);
        session.set_biometrics_available(false);
        session.begin_idle();

        let status = session.resume_with_passphrase(PASS).unwrap();
        assert!(status.permits_app_content());
    }

    #[test]
    fn a_wrong_passphrase_leaves_the_session_idle() {
        let drive = FakeDrive::new("AAA1");
        let (_mock, session) = unlocked_session(&drive);
        session.begin_idle();

        assert!(matches!(
            session.resume_with_passphrase(OTHER_PASS),
            Err(SessionError::UnlockFailed)
        ));
        assert!(session.is_idle(), "a bad guess must not reopen the app");
        assert!(!session.status().permits_app_content());
    }

    #[test]
    fn resuming_is_throttled_like_unlocking() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = Session::with_config(
            Arc::clone(&mock),
            Arc::new(relay::mock::MockRelay::accepting()),
            SessionConfig {
                kdf_params: KdfParams::INSECURE_FOR_TESTS,
                throttle_base: Duration::from_secs(10),
                throttle_max: Duration::from_secs(30),
                machine_id: Some(THIS_MACHINE.to_string()),
            },
        );
        session.register("alice", PASS).unwrap();
        session.begin_idle();

        assert!(matches!(
            session.resume_with_passphrase(OTHER_PASS),
            Err(SessionError::UnlockFailed)
        ));
        assert!(matches!(
            session.resume_with_passphrase(PASS),
            Err(SessionError::Throttled { .. })
        ));
    }

    #[test]
    fn removing_the_drive_while_idle_wipes_the_key() {
        let drive = FakeDrive::new("AAA1");
        let (mock, session) = unlocked_session(&drive);
        session.begin_idle();

        mock.remove_all();
        let status = session.refresh();

        assert_eq!(status, Status::NoDevice);
        assert!(!session.is_unlocked(), "the key must be gone, not merely hidden");
        assert!(!session.is_idle());
        assert!(matches!(
            session.resume_verified(),
            Err(SessionError::NotIdle)
        ));
    }

    #[test]
    fn resuming_a_session_that_is_not_idle_is_refused() {
        let drive = FakeDrive::new("AAA1");
        let (_mock, session) = unlocked_session(&drive);

        assert!(matches!(
            session.resume_verified(),
            Err(SessionError::NotIdle)
        ));
        assert!(matches!(
            session.resume_with_passphrase(PASS),
            Err(SessionError::NotIdle)
        ));
    }

    #[test]
    fn going_idle_with_nothing_unlocked_does_nothing() {
        let mock = Arc::new(MockVolumeProvider::new());
        let session = session(&mock);
        assert_eq!(session.begin_idle(), Status::NoDevice);
        assert!(!session.is_idle());
    }

    #[test]
    fn locking_from_idle_wipes_the_key() {
        let drive = FakeDrive::new("AAA1");
        let (_mock, session) = unlocked_session(&drive);
        session.begin_idle();

        session.lock();
        assert!(!session.is_unlocked());
        assert!(!session.is_idle());
        assert!(matches!(session.status(), Status::Locked { .. }));
    }

    #[test]
    fn fingerprint_is_grouped_hex_of_the_public_key() {
        let key = [0xABu8; 32];
        let printed = fingerprint(&key);
        assert!(printed.starts_with("ABAB ABAB "));
        assert_eq!(printed.replace(' ', ""), to_hex(&key));
    }

    // --- Choosing between drives ------------------------------------------

    fn mount(drive: &FakeDrive) -> String {
        drive.path.display().to_string()
    }

    fn two_blank_drives() -> (FakeDrive, FakeDrive, Arc<MockVolumeProvider>) {
        let a = FakeDrive::new("AAA1");
        let b = FakeDrive::new("BBB2");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![a.volume(), b.volume()]));
        (a, b, mock)
    }

    #[test]
    fn the_picker_lists_every_plugged_in_drive() {
        let (a, b, mock) = two_blank_drives();
        let session = session(&mock);

        let drives = session.drives();
        assert_eq!(drives.len(), 2);
        assert!(drives.iter().all(|d| !d.has_identity));
        assert!(drives.iter().any(|d| d.mount_point == mount(&a)));
        assert!(drives.iter().any(|d| d.mount_point == mount(&b)));
        assert_eq!(drives.iter().filter(|d| d.current).count(), 1);
    }

    #[test]
    fn selecting_a_drive_sets_up_an_identity_on_that_drive() {
        let (a, b, mock) = two_blank_drives();
        let session = session(&mock);

        let status = session.select_drive(&mount(&b)).unwrap();
        assert!(
            matches!(&status, Status::Registrable { mount_point, .. } if *mount_point == mount(&b)),
            "got {status:?}"
        );

        session.register("alice", PASS).unwrap();
        assert!(b.volume().has_identity());
        assert!(!a.volume().has_identity(), "the other drive must be untouched");
    }

    #[test]
    fn two_users_can_take_turns_on_two_drives() {
        let (a, b, mock) = two_blank_drives();
        let session = session(&mock);

        session.select_drive(&mount(&a)).unwrap();
        session.register("alice", PASS).unwrap();

        let status = session.select_drive(&mount(&b)).unwrap();
        assert!(matches!(status, Status::Registrable { .. }), "got {status:?}");
        let status = session.register("bob", PASS).unwrap();
        assert!(matches!(&status, Status::Unlocked { username, .. } if username == "bob"));

        let status = session.select_drive(&mount(&a)).unwrap();
        assert!(matches!(status, Status::Locked { .. }), "got {status:?}");
        let status = session.unlock(PASS).unwrap();
        assert!(matches!(&status, Status::Unlocked { username, .. } if username == "alice"));
    }

    #[test]
    fn switching_drives_locks_the_current_session() {
        let (a, b, mock) = two_blank_drives();
        let session = session(&mock);
        session.select_drive(&mount(&a)).unwrap();
        session.register("alice", PASS).unwrap();
        assert!(session.is_unlocked());
        assert!(session.public_key().is_some());

        session.select_drive(&mount(&b)).unwrap();

        assert!(!session.is_unlocked());
        assert!(session.public_key().is_none(), "the key must be wiped");
        assert!(session.with_identity(|_| ()).is_none());
    }

    #[test]
    fn an_unknown_drive_is_refused_and_changes_nothing() {
        let (a, _b, mock) = two_blank_drives();
        let session = session(&mock);
        session.select_drive(&mount(&a)).unwrap();
        session.register("alice", PASS).unwrap();

        assert!(matches!(
            session.select_drive("Z:\\not-a-drive"),
            Err(SessionError::UnknownDrive)
        ));
        assert!(session.is_unlocked());
    }

    #[test]
    fn a_selected_drive_that_is_pulled_falls_back_to_the_others() {
        let (a, b, mock) = two_blank_drives();
        let session = session(&mock);
        session.select_drive(&mount(&b)).unwrap();

        mock.set_volumes(vec![a.volume()]);
        let status = session.refresh();

        assert!(
            matches!(&status, Status::Registrable { mount_point, .. } if *mount_point == mount(&a)),
            "got {status:?}"
        );
    }

    #[test]
    fn selecting_a_drive_with_a_copied_identity_is_still_denied() {
        let original = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![original.volume()]));
        let session = session(&mock);
        session.register("alice", PASS).unwrap();

        let thief = FakeDrive::new("BBB2");
        thief.volume().write_identity(&original.identity_bytes()).unwrap();
        mock.set_volumes(vec![original.volume(), thief.volume()]);

        let status = session.select_drive(&mount(&thief)).unwrap();

        assert!(matches!(status, Status::Denied { .. }), "got {status:?}");
        assert!(!session.is_unlocked());
        assert!(matches!(session.unlock(PASS), Err(SessionError::NotLocked)));
    }
}