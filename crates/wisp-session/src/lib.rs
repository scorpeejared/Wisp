//! The Wisp access gate.
//!
//! Everything the app can do is downstream of this type. [`Session`] owns the
//! only decrypted copy of the identity key in the process, and it is the only
//! thing that decides whether the UI may render anything beyond a gate screen.
//!
//! # The rules it enforces
//!
//! - No drive, or the wrong drive, means **no application state is reachable**
//!   — not a chat list, not a username, nothing but the gate screen.
//! - The device binding check runs **before** the passphrase prompt, so "wrong
//!   drive" and "wrong passphrase" are distinct outcomes for the user.
//! - Pulling the drive **zeroizes the key immediately** and drops the session
//!   back to the zero-access state.
//! - The passphrase is never retained. Unlocking keeps the *decrypted key* in
//!   protected memory for the session; the passphrase itself is dropped as soon
//!   as it has been used, so there is nothing to cache and nothing to leak.
//!
//! # Session caching
//!
//! Per the resolved design decision, a successful unlock lasts until the drive
//! is removed, the session is locked, or the app exits. The exposure window is
//! therefore bounded by physical possession of the drive, which is the property
//! the whole model is built on.

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

    #[error("this computer cannot be identified, so it cannot be bound to")]
    MachineUnidentifiable,

    #[error("trusted-computer binding is already in that state")]
    BindingUnchanged,

    /// Deliberately covers both a wrong passphrase and a damaged file. The
    /// wrong-*drive* case never reaches here — it is caught by the gate.
    #[error("could not unlock the identity")]
    UnlockFailed,

    #[error("too many failed attempts; wait {} seconds", .retry_after.as_secs().max(1))]
    Throttled { retry_after: Duration },

    #[error(transparent)]
    Identity(#[from] wisp_core::Error),

    #[error("invite code is not valid: {0}")]
    InviteMalformed(#[from] wisp_invite::InviteError),

    #[error("{0}")]
    Relay(#[from] RelayError),

    #[error("could not write the identity to the drive: {0}")]
    Io(#[from] std::io::Error),
}

/// A snapshot of the gate for the UI. Contains no secrets by construction.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum Status {
    /// Render the insert-USB screen and nothing else.
    NoDevice,

    /// A drive is present but unusable.
    #[serde(rename_all = "camelCase")]
    Unusable { mount_point: String, reason: String },

    /// A blank, bindable drive: offer registration.
    #[serde(rename_all = "camelCase")]
    Registrable {
        mount_point: String,
        label: Option<String>,
        /// `false` when the drive reports no device serial, so the binding
        /// would rest on a volume serial that a reformat destroys.
        strong_binding: bool,
    },

    /// Wrong drive. No passphrase prompt.
    #[serde(rename_all = "camelCase")]
    Denied { mount_point: String },

    /// Right drive, wrong computer. No passphrase prompt.
    #[serde(rename_all = "camelCase")]
    DeniedComputer { mount_point: String },

    /// Right drive. Prompt for the passphrase.
    #[serde(rename_all = "camelCase")]
    Locked {
        mount_point: String,
        label: Option<String>,
    },

    /// Unlocked but idle: the screen is covered pending re-authentication.
    ///
    /// The key is **still in memory**. This is a screen lock, not the USB gate
    /// — it stops someone walking up to an unattended machine, and nothing
    /// more. Only `Locked`/`NoDevice` mean the key is actually gone.
    #[serde(rename_all = "camelCase")]
    Idle {
        username: String,
        /// Whether to offer a biometric prompt or go straight to the
        /// passphrase.
        biometrics_available: bool,
    },

    /// Unlocked. The only status under which app content may render.
    #[serde(rename_all = "camelCase")]
    Unlocked {
        username: String,
        /// Uppercase hex of the public identity key.
        public_key: String,
        /// The same key grouped for reading aloud or comparing by eye.
        fingerprint: String,
        mount_point: String,
        /// Whether this identity is restricted to this computer.
        trusted_computer: bool,
        /// Whether this computer can be bound to at all.
        can_bind_computer: bool,
    },
}

impl Status {
    /// The single place that answers "may the app render anything real?".
    pub fn permits_app_content(&self) -> bool {
        matches!(self, Status::Unlocked { .. })
    }
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Argon2id cost for newly created identities. Existing files carry their
    /// own parameters and are unaffected.
    pub kdf_params: KdfParams,
    /// Base delay applied after a failed unlock, doubling each time.
    pub throttle_base: Duration,
    pub throttle_max: Duration,
    /// This computer's identity, for trusted-computer binding.
    ///
    /// Injected rather than read here so the gate can be tested against any
    /// machine, real or imagined.
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

/// Owns the gate state and the decrypted identity.
pub struct Session<P: VolumeProvider> {
    provider: Arc<P>,
    /// A trait object rather than a generic, so adding the relay did not force
    /// a second type parameter through every use site.
    relay: Arc<dyn RelayClient>,
    config: SessionConfig,
    inner: Mutex<Inner>,
}

struct Inner {
    gate: Gate,
    /// The only decrypted identity in the process.
    identity: Option<UnlockedIdentity>,
    /// The exact volume the unlock was performed against, compared in full on
    /// every refresh so that swapping drives cannot go unnoticed.
    bound: Option<RemovableVolume>,
    /// Screen covered, key retained. See [`Status::Idle`].
    idle: bool,
    /// Set by the app layer, which is the part that knows about hardware.
    /// Re-checked rather than assumed constant: enrolment can be removed while
    /// the app runs.
    biometrics_available: bool,
    /// Copied from config so status snapshots can be built without it.
    machine_id: Option<String>,
    failed_attempts: u32,
    last_failure: Option<Instant>,
}

impl Inner {
    /// Wipes the key and returns to the zero-access state.
    fn wipe(&mut self) {
        if let Some(identity) = &mut self.identity {
            // Explicit wipe before the drop, so the zeroization happens here
            // rather than whenever the allocator gets around to it.
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
            }),
        };
        session.refresh();
        session
    }

    /// Re-reads the hardware and reconciles the session against it.
    ///
    /// Safe and cheap to call often — this is what the USB watcher drives.
    pub fn refresh(&self) -> Status {
        // An enumeration failure means "no information", never "the drive was
        // removed". Treating a transient API error as a removal would lock the
        // user out at random, so the previous state is kept.
        let Ok(volumes) = self.provider.list_removable() else {
            return self.status();
        };

        let mut inner = self.inner.lock().unwrap();

        if let Some(bound) = inner.bound.clone() {
            // Full equality, so a different stick occupying the same drive
            // letter counts as a removal.
            let still_present = volumes
                .iter()
                .any(|volume| *volume == bound && volume.has_identity());
            if still_present {
                return status_of(&inner);
            }
            inner.wipe();
        }

        inner.gate = gate::evaluate(&volumes, self.config.machine_id.as_deref());
        status_of(&inner)
    }

    pub fn status(&self) -> Status {
        status_of(&self.inner.lock().unwrap())
    }

    pub fn is_unlocked(&self) -> bool {
        self.inner.lock().unwrap().identity.is_some()
    }

    /// Attempts to decrypt the identity on the currently-inserted drive.
    ///
    /// Only valid from [`Status::Locked`]. Calling it in any other state is a
    /// programming error, not an authentication failure, and is reported as
    /// such rather than being silently treated as a bad passphrase.
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

    /// Redeems an invite code, creates an identity on the blank drive, and
    /// unlocks it.
    ///
    /// # Ordering
    ///
    /// The steps are sequenced so that the cheapest and most reversible checks
    /// happen first, and so that a failure never spends an invite code for
    /// nothing:
    ///
    /// 1. Validate the invite code's format **locally**. A typo is caught here
    ///    without a round trip, and without burning one of the relay's
    ///    rate-limited attempts.
    /// 2. Enforce the passphrase policy and the username rules — still nothing
    ///    written, nothing sent.
    /// 3. Generate the identity and seal it.
    /// 4. **Stage** the file to the drive. This proves the drive is writable
    ///    *before* the invite is spent. Discovering a full or write-protected
    ///    drive after redemption would consume a single-use code and leave the
    ///    user with no account and no way back.
    /// 5. Redeem the invite with the relay.
    /// 6. Commit the staged file.
    ///
    /// If step 5 fails, the staged file is discarded and the drive is left
    /// exactly as it was, so the user can retry with the same code.
    pub fn register(
        &self,
        invite_code: &str,
        username: &str,
        passphrase: &str,
    ) -> Result<Status, SessionError> {
        let mut inner = self.inner.lock().unwrap();

        let Gate::Registrable { volume, .. } = inner.gate.clone() else {
            return Err(SessionError::NotRegistrable);
        };

        // 1. Local format check, before any network call.
        let invite = wisp_invite::InviteCode::parse(invite_code)?;

        // 2. Normalise before generating, so the canonical form is what gets
        //    sealed into the file, signed, and sent — all three must agree.
        let username = wisp_core::identity::normalise_username(username);
        wisp_core::identity::check_username(&username)?;
        wisp_core::passphrase::enforce(passphrase).map_err(wisp_core::Error::WeakPassphrase)?;

        // 3. Generate and seal.
        let identity = UnlockedIdentity::generate(&username)?;
        // New identities are never machine-bound: it is an opt-in the user
        // turns on afterwards, from Settings, with a warning.
        let file = IdentityFile::create(
            &identity,
            passphrase,
            &volume.identifiers,
            None,
            self.config.kdf_params,
        )?;

        // 4. Prove the drive is writable before spending the code.
        volume.stage_identity(&file.encode())?;

        // 5. Redeem.
        let public_key = identity.public_key()?;
        let username_hash = wisp_core::protocol::username_hash(&username);
        let signature = identity.sign(&wisp_core::protocol::registration_challenge(
            &invite.redemption_hash().0,
            &public_key,
            &username_hash,
        ))?;

        if let Err(e) = self.relay.register(&RegistrationRequest {
            invite_code: invite.to_string(),
            username: username.clone(),
            public_key,
            signature,
        }) {
            volume.discard_staged_identity();
            return Err(e.into());
        }

        // 6. Commit.
        volume.commit_identity()?;

        // The user has just proved the passphrase by choosing it; making them
        // retype it immediately would be friction with no security value.
        inner.gate = Gate::Locked {
            volume: volume.clone(),
            file: Box::new(file),
        };
        inner.identity = Some(identity);
        inner.bound = Some(volume);
        Ok(status_of(&inner))
    }

    /// Tells the session whether biometrics can be offered.
    ///
    /// Lives here rather than in config because hardware state changes while
    /// the app runs — a reader can be disabled, or enrolment removed.
    pub fn set_biometrics_available(&self, available: bool) {
        self.inner.lock().unwrap().biometrics_available = available;
    }

    /// Covers the screen without wiping the key.
    ///
    /// **This is a screen lock, not the USB gate.** The identity key stays in
    /// protected memory so that a biometric prompt — which yields no key
    /// material and could not decrypt anything — is enough to come back. It
    /// stops a passer-by at an unattended machine; it does not stop code
    /// already running on it. Use [`Session::lock`] for that.
    ///
    /// A no-op when nothing is unlocked.
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

    /// Resumes after the caller has verified the user by other means.
    ///
    /// The verification itself is the caller's job — this only records that it
    /// happened. It is deliberately **not** a Tauri command: the biometric
    /// prompt runs in Rust and calls this only on success, so a compromised
    /// renderer cannot resume by asking nicely.
    pub fn resume_verified(&self) -> Result<Status, SessionError> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.idle || inner.identity.is_none() {
            return Err(SessionError::NotIdle);
        }
        inner.idle = false;
        Ok(status_of(&inner))
    }

    /// Resumes by re-entering the passphrase.
    ///
    /// Always available, whether or not biometrics exist — biometrics are a
    /// shortcut, never the only way back. Throttled on the same counter as the
    /// initial unlock, so idle is not a cheaper place to guess.
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

    /// Whether this identity is currently restricted to one computer.
    pub fn is_trusted_computer_bound(&self) -> bool {
        matches!(
            &self.inner.lock().unwrap().gate,
            Gate::Locked { file, .. } if file.machine_binding
        )
    }

    /// Turns trusted-computer binding on or off.
    ///
    /// Requires the passphrase in both directions, and not as a policy check:
    /// changing the setting means decrypting the identity and re-encrypting it
    /// under a different key schedule, which is impossible without it.
    ///
    /// The new file is staged and committed like registration, so a drive
    /// pulled mid-write leaves the old identity intact rather than a truncated
    /// one. Losing an identity to a settings toggle would be unforgivable.
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

        // What the file is bound to now, and what it should be bound to after.
        let current = file.machine_binding.then_some(machine_id).flatten();
        let next = enabled.then_some(machine_id).flatten();

        let rebound = file.rebind(passphrase, &volume.identifiers, current, next)?;
        volume.stage_identity(&rebound.encode())?;
        volume.commit_identity()?;

        // The session stays open: the user proved the passphrase, and making
        // them unlock again would be friction with no security value.
        inner.gate = Gate::Locked {
            volume,
            file: Box::new(rebound),
        };
        Ok(status_of(&inner))
    }

    /// Locks the session, wiping the key but leaving the drive alone.
    pub fn lock(&self) -> Status {
        let mut inner = self.inner.lock().unwrap();
        inner.wipe();
        drop(inner);
        self.refresh()
    }

    /// Scoped access to the unlocked identity.
    ///
    /// The closure runs while the session lock is held, so the identity cannot
    /// outlive the unlocked state by accident. A caller that copies key
    /// material out is responsible for wiping it — the messaging layer needs
    /// exactly one such copy to build its own store, and zeroizes it after.
    ///
    /// Returns `None` when locked, which is the only correct answer then.
    pub fn with_identity<T>(&self, f: impl FnOnce(&UnlockedIdentity) -> T) -> Option<T> {
        self.inner.lock().unwrap().identity.as_ref().map(f)
    }

    /// The public identity key, when unlocked.
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
                // Read from the file itself rather than tracked separately, so
                // the switch in Settings can never disagree with what is
                // actually sealed on the drive.
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

fn display(path: &std::path::Path) -> String {
    path.display().to_string()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// The public key in readable groups, for comparing identities out of band.
///
/// Desktop has no camera for QR scanning, so this is what one user reads to
/// another to confirm they are talking to who they think.
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
    /// Pinned so tests never depend on whichever machine runs them.
    const THIS_MACHINE: &str = "2a48fb29-1111-2222-3333-444455556666";
    const OTHER_MACHINE: &str = "9f86d081-884c-4d65-9a2d-1f7a2b3c4d5e";
    const OTHER_PASS: &str = "Zx9!qWeRtY&asdfGH42";

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// A temp directory standing in for a mounted drive.
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

        /// Same physical path, but the platform now reports a different device.
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

    fn invite() -> String {
        wisp_invite::InviteCode::generate().to_string()
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
                // Throttling has its own dedicated test; it must not slow
                // down the others.
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

        let status = session.register(&invite(), "alice", PASS).unwrap();
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

        assert!(session.register(&invite(), "alice", "short").is_err());
        assert!(
            !drive.volume().has_identity(),
            "a rejected passphrase must leave the drive untouched"
        );
    }

    /// A typo must not cost a round trip, and must not burn one of the relay's
    /// rate-limited redemption attempts.
    #[test]
    fn a_malformed_invite_code_never_reaches_the_relay() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let relay = Arc::new(relay::mock::MockRelay::accepting());
        let session = session_with_relay(&mock, relay.clone());

        assert!(matches!(
            session.register("WISP-NOT-A-REAL-CODE", "alice", PASS),
            Err(SessionError::InviteMalformed(_))
        ));
        assert!(relay.requests().is_empty(), "a typo reached the relay");
        assert!(!drive.volume().has_identity());
    }

    /// The drive is proven writable before the code is spent, and a rejection
    /// must leave nothing behind.
    #[test]
    fn a_rejected_registration_leaves_the_drive_exactly_as_it_was() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let relay = Arc::new(relay::mock::MockRelay::failing(RelayError::rejected(
            "that invite code is not valid",
        )));
        let session = session_with_relay(&mock, relay);

        assert!(matches!(
            session.register(&invite(), "alice", PASS),
            Err(SessionError::Relay(_))
        ));
        assert!(!drive.volume().has_identity());
        assert!(!session.is_unlocked());
        // The staging file must be cleaned up too, not merely left unreferenced.
        assert!(!drive.path.join(".wisp").join("identity.wisp.tmp").exists());
    }

    /// An unreachable relay almost certainly has not spent the code, so the
    /// same code must still work on a retry.
    #[test]
    fn an_unreachable_relay_allows_a_retry_with_the_same_code() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let relay = Arc::new(relay::mock::MockRelay::failing(RelayError::unreachable(
            "connection refused",
        )));
        let session = session_with_relay(&mock, relay.clone());

        let code = invite();
        let failure = session.register(&code, "alice", PASS).unwrap_err();
        let SessionError::Relay(e) = &failure else {
            panic!("expected a relay error, got {failure:?}");
        };
        assert!(e.is_unreachable());
        assert!(!drive.volume().has_identity());

        // The relay comes back; the same code succeeds.
        relay.set_response(None);
        session.refresh();
        session.register(&code, "alice", PASS).unwrap();
        assert!(drive.volume().has_identity());
        assert!(session.is_unlocked());
    }

    #[test]
    fn the_relay_receives_a_canonical_username_and_a_verifiable_signature() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let relay = Arc::new(relay::mock::MockRelay::accepting());
        let session = session_with_relay(&mock, relay.clone());

        let code = invite();
        session.register(&code, "  Alice  ", PASS).unwrap();

        let requests = relay.requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];

        assert_eq!(request.username, "alice", "username must be canonical");
        assert_eq!(request.public_key, session.public_key().unwrap());

        // The signature must verify against exactly what the relay will rebuild.
        let invite_code = wisp_invite::InviteCode::parse(&request.invite_code).unwrap();
        let message = wisp_core::protocol::registration_challenge(
            &invite_code.redemption_hash().0,
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

        assert!(session.register(&invite(), "no", PASS).is_err());
        assert!(relay.requests().is_empty());
        assert!(!drive.volume().has_identity());
    }

    #[test]
    fn removing_the_drive_wipes_the_key_and_locks_out() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);
        session.register(&invite(), "alice", PASS).unwrap();
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
        session.register(&invite(), "alice", PASS).unwrap();

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
        session.register(&invite(), "alice", PASS).unwrap();
        session.lock();

        assert!(matches!(
            session.unlock(OTHER_PASS),
            Err(SessionError::UnlockFailed)
        ));
        assert!(!session.is_unlocked());
        assert!(matches!(session.status(), Status::Locked { .. }));
    }

    /// The headline behaviour: a copied identity file on a different drive is
    /// denied outright, before any passphrase is requested.
    #[test]
    fn copied_identity_on_another_drive_is_denied_before_any_prompt() {
        let original = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![original.volume()]));
        let session = session(&mock);
        session.register(&invite(), "alice", PASS).unwrap();

        // Copy the file to a second stick, exactly as a file-sync or a casual
        // copy would.
        let thief = FakeDrive::new("BBB2");
        thief.volume().write_identity(&original.identity_bytes()).unwrap();

        mock.set_volumes(vec![thief.volume()]);
        let status = session.refresh();

        assert!(
            matches!(status, Status::Denied { .. }),
            "expected denial, got {status:?}"
        );
        assert!(!session.is_unlocked());

        // And the correct passphrase gets no further, because the gate never
        // offers a prompt in this state.
        assert!(matches!(
            session.unlock(PASS),
            Err(SessionError::NotLocked)
        ));
    }

    /// Even bypassing the gate entirely, the crypto still requires the drive.
    #[test]
    fn copied_identity_cannot_be_decrypted_even_bypassing_the_gate() {
        let original = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![original.volume()]));
        session(&mock).register(&invite(), "alice", PASS).unwrap();

        let thief = FakeDrive::new("BBB2");
        let file = IdentityFile::decode(&original.identity_bytes()).unwrap();

        assert!(file
            .unlock(PASS, &thief.volume().identifiers, Some(THIS_MACHINE))
            .is_err());
    }

    /// Drive letters get recycled. Swapping sticks under an unlocked session
    /// must lock it, not go unnoticed.
    #[test]
    fn swapping_drives_mid_session_locks_immediately() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);
        session.register(&invite(), "alice", PASS).unwrap();
        assert!(session.is_unlocked());

        // Same mount point, different physical device.
        mock.set_volumes(vec![drive.volume_with_serial("CCC3")]);
        session.refresh();

        assert!(!session.is_unlocked(), "a swapped drive must lock the session");
    }

    /// Deleting the identity file out from under an unlocked session also
    /// counts as losing the drive.
    #[test]
    fn deleting_the_identity_file_locks_the_session() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);
        session.register(&invite(), "alice", PASS).unwrap();

        std::fs::remove_file(drive.volume().identity_path()).unwrap();
        session.refresh();

        assert!(!session.is_unlocked());
    }

    /// A transient enumeration error must not be mistaken for removal.
    #[test]
    fn enumeration_failure_does_not_lock_the_session() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);
        session.register(&invite(), "alice", PASS).unwrap();

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

    /// A matching drive wins even when a mismatched one is also plugged in.
    #[test]
    fn the_correct_drive_wins_over_a_mismatched_one() {
        let original = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![original.volume()]));
        let session = session(&mock);
        session.register(&invite(), "alice", PASS).unwrap();

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
        session.register(&invite(), "alice", PASS).unwrap();
        session.lock();

        assert!(matches!(
            session.unlock(OTHER_PASS),
            Err(SessionError::UnlockFailed)
        ));
        // The next attempt is refused without even trying the passphrase.
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
        let status = session.register(&invite(), "alice", PASS).unwrap();

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

    /// New identities are unbound; it is opt-in.
    #[test]
    fn a_new_identity_is_not_machine_bound() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);
        let status = session.register(&invite(), "alice", PASS).unwrap();

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
        session.register(&invite(), "alice", PASS).unwrap();

        let status = session.set_trusted_computer(true, PASS).unwrap();
        assert!(matches!(
            status,
            Status::Unlocked {
                trusted_computer: true,
                ..
            }
        ));
        assert!(session.is_trusted_computer_bound());
        // The session stays open — the user just proved the passphrase.
        assert!(session.is_unlocked());
    }

    /// Changing the setting requires the passphrase, in both directions.
    #[test]
    fn changing_the_setting_needs_the_passphrase() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session(&mock);
        session.register(&invite(), "alice", PASS).unwrap();

        assert!(session.set_trusted_computer(true, OTHER_PASS).is_err());
        assert!(!session.is_trusted_computer_bound());

        session.set_trusted_computer(true, PASS).unwrap();
        assert!(session.set_trusted_computer(false, OTHER_PASS).is_err());
        assert!(session.is_trusted_computer_bound());
    }

    /// The headline case: the drive works, the computer does not.
    #[test]
    fn a_bound_identity_is_denied_on_another_computer() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));

        let session = session_on_machine(&mock, Some(THIS_MACHINE));
        session.register(&invite(), "alice", PASS).unwrap();
        session.set_trusted_computer(true, PASS).unwrap();

        // Same drive, different computer.
        let elsewhere = session_on_machine(&mock, Some(OTHER_MACHINE));
        let status = elsewhere.status();

        assert!(
            matches!(status, Status::DeniedComputer { .. }),
            "expected a computer denial, got {status:?}"
        );
        assert!(!status.permits_app_content());
        // No passphrase prompt is offered at all.
        assert!(matches!(
            elsewhere.unlock(PASS),
            Err(SessionError::NotLocked)
        ));
    }

    /// A computer that cannot identify itself is refused too.
    #[test]
    fn a_bound_identity_is_denied_on_an_unidentifiable_computer() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));

        let session = session_on_machine(&mock, Some(THIS_MACHINE));
        session.register(&invite(), "alice", PASS).unwrap();
        session.set_trusted_computer(true, PASS).unwrap();

        let nameless = session_on_machine(&mock, None);
        assert!(matches!(nameless.status(), Status::DeniedComputer { .. }));
    }

    /// Disabling restores portability.
    #[test]
    fn disabling_restores_use_on_other_computers() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));

        let session = session_on_machine(&mock, Some(THIS_MACHINE));
        session.register(&invite(), "alice", PASS).unwrap();
        session.set_trusted_computer(true, PASS).unwrap();
        session.set_trusted_computer(false, PASS).unwrap();

        let elsewhere = session_on_machine(&mock, Some(OTHER_MACHINE));
        assert!(matches!(elsewhere.status(), Status::Locked { .. }));
        assert!(elsewhere.unlock(PASS).is_ok());
    }

    /// The change must reach the drive, not just this session's memory.
    #[test]
    fn the_setting_is_written_to_the_drive() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));

        let session = session_on_machine(&mock, Some(THIS_MACHINE));
        session.register(&invite(), "alice", PASS).unwrap();
        session.set_trusted_computer(true, PASS).unwrap();

        let file = IdentityFile::decode(&drive.identity_bytes()).unwrap();
        assert!(file.machine_binding, "the drive still holds an unbound identity");
    }

    #[test]
    fn a_computer_that_cannot_be_identified_cannot_be_bound_to() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session_on_machine(&mock, None);

        let status = session.register(&invite(), "alice", PASS).unwrap();
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
        session.register(&invite(), "alice", PASS).unwrap();

        assert!(matches!(
            session.set_trusted_computer(false, PASS),
            Err(SessionError::BindingUnchanged)
        ));
    }

    /// Unlocking normally must keep working once bound.
    #[test]
    fn a_bound_identity_still_unlocks_on_its_own_computer() {
        let drive = FakeDrive::new("AAA1");
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![drive.volume()]));
        let session = session_on_machine(&mock, Some(THIS_MACHINE));
        session.register(&invite(), "alice", PASS).unwrap();
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
        session.register(&invite(), "alice", PASS).unwrap();
        (mock, session)
    }

    /// Idle covers the screen; it does not wipe anything.
    #[test]
    fn going_idle_keeps_the_key_but_hides_the_app() {
        let drive = FakeDrive::new("AAA1");
        let (_mock, session) = unlocked_session(&drive);

        let status = session.begin_idle();
        assert!(matches!(status, Status::Idle { .. }));
        assert!(!status.permits_app_content(), "idle must render no app content");
        assert!(session.is_idle());
        // The key is still held — that is what makes a consent-only prompt
        // sufficient to come back.
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

    /// The passphrase always works, whether or not biometrics exist.
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

    /// Idle must not be a cheaper place to guess than the initial unlock.
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
        session.register(&invite(), "alice", PASS).unwrap();
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

    /// The drive is still the real gate: pulling it during idle wipes the key
    /// rather than leaving a session a fingerprint could reopen.
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

    /// An explicit lock during idle is a real lock.
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
}
