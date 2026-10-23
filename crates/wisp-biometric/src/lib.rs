//! Biometric re-authentication.
//!
//! # What this is for, precisely
//!
//! Biometrics in Wisp are a **faster way back into an already-unlocked
//! session**, and nothing else. They never substitute for the USB drive and
//! never substitute for the passphrase that decrypted the identity in the first
//! place. The drive must be physically present the entire time; pull it and the
//! key is wiped regardless of what any fingerprint reader says.
//!
//! # What it is not
//!
//! Windows Hello's `UserConsentVerifier` is a **consent check**, not a key
//! store. It answers "is the person at this machine the account owner?" and
//! returns nothing else — no key material, no signature, nothing that could
//! decrypt anything. So an idle lock backed by it is a *screen lock*: the
//! identity key stays in protected memory while the screen is covered, and a
//! successful Hello prompt uncovers it.
//!
//! That defends against someone walking up to an unattended machine. It does
//! **not** defend against code already running on that machine, which could
//! read the key out of memory whether the screen is covered or not. The idle
//! lock is not the USB gate: the USB gate wipes the key, this one only hides
//! it.
//!
//! A genuinely cryptographic version would use `KeyCredentialManager` to get a
//! TPM-backed key and wrap the identity key with it, so idle could wipe the
//! plaintext and Hello could restore it. That is a larger change than the spec
//! asked for, and is noted in the README as the upgrade path.

use serde::Serialize;

/// Whether biometric verification can be offered at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Availability {
    /// Hardware present, user enrolled, policy permits.
    Available,
    /// No fingerprint reader or IR camera.
    NoHardware,
    /// Hardware present but the user has not enrolled.
    NotEnrolled,
    /// Blocked by group policy.
    DisabledByPolicy,
    /// Temporarily in use by something else.
    Busy,
    /// This platform has no implementation.
    Unsupported,
}

impl Availability {
    pub fn is_available(self) -> bool {
        matches!(self, Availability::Available)
    }

    /// A short line the onboarding screen can show verbatim.
    pub fn describe(self) -> &'static str {
        match self {
            Availability::Available => "Windows Hello is available",
            Availability::NoHardware => "No biometric hardware detected",
            Availability::NotEnrolled => "Biometric hardware found, but nothing is enrolled",
            Availability::DisabledByPolicy => "Biometrics are disabled by policy",
            Availability::Busy => "Biometric hardware is busy",
            Availability::Unsupported => "Biometrics are not supported on this platform",
        }
    }
}

/// The outcome of asking the user to verify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "camelCase")]
pub enum Verification {
    Verified,
    /// The user dismissed the prompt. Not a failure — the passphrase is still
    /// there.
    Declined,
    /// Too many bad attempts; Windows will not ask again for a while.
    RetriesExhausted,
    Unavailable { reason: Availability },
    Failed { detail: String },
}

impl Verification {
    pub fn is_verified(&self) -> bool {
        matches!(self, Verification::Verified)
    }
}

/// An opaque handle to the window the prompt should attach to.
///
/// Desktop apps must anchor the Hello dialog to a window; the bare
/// `RequestVerificationAsync` is UWP-only and fails outside it. Carried as a
/// pointer-sized integer so this crate's signatures do not change shape per
/// platform.
#[derive(Debug, Clone, Copy)]
pub struct WindowHandle(pub isize);

/// Can biometrics be offered right now?
///
/// Re-checked on every call rather than cached: hardware can be disabled, or
/// enrolment removed, while the app is running.
pub fn availability() -> Availability {
    platform::availability()
}

/// Prompts the user to verify.
///
/// Blocks until they respond, so call it off the UI thread. `message` appears
/// in the system dialog and should say what is being unlocked.
pub fn verify(window: WindowHandle, message: &str) -> Verification {
    platform::verify(window, message)
}

#[cfg(windows)]
mod platform {
    use super::{Availability, Verification, WindowHandle};

    use windows::core::{factory, HSTRING};
    use windows::Foundation::IAsyncOperation;
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    };
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
    use windows::Win32::System::WinRT::IUserConsentVerifierInterop;

    /// WinRT calls need COM on the calling thread.
    ///
    /// Tauri's worker threads have not necessarily initialised it. A thread
    /// already in another apartment returns `RPC_E_CHANGED_MODE`, which is
    /// fine: COM is up, just not in the mode requested.
    fn ensure_com() {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        }
    }

    pub fn availability() -> Availability {
        ensure_com();

        match UserConsentVerifier::CheckAvailabilityAsync().and_then(|op| op.get()) {
            Ok(value) => match value {
                UserConsentVerifierAvailability::Available => Availability::Available,
                UserConsentVerifierAvailability::DeviceNotPresent => Availability::NoHardware,
                UserConsentVerifierAvailability::NotConfiguredForUser => Availability::NotEnrolled,
                UserConsentVerifierAvailability::DisabledByPolicy => Availability::DisabledByPolicy,
                UserConsentVerifierAvailability::DeviceBusy => Availability::Busy,
                // An unrecognised value is treated as unavailable rather than
                // optimistically assumed usable.
                _ => Availability::Unsupported,
            },
            // Windows editions without the Hello stack fail the call outright.
            Err(_) => Availability::Unsupported,
        }
    }

    pub fn verify(window: WindowHandle, message: &str) -> Verification {
        let available = availability();
        if !available.is_available() {
            return Verification::Unavailable { reason: available };
        }

        ensure_com();

        let interop = match factory::<UserConsentVerifier, IUserConsentVerifierInterop>() {
            Ok(interop) => interop,
            Err(e) => {
                return Verification::Failed {
                    detail: format!("Windows Hello is unavailable: {e}"),
                }
            }
        };

        let operation: windows::core::Result<IAsyncOperation<UserConsentVerificationResult>> = unsafe {
            interop.RequestVerificationForWindowAsync(
                HWND(window.0 as *mut _),
                &HSTRING::from(message),
            )
        };

        let result = match operation.and_then(|op| op.get()) {
            Ok(result) => result,
            Err(e) => {
                return Verification::Failed {
                    detail: format!("Windows Hello failed: {e}"),
                }
            }
        };

        match result {
            UserConsentVerificationResult::Verified => Verification::Verified,
            UserConsentVerificationResult::Canceled => Verification::Declined,
            UserConsentVerificationResult::RetriesExhausted => Verification::RetriesExhausted,
            UserConsentVerificationResult::DeviceNotPresent => Verification::Unavailable {
                reason: Availability::NoHardware,
            },
            UserConsentVerificationResult::NotConfiguredForUser => Verification::Unavailable {
                reason: Availability::NotEnrolled,
            },
            UserConsentVerificationResult::DisabledByPolicy => Verification::Unavailable {
                reason: Availability::DisabledByPolicy,
            },
            UserConsentVerificationResult::DeviceBusy => Verification::Unavailable {
                reason: Availability::Busy,
            },
            _ => Verification::Failed {
                detail: "Windows Hello returned an unrecognised result".into(),
            },
        }
    }
}

/// macOS Touch ID is deliberately not implemented.
///
/// `Unsupported` is the honest answer, and the app is required to degrade
/// silently where biometrics are absent — so this keeps the fallback path
/// exercised rather than leaving it a branch nobody runs. Implementing it needs
/// a `LocalAuthentication` bridge and a Mac to verify on.
#[cfg(not(windows))]
mod platform {
    use super::{Availability, Verification, WindowHandle};

    pub fn availability() -> Availability {
        Availability::Unsupported
    }

    pub fn verify(_window: WindowHandle, _message: &str) -> Verification {
        Verification::Unavailable {
            reason: Availability::Unsupported,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs against whatever this machine actually has, asserting only what
    /// holds either way.
    #[test]
    fn availability_is_answerable_on_this_machine() {
        let availability = availability();
        assert!(!availability.describe().is_empty());
        assert_eq!(
            availability.is_available(),
            matches!(availability, Availability::Available)
        );
    }

    #[test]
    fn every_availability_has_a_description() {
        for value in [
            Availability::Available,
            Availability::NoHardware,
            Availability::NotEnrolled,
            Availability::DisabledByPolicy,
            Availability::Busy,
            Availability::Unsupported,
        ] {
            assert!(!value.describe().is_empty(), "{value:?} has no description");
        }
    }

    #[test]
    fn only_available_counts_as_available() {
        assert!(Availability::Available.is_available());
        for value in [
            Availability::NoHardware,
            Availability::NotEnrolled,
            Availability::DisabledByPolicy,
            Availability::Busy,
            Availability::Unsupported,
        ] {
            assert!(!value.is_available(), "{value:?} must not count as available");
        }
    }

    /// A declined prompt is not a verified one — that difference decides
    /// whether the session reopens.
    #[test]
    fn only_verified_counts_as_verified() {
        assert!(Verification::Verified.is_verified());
        for outcome in [
            Verification::Declined,
            Verification::RetriesExhausted,
            Verification::Unavailable {
                reason: Availability::NoHardware,
            },
            Verification::Failed {
                detail: "boom".into(),
            },
        ] {
            assert!(!outcome.is_verified(), "{outcome:?} must not verify");
        }
    }

    #[test]
    fn outcomes_serialise_for_the_ui() {
        let json = serde_json::to_string(&Verification::Declined).unwrap();
        assert!(json.contains("declined"), "{json}");

        let json = serde_json::to_string(&Verification::Unavailable {
            reason: Availability::NotEnrolled,
        })
        .unwrap();
        assert!(json.contains("notEnrolled"), "{json}");
    }

    /// Verification without hardware must report unavailable rather than hang
    /// or panic. Skipped where Hello exists, because it would put a real dialog
    /// on screen mid-test-run.
    #[test]
    fn verification_without_hardware_reports_unavailable() {
        if availability().is_available() {
            eprintln!("skipped: this machine has Windows Hello, which would prompt");
            return;
        }
        assert!(matches!(
            verify(WindowHandle(0), "test"),
            Verification::Unavailable { .. }
        ));
    }
}
