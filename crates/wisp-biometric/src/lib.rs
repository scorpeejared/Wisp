use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Availability {
    Available,
    NoHardware,
    NotEnrolled,
    DisabledByPolicy,
    Busy,
    Unsupported,
}

impl Availability {
    pub fn is_available(self) -> bool {
        matches!(self, Availability::Available)
    }

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "camelCase")]
pub enum Verification {
    Verified,
    Declined,
    RetriesExhausted,
    Unavailable { reason: Availability },
    Failed { detail: String },
}

impl Verification {
    pub fn is_verified(&self) -> bool {
        matches!(self, Verification::Verified)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WindowHandle(pub isize);

pub fn availability() -> Availability {
    platform::availability()
}

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
                _ => Availability::Unsupported,
            },
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
