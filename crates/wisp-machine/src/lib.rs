//! Machine identity for the optional trusted-computer binding.
//!
//! Reads a stable per-installation identifier so an identity can be restricted
//! to one computer. This crate only *reads* it; the hashing and the key
//! schedule live in `wisp-core`, exactly as they do for USB identifiers — one
//! crate finds the bytes, another decides what they mean.
//!
//! # What identifier, and what breaks it
//!
//! On Windows this is `MachineGuid` from
//! `HKLM\SOFTWARE\Microsoft\Cryptography`. It is written once when Windows is
//! installed and does not change afterwards.
//!
//! - **Survives:** motherboard swaps, CPU/RAM/GPU changes, disk cloning to
//!   larger media, Windows updates and feature upgrades.
//! - **Breaks:** reinstalling Windows, resetting the PC, or moving to a
//!   different Windows installation.
//!
//! That is an *OS install* identity, not a hardware one. The honest consequence
//! is that someone who images the whole system disk and boots it elsewhere
//! carries `MachineGuid` with them, so trusted-computer binding does not stop
//! that. It stops the realistic case it was asked to stop: a stolen USB drive
//! plugged into someone else's machine, where the passphrase is still required
//! regardless.
//!
//! A hardware-level alternative (the SMBIOS system UUID) would survive an OS
//! reinstall but break on a motherboard swap, and would not travel with a disk
//! image. Neither is strictly better; `MachineGuid` was chosen because
//! reinstalling Windows is a deliberate act the user will remember, whereas
//! replacing a motherboard after a fault may not be. The binding is versioned so
//! a different source can be added later.

use serde::Serialize;

/// What this machine reports about itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineIdentity {
    /// The value the binding is derived from. `None` means this machine cannot
    /// be bound to at all.
    pub machine_id: Option<String>,
    /// Shown in settings so the user can tell which computer this is.
    pub description: Option<String>,
}

impl MachineIdentity {
    /// Whether trusted-computer binding can be offered here.
    pub fn is_bindable(&self) -> bool {
        self.machine_id.is_some()
    }

    /// A label for the settings screen.
    pub fn label(&self) -> String {
        self.description
            .clone()
            .unwrap_or_else(|| "this computer".to_string())
    }
}

/// Reads this machine's identity.
///
/// Cheap enough to call whenever a screen needs it, and re-read rather than
/// cached so a changed identifier is noticed rather than assumed.
pub fn identify() -> MachineIdentity {
    platform::identify()
}

/// Normalises a raw machine identifier, or discards it if it carries no
/// information.
///
/// Shared across platforms so the same value always hashes the same way,
/// whatever read it.
pub fn normalise(raw: &str) -> Option<String> {
    let trimmed = raw
        .trim()
        .trim_matches(char::from(0))
        .trim()
        .trim_matches(['{', '}'])
        .to_ascii_lowercase();

    if trimmed.len() < 8 {
        return None;
    }
    // An all-zero or single-character GUID is a placeholder, not an identity.
    let first = trimmed.as_bytes()[0];
    if trimmed
        .bytes()
        .all(|b| b == first || b == b'-')
    {
        return None;
    }
    Some(trimmed)
}

#[cfg(windows)]
mod platform {
    use super::{normalise, MachineIdentity};

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY,
    };
    use windows::Win32::System::SystemInformation::{
        GetComputerNameExW, ComputerNameDnsHostname,
    };

    pub fn identify() -> MachineIdentity {
        MachineIdentity {
            machine_id: machine_guid().as_deref().and_then(normalise),
            description: computer_name(),
        }
    }

    /// Reads `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`.
    ///
    /// Forced to the 64-bit view: a 32-bit build would otherwise be redirected
    /// to `Wow6432Node` and could read a different value than a 64-bit build on
    /// the same machine, which would silently break the binding on a rebuild.
    fn machine_guid() -> Option<String> {
        let subkey = to_wide(r"SOFTWARE\Microsoft\Cryptography");
        let value = to_wide("MachineGuid");

        // Ask for the size first; the value is a GUID string but querying
        // rather than assuming keeps this correct if that ever changes.
        let mut size: u32 = 0;
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey.as_ptr()),
                PCWSTR(value.as_ptr()),
                RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
                None,
                None,
                Some(&mut size),
            )
        };
        if status != ERROR_SUCCESS || size == 0 {
            return None;
        }

        let mut buffer = vec![0u16; (size as usize).div_ceil(2) + 1];
        let mut size_again = size;
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey.as_ptr()),
                PCWSTR(value.as_ptr()),
                RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
                None,
                Some(buffer.as_mut_ptr() as *mut _),
                Some(&mut size_again),
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }

        Some(from_wide(&buffer))
    }

    fn computer_name() -> Option<String> {
        let mut size: u32 = 0;
        // First call fails with the required size, which is expected.
        unsafe {
            let _ = GetComputerNameExW(
                ComputerNameDnsHostname,
                windows::core::PWSTR::null(),
                &mut size,
            );
        }
        if size == 0 {
            return None;
        }

        let mut buffer = vec![0u16; size as usize + 1];
        let ok = unsafe {
            GetComputerNameExW(
                ComputerNameDnsHostname,
                windows::core::PWSTR(buffer.as_mut_ptr()),
                &mut size,
            )
        };
        if ok.is_err() {
            return None;
        }

        let name = from_wide(&buffer);
        (!name.is_empty()).then_some(name)
    }

    fn to_wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn from_wide(buffer: &[u16]) -> String {
        let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        String::from_utf16_lossy(&buffer[..end]).trim().to_string()
    }
}

/// Non-Windows platforms report no machine identity.
///
/// Trusted-computer binding is simply not offered there, which is the honest
/// answer until a per-platform identifier is chosen and tested on real
/// hardware.
#[cfg(not(windows))]
mod platform {
    use super::MachineIdentity;

    pub fn identify() -> MachineIdentity {
        MachineIdentity::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalisation_strips_decoration_and_case() {
        assert_eq!(
            normalise("{A1B2C3D4-5678-90AB-CDEF-1234567890AB}").as_deref(),
            Some("a1b2c3d4-5678-90ab-cdef-1234567890ab")
        );
        assert_eq!(
            normalise("  a1b2c3d4-5678-90ab-cdef-1234567890ab \0 ").as_deref(),
            Some("a1b2c3d4-5678-90ab-cdef-1234567890ab")
        );
    }

    #[test]
    fn placeholders_are_rejected() {
        for placeholder in [
            "",
            "    ",
            "short",
            "00000000-0000-0000-0000-000000000000",
            "--------------------",
        ] {
            assert!(
                normalise(placeholder).is_none(),
                "{placeholder:?} should not count as a machine identity"
            );
        }
    }

    #[test]
    fn a_real_guid_survives_normalisation() {
        let guid = "9f86d081-884c-4d65-9a2d-1f7a2b3c4d5e";
        assert_eq!(normalise(guid).as_deref(), Some(guid));
    }

    /// Runs against this machine. Asserts only what holds either way, so it is
    /// not machine-dependent.
    #[test]
    fn this_machine_is_answerable() {
        let identity = identify();
        assert!(!identity.label().is_empty());

        if let Some(id) = &identity.machine_id {
            // Whatever came back must already be canonical, or the binding
            // would change between reads.
            assert_eq!(normalise(id).as_deref(), Some(id.as_str()));
            assert!(identity.is_bindable());
        } else {
            assert!(!identity.is_bindable());
        }
    }

    /// The identifier must be stable within a run, or the binding would break
    /// itself.
    #[test]
    fn reading_twice_gives_the_same_answer() {
        assert_eq!(identify().machine_id, identify().machine_id);
    }
}
