use serde::Serialize;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineIdentity {
    pub machine_id: Option<String>,
    pub description: Option<String>,
}

impl MachineIdentity {
    pub fn is_bindable(&self) -> bool {
        self.machine_id.is_some()
    }

    pub fn label(&self) -> String {
        self.description
            .clone()
            .unwrap_or_else(|| "this computer".to_string())
    }
}

pub fn identify() -> MachineIdentity {
    platform::identify()
}

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

    fn machine_guid() -> Option<String> {
        let subkey = to_wide(r"SOFTWARE\Microsoft\Cryptography");
        let value = to_wide("MachineGuid");

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

    #[test]
    fn this_machine_is_answerable() {
        let identity = identify();
        assert!(!identity.label().is_empty());

        if let Some(id) = &identity.machine_id {
            assert_eq!(normalise(id).as_deref(), Some(id.as_str()));
            assert!(identity.is_bindable());
        } else {
            assert!(!identity.is_bindable());
        }
    }

    #[test]
    fn reading_twice_gives_the_same_answer() {
        assert_eq!(identify().machine_id, identify().machine_id);
    }
}
