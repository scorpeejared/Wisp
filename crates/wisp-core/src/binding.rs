//! USB device binding.
//!
//! **This is device binding, not hardware authentication.** USB identifiers can
//! be duplicated by cheap hardware, rewritten, or spoofed at the driver level,
//! and some drives report no serial at all. Nothing in this module should ever
//! be described to a user as proving a drive is genuine. What it does achieve
//! is closing the realistic attack path — a copied file, a synced folder, a
//! lost drive someone imaged — by making the identity useless without the
//! original device's descriptors.
//!
//! # Fingerprint profiles
//!
//! Identifiers differ in how stable they are. The device serial survives
//! reformatting; the filesystem volume serial does not. Mixing them would mean
//! a routine reformat permanently destroys the identity, so Wisp picks exactly
//! one profile at registration and records which one it used:
//!
//! - [`BindingStrength::Strong`] — device serial + vendor + product id. Stable
//!   across reformats and across machines.
//! - [`BindingStrength::Weak`] — vendor + product + *volume* serial, used only
//!   when the drive reports no device serial. Vendor and product alone are
//!   shared by every drive of the same model, so the volume serial is doing all
//!   the distinguishing work here, and reformatting the drive will break it.
//!
//! The UI is expected to warn on `Weak` at registration time and suggest a
//! different drive.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

pub const BINDING_SALT_LEN: usize = 32;
pub const BINDING_VALUE_LEN: usize = 32;

const DOMAIN: &[u8] = b"wisp.usb.binding.v1";
const MACHINE_DOMAIN: &[u8] = b"wisp.machine.binding.v1";
const COMBINED_DOMAIN: &[u8] = b"wisp.binding.combined.v1";

const TAG_DEVICE_SERIAL: u8 = 0x01;
const TAG_VOLUME_SERIAL: u8 = 0x04;
// 0x02/0x03 were vendor/product id. Deliberately never used in the
// fingerprint — see `canonical`. Left unallocated so a later format version
// cannot quietly reuse them and change existing fingerprints.

/// How much distinguishing power the fingerprint actually has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingStrength {
    /// No device serial was available; falls back to the volume serial, which
    /// a reformat will change.
    Weak = 0,
    /// Backed by a device serial that survives reformatting.
    Strong = 1,
}

impl BindingStrength {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Weak),
            1 => Some(Self::Strong),
            _ => None,
        }
    }
}

/// Raw identifiers as reported by the platform. Any field may be absent.
///
/// Only `device_serial` and `volume_serial` feed the fingerprint. The vendor
/// and product fields are carried for display and diagnostics only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceIdentifiers {
    /// Serial from the USB device descriptor / storage query. The strong one.
    pub device_serial: Option<String>,
    /// Filesystem volume serial. Changes on reformat.
    pub volume_serial: Option<String>,
    /// Human-readable vendor, e.g. "SanDisk". Diagnostics only.
    pub vendor: Option<String>,
    /// Human-readable product, e.g. "Cruzer Blade". Diagnostics only.
    pub product: Option<String>,
}

impl DeviceIdentifiers {
    /// Normalises a raw identifier string, or drops it if it carries no
    /// information.
    ///
    /// Platform APIs are inconsistent about case and padding for the same
    /// physical device, and some drives report placeholder serials. Both would
    /// otherwise produce an unstable or worthless fingerprint.
    fn normalise(value: &Option<String>) -> Option<String> {
        let raw = value.as_ref()?;
        let trimmed: String = raw
            .trim()
            .trim_matches(char::from(0))
            .trim()
            .to_ascii_uppercase();

        if trimmed.is_empty() {
            return None;
        }
        // A serial of all zeroes, all spaces, or a single repeated character is
        // a placeholder, not an identifier.
        let first = trimmed.as_bytes()[0];
        if trimmed.len() < 4 || trimmed.bytes().all(|b| b == first) {
            return None;
        }
        Some(trimmed)
    }

    /// Which profile these identifiers support, or an error if there is nothing
    /// usable to bind to at all.
    pub fn strength(&self) -> Result<BindingStrength> {
        if Self::normalise(&self.device_serial).is_some() {
            Ok(BindingStrength::Strong)
        } else if Self::normalise(&self.volume_serial).is_some() {
            Ok(BindingStrength::Weak)
        } else {
            Err(Error::NoDeviceIdentifiers)
        }
    }

    /// Deterministic byte encoding of the identifiers for a given profile.
    ///
    /// The field is tag- and length-prefixed so that two different sets of
    /// identifiers can never encode to the same bytes — without the tags,
    /// `device_serial="AB"` and `volume_serial="AB"` would collide.
    ///
    /// # Why only one field contributes
    ///
    /// A registered drive has to unlock on **any** authorised Windows or macOS
    /// machine, so every byte in here must be reported identically by both
    /// platforms. Vendor and product fail that test: Windows'
    /// `STORAGE_DEVICE_DESCRIPTOR` yields strings ("SanDisk", "Cruzer Blade")
    /// while IOKit yields numeric USB VID/PID. Folding either in would make a
    /// drive registered on one OS fail to unlock on the other — a permanent
    /// lockout, in exchange for collision resistance that only matters if two
    /// drives already share a serial. So they stay out, and the serial does all
    /// the work.
    fn canonical(&self, strength: BindingStrength) -> Result<Vec<u8>> {
        let (tag, value) = match strength {
            BindingStrength::Strong => (
                TAG_DEVICE_SERIAL,
                Self::normalise(&self.device_serial).ok_or(Error::NoDeviceIdentifiers)?,
            ),
            BindingStrength::Weak => (
                TAG_VOLUME_SERIAL,
                Self::normalise(&self.volume_serial).ok_or(Error::NoDeviceIdentifiers)?,
            ),
        };

        let mut out = Vec::with_capacity(DOMAIN.len() + 7 + value.len());
        out.extend_from_slice(DOMAIN);
        out.push(0x00);
        out.push(strength as u8);
        out.push(tag);
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value.as_bytes());
        Ok(out)
    }

    /// `SHA256` of the canonical encoding.
    ///
    /// This value is an input to the identity file's key schedule and is
    /// **never written to disk**. See [`crate::crypto`].
    pub fn fingerprint_hash(&self, strength: BindingStrength) -> Result<[u8; 32]> {
        let canonical = self.canonical(strength)?;
        let mut hasher = Sha256::new();
        hasher.update(&canonical);
        Ok(hasher.finalize().into())
    }

    /// The salted value stored in the identity file for the fast pre-check.
    ///
    /// Salted per identity so the same drive registered twice produces two
    /// unrelated values, and so a stored value cannot be matched against a
    /// precomputed table of serials.
    pub fn binding_value(
        &self,
        strength: BindingStrength,
        salt: &[u8; BINDING_SALT_LEN],
    ) -> Result<[u8; BINDING_VALUE_LEN]> {
        let canonical = self.canonical(strength)?;
        let mut mac =
            HmacSha256::new_from_slice(salt).expect("HMAC-SHA256 accepts keys of any length");
        mac.update(&canonical);
        Ok(mac.finalize().into_bytes().into())
    }

    /// Constant-time check of the currently-inserted device against a stored
    /// binding value.
    ///
    /// Compared in constant time so that a local attacker cannot learn the
    /// stored value byte-by-byte from timing. Returns `false` rather than an
    /// error when identifiers are missing: an unreadable drive is a
    /// non-matching drive.
    pub fn matches(
        &self,
        strength: BindingStrength,
        salt: &[u8; BINDING_SALT_LEN],
        expected: &[u8; BINDING_VALUE_LEN],
    ) -> bool {
        match self.binding_value(strength, salt) {
            Ok(actual) => actual.ct_eq(expected).into(),
            Err(_) => false,
        }
    }
}

// --- Trusted computer binding ----------------------------------------------

/// `SHA256` of a machine identifier.
///
/// Never written to the identity file. Like the USB fingerprint hash, this is
/// an input to the key schedule, which is what makes the binding
/// cryptographic rather than a comparison an attacker can patch out.
pub fn machine_fingerprint_hash(machine_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MACHINE_DOMAIN);
    hasher.update(b" ");
    hasher.update(machine_id.as_bytes());
    hasher.finalize().into()
}

/// The salted value stored in the identity file for the pre-passphrase check.
///
/// Salted per identity so the same computer bound twice produces two unrelated
/// values, and so a stored value cannot be matched against a precomputed table
/// of machine GUIDs.
pub fn machine_binding_value(machine_id: &str, salt: &[u8; BINDING_SALT_LEN]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(salt).expect("HMAC-SHA256 accepts any key length");
    mac.update(MACHINE_DOMAIN);
    mac.update(b" ");
    mac.update(machine_id.as_bytes());
    mac.finalize().into_bytes().into()
}

/// Constant-time check of this computer against a stored binding value.
///
/// `None` — a machine that reports no identity — never matches. Failing closed
/// matters here: a machine that cannot identify itself must not be able to open
/// an identity restricted to one that can.
pub fn machine_matches(
    machine_id: Option<&str>,
    salt: &[u8; BINDING_SALT_LEN],
    expected: &[u8; 32],
) -> bool {
    match machine_id {
        Some(id) => machine_binding_value(id, salt).ct_eq(expected).into(),
        None => false,
    }
}

/// Folds the USB and machine fingerprints into the single value the key
/// schedule uses.
///
/// With no machine binding this is the USB hash unchanged, so a format-1 file
/// and a format-2 file with the binding off derive identical keys — turning the
/// feature on and off must not silently change what a correct passphrase
/// unlocks.
pub fn combined_fingerprint_hash(
    usb_hash: &[u8; 32],
    machine_hash: Option<&[u8; 32]>,
) -> [u8; 32] {
    match machine_hash {
        None => *usb_hash,
        Some(machine) => {
            let mut hasher = Sha256::new();
            hasher.update(COMBINED_DOMAIN);
            hasher.update(usb_hash);
            hasher.update(machine);
            hasher.finalize().into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strong() -> DeviceIdentifiers {
        DeviceIdentifiers {
            device_serial: Some("AA04012700007652".into()),
            volume_serial: Some("1A2B-3C4D".into()),
            vendor: Some("SanDisk".into()),
            product: Some("Cruzer Blade".into()),
        }
    }

    #[test]
    fn serial_present_is_strong() {
        assert_eq!(strong().strength().unwrap(), BindingStrength::Strong);
    }

    #[test]
    fn no_serial_falls_back_to_weak() {
        let ids = DeviceIdentifiers {
            device_serial: None,
            volume_serial: Some("1A2B-3C4D".into()),
            ..strong()
        };
        assert_eq!(ids.strength().unwrap(), BindingStrength::Weak);
    }

    #[test]
    fn nothing_usable_is_an_error() {
        let ids = DeviceIdentifiers::default();
        assert!(matches!(ids.strength(), Err(Error::NoDeviceIdentifiers)));
    }

    #[test]
    fn placeholder_serials_are_rejected() {
        for placeholder in ["", "    ", "0000000000", "\0\0\0\0", "AAAAAAAA", "123"] {
            let ids = DeviceIdentifiers {
                device_serial: Some(placeholder.into()),
                volume_serial: None,
                ..Default::default()
            };
            assert!(
                ids.strength().is_err(),
                "{placeholder:?} should not count as an identifier"
            );
        }
    }

    #[test]
    fn identifiers_are_case_and_whitespace_insensitive() {
        let salt = [1u8; BINDING_SALT_LEN];
        let a = strong();
        let b = DeviceIdentifiers {
            device_serial: Some("  aa04012700007652\0 ".into()),
            ..strong()
        };
        assert_eq!(
            a.binding_value(BindingStrength::Strong, &salt).unwrap(),
            b.binding_value(BindingStrength::Strong, &salt).unwrap()
        );
    }

    /// A strong binding must survive a reformat, so the volume serial must not
    /// contribute to it.
    #[test]
    fn strong_binding_ignores_volume_serial() {
        let salt = [1u8; BINDING_SALT_LEN];
        let reformatted = DeviceIdentifiers {
            volume_serial: Some("FFFF-0000".into()),
            ..strong()
        };
        assert!(reformatted.matches(
            BindingStrength::Strong,
            &salt,
            &strong().binding_value(BindingStrength::Strong, &salt).unwrap()
        ));
    }

    #[test]
    fn different_device_does_not_match() {
        let salt = [1u8; BINDING_SALT_LEN];
        let expected = strong().binding_value(BindingStrength::Strong, &salt).unwrap();
        let other = DeviceIdentifiers {
            device_serial: Some("BB99999900001111".into()),
            ..strong()
        };
        assert!(!other.matches(BindingStrength::Strong, &salt, &expected));
    }

    /// Same physical drive, same profile, two registrations: the stored values
    /// must not be linkable.
    #[test]
    fn per_identity_salt_unlinks_the_same_drive() {
        let a = strong().binding_value(BindingStrength::Strong, &[1u8; 32]).unwrap();
        let b = strong().binding_value(BindingStrength::Strong, &[2u8; 32]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn tagging_prevents_field_confusion() {
        let salt = [1u8; BINDING_SALT_LEN];
        let as_serial = DeviceIdentifiers {
            device_serial: Some("SHAREDVALUE".into()),
            ..Default::default()
        };
        let as_volume = DeviceIdentifiers {
            volume_serial: Some("SHAREDVALUE".into()),
            ..Default::default()
        };
        assert_ne!(
            as_serial.binding_value(BindingStrength::Strong, &salt).unwrap(),
            as_volume.binding_value(BindingStrength::Weak, &salt).unwrap()
        );
    }

    #[test]
    fn fingerprint_hash_is_not_the_stored_binding_value() {
        let salt = [1u8; BINDING_SALT_LEN];
        let hash = strong().fingerprint_hash(BindingStrength::Strong).unwrap();
        let stored = strong().binding_value(BindingStrength::Strong, &salt).unwrap();
        assert_ne!(hash, stored);
    }

    /// The registered drive must unlock on any authorised machine, so the
    /// fingerprint may not depend on anything the two platforms report
    /// differently. Windows gives vendor/product as strings, macOS as numeric
    /// USB ids; neither may reach the fingerprint.
    #[test]
    fn fingerprint_is_stable_across_platforms() {
        let salt = [1u8; BINDING_SALT_LEN];
        let on_windows = strong();
        let on_macos = DeviceIdentifiers {
            vendor: Some("0x0781".into()),
            product: Some("0x5583".into()),
            ..strong()
        };
        assert!(on_macos.matches(
            BindingStrength::Strong,
            &salt,
            &on_windows
                .binding_value(BindingStrength::Strong, &salt)
                .unwrap()
        ));

        // Absent entirely, as when a platform reports no vendor string at all.
        let bare = DeviceIdentifiers {
            device_serial: strong().device_serial,
            ..Default::default()
        };
        assert!(bare.matches(
            BindingStrength::Strong,
            &salt,
            &on_windows
                .binding_value(BindingStrength::Strong, &salt)
                .unwrap()
        ));
    }

    // --- Trusted computer binding ------------------------------------------

    const MACHINE: &str = "2a48fb29-1111-2222-3333-444455556666";
    const OTHER_MACHINE: &str = "9f86d081-884c-4d65-9a2d-1f7a2b3c4d5e";

    #[test]
    fn the_right_computer_matches() {
        let salt = [3u8; BINDING_SALT_LEN];
        let stored = machine_binding_value(MACHINE, &salt);
        assert!(machine_matches(Some(MACHINE), &salt, &stored));
    }

    #[test]
    fn another_computer_does_not_match() {
        let salt = [3u8; BINDING_SALT_LEN];
        let stored = machine_binding_value(MACHINE, &salt);
        assert!(!machine_matches(Some(OTHER_MACHINE), &salt, &stored));
    }

    /// A machine that cannot identify itself must not open an identity
    /// restricted to one that can.
    #[test]
    fn an_unidentifiable_computer_never_matches() {
        let salt = [3u8; BINDING_SALT_LEN];
        let stored = machine_binding_value(MACHINE, &salt);
        assert!(!machine_matches(None, &salt, &stored));
    }

    #[test]
    fn machine_salt_unlinks_the_same_computer() {
        assert_ne!(
            machine_binding_value(MACHINE, &[1u8; 32]),
            machine_binding_value(MACHINE, &[2u8; 32])
        );
    }

    /// The stored value must not be the key-schedule input, or storing it would
    /// hand over the thing it is meant to protect.
    #[test]
    fn the_machine_hash_is_not_the_stored_value() {
        assert_ne!(
            machine_fingerprint_hash(MACHINE),
            machine_binding_value(MACHINE, &[1u8; 32])
        );
    }

    /// USB and machine bindings must not collide even given the same input.
    #[test]
    fn usb_and_machine_domains_are_separated() {
        let salt = [1u8; BINDING_SALT_LEN];
        let shared = DeviceIdentifiers {
            device_serial: Some(MACHINE.to_ascii_uppercase()),
            ..Default::default()
        };
        assert_ne!(
            shared.binding_value(BindingStrength::Strong, &salt).unwrap(),
            machine_binding_value(MACHINE, &salt)
        );
    }

    /// Turning the feature off must derive exactly the key a format-1 file
    /// derives, or existing identities would stop opening.
    #[test]
    fn no_machine_binding_leaves_the_usb_hash_untouched() {
        let usb = [7u8; 32];
        assert_eq!(combined_fingerprint_hash(&usb, None), usb);
    }

    #[test]
    fn adding_a_machine_changes_the_key_schedule_input() {
        let usb = [7u8; 32];
        let machine = machine_fingerprint_hash(MACHINE);
        let combined = combined_fingerprint_hash(&usb, Some(&machine));

        assert_ne!(combined, usb);
        assert_ne!(combined, machine);
        // And a different computer gives a different input, so the wrong
        // machine cannot derive the key even with the right passphrase.
        assert_ne!(
            combined,
            combined_fingerprint_hash(&usb, Some(&machine_fingerprint_hash(OTHER_MACHINE)))
        );
    }

    #[test]
    fn a_different_drive_changes_the_combined_input() {
        let machine = machine_fingerprint_hash(MACHINE);
        assert_ne!(
            combined_fingerprint_hash(&[7u8; 32], Some(&machine)),
            combined_fingerprint_hash(&[8u8; 32], Some(&machine))
        );
    }

    #[test]
    fn unreadable_device_never_matches() {
        assert!(!DeviceIdentifiers::default().matches(
            BindingStrength::Strong,
            &[1u8; 32],
            &[0u8; 32]
        ));
    }
}
