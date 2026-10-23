//! A directory that pretends to be a removable drive.
//!
//! **Debug builds only.** The whole module is behind `debug_assertions`, so a
//! release build compiles none of it and there is no way to reach it in a
//! shipped binary. That matters: a way to fake the USB gate is precisely the
//! thing that must not exist in something a user runs.
//!
//! It exists because the unlocked screens — Messages, Identity, Settings — are
//! unreachable without a registered identity, which means unreachable without
//! spending a real invite code and writing to a real USB stick. Being unable to
//! look at them made UI changes unverifiable.
//!
//! ```text
//! WISP_FAKE_DRIVE=C:\tmp\fake-usb cargo run -p wisp-desktop
//! ```
//!
//! The directory is treated exactly as a mounted volume: the identity is
//! written to `<dir>/.wisp/identity.wisp` by the same code that writes to a
//! real one. Only the enumeration is faked, never the crypto or the binding.

use std::path::PathBuf;

use wisp_core::DeviceIdentifiers;
use wisp_usb::{PlatformVolumeProvider, RemovableVolume, Result, VolumeProvider};

/// Environment variable naming the directory to present as a drive.
pub const FAKE_DRIVE_VAR: &str = "WISP_FAKE_DRIVE";

/// The provider the app actually uses.
///
/// An enum rather than a trait object because [`wisp_session::Session`] and the
/// USB watcher are both generic over the provider, and one concrete type keeps
/// them agreeing without a second type parameter.
pub enum AppVolumeProvider {
    Platform(PlatformVolumeProvider),
    #[cfg(debug_assertions)]
    Fake { path: PathBuf },
}

impl AppVolumeProvider {
    /// Uses a fake drive when asked for one in a debug build; the real one
    /// otherwise.
    pub fn from_env() -> Self {
        #[cfg(debug_assertions)]
        if let Ok(path) = std::env::var(FAKE_DRIVE_VAR) {
            let path = PathBuf::from(path);
            eprintln!(
                "[wisp] DEBUG BUILD: presenting {} as a removable drive",
                path.display()
            );
            return Self::Fake { path };
        }
        Self::Platform(PlatformVolumeProvider)
    }
}

impl VolumeProvider for AppVolumeProvider {
    fn list_removable(&self) -> Result<Vec<RemovableVolume>> {
        match self {
            Self::Platform(provider) => provider.list_removable(),

            #[cfg(debug_assertions)]
            Self::Fake { path } => {
                // A directory that has gone away is a drive that has been
                // pulled, which makes lock-on-removal testable by deleting it.
                if !path.is_dir() {
                    return Ok(Vec::new());
                }

                let serial = fake_serial(path);

                Ok(vec![RemovableVolume {
                    label: Some("FAKE-DRIVE".to_string()),
                    mount_point: path.clone(),
                    identifiers: DeviceIdentifiers {
                        device_serial: Some(serial),
                        volume_serial: Some("0000-DEV0".to_string()),
                        vendor: Some("Wisp".to_string()),
                        product: Some("Development Drive".to_string()),
                    },
                }])
            }
        }
    }
}

/// Stable across the different spellings of the same directory.
///
/// Derived from the *canonical* path: `C:/x` and `C:\x` are the same folder
/// but different strings, and hashing the raw string made the app and the
/// seeding tool disagree about which drive this was.
fn fake_serial(path: &std::path::Path) -> String {
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    format!(
        "FAKE{:016X}",
        canonical
            .to_string_lossy()
            .to_lowercase()
            .bytes()
            .fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fake_drive_reports_a_bindable_volume() {
        let dir = std::env::temp_dir().join(format!("wisp-dev-drive-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let provider = AppVolumeProvider::Fake { path: dir.clone() };
        let volumes = provider.list_removable().unwrap();

        assert_eq!(volumes.len(), 1);
        assert!(
            volumes[0].identifiers.strength().is_ok(),
            "a fake drive must be bindable, or registration cannot be exercised"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Deleting the directory stands in for pulling the drive.
    #[test]
    fn a_missing_directory_reports_no_volumes() {
        let provider = AppVolumeProvider::Fake {
            path: PathBuf::from("Z:\\definitely-not-a-real-directory"),
        };
        assert!(provider.list_removable().unwrap().is_empty());
    }

    /// Two directories must not look like the same drive, or a copied identity
    /// would appear to be on its own stick.
    #[test]
    fn different_directories_are_different_drives() {
        let a = AppVolumeProvider::Fake {
            path: PathBuf::from("C:\\one"),
        };
        let b = AppVolumeProvider::Fake {
            path: PathBuf::from("C:\\two"),
        };
        // The serial is a pure function of the canonical path.
        let serial = |p: &AppVolumeProvider| match p {
            AppVolumeProvider::Fake { path } => fake_serial(path),
            _ => unreachable!(),
        };
        assert_ne!(serial(&a), serial(&b));
    }
}
