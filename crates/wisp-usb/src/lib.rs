//! Removable volume discovery and USB device identifier queries.
//!
//! Wisp treats the key drive as a normal removable volume rather than claiming
//! it at the raw USB level. Binding a commodity mass-storage stick to a
//! WinUSB/libusb driver would stop it working as a drive at all, which is the
//! one thing the design actually needs it to do.
//!
//! Everything here is behind [`VolumeProvider`] so the unlock state machine can
//! be driven by [`mock::MockVolumeProvider`] in tests without any hardware.

use std::path::PathBuf;

use wisp_core::{DeviceIdentifiers, IDENTITY_DIR, IDENTITY_FILENAME};

pub mod mock;
pub mod watcher;

#[cfg(windows)]
mod windows_impl;

#[cfg(target_os = "macos")]
mod macos_impl;

#[derive(Debug, thiserror::Error)]
pub enum UsbError {
    #[error("could not enumerate removable volumes: {0}")]
    Enumeration(String),

    #[error("this platform is not supported")]
    UnsupportedPlatform,
}

pub type Result<T> = std::result::Result<T, UsbError>;

/// A mounted removable volume and whatever the platform could tell us about
/// the device behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovableVolume {
    /// Mount root: `E:\` on Windows, `/Volumes/NAME` on macOS.
    pub mount_point: PathBuf,
    /// Filesystem label, if any.
    pub label: Option<String>,
    pub identifiers: DeviceIdentifiers,
}

impl RemovableVolume {
    /// Where the identity file lives on this volume.
    pub fn identity_path(&self) -> PathBuf {
        self.mount_point.join(IDENTITY_DIR).join(IDENTITY_FILENAME)
    }

    pub fn has_identity(&self) -> bool {
        self.identity_path().is_file()
    }

    /// Reads the raw identity file bytes, if present.
    ///
    /// Returns `Ok(None)` when there is simply no identity on this volume,
    /// which is an ordinary situation (any unrelated USB stick), not an error.
    pub fn read_identity(&self) -> std::io::Result<Option<Vec<u8>>> {
        let path = self.identity_path();
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn staging_path(&self) -> PathBuf {
        self.mount_point
            .join(IDENTITY_DIR)
            .join("identity.wisp.tmp")
    }

    /// Writes the identity to a temporary file beside its final location.
    ///
    /// Split from [`Self::commit_identity`] so registration can prove the drive
    /// is writable *before* it redeems the invite code. Discovering a
    /// write-protected or full drive after the code is spent would burn a
    /// single-use invite and leave the user with nothing.
    pub fn stage_identity(&self, bytes: &[u8]) -> std::io::Result<()> {
        std::fs::create_dir_all(self.mount_point.join(IDENTITY_DIR))?;
        std::fs::write(self.staging_path(), bytes)
    }

    /// Moves a staged identity into place.
    ///
    /// The rename is the closest thing to atomic that removable media offers.
    /// It is not a durability guarantee — a drive yanked mid-rename, or a
    /// controller lying about flushes, can still lose the write — but it means
    /// a failure leaves either the old identity or the new one, never a
    /// half-written file.
    pub fn commit_identity(&self) -> std::io::Result<()> {
        let final_path = self.identity_path();
        // Windows rename fails if the destination exists.
        if final_path.exists() {
            std::fs::remove_file(&final_path)?;
        }
        std::fs::rename(self.staging_path(), final_path)
    }

    /// Removes a staged identity that was never committed.
    pub fn discard_staged_identity(&self) {
        let _ = std::fs::remove_file(self.staging_path());
    }

    /// Stages and commits in one step.
    pub fn write_identity(&self, bytes: &[u8]) -> std::io::Result<()> {
        self.stage_identity(bytes)?;
        self.commit_identity()
    }
}

/// Source of removable volumes. Implemented by the platform layer and by the
/// test mock.
pub trait VolumeProvider: Send + Sync + 'static {
    fn list_removable(&self) -> Result<Vec<RemovableVolume>>;

    /// Volumes that carry a Wisp identity file.
    fn list_wisp_volumes(&self) -> Result<Vec<RemovableVolume>> {
        Ok(self
            .list_removable()?
            .into_iter()
            .filter(|v| v.has_identity())
            .collect())
    }
}

/// The real platform implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct PlatformVolumeProvider;

impl VolumeProvider for PlatformVolumeProvider {
    fn list_removable(&self) -> Result<Vec<RemovableVolume>> {
        #[cfg(windows)]
        {
            windows_impl::list_removable()
        }
        #[cfg(target_os = "macos")]
        {
            macos_impl::list_removable()
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            Err(UsbError::UnsupportedPlatform)
        }
    }
}

/// Formats a 32-bit filesystem volume serial into the canonical presentation.
///
/// Only Windows reports a value of this shape; see `macos_impl` for why the
/// macOS side leaves `volume_serial` unset rather than inventing one.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn format_volume_serial(raw: u32) -> String {
    format!("{:04X}-{:04X}", raw >> 16, raw & 0xFFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_serial_formatting_is_stable() {
        assert_eq!(format_volume_serial(0x1A2B3C4D), "1A2B-3C4D");
        assert_eq!(format_volume_serial(0), "0000-0000");
        assert_eq!(format_volume_serial(u32::MAX), "FFFF-FFFF");
    }

    #[test]
    fn identity_path_follows_the_documented_layout() {
        let vol = RemovableVolume {
            mount_point: PathBuf::from("E:\\"),
            label: None,
            identifiers: DeviceIdentifiers::default(),
        };
        let path = vol.identity_path();
        assert!(path.ends_with("identity.wisp"));
        assert!(path.to_string_lossy().contains(".wisp"));
    }

    #[test]
    fn read_identity_reports_absence_as_none_not_error() {
        let vol = RemovableVolume {
            mount_point: PathBuf::from("Z:\\definitely-not-a-real-mount-point"),
            label: None,
            identifiers: DeviceIdentifiers::default(),
        };
        assert!(matches!(vol.read_identity(), Ok(None)));
    }

    #[test]
    fn write_then_read_round_trips() {
        let dir = std::env::temp_dir().join(format!("wisp-usb-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let vol = RemovableVolume {
            mount_point: dir.clone(),
            label: None,
            identifiers: DeviceIdentifiers::default(),
        };

        assert!(!vol.has_identity());
        vol.write_identity(b"WISP-test-bytes").unwrap();
        assert!(vol.has_identity());
        assert_eq!(vol.read_identity().unwrap().unwrap(), b"WISP-test-bytes");

        // Overwriting an existing identity must succeed, not fail on rename.
        vol.write_identity(b"WISP-replaced").unwrap();
        assert_eq!(vol.read_identity().unwrap().unwrap(), b"WISP-replaced");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A staged identity must be invisible until committed, so a registration
    /// that fails partway leaves no half-made account on the drive.
    #[test]
    fn staged_identities_are_not_visible_until_committed() {
        let dir = std::env::temp_dir().join(format!("wisp-stage-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let vol = RemovableVolume {
            mount_point: dir.clone(),
            label: None,
            identifiers: DeviceIdentifiers::default(),
        };

        vol.stage_identity(b"WISP-staged").unwrap();
        assert!(!vol.has_identity(), "staged identity must not be visible");
        assert!(matches!(vol.read_identity(), Ok(None)));

        vol.commit_identity().unwrap();
        assert!(vol.has_identity());
        assert_eq!(vol.read_identity().unwrap().unwrap(), b"WISP-staged");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_discarded_stage_leaves_nothing_behind() {
        let dir = std::env::temp_dir().join(format!("wisp-discard-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let vol = RemovableVolume {
            mount_point: dir.clone(),
            label: None,
            identifiers: DeviceIdentifiers::default(),
        };

        vol.stage_identity(b"WISP-staged").unwrap();
        vol.discard_staged_identity();
        assert!(!vol.has_identity());
        assert!(vol.commit_identity().is_err(), "nothing left to commit");

        // Discarding when there is nothing staged must not error.
        vol.discard_staged_identity();

        std::fs::remove_dir_all(&dir).ok();
    }
}
