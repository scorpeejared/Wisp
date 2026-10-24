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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovableVolume {
    pub mount_point: PathBuf,
    pub label: Option<String>,
    pub identifiers: DeviceIdentifiers,
}

impl RemovableVolume {
    pub fn identity_path(&self) -> PathBuf {
        self.mount_point.join(IDENTITY_DIR).join(IDENTITY_FILENAME)
    }

    pub fn has_identity(&self) -> bool {
        self.identity_path().is_file()
    }

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

    pub fn stage_identity(&self, bytes: &[u8]) -> std::io::Result<()> {
        std::fs::create_dir_all(self.mount_point.join(IDENTITY_DIR))?;
        std::fs::write(self.staging_path(), bytes)
    }

    pub fn commit_identity(&self) -> std::io::Result<()> {
        let final_path = self.identity_path();
        if final_path.exists() {
            std::fs::remove_file(&final_path)?;
        }
        std::fs::rename(self.staging_path(), final_path)
    }

    pub fn discard_staged_identity(&self) {
        let _ = std::fs::remove_file(self.staging_path());
    }

    pub fn write_identity(&self, bytes: &[u8]) -> std::io::Result<()> {
        self.stage_identity(bytes)?;
        self.commit_identity()
    }
}

pub trait VolumeProvider: Send + Sync + 'static {
    fn list_removable(&self) -> Result<Vec<RemovableVolume>>;

    fn list_wisp_volumes(&self) -> Result<Vec<RemovableVolume>> {
        Ok(self
            .list_removable()?
            .into_iter()
            .filter(|v| v.has_identity())
            .collect())
    }
}

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

        vol.write_identity(b"WISP-replaced").unwrap();
        assert_eq!(vol.read_identity().unwrap().unwrap(), b"WISP-replaced");

        std::fs::remove_dir_all(&dir).ok();
    }

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

        vol.discard_staged_identity();

        std::fs::remove_dir_all(&dir).ok();
    }
}
