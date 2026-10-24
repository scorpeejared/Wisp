use std::path::PathBuf;

use wisp_core::DeviceIdentifiers;
use wisp_usb::{PlatformVolumeProvider, RemovableVolume, Result, VolumeProvider};

pub const FAKE_DRIVE_VAR: &str = "WISP_FAKE_DRIVE";

pub enum AppVolumeProvider {
    Platform(PlatformVolumeProvider),
    #[cfg(debug_assertions)]
    Fake { paths: Vec<PathBuf> },
}

impl AppVolumeProvider {
    pub fn from_env() -> Self {
        #[cfg(debug_assertions)]
        if let Some(value) = std::env::var_os(FAKE_DRIVE_VAR) {
            let paths: Vec<PathBuf> = std::env::split_paths(&value)
                .filter(|p| !p.as_os_str().is_empty())
                .collect();
            if !paths.is_empty() {
                for path in &paths {
                    eprintln!(
                        "[wisp] DEBUG BUILD: presenting {} as a removable drive",
                        path.display()
                    );
                }
                return Self::Fake { paths };
            }
        }
        Self::Platform(PlatformVolumeProvider)
    }
}

impl VolumeProvider for AppVolumeProvider {
    fn list_removable(&self) -> Result<Vec<RemovableVolume>> {
        match self {
            Self::Platform(provider) => provider.list_removable(),

            #[cfg(debug_assertions)]
            Self::Fake { paths } => {
                Ok(paths
                    .iter()
                    .filter(|path| path.is_dir())
                    .map(|path| RemovableVolume {
                        label: Some(
                            path.file_name()
                                .map(|n| n.to_string_lossy().to_uppercase())
                                .unwrap_or_else(|| "FAKE-DRIVE".to_string()),
                        ),
                        mount_point: path.clone(),
                        identifiers: DeviceIdentifiers {
                            device_serial: Some(fake_serial(path)),
                            volume_serial: Some("0000-DEV0".to_string()),
                            vendor: Some("Wisp".to_string()),
                            product: Some("Development Drive".to_string()),
                        },
                    })
                    .collect())
            }
        }
    }
}
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

        let provider = AppVolumeProvider::Fake {
            paths: vec![dir.clone()],
        };
        let volumes = provider.list_removable().unwrap();

        assert_eq!(volumes.len(), 1);
        assert!(
            volumes[0].identifiers.strength().is_ok(),
            "a fake drive must be bindable, or registration cannot be exercised"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_directory_reports_no_volumes() {
        let provider = AppVolumeProvider::Fake {
            paths: vec![PathBuf::from("Z:\\definitely-not-a-real-directory")],
        };
        assert!(provider.list_removable().unwrap().is_empty());
    }

    #[test]
    fn different_directories_are_different_drives() {
        let a = AppVolumeProvider::Fake {
            paths: vec![PathBuf::from("C:\\one")],
        };
        let b = AppVolumeProvider::Fake {
            paths: vec![PathBuf::from("C:\\two")],
        };
        let serial = |p: &AppVolumeProvider| match p {
            AppVolumeProvider::Fake { paths } => fake_serial(&paths[0]),
            _ => unreachable!(),
        };
        assert_ne!(serial(&a), serial(&b));
    }

    #[test]
    fn several_directories_are_several_drives() {
        let root = std::env::temp_dir().join(format!("wisp-dev-multi-{}", std::process::id()));
        let (one, two) = (root.join("usb-one"), root.join("usb-two"));
        std::fs::create_dir_all(&one).unwrap();
        std::fs::create_dir_all(&two).unwrap();

        let provider = AppVolumeProvider::Fake {
            paths: vec![one.clone(), two.clone()],
        };
        let volumes = provider.list_removable().unwrap();

        assert_eq!(volumes.len(), 2);
        assert_ne!(
            volumes[0].identifiers.device_serial,
            volumes[1].identifiers.device_serial
        );
        assert_eq!(volumes[0].label.as_deref(), Some("USB-ONE"));

        std::fs::remove_dir_all(&one).unwrap();
        assert_eq!(provider.list_removable().unwrap().len(), 1);

        std::fs::remove_dir_all(&root).ok();
    }}
