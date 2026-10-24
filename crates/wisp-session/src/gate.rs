use std::path::PathBuf;

use wisp_core::{BindingStrength, IdentityFile};
use wisp_usb::RemovableVolume;

#[derive(Debug, Clone)]
pub enum Gate {
    NoDevice,

    Unusable { mount_point: PathBuf, reason: String },

    Registrable {
        volume: RemovableVolume,
        strength: BindingStrength,
    },

    Denied { mount_point: PathBuf },

    WrongComputer { mount_point: PathBuf },

    Locked {
        volume: RemovableVolume,
        file: Box<IdentityFile>,
    },
}

impl Gate {
    pub fn mount_point(&self) -> Option<&std::path::Path> {
        match self {
            Gate::NoDevice => None,
            Gate::Unusable { mount_point, .. }
            | Gate::Denied { mount_point }
            | Gate::WrongComputer { mount_point } => Some(mount_point),
            Gate::Registrable { volume, .. } | Gate::Locked { volume, .. } => {
                Some(&volume.mount_point)
            }
        }
    }

    pub fn permits_app_content(&self) -> bool {
        false
    }
}

pub fn evaluate(volumes: &[RemovableVolume], machine_id: Option<&str>) -> Gate {
    if volumes.is_empty() {
        return Gate::NoDevice;
    }

    let mut sorted = volumes.to_vec();
    sorted.sort_by(|a, b| a.mount_point.cmp(&b.mount_point));

    let mut carries_identity: Vec<(&RemovableVolume, Vec<u8>)> = Vec::new();
    let mut blank: Vec<&RemovableVolume> = Vec::new();

    for volume in &sorted {
        match volume.read_identity() {
            Ok(Some(bytes)) => carries_identity.push((volume, bytes)),
            Ok(None) => blank.push(volume),
            Err(_) => continue,
        }
    }

    let mut decode_failure: Option<(PathBuf, String)> = None;
    let mut saw_valid_identity: Option<PathBuf> = None;
    let mut wrong_computer: Option<PathBuf> = None;

    for (volume, bytes) in &carries_identity {
        match IdentityFile::decode(bytes) {
            Ok(file) => {
                if file.device_matches(&volume.identifiers) {
                    if file.computer_matches(machine_id) {
                        return Gate::Locked {
                            volume: (*volume).clone(),
                            file: Box::new(file),
                        };
                    }
                    wrong_computer.get_or_insert_with(|| volume.mount_point.clone());
                    continue;
                }
                saw_valid_identity.get_or_insert_with(|| volume.mount_point.clone());
            }
            Err(e) => {
                decode_failure
                    .get_or_insert_with(|| (volume.mount_point.clone(), e.to_string()));
            }
        }
    }

    if let Some(mount_point) = wrong_computer {
        return Gate::WrongComputer { mount_point };
    }

    if let Some(mount_point) = saw_valid_identity {
        return Gate::Denied { mount_point };
    }
    if let Some((mount_point, reason)) = decode_failure {
        return Gate::Unusable {
            mount_point,
            reason,
        };
    }

    for volume in &blank {
        if let Ok(strength) = volume.identifiers.strength() {
            return Gate::Registrable {
                volume: (*volume).clone(),
                strength,
            };
        }
    }

    match blank.first() {
        Some(volume) => Gate::Unusable {
            mount_point: volume.mount_point.clone(),
            reason: "this drive reports no serial number that Wisp can bind an identity to"
                .into(),
        },
        None => Gate::NoDevice,
    }
}
