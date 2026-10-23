//! Deciding what the app is allowed to show, from what is plugged in.
//!
//! This is a pure function of the currently-visible volumes and their contents.
//! Keeping it free of session state means the "what may the user see" decision
//! can be tested exhaustively, and cannot drift out of sync with the UI.
//!
//! # Ordering
//!
//! The gate deliberately reports [`Gate::Denied`] rather than silently falling
//! through to registration when a drive carries an identity that does not match
//! it. Offering "set up a new identity" to someone holding a copied identity
//! file would quietly overwrite the file they copied, and would blur the one
//! distinction the design exists to make clear: *this is the wrong drive*.

use std::path::PathBuf;

use wisp_core::{BindingStrength, IdentityFile};
use wisp_usb::RemovableVolume;

/// What the access gate permits right now.
#[derive(Debug, Clone)]
pub enum Gate {
    /// Nothing plugged in. The app renders the insert-USB screen and nothing
    /// else.
    NoDevice,

    /// A drive is present but cannot carry an identity — no device serial and
    /// no volume serial, or an identity file that will not parse.
    Unusable { mount_point: PathBuf, reason: String },

    /// A usable drive with no identity on it: offer registration.
    Registrable {
        volume: RemovableVolume,
        strength: BindingStrength,
    },

    /// An identity is present but bound to a different physical drive.
    /// Immediate denial, with no passphrase prompt.
    Denied { mount_point: PathBuf },

    /// The right drive, on the wrong computer.
    ///
    /// Separate from [`Gate::Denied`] because the user's situation is
    /// different: their drive is fine, and the fix is to use the computer this
    /// identity was bound to — or, if that computer is gone, nothing. Telling
    /// them "wrong drive" would send them looking for the wrong problem.
    WrongComputer { mount_point: PathBuf },

    /// The right drive. Prompt for the passphrase.
    Locked {
        volume: RemovableVolume,
        file: Box<IdentityFile>,
    },
}

impl Gate {
    /// Whether any application state beyond the gate screens may be rendered.
    ///
    /// Always false here: the gate never unlocks anything by itself. Present so
    /// the UI layer asks a question with an obvious answer rather than
    /// reimplementing the rule.
    pub fn permits_app_content(&self) -> bool {
        false
    }
}

/// Evaluates the gate against the currently-visible volumes.
///
/// Reads each volume's identity file, so this touches the filesystem. Volumes
/// that error on read are skipped rather than failing the whole evaluation: one
/// flaky drive must not be able to deny access to the correct one.
pub fn evaluate(volumes: &[RemovableVolume], machine_id: Option<&str>) -> Gate {
    if volumes.is_empty() {
        return Gate::NoDevice;
    }

    // Deterministic order, so which drive gets picked never depends on the
    // order the platform happened to enumerate them in.
    let mut sorted = volumes.to_vec();
    sorted.sort_by(|a, b| a.mount_point.cmp(&b.mount_point));

    let mut carries_identity: Vec<(&RemovableVolume, Vec<u8>)> = Vec::new();
    let mut blank: Vec<&RemovableVolume> = Vec::new();

    for volume in &sorted {
        match volume.read_identity() {
            Ok(Some(bytes)) => carries_identity.push((volume, bytes)),
            Ok(None) => blank.push(volume),
            // Unreadable drive: treat as if it were not there at all.
            Err(_) => continue,
        }
    }

    // 1. A drive whose identity matches it wins outright, even if some other
    //    drive is also plugged in with a mismatched identity.
    let mut decode_failure: Option<(PathBuf, String)> = None;
    let mut saw_valid_identity: Option<PathBuf> = None;
    let mut wrong_computer: Option<PathBuf> = None;

    for (volume, bytes) in &carries_identity {
        match IdentityFile::decode(bytes) {
            Ok(file) => {
                if file.device_matches(&volume.identifiers) {
                    // The drive is right. Check the computer before offering a
                    // passphrase prompt, so "wrong computer" is its own answer.
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

    // 2. A drive that matched but whose computer did not is the most specific
    //    answer available, so it outranks a mismatched drive elsewhere.
    if let Some(mount_point) = wrong_computer {
        return Gate::WrongComputer { mount_point };
    }

    // 3. A well-formed identity that belongs to another drive is the more
    //    informative signal, so it outranks a corrupt file elsewhere.
    if let Some(mount_point) = saw_valid_identity {
        return Gate::Denied { mount_point };
    }
    if let Some((mount_point, reason)) = decode_failure {
        return Gate::Unusable {
            mount_point,
            reason,
        };
    }

    // 4. No identities anywhere: offer the first drive that can actually be
    //    bound.
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
