//! Writes an identity onto a development fake drive, for looking at the
//! unlocked screens.
//!
//! ```text
//! cargo run -p wisp-session --example seed_identity -- <dir> <username> <passphrase>
//! ```
//!
//! Creates the identity locally and writes it to `<dir>/.wisp/identity.wisp`.
//! It does **not** register with the relay, so the app will unlock and then
//! report itself offline — which is enough to inspect every unlocked screen,
//! and avoids spending a real invite code to look at a layout.
//!
//! Pair it with `WISP_FAKE_DRIVE=<dir>` when launching the app.

use std::path::PathBuf;

use wisp_core::crypto::KdfParams;
use wisp_core::{DeviceIdentifiers, IdentityFile, UnlockedIdentity};
use wisp_usb::RemovableVolume;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [dir, username, passphrase] = args.as_slice() else {
        eprintln!("usage: seed_identity <dir> <username> <passphrase>");
        std::process::exit(2);
    };

    let path = PathBuf::from(dir);
    std::fs::create_dir_all(&path).expect("creating the fake drive directory");

    let volume = RemovableVolume {
        label: Some("FAKE-DRIVE".into()),
        mount_point: path.clone(),
        identifiers: DeviceIdentifiers {
            device_serial: Some(fake_serial(&path)),
            volume_serial: Some("0000-DEV0".into()),
            vendor: Some("Wisp".into()),
            product: Some("Development Drive".into()),
        },
    };

    let identity = UnlockedIdentity::generate(username).expect("username");
    let file = IdentityFile::create(
        &identity,
        passphrase,
        &volume.identifiers,
        // Never machine-bound: the point is to be able to open it.
        None,
        // Real cost. Seeding is a one-off and matching production means the
        // unlock this produces feels like the real thing.
        KdfParams::RECOMMENDED,
    )
    .expect("sealing the identity");

    volume
        .write_identity(&file.encode())
        .expect("writing to the fake drive");

    println!("wrote {}", volume.identity_path().display());
    println!("username    {username}");
    println!(
        "fingerprint {}",
        identity
            .public_key()
            .expect("public key")
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|pair| pair.concat())
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!();
    println!("launch with: WISP_FAKE_DRIVE={dir}");
}

/// Must match `fake_serial` in `src-tauri/src/dev_drive.rs`, or the app will
/// compute a different drive identity and refuse what this wrote.
///
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
