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
        None,
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
