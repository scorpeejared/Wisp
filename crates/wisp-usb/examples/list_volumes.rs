//! Prints the removable volumes Wisp can see, and what it would bind to.
//!
//! `cargo run -p wisp-usb --example list_volumes`
//!
//! Useful for checking a specific USB stick before registering an identity on
//! it — particularly whether it reports a device serial, since a drive without
//! one can only be bound weakly.

use wisp_usb::{PlatformVolumeProvider, VolumeProvider};

fn main() {
    let volumes = match PlatformVolumeProvider.list_removable() {
        Ok(volumes) => volumes,
        Err(e) => {
            eprintln!("enumeration failed: {e}");
            std::process::exit(1);
        }
    };

    if volumes.is_empty() {
        println!("No removable volumes detected.");
        return;
    }

    for volume in &volumes {
        let ids = &volume.identifiers;
        println!("{}", volume.mount_point.display());
        println!("  label          {}", ids_or_dash(&volume.label));
        println!("  vendor         {}", ids_or_dash(&ids.vendor));
        println!("  product        {}", ids_or_dash(&ids.product));
        println!("  device serial  {}", ids_or_dash(&ids.device_serial));
        println!("  volume serial  {}", ids_or_dash(&ids.volume_serial));
        match ids.strength() {
            Ok(strength) => println!("  binding        {strength:?}"),
            Err(e) => println!("  binding        UNUSABLE ({e})"),
        }
        println!("  has identity   {}", volume.has_identity());
        println!();
    }
}

fn ids_or_dash(value: &Option<String>) -> String {
    value.clone().unwrap_or_else(|| "-".into())
}
