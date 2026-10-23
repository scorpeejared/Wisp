//! macOS removable volume enumeration and device identifier queries.
//!
//! Mount points come from `/Volumes`, the backing BSD device from `statfs`, and
//! the USB descriptor strings from the IO registry by walking *up* the parent
//! chain from the disk node to the USB device node.
//!
//! # Status
//!
//! **This module has not been compiled or run on macOS.** It was written on a
//! Windows machine, where it is `cfg`-ed out entirely, so it cannot affect the
//! Windows build — but it needs a `cargo test -p wisp-usb` pass and a
//! real-hardware check on a Mac before it can be trusted. The tests at the
//! bottom cover the parsing that does not need hardware; the FFI itself is
//! unverified.
//!
//! # Why the IOKit bindings are hand-declared
//!
//! Four `extern "C"` declarations against a stable, decades-old C ABI are
//! easier to get right unverified than a third-party crate's evolving Rust API.
//! `core-foundation` is still used for the CF types, where the safe wrappers
//! genuinely help.
//!
//! # No volume serial on this platform
//!
//! [`wisp_core::BindingStrength::Weak`] bindings fall back to the filesystem
//! volume serial, which macOS does not expose in a form comparable to the
//! 32-bit value Windows reports. Rather than invent a macOS-only value that
//! would silently fail to match a Windows registration, `volume_serial` is left
//! `None` here.
//!
//! The consequence, stated plainly: a drive with **no device serial** cannot be
//! registered or unlocked on macOS at all, and an identity weakly bound on
//! Windows will not open on a Mac. Drives without serials are uncommon, the
//! registration UI already warns when it is about to create a weak binding, and
//! failing closed with a clear message beats appearing to work and then denying
//! access on the other machine.

use std::ffi::{c_char, c_void, CStr, CString};
use std::path::Path;

use core_foundation::base::TCFType;
use core_foundation::string::{CFString, CFStringRef};

use wisp_core::DeviceIdentifiers;

use crate::{RemovableVolume, Result, UsbError};

#[allow(non_camel_case_types)]
type io_object_t = u32;
#[allow(non_camel_case_types)]
type io_service_t = io_object_t;
#[allow(non_camel_case_types)]
type io_registry_entry_t = io_object_t;
#[allow(non_camel_case_types)]
type mach_port_t = u32;
#[allow(non_camel_case_types)]
type kern_return_t = i32;

const K_IO_REGISTRY_ITERATE_RECURSIVELY: u32 = 1;
const K_IO_REGISTRY_ITERATE_PARENTS: u32 = 2;
/// `kIOMainPortDefault` is `MACH_PORT_NULL`, and passing null selects the
/// default port — which avoids linking against a symbol that was renamed from
/// `kIOMasterPortDefault` in macOS 12.
const DEFAULT_PORT: mach_port_t = 0;

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    fn IOBSDNameMatching(
        main_port: mach_port_t,
        options: u32,
        bsd_name: *const c_char,
    ) -> *const c_void;

    /// Consumes one reference to `matching`; it must not be released by us.
    fn IOServiceGetMatchingService(main_port: mach_port_t, matching: *const c_void)
        -> io_service_t;

    fn IORegistryEntrySearchCFProperty(
        entry: io_registry_entry_t,
        plane: *const c_char,
        key: CFStringRef,
        allocator: *const c_void,
        options: u32,
    ) -> *const c_void;

    fn IOObjectRelease(object: io_object_t) -> kern_return_t;
}

/// Releases its IO object on every exit path.
struct IoObject(io_service_t);

impl Drop for IoObject {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                IOObjectRelease(self.0);
            }
        }
    }
}

#[derive(Debug, Default)]
struct DeviceInfo {
    serial: Option<String>,
    vendor: Option<String>,
    product: Option<String>,
    is_usb: bool,
}

pub fn list_removable() -> Result<Vec<RemovableVolume>> {
    let entries = std::fs::read_dir("/Volumes")
        .map_err(|e| UsbError::Enumeration(format!("could not read /Volumes: {e}")))?;

    let mut volumes = Vec::new();
    for entry in entries.flatten() {
        let mount_point = entry.path();
        // /Volumes contains a symlink to `/` for the boot volume; following it
        // would offer the system disk as a key drive candidate.
        if entry.file_type().map(|t| t.is_symlink()).unwrap_or(true) {
            continue;
        }

        let Some(bsd_name) = backing_device(&mount_point) else {
            continue;
        };
        let device = query_device(&bsd_name).unwrap_or_default();
        // The parent-chain search only finds these properties under a USB
        // controller, so this doubles as the "is it USB?" test.
        if !device.is_usb {
            continue;
        }

        volumes.push(RemovableVolume {
            label: mount_point
                .file_name()
                .map(|name| name.to_string_lossy().to_string()),
            mount_point,
            identifiers: DeviceIdentifiers {
                device_serial: device.serial,
                // See the module docs: deliberately absent on macOS.
                volume_serial: None,
                vendor: device.vendor,
                product: device.product,
            },
        });
    }

    volumes.sort_by(|a, b| a.mount_point.cmp(&b.mount_point));
    Ok(volumes)
}

/// Maps a mount point to its BSD device name, e.g. `disk4s1`.
fn backing_device(mount_point: &Path) -> Option<String> {
    let path = CString::new(mount_point.as_os_str().as_encoded_bytes()).ok()?;

    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut buf) } != 0 {
        return None;
    }

    let raw = unsafe { CStr::from_ptr(buf.f_mntfromname.as_ptr()) };
    strip_dev_prefix(&raw.to_string_lossy())
}

/// `/dev/disk4s1` -> `disk4s1`. Anything not under `/dev/` is not a local disk.
fn strip_dev_prefix(device: &str) -> Option<String> {
    let name = device.strip_prefix("/dev/")?;
    (!name.is_empty()).then(|| name.to_string())
}

/// Looks up the USB descriptor strings for a BSD disk node.
fn query_device(bsd_name: &str) -> Option<DeviceInfo> {
    let name = CString::new(bsd_name).ok()?;

    let matching = unsafe { IOBSDNameMatching(DEFAULT_PORT, 0, name.as_ptr()) };
    if matching.is_null() {
        return None;
    }

    // IOServiceGetMatchingService consumes the dictionary reference, so there
    // is nothing to release here even on failure.
    let service = unsafe { IOServiceGetMatchingService(DEFAULT_PORT, matching) };
    if service == 0 {
        return None;
    }
    let service = IoObject(service);

    let serial = search_parent_property(service.0, "USB Serial Number");
    let vendor = search_parent_property(service.0, "USB Vendor Name");
    let product = search_parent_property(service.0, "USB Product Name");

    Some(DeviceInfo {
        is_usb: serial.is_some() || vendor.is_some() || product.is_some(),
        serial,
        vendor,
        product,
    })
}

/// Walks up the IOService plane looking for a string property.
///
/// The disk node itself carries no USB information; it lives several levels up,
/// on the USB device node that the disk hangs off.
fn search_parent_property(entry: io_registry_entry_t, key: &str) -> Option<String> {
    let plane = CString::new("IOService").ok()?;
    let cf_key = CFString::new(key);

    let value = unsafe {
        IORegistryEntrySearchCFProperty(
            entry,
            plane.as_ptr(),
            cf_key.as_concrete_TypeRef(),
            std::ptr::null(),
            K_IO_REGISTRY_ITERATE_RECURSIVELY | K_IO_REGISTRY_ITERATE_PARENTS,
        )
    };
    if value.is_null() {
        return None;
    }

    // Returned under the create rule: wrapping it transfers ownership, so it is
    // released when the wrapper drops.
    let text = unsafe { CFString::wrap_under_create_rule(value as CFStringRef) }.to_string();
    let text = text.trim().to_string();
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_the_dev_prefix() {
        assert_eq!(strip_dev_prefix("/dev/disk4s1").as_deref(), Some("disk4s1"));
        assert_eq!(strip_dev_prefix("/dev/disk4").as_deref(), Some("disk4"));
    }

    #[test]
    fn rejects_non_dev_sources() {
        // Network mounts and synthetic filesystems are not local disks.
        assert_eq!(strip_dev_prefix("map -hosts"), None);
        assert_eq!(strip_dev_prefix("//user@server/share"), None);
        assert_eq!(strip_dev_prefix("/dev/"), None);
        assert_eq!(strip_dev_prefix(""), None);
    }

    /// Exercises the real platform API. Asserts only what holds with or
    /// without a drive attached.
    #[test]
    fn enumerating_the_real_machine_is_well_formed() {
        let volumes = list_removable().expect("enumeration should not fail");
        for volume in &volumes {
            assert!(volume.mount_point.starts_with("/Volumes"));
            assert!(
                volume.identifiers.strength().is_ok(),
                "listed volume is not bindable: {:?}",
                volume.identifiers
            );
        }
    }
}
