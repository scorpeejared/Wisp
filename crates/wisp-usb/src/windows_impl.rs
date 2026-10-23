//! Windows removable volume enumeration and device identifier queries.
//!
//! Drive letters come from `GetLogicalDrives`, the filesystem volume serial
//! from `GetVolumeInformationW`, and the device serial from
//! `IOCTL_STORAGE_QUERY_PROPERTY` against `\\.\X:`.
//!
//! The device handle is opened with **zero** desired access. That is enough for
//! a property query and — unlike `GENERIC_READ` — does not require
//! Administrator, so the access gate works for a normal user account.

use std::ffi::c_void;
use std::path::PathBuf;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW, BusTypeUsb,
    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Ioctl::{
    PropertyStandardQuery, StorageDeviceProperty, IOCTL_STORAGE_QUERY_PROPERTY,
    STORAGE_DEVICE_DESCRIPTOR, STORAGE_PROPERTY_QUERY,
};
use windows::Win32::System::IO::DeviceIoControl;

use wisp_core::DeviceIdentifiers;

use crate::{format_volume_serial, RemovableVolume, Result, UsbError};

const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;

/// Closes its handle on every exit path, including early `?` returns.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
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
    let mask = unsafe { GetLogicalDrives() };
    if mask == 0 {
        return Err(UsbError::Enumeration(
            "GetLogicalDrives returned no drives".into(),
        ));
    }

    let mut volumes = Vec::new();
    for index in 0..26u32 {
        if mask & (1 << index) == 0 {
            continue;
        }
        let letter = (b'A' + index as u8) as char;
        let root = format!("{letter}:\\");
        let wide_root = to_wide(&root);

        let drive_type = unsafe { GetDriveTypeW(PCWSTR(wide_root.as_ptr())) };
        // Network shares, optical drives, and RAM disks can never be the key
        // drive. Fixed drives are still queried, because plenty of USB SSDs and
        // some flash drives enumerate as fixed rather than removable, and
        // refusing those would reject hardware that works perfectly well.
        if drive_type != DRIVE_REMOVABLE && drive_type != DRIVE_FIXED {
            continue;
        }

        let device = query_device(letter).unwrap_or_default();
        if drive_type != DRIVE_REMOVABLE && !device.is_usb {
            continue;
        }

        // A card reader with no card, or a drive that vanished mid-scan, fails
        // here. That is a normal race, not an error worth surfacing.
        let Some((label, volume_serial)) = volume_info(&wide_root) else {
            continue;
        };

        volumes.push(RemovableVolume {
            mount_point: PathBuf::from(&root),
            label,
            identifiers: DeviceIdentifiers {
                device_serial: device.serial,
                volume_serial: Some(format_volume_serial(volume_serial)),
                vendor: device.vendor,
                product: device.product,
            },
        });
    }

    Ok(volumes)
}

/// Reads the label and 32-bit volume serial, or `None` if the volume is not
/// readable right now.
fn volume_info(wide_root: &[u16]) -> Option<(Option<String>, u32)> {
    let mut label_buf = [0u16; 256];
    let mut serial: u32 = 0;

    unsafe {
        GetVolumeInformationW(
            PCWSTR(wide_root.as_ptr()),
            Some(&mut label_buf),
            Some(&mut serial),
            None,
            None,
            None,
        )
    }
    .ok()?;

    let label = from_wide(&label_buf);
    Some((if label.is_empty() { None } else { Some(label) }, serial))
}

/// Queries the storage device behind a drive letter.
fn query_device(letter: char) -> Option<DeviceInfo> {
    let path = to_wide(&format!(r"\\.\{letter}:"));

    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            // Zero access: enough to query properties, and avoids needing
            // Administrator rights.
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .ok()?;
    let handle = OwnedHandle(handle);

    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
    };

    // Large enough for the descriptor plus its trailing string block.
    let mut buf = vec![0u8; 2048];
    let mut returned: u32 = 0;

    unsafe {
        DeviceIoControl(
            handle.0,
            IOCTL_STORAGE_QUERY_PROPERTY,
            Some(&query as *const _ as *const c_void),
            std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            Some(buf.as_mut_ptr() as *mut c_void),
            buf.len() as u32,
            Some(&mut returned),
            None,
        )
    }
    .ok()?;

    parse_device_descriptor(&buf[..returned as usize])
}

/// Extracts the identifier strings from a `STORAGE_DEVICE_DESCRIPTOR`.
///
/// The descriptor is a fixed header followed by a block of NUL-terminated
/// ASCII, referenced by byte offsets from the start of the buffer. Every offset
/// is bounds-checked: this is data from a device, and a malformed or hostile
/// descriptor must not be able to read past the buffer.
fn parse_device_descriptor(buf: &[u8]) -> Option<DeviceInfo> {
    if buf.len() < std::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>() {
        return None;
    }

    // `read_unaligned`: `buf` is a `Vec<u8>` and carries no alignment
    // guarantee for the descriptor type.
    let descriptor: STORAGE_DEVICE_DESCRIPTOR =
        unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const STORAGE_DEVICE_DESCRIPTOR) };

    let string_at = |offset: u32| -> Option<String> {
        let start = offset as usize;
        if offset == 0 || start >= buf.len() {
            return None;
        }
        let end = buf[start..]
            .iter()
            .position(|&b| b == 0)
            .map_or(buf.len(), |p| start + p);
        let text = String::from_utf8_lossy(&buf[start..end]).trim().to_string();
        (!text.is_empty()).then_some(text)
    };

    Some(DeviceInfo {
        serial: string_at(descriptor.SerialNumberOffset),
        vendor: string_at(descriptor.VendorIdOffset),
        product: string_at(descriptor.ProductIdOffset),
        is_usb: descriptor.BusType == BusTypeUsb,
    })
}

fn to_wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end]).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_round_trip() {
        assert_eq!(from_wide(&to_wide("E:\\")), "E:\\");
        assert_eq!(from_wide(&to_wide("")), "");
    }

    #[test]
    fn from_wide_stops_at_the_terminator() {
        let buf = [b'W' as u16, b'I' as u16, 0, b'X' as u16];
        assert_eq!(from_wide(&buf), "WI");
    }

    #[test]
    fn descriptor_parsing_rejects_a_short_buffer() {
        assert!(parse_device_descriptor(&[]).is_none());
        assert!(parse_device_descriptor(&[0u8; 8]).is_none());
    }

    /// Offsets come from the device and must never be trusted.
    #[test]
    fn descriptor_parsing_survives_hostile_offsets() {
        let size = std::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>();
        let mut buf = vec![0u8; size + 32];

        // SerialNumberOffset far past the end of the buffer.
        let serial_offset = std::mem::offset_of!(STORAGE_DEVICE_DESCRIPTOR, SerialNumberOffset);
        buf[serial_offset..serial_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());

        let info = parse_device_descriptor(&buf).expect("header is long enough to parse");
        assert!(info.serial.is_none(), "out-of-range offset must be ignored");
    }

    /// An unterminated string block must stop at the buffer end, not run off it.
    #[test]
    fn descriptor_parsing_handles_a_missing_terminator() {
        let size = std::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>();
        let mut buf = vec![0u8; size + 8];
        let serial_offset = std::mem::offset_of!(STORAGE_DEVICE_DESCRIPTOR, SerialNumberOffset);
        buf[serial_offset..serial_offset + 4].copy_from_slice(&(size as u32).to_le_bytes());
        // Fill the tail with non-NUL bytes.
        buf[size..].fill(b'A');

        let info = parse_device_descriptor(&buf).unwrap();
        assert_eq!(info.serial.as_deref(), Some("AAAAAAAA"));
    }

    /// Exercises the real platform API. Asserts only invariants that hold with
    /// or without a USB drive plugged in, so it is not machine-dependent.
    #[test]
    fn enumerating_the_real_machine_is_well_formed() {
        let volumes = list_removable().expect("enumeration should not fail");
        for volume in &volumes {
            assert!(
                volume.mount_point.to_string_lossy().ends_with(":\\"),
                "unexpected mount point: {:?}",
                volume.mount_point
            );
            assert!(
                volume.identifiers.volume_serial.is_some(),
                "a listed volume always has a filesystem serial"
            );
            // Whatever we listed must be bindable, or the registration flow
            // would offer the user a drive it cannot actually use.
            assert!(
                volume.identifiers.strength().is_ok(),
                "listed volume is not bindable: {:?}",
                volume.identifiers
            );
        }
    }
}
