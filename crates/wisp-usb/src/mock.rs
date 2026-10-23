//! A scriptable [`VolumeProvider`] for tests.
//!
//! The access gate's most important behaviours — deny before prompting, wipe
//! the key the instant the drive vanishes — are all reactions to hardware
//! events. Reproducing those by hand with a real USB stick is slow and
//! unrepeatable, so the whole state machine is tested against this instead.

use std::sync::{Arc, Mutex};

use crate::{RemovableVolume, Result, UsbError, VolumeProvider};

/// A provider whose volume list can be changed at will from the test body.
#[derive(Clone, Default)]
pub struct MockVolumeProvider {
    state: Arc<Mutex<MockState>>,
}

#[derive(Default)]
struct MockState {
    volumes: Vec<RemovableVolume>,
    /// When set, enumeration fails — simulating a platform API error.
    failure: Option<String>,
}

impl MockVolumeProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_volumes(volumes: Vec<RemovableVolume>) -> Self {
        let this = Self::new();
        this.set_volumes(volumes);
        this
    }

    /// Replaces the currently-visible volumes, as if drives were inserted or
    /// removed between polls.
    pub fn set_volumes(&self, volumes: Vec<RemovableVolume>) {
        let mut state = self.state.lock().unwrap();
        state.volumes = volumes;
        state.failure = None;
    }

    pub fn insert(&self, volume: RemovableVolume) {
        self.state.lock().unwrap().volumes.push(volume);
    }

    /// Simulates every drive being pulled at once.
    pub fn remove_all(&self) {
        self.state.lock().unwrap().volumes.clear();
    }

    /// Makes subsequent enumeration calls fail.
    pub fn fail_with(&self, message: &str) {
        self.state.lock().unwrap().failure = Some(message.to_string());
    }
}

impl VolumeProvider for MockVolumeProvider {
    fn list_removable(&self) -> Result<Vec<RemovableVolume>> {
        let state = self.state.lock().unwrap();
        match &state.failure {
            Some(message) => Err(UsbError::Enumeration(message.clone())),
            None => Ok(state.volumes.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use wisp_core::DeviceIdentifiers;

    fn volume(letter: &str) -> RemovableVolume {
        RemovableVolume {
            mount_point: PathBuf::from(letter),
            label: Some("WISP".into()),
            identifiers: DeviceIdentifiers {
                device_serial: Some(format!("SERIAL-{letter}")),
                ..Default::default()
            },
        }
    }

    #[test]
    fn starts_empty() {
        assert!(MockVolumeProvider::new().list_removable().unwrap().is_empty());
    }

    #[test]
    fn reflects_insertion_and_removal() {
        let mock = MockVolumeProvider::new();
        mock.insert(volume("E:\\"));
        assert_eq!(mock.list_removable().unwrap().len(), 1);
        mock.remove_all();
        assert!(mock.list_removable().unwrap().is_empty());
    }

    #[test]
    fn can_simulate_platform_failure() {
        let mock = MockVolumeProvider::with_volumes(vec![volume("E:\\")]);
        mock.fail_with("access denied");
        assert!(mock.list_removable().is_err());
        // Setting volumes again clears the failure.
        mock.set_volumes(vec![]);
        assert!(mock.list_removable().is_ok());
    }
}
