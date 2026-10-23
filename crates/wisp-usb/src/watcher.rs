//! Detecting insertion and removal.
//!
//! # Why polling
//!
//! This watcher polls. The event-driven alternatives (`WM_DEVICECHANGE` on
//! Windows, DiskArbitration on macOS) both require owning a message loop or a
//! run loop, and both still need a reconciling poll to survive missed or
//! coalesced events. Polling a handful of drive letters is cheap, has identical
//! behaviour on both platforms, and cannot silently stop working.
//!
//! The cost is honest and bounded: removal is noticed within one
//! [`DEFAULT_POLL_INTERVAL`], not instantly. The decrypted key therefore
//! survives in memory for up to that long after the drive is physically pulled.
//! That window is the reason the interval is short and configurable — and the
//! reason an event-driven upgrade is worth doing later, layered on top of the
//! poll rather than replacing it.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::{RemovableVolume, VolumeProvider};

/// Upper bound on how long a removed drive can go unnoticed.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeEvent {
    Inserted(RemovableVolume),
    Removed { mount_point: PathBuf },
}

/// Computes the events between two observations.
///
/// Split out from the polling thread so the interesting logic is testable
/// without timing or hardware.
///
/// A mount point whose device identifiers changed between polls is reported as
/// a removal *and* an insertion, never as a no-op. Drive letters get reused:
/// pulling one stick and inserting another before the next poll would otherwise
/// look like nothing happened, and an unlocked session would silently continue
/// against a drive that is no longer the registered one.
pub fn diff(previous: &[RemovableVolume], current: &[RemovableVolume]) -> Vec<VolumeEvent> {
    let before: BTreeMap<&PathBuf, &RemovableVolume> =
        previous.iter().map(|v| (&v.mount_point, v)).collect();
    let after: BTreeMap<&PathBuf, &RemovableVolume> =
        current.iter().map(|v| (&v.mount_point, v)).collect();

    let mut events = Vec::new();

    // Removals first: a consumer that locks on removal should see the lock
    // before it sees any replacement drive appear.
    for (mount_point, old) in &before {
        match after.get(*mount_point) {
            None => events.push(VolumeEvent::Removed {
                mount_point: (*mount_point).clone(),
            }),
            Some(new) if new != old => events.push(VolumeEvent::Removed {
                mount_point: (*mount_point).clone(),
            }),
            Some(_) => {}
        }
    }

    for (mount_point, new) in &after {
        match before.get(*mount_point) {
            None => events.push(VolumeEvent::Inserted((*new).clone())),
            Some(old) if new != old => events.push(VolumeEvent::Inserted((*new).clone())),
            Some(_) => {}
        }
    }

    events
}

/// A background thread that reports volume changes until dropped.
pub struct Watcher {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Watcher {
    /// Starts watching. `on_event` runs on the watcher thread.
    ///
    /// The initial poll reports every already-present volume as `Inserted`, so
    /// a consumer that starts with an empty view and only reacts to events
    /// converges on the correct state without a separate startup query.
    pub fn spawn<P, F>(provider: Arc<P>, interval: Duration, mut on_event: F) -> Self
    where
        P: VolumeProvider,
        F: FnMut(VolumeEvent) + Send + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);

        let handle = std::thread::Builder::new()
            .name("wisp-usb-watcher".into())
            .spawn(move || {
                let mut previous: Vec<RemovableVolume> = Vec::new();

                while !thread_stop.load(Ordering::Relaxed) {
                    // An enumeration failure is treated as "no information",
                    // not as "no drives". Reporting spurious removals would
                    // lock the user out every time a transient API error hit.
                    if let Ok(current) = provider.list_removable() {
                        for event in diff(&previous, &current) {
                            on_event(event);
                        }
                        previous = current;
                    }

                    // Sleep in slices so shutdown does not wait a full interval.
                    let deadline = std::time::Instant::now() + interval;
                    while std::time::Instant::now() < deadline
                        && !thread_stop.load(Ordering::Relaxed)
                    {
                        std::thread::sleep(Duration::from_millis(25).min(interval));
                    }
                }
            })
            .expect("spawning the USB watcher thread");

        Self {
            stop,
            handle: Some(handle),
        }
    }

    /// Signals the thread to stop and waits for it.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockVolumeProvider;
    use std::sync::Mutex;
    use wisp_core::DeviceIdentifiers;

    fn volume(mount: &str, serial: &str) -> RemovableVolume {
        RemovableVolume {
            mount_point: PathBuf::from(mount),
            label: Some("WISP".into()),
            identifiers: DeviceIdentifiers {
                device_serial: Some(serial.into()),
                ..Default::default()
            },
        }
    }

    #[test]
    fn no_change_produces_no_events() {
        let v = vec![volume("E:\\", "AAA1")];
        assert!(diff(&v, &v).is_empty());
    }

    #[test]
    fn insertion_is_reported() {
        let events = diff(&[], &[volume("E:\\", "AAA1")]);
        assert_eq!(events, vec![VolumeEvent::Inserted(volume("E:\\", "AAA1"))]);
    }

    #[test]
    fn removal_is_reported() {
        let events = diff(&[volume("E:\\", "AAA1")], &[]);
        assert_eq!(
            events,
            vec![VolumeEvent::Removed {
                mount_point: PathBuf::from("E:\\")
            }]
        );
    }

    /// The drive-letter reuse case: a different stick on the same mount point
    /// must not look like "nothing happened".
    #[test]
    fn swapped_drive_on_same_mount_point_reports_removal_then_insertion() {
        let events = diff(&[volume("E:\\", "AAA1")], &[volume("E:\\", "BBB2")]);
        assert_eq!(
            events,
            vec![
                VolumeEvent::Removed {
                    mount_point: PathBuf::from("E:\\")
                },
                VolumeEvent::Inserted(volume("E:\\", "BBB2")),
            ]
        );
    }

    #[test]
    fn removals_are_ordered_before_insertions() {
        let events = diff(&[volume("E:\\", "AAA1")], &[volume("F:\\", "BBB2")]);
        assert!(matches!(events[0], VolumeEvent::Removed { .. }));
        assert!(matches!(events[1], VolumeEvent::Inserted(_)));
    }

    #[test]
    fn watcher_reports_live_changes() {
        let mock = Arc::new(MockVolumeProvider::new());
        let seen = Arc::new(Mutex::new(Vec::new()));

        let sink = Arc::clone(&seen);
        let mut watcher = Watcher::spawn(
            Arc::clone(&mock),
            Duration::from_millis(20),
            move |event| sink.lock().unwrap().push(event),
        );

        mock.set_volumes(vec![volume("E:\\", "AAA1")]);
        wait_until(&seen, |events| {
            events.iter().any(|e| matches!(e, VolumeEvent::Inserted(_)))
        });

        mock.remove_all();
        wait_until(&seen, |events| {
            events
                .iter()
                .any(|e| matches!(e, VolumeEvent::Removed { .. }))
        });

        watcher.stop();
    }

    /// A transient enumeration failure must not be mistaken for the drive
    /// being pulled — that would lock the user out at random.
    #[test]
    fn enumeration_failure_does_not_report_removal() {
        let mock = Arc::new(MockVolumeProvider::with_volumes(vec![volume("E:\\", "AAA1")]));
        let seen = Arc::new(Mutex::new(Vec::new()));

        let sink = Arc::clone(&seen);
        let mut watcher = Watcher::spawn(
            Arc::clone(&mock),
            Duration::from_millis(20),
            move |event| sink.lock().unwrap().push(event),
        );

        wait_until(&seen, |events| !events.is_empty());
        mock.fail_with("simulated platform error");
        std::thread::sleep(Duration::from_millis(150));
        watcher.stop();

        let events = seen.lock().unwrap();
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, VolumeEvent::Removed { .. })),
            "a failed enumeration was misread as a removal: {events:?}"
        );
    }

    fn wait_until<F>(seen: &Arc<Mutex<Vec<VolumeEvent>>>, predicate: F)
    where
        F: Fn(&[VolumeEvent]) -> bool,
    {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if predicate(&seen.lock().unwrap()) {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for expected event; saw {:?}",
                seen.lock().unwrap()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
