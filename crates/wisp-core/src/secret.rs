//! Protected in-memory secret storage.
//!
//! Every decrypted secret in Wisp lives in a [`SecretBytes`]. Two properties
//! matter, in this order:
//!
//! 1. **Zeroization on drop.** When the USB drive is pulled, the session lock
//!    fires, or the process exits normally, the bytes are overwritten rather
//!    than left in freed heap memory. This is the property the whole
//!    "yank the drive and the key is gone" guarantee rests on.
//! 2. **Best-effort exclusion from swap.** Pages are locked via `mlock`/
//!    `VirtualLock` where the OS permits it, so the plaintext key is less
//!    likely to be written to a pagefile that outlives the session.
//!
//! Property 2 is genuinely best-effort and is *not* a security guarantee:
//! locking can fail on quota limits, and it does nothing about hibernation
//! images or a core dump. It reduces incidental exposure; it does not defend
//! against an attacker with memory-read access to a running, unlocked session.

use zeroize::Zeroize;

/// A heap buffer that is wiped when dropped and kept out of swap where possible.
///
/// The buffer is allocated once at construction and never reallocated, because
/// a reallocating `Vec` would leave un-zeroized copies of the secret scattered
/// across the heap at each growth step.
pub struct SecretBytes {
    buf: Box<[u8]>,
    locked: bool,
}

impl SecretBytes {
    /// Allocates `len` zeroed bytes, ready to be filled in place.
    pub fn zeroed(len: usize) -> Self {
        let buf = vec![0u8; len].into_boxed_slice();
        let mut this = Self { buf, locked: false };
        this.lock_pages();
        this
    }

    /// Takes ownership of `bytes`, wiping the caller's copy.
    pub fn from_slice_mut(bytes: &mut [u8]) -> Self {
        let mut this = Self::zeroed(bytes.len());
        this.buf.copy_from_slice(bytes);
        bytes.zeroize();
        this
    }

    /// Copies from a slice the caller cannot give up ownership of.
    ///
    /// Prefer [`SecretBytes::from_slice_mut`] wherever the source is yours to
    /// wipe; this variant necessarily leaves the original intact.
    pub fn copy_from_slice(bytes: &[u8]) -> Self {
        let mut this = Self::zeroed(bytes.len());
        this.buf.copy_from_slice(bytes);
        this
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Whether the OS accepted the request to keep these pages resident.
    ///
    /// Exposed so the UI can be honest about it rather than implying a
    /// guarantee the platform did not actually give us.
    pub fn is_swap_locked(&self) -> bool {
        self.locked
    }

    /// Wipes the contents immediately, without waiting for drop.
    pub fn wipe(&mut self) {
        self.buf.zeroize();
    }

    fn lock_pages(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        self.locked = platform::lock(self.buf.as_ptr(), self.buf.len());
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.buf.zeroize();
        if self.locked {
            platform::unlock(self.buf.as_ptr(), self.buf.len());
        }
    }
}

// Deliberately no Debug/Display/Clone: a secret should be impossible to
// accidentally log, and cloning one silently doubles the number of copies
// that have to be wiped.
impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes({} bytes, redacted)", self.buf.len())
    }
}

#[cfg(windows)]
mod platform {
    // VirtualLock/VirtualUnlock are declared here rather than pulled from the
    // `windows` crate so that wisp-core stays dependency-free and portable;
    // these two signatures are stable ABI.
    extern "system" {
        fn VirtualLock(addr: *const core::ffi::c_void, size: usize) -> i32;
        fn VirtualUnlock(addr: *const core::ffi::c_void, size: usize) -> i32;
    }

    pub fn lock(ptr: *const u8, len: usize) -> bool {
        unsafe { VirtualLock(ptr as *const _, len) != 0 }
    }

    pub fn unlock(ptr: *const u8, len: usize) {
        unsafe {
            VirtualUnlock(ptr as *const _, len);
        }
    }
}

#[cfg(unix)]
mod platform {
    extern "C" {
        fn mlock(addr: *const core::ffi::c_void, len: usize) -> i32;
        fn munlock(addr: *const core::ffi::c_void, len: usize) -> i32;
    }

    pub fn lock(ptr: *const u8, len: usize) -> bool {
        unsafe { mlock(ptr as *const _, len) == 0 }
    }

    pub fn unlock(ptr: *const u8, len: usize) {
        unsafe {
            munlock(ptr as *const _, len);
        }
    }
}

#[cfg(not(any(windows, unix)))]
mod platform {
    pub fn lock(_ptr: *const u8, _len: usize) -> bool {
        false
    }
    pub fn unlock(_ptr: *const u8, _len: usize) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroed_allocates_requested_length() {
        let s = SecretBytes::zeroed(32);
        assert_eq!(s.len(), 32);
        assert_eq!(s.as_slice(), &[0u8; 32]);
    }

    #[test]
    fn from_slice_mut_wipes_the_source() {
        let mut src = *b"correct horse battery staple____";
        let s = SecretBytes::from_slice_mut(&mut src);
        assert_eq!(s.as_slice(), b"correct horse battery staple____");
        assert_eq!(src, [0u8; 32], "source buffer must be wiped");
    }

    #[test]
    fn wipe_clears_contents_in_place() {
        let mut s = SecretBytes::copy_from_slice(&[0xAB; 16]);
        s.wipe();
        assert_eq!(s.as_slice(), &[0u8; 16]);
    }

    #[test]
    fn debug_does_not_leak_contents() {
        let s = SecretBytes::copy_from_slice(b"super secret value");
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("secret value"), "got: {rendered}");
    }
}
