use zeroize::Zeroize;

pub struct SecretBytes {
    buf: Box<[u8]>,
    locked: bool,
}

impl SecretBytes {
    pub fn zeroed(len: usize) -> Self {
        let buf = vec![0u8; len].into_boxed_slice();
        let mut this = Self { buf, locked: false };
        this.lock_pages();
        this
    }

    pub fn from_slice_mut(bytes: &mut [u8]) -> Self {
        let mut this = Self::zeroed(bytes.len());
        this.buf.copy_from_slice(bytes);
        bytes.zeroize();
        this
    }

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

    pub fn is_swap_locked(&self) -> bool {
        self.locked
    }

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

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes({} bytes, redacted)", self.buf.len())
    }
}

#[cfg(windows)]
mod platform {
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
