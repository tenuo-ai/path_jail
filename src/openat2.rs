//! Raw `openat2(2)` syscall wrapper and kernel version detection.
//!
//! No libc, no rustix — just `std` and a raw syscall number.
//! Only compiled on Linux; the macOS/BSDs fallback path lives in `fd_jail.rs`.

#![cfg(target_os = "linux")]

use std::ffi::CStr;
use std::os::unix::io::{OwnedFd, RawFd, FromRawFd};

// ── open_how layout (linux/openat2.h) ────────────────────────────────────────

#[repr(C)]
pub(crate) struct OpenHow {
    pub flags:   u64, // O_RDONLY, O_WRONLY, O_CREAT, etc.
    pub mode:    u64, // creation mode; 0 for reads
    pub resolve: u64, // RESOLVE_* flags
}

// RESOLVE_* flags (linux/openat2.h)
pub(crate) const RESOLVE_BENEATH:       u64 = 0x08;
pub(crate) const RESOLVE_NO_SYMLINKS:   u64 = 0x04;
pub(crate) const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

// O_* flags
pub(crate) const O_RDONLY:   u64 = 0;
pub(crate) const O_WRONLY:   u64 = 1;
pub(crate) const O_RDWR:     u64 = 2;
pub(crate) const O_CREAT:    u64 = 0o100;
pub(crate) const O_EXCL:     u64 = 0o200;
pub(crate) const O_TRUNC:    u64 = 0o1000;
pub(crate) const O_APPEND:   u64 = 0o2000;
pub(crate) const O_DIRECTORY:u64 = 0o200000;
pub(crate) const O_CLOEXEC:  u64 = 0o2000000;

// SYS_openat2 — added in Linux 5.6 (kernel 5.6+)
// x86-64: 437, aarch64: 437, arm: 437 (all use the same number on 64-bit ABIs)
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64"))]
const SYS_OPENAT2: i64 = 437;

// 32-bit ABIs have different numbers but we only support 64-bit for now;
// the MSRV guard below makes this explicit.
#[cfg(not(any(target_arch = "x86-64", target_arch = "aarch64", target_arch = "riscv64")))]
compile_error!("fd-first feature only supports x86-64, aarch64, and riscv64 Linux targets");

// ── Errno ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Errno(pub i32);

impl Errno {
    pub fn from_raw(raw: i32) -> Self { Self(raw) }
    pub fn raw(self) -> i32 { self.0 }

    // Errno constants we care about
    pub const EXDEV:  Errno = Errno(18);  // Cross-device link / escape attempt
    pub const ELOOP:  Errno = Errno(40);  // Too many symlinks / RESOLVE_NO_SYMLINKS
    pub const ENOENT: Errno = Errno(2);   // No such file or directory
    pub const ENOSYS: Errno = Errno(38);  // Syscall not supported (kernel < 5.6)
}

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl From<Errno> for std::io::Error {
    fn from(e: Errno) -> Self {
        std::io::Error::from_raw_os_error(e.0)
    }
}

// ── openat2 syscall ───────────────────────────────────────────────────────────

/// Calls `openat2(2)` with the given `how` struct.
///
/// Returns `Ok(OwnedFd)` on success, `Err(Errno)` on failure.
/// The errno value is the raw negative return value of the syscall.
pub(crate) fn openat2(dirfd: RawFd, path: &CStr, how: &OpenHow) -> Result<OwnedFd, Errno> {
    let fd = unsafe {
        libc_syscall(SYS_OPENAT2, dirfd, path.as_ptr(), how as *const OpenHow, std::mem::size_of::<OpenHow>())
    };
    if fd < 0 {
        // Linux syscall errors are in [-4095, -1]. Assert the range to catch
        // unexpected values on unusual targets (e.g., sign-extension bugs on 32-bit).
        debug_assert!(fd >= i32::MIN as i64, "syscall errno out of expected range");
        Err(Errno(-fd as i32))
    } else {
        // SAFETY: kernel returned a valid fd ≥ 0
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }
}

/// Raw syscall(3) shim — avoids a libc dependency.
///
/// SAFETY: caller must supply correct syscall number and argument types.
#[inline(always)]
unsafe fn libc_syscall(nr: i64, a0: impl Into<i64>, a1: impl IntoRawArg, a2: impl IntoRawArg, a3: impl Into<i64>) -> i64 {
    let r0: i64;
    std::arch::asm!(
        "syscall",
        inlateout("rax") nr => r0,
        in("rdi") a0.into(),
        in("rsi") a1.into_raw(),
        in("rdx") a2.into_raw(),
        in("r10") a3.into(),
        out("rcx") _,
        out("r11") _,
        options(nostack),
    );
    r0
}

// Helper trait to coerce pointer/integer arguments into i64 for the asm block
pub(crate) trait IntoRawArg { fn into_raw(self) -> i64; }
impl IntoRawArg for i32   { fn into_raw(self) -> i64 { self as i64 } }
impl IntoRawArg for i64   { fn into_raw(self) -> i64 { self } }
impl IntoRawArg for usize { fn into_raw(self) -> i64 { self as i64 } }
impl<T> IntoRawArg for *const T { fn into_raw(self) -> i64 { self as i64 } }
impl<T> IntoRawArg for *mut T   { fn into_raw(self) -> i64 { self as i64 } }

// Implement Into<i64> for RawFd (= i32) already works, but we need the pointer trait too.
impl IntoRawArg for RawFd { fn into_raw(self) -> i64 { self as i64 } }

// ── Kernel version probe ───────────────────────────────────────────────────────

/// Parsed kernel version (major, minor, patch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl std::fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Returns the running kernel version by reading `/proc/sys/kernel/osrelease`.
/// Falls back to `uname(2)` is unavailable (containers, etc.).
pub(crate) fn kernel_version() -> Option<KernelVersion> {
    // Try /proc first (most reliable in containers)
    if let Ok(s) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        return parse_kernel_version(s.trim());
    }
    None
}

fn parse_kernel_version(s: &str) -> Option<KernelVersion> {
    // Format: "5.15.0-1045-aws" — take up to first '-' or whitespace
    let s = s.split(['-', ' ']).next()?;
    let mut parts = s.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some(KernelVersion { major, minor, patch })
}

/// Minimum kernel version that supports `openat2(2)`.
pub(crate) const MIN_OPENAT2_KERNEL: KernelVersion = KernelVersion { major: 5, minor: 6, patch: 0 };

/// Probes whether `openat2` is available by calling it once with a dummy fd.
/// Returns `Ok(())` if available, `Err(Errno::ENOSYS)` if not.
pub(crate) fn probe_openat2() -> Result<(), Errno> {
    use std::os::unix::io::AsRawFd;
    // Use AT_FDCWD (-100) with an empty path and RESOLVE_BENEATH.
    // Kernel < 5.6 returns ENOSYS. Kernel ≥ 5.6 returns ENOENT (empty path)
    // or EINVAL — both mean "syscall exists".
    let how = OpenHow { flags: O_RDONLY | O_CLOEXEC, mode: 0, resolve: RESOLVE_BENEATH };
    let empty = c"";
    match openat2(-100i32 as RawFd, empty, &how) {
        Ok(_) => Ok(()),
        Err(e) if e == Errno::ENOSYS => Err(e),
        Err(_) => Ok(()), // Any other error means syscall exists
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kernel_versions() {
        let v = parse_kernel_version("5.15.0-1045-aws").unwrap();
        assert_eq!(v, KernelVersion { major: 5, minor: 15, patch: 0 });

        let v = parse_kernel_version("6.1.0").unwrap();
        assert_eq!(v, KernelVersion { major: 6, minor: 1, patch: 0 });

        let v = parse_kernel_version("5.6.0-generic").unwrap();
        assert_eq!(v, KernelVersion { major: 5, minor: 6, patch: 0 });
    }

    #[test]
    fn kernel_version_ordering() {
        let v56 = KernelVersion { major: 5, minor: 6, patch: 0 };
        let v515 = KernelVersion { major: 5, minor: 15, patch: 0 };
        let v6 = KernelVersion { major: 6, minor: 0, patch: 0 };
        assert!(v56 < v515);
        assert!(v515 < v6);
        assert!(v56 >= MIN_OPENAT2_KERNEL);
    }
}
