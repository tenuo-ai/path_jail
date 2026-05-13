//! Raw `openat2(2)` syscall wrapper and kernel version detection.
//!
//! No libc, no rustix — just `std` and a raw syscall number.
//! Only compiled on Linux; the macOS/BSDs fallback path lives in `fd_jail.rs`.

#![cfg(target_os = "linux")]

use std::ffi::CStr;
use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use std::sync::OnceLock;

// ── Architecture guard ────────────────────────────────────────────────────────

// The inline-asm syscall shim is implemented for x86_64 and aarch64.
// riscv64 uses a different register convention (a7/a0-a5) and is not yet
// supported. Reject other architectures with a compile error rather than
// silently producing broken binaries.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "path_jail guard: only x86_64 and aarch64 Linux are currently supported for the raw-asm syscall path. \
     riscv64 support is planned. Track: https://github.com/tenuo-ai/path_jail/issues"
);

// SYS_openat2 — syscall number on Linux (added in 5.6). Same value on x86_64
// and aarch64 (the kernel keeps recent syscall numbers aligned across arches).
const SYS_OPENAT2: i64 = 437;

// ── open_how layout (linux/openat2.h) ────────────────────────────────────────

#[repr(C)]
pub(crate) struct OpenHow {
    pub flags: u64,   // O_RDONLY, O_WRONLY, O_CREAT, etc.
    pub mode: u64,    // creation mode; 0 for reads
    pub resolve: u64, // RESOLVE_* flags
}

// RESOLVE_* flags (linux/openat2.h)
pub(crate) const RESOLVE_BENEATH: u64 = 0x08;
pub(crate) const RESOLVE_NO_SYMLINKS: u64 = 0x04;
pub(crate) const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
pub(crate) const RESOLVE_NO_XDEV: u64 = 0x01;

// O_* flags (x86_64 Linux)
pub(crate) const O_RDONLY: u64 = 0;
pub(crate) const O_WRONLY: u64 = 1;
#[allow(dead_code)]
pub(crate) const O_RDWR: u64 = 2;
pub(crate) const O_CREAT: u64 = 0o100;
pub(crate) const O_EXCL: u64 = 0o200;
pub(crate) const O_TRUNC: u64 = 0o1000;
pub(crate) const O_APPEND: u64 = 0o2000;
pub(crate) const O_CLOEXEC: u64 = 0o2000000;

// ── Errno ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Errno(pub i32);

impl Errno {
    // Errno constants we care about
    pub const EXDEV: Errno = Errno(18); // Cross-device link / escape attempt
    pub const ELOOP: Errno = Errno(40); // Too many symlinks / RESOLVE_NO_SYMLINKS
    pub const ENOSYS: Errno = Errno(38); // Syscall not supported (kernel < 5.6)
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
        syscall4(
            SYS_OPENAT2,
            dirfd as i64,
            path.as_ptr() as i64,
            how as *const OpenHow as i64,
            std::mem::size_of::<OpenHow>() as i64,
        )
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

/// Raw 4-argument syscall shim — avoids a libc dependency.
///
/// # Safety
///
/// Caller must supply the correct syscall number and argument types.
/// Undefined behaviour if arguments do not match the kernel ABI for `nr`.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall4(nr: i64, a0: i64, a1: i64, a2: i64, a3: i64) -> i64 {
    let ret: i64;
    // x86_64 Linux syscall ABI:
    //   nr  → rax (inlateout so the return value lands back in rax)
    //   a0  → rdi
    //   a1  → rsi
    //   a2  → rdx
    //   a3  → r10  (NOT rcx — the kernel uses rcx internally for SYSCALL)
    // rcx and r11 are clobbered by SYSCALL.
    std::arch::asm!(
        "syscall",
        inlateout("rax") nr => ret,
        in("rdi") a0,
        in("rsi") a1,
        in("rdx") a2,
        in("r10") a3,
        out("rcx") _,
        out("r11") _,
        options(nostack),
    );
    ret
}

/// aarch64 Linux variant of [`syscall4`].
///
/// # Safety
///
/// Same contract as the x86_64 variant — caller supplies a valid syscall
/// number and matching arguments.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall4(nr: i64, a0: i64, a1: i64, a2: i64, a3: i64) -> i64 {
    let ret: i64;
    // aarch64 Linux syscall ABI:
    //   nr  → x8
    //   a0  → x0  (inout so the return value lands back in x0)
    //   a1  → x1
    //   a2  → x2
    //   a3  → x3
    // The svc #0 instruction triggers the syscall; the kernel preserves
    // all callee-saved registers, so no explicit clobbers are needed.
    std::arch::asm!(
        "svc #0",
        in("x8") nr,
        inout("x0") a0 => ret,
        in("x1") a1,
        in("x2") a2,
        in("x3") a3,
        options(nostack),
    );
    ret
}

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

/// Minimum kernel version that supports `openat2(2)`.
pub(crate) const MIN_OPENAT2_KERNEL: KernelVersion = KernelVersion {
    major: 5,
    minor: 6,
    patch: 0,
};

/// Returns the running kernel version, cached after the first call.
///
/// Reads `/proc/sys/kernel/osrelease` on the first call and caches the result
/// in a `OnceLock`. Returns `None` if the file is unreadable (some containers
/// restrict `/proc` access).
pub(crate) fn kernel_version() -> Option<KernelVersion> {
    static CACHED: OnceLock<Option<KernelVersion>> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .and_then(|s| parse_kernel_version(s.trim()))
    })
}

fn parse_kernel_version(s: &str) -> Option<KernelVersion> {
    // Format: "5.15.0-1045-aws" — strip everything from the first '-' or space.
    // This correctly handles distro suffixes like -aws, -generic, -microsoft-standard.
    let s = s.split(['-', ' ']).next()?;
    let mut parts = s.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some(KernelVersion {
        major,
        minor,
        patch,
    })
}

/// Probes whether `openat2` is available via a single live syscall, cached.
///
/// Uses `AT_FDCWD` (-100) with an empty path and `RESOLVE_BENEATH`.
/// - Kernel < 5.6 → `ENOSYS` → `Err(Errno::ENOSYS)`
/// - Kernel ≥ 5.6 → `ENOENT` or `EINVAL` (empty path) → `Ok(())`
///
/// The result is cached in a `OnceLock` so repeated calls to `FdJail::new`
/// in tight loops do not re-probe the kernel every time.
pub(crate) fn probe_openat2() -> Result<(), Errno> {
    static CACHED: OnceLock<Result<(), Errno>> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let how = OpenHow {
            flags: O_RDONLY | O_CLOEXEC,
            mode: 0,
            resolve: RESOLVE_BENEATH,
        };
        let empty = c"";
        match openat2(-100i32 as RawFd, empty, &how) {
            Ok(_) => Ok(()),
            Err(e) if e == Errno::ENOSYS => Err(e),
            Err(_) => Ok(()), // Any other error means the syscall exists
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kernel_versions() {
        let v = parse_kernel_version("5.15.0-1045-aws").unwrap();
        assert_eq!(
            v,
            KernelVersion {
                major: 5,
                minor: 15,
                patch: 0
            }
        );

        let v = parse_kernel_version("6.1.0").unwrap();
        assert_eq!(
            v,
            KernelVersion {
                major: 6,
                minor: 1,
                patch: 0
            }
        );

        let v = parse_kernel_version("5.6.0-generic").unwrap();
        assert_eq!(
            v,
            KernelVersion {
                major: 5,
                minor: 6,
                patch: 0
            }
        );

        // microsoft-standard suffix (WSL2)
        let v = parse_kernel_version("5.15.153.1-microsoft-standard-WSL2").unwrap();
        assert_eq!(
            v,
            KernelVersion {
                major: 5,
                minor: 15,
                patch: 153
            }
        );
    }

    #[test]
    fn kernel_version_ordering() {
        let v56 = KernelVersion {
            major: 5,
            minor: 6,
            patch: 0,
        };
        let v515 = KernelVersion {
            major: 5,
            minor: 15,
            patch: 0,
        };
        let v6 = KernelVersion {
            major: 6,
            minor: 0,
            patch: 0,
        };
        assert!(v56 < v515);
        assert!(v515 < v6);
        assert!(v56 >= MIN_OPENAT2_KERNEL);
    }

    #[test]
    fn probe_is_cached() {
        // Calling probe twice should not do two syscalls (OnceLock ensures this).
        // We can't directly observe the call count without mocking, but we can
        // verify the result is consistent across calls.
        let r1 = probe_openat2();
        let r2 = probe_openat2();
        assert_eq!(r1.is_ok(), r2.is_ok());
    }

    #[test]
    fn kernel_version_is_cached() {
        let v1 = kernel_version();
        let v2 = kernel_version();
        assert_eq!(v1, v2);
    }
}
