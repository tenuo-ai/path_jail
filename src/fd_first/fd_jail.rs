//! fd-first jail operations backed by `openat2(RESOLVE_BENEATH)` on Linux 5.6+.
//!
//! On macOS/BSDs the same API surface falls back to a `openat(O_NOFOLLOW)` chain
//! (equivalent to what cap-std does on older kernels). The fallback is *not*
//! TOCTOU-safe under concurrent rename attacks; this is reflected in
//! `Attestation::toctou_safe = false`.
//!
//! # Feature flag
//!
//! Enable the `fd-first` feature to opt into this API:
//!
//! ```toml
//! [dependencies]
//! path_jail = { version = "0.4", features = ["fd-first"] }
//! ```

use crate::error::JailError;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

// ── Platform dispatch ─────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
use crate::openat2::{
    kernel_version, probe_openat2, KernelVersion, OpenHow, MIN_OPENAT2_KERNEL, O_APPEND, O_CLOEXEC,
    O_CREAT, O_EXCL, O_RDONLY, O_TRUNC, O_WRONLY, RESOLVE_BENEATH, RESOLVE_NO_MAGICLINKS,
    RESOLVE_NO_SYMLINKS,
};

#[cfg(target_os = "linux")]
use crate::openat2::{openat2, Errno};

// macOS/BSD: no platform import needed; fallback_impl is self-contained

// ── Public types ──────────────────────────────────────────────────────────────

/// A file opened through `Jail::open` or `Jail::create` (fd-first API).
///
/// Holds both the open file descriptor and attestation data recorded at open
/// time. On Linux 5.6+ the open is performed by a single `openat2` syscall and
/// is therefore TOCTOU-safe by construction; on other platforms a fallback path
/// is used and `attestation().toctou_safe` will be `false`.
pub struct JailFile {
    pub(crate) file: File,
    pub(crate) attestation: Attestation,
}

impl JailFile {
    /// Returns a reference to the underlying [`File`].
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Consumes `self` and returns the underlying [`File`].
    pub fn into_file(self) -> File {
        self.file
    }

    /// Returns the attestation recorded when this file was opened.
    pub fn attestation(&self) -> &Attestation {
        &self.attestation
    }

    /// Returns `true` if the file has more than one hard link.
    ///
    /// Hard links cannot be detected before the file is opened. If your
    /// security policy prohibits hard links (e.g., to prevent data exfiltration
    /// via a link to a sensitive file inside the jail), check this *before*
    /// reading or writing:
    ///
    /// ```no_run
    /// # use path_jail::{Jail, fd_first::OpenOptions};
    /// # let jail = Jail::new("/var/uploads").unwrap();
    /// let jf = jail.open_file("report.pdf", OpenOptions::new().read(true)).unwrap();
    /// if jf.has_hard_links() {
    ///     // Reject — policy violation
    ///     return;
    /// }
    /// ```
    pub fn has_hard_links(&self) -> bool {
        self.attestation.nlink > 1
    }
}

impl std::fmt::Debug for JailFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JailFile")
            .field("attestation", &self.attestation)
            .finish_non_exhaustive()
    }
}

impl std::ops::Deref for JailFile {
    type Target = File;
    fn deref(&self) -> &File {
        &self.file
    }
}

impl std::ops::DerefMut for JailFile {
    fn deref_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

impl std::io::Read for JailFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl std::io::Write for JailFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl std::io::Seek for JailFile {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.file.seek(pos)
    }
}

// ── Attestation ───────────────────────────────────────────────────────────────

/// Attestation data recorded at the moment a file is opened through the jail.
///
/// The Ed25519 signature (when present) is the **trust anchor** for all other
/// fields — an attacker who can forge an attestation struct can claim any inode
/// values. Enforcement points **MUST** verify the signature before reading any
/// other field.
///
/// # Signing
///
/// Attestations can be signed with an Ed25519 key by calling
/// `sign_attestation` (see future Ed25519 signing support). Unsigned attestations are valid for logging
/// and debugging but **MUST NOT** be accepted by the Tenuo enforcement point as
/// proof of guard execution.
///
/// # Determinism
///
/// [`content_bytes`](Attestation::content_bytes) returns a canonical serialization
/// of all fields *except* `opened_at` and `signature`. Two calls to `Jail::open`
/// for the same path in the same jail will produce identical `content_bytes`.
/// `opened_at` intentionally differs and is excluded from `content_bytes`.
#[derive(Debug, Clone)]
pub struct Attestation {
    /// Canonicalized jail root at the time of `Jail::new`.
    pub jail_root: PathBuf,
    /// The path that was requested (relative to jail root).
    pub opened_path: PathBuf,
    /// Inode of the jail root directory (from `fstat` on the pinned `dirfd`).
    pub root_inode: u64,
    /// Inode of the opened file (from `fstat` on the opened fd).
    pub file_inode: u64,
    /// Device number (`st_dev`). Same device as root ⇒ hard link detection is valid.
    pub device: u64,
    /// Hard link count (`st_nlink`). Caller decides policy; see [`JailFile::has_hard_links`].
    pub nlink: u64,
    /// `true` if the open used `openat2(RESOLVE_BENEATH)` (Linux 5.6+), `false`
    /// on macOS/BSD fallback path.
    pub toctou_safe: bool,
    /// Timestamp recorded immediately after the file descriptor was obtained.
    pub opened_at: SystemTime,
    /// Ed25519 signature over the wire encoding (see [`content_bytes`](Self::content_bytes)).
    /// `None` if no signing key was configured.
    pub signature: Option<[u8; 64]>,
}

impl Attestation {
    /// Returns the canonical byte representation of all fields **except**
    /// `opened_at` and `signature`.
    ///
    /// Use this for content-equality checks (two opens of the same path should
    /// produce identical `content_bytes`). The full signing wire format (which
    /// *does* include `opened_at`) is what the Ed25519 signature covers; this
    /// helper is not a substitute for signature verification.
    ///
    /// Wire format:
    /// ```text
    /// len(jail_root_bytes)      as u32 LE
    /// || jail_root_bytes
    /// || len(opened_path_bytes) as u32 LE
    /// || opened_path_bytes
    /// || root_inode             as u64 LE
    /// || file_inode             as u64 LE
    /// || device                 as u64 LE
    /// || nlink                  as u64 LE
    /// || toctou_safe            as u8  (1 = true, 0 = false)
    /// ```
    pub fn content_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        encode_path_field(&mut buf, &self.jail_root);
        encode_path_field(&mut buf, &self.opened_path);
        buf.extend_from_slice(&self.root_inode.to_le_bytes());
        buf.extend_from_slice(&self.file_inode.to_le_bytes());
        buf.extend_from_slice(&self.device.to_le_bytes());
        buf.extend_from_slice(&self.nlink.to_le_bytes());
        buf.push(if self.toctou_safe { 1 } else { 0 });
        buf
    }

    /// Returns the full signing wire format (content bytes + `opened_at` nanos).
    ///
    /// This is the byte slice that the Ed25519 signature covers. It is
    /// intentionally not pub — callers will use `JailFile::sign_attestation` (future work).
    #[allow(dead_code)] // Used by future Ed25519 signing integration
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = self.content_bytes();
        let nanos = self
            .opened_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        buf.extend_from_slice(&nanos.to_le_bytes());
        buf
    }
}

fn encode_path_field(buf: &mut Vec<u8>, path: &Path) {
    let bytes = path.as_os_str().as_encoded_bytes();
    let len = bytes.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

// ── OpenOptions ───────────────────────────────────────────────────────────────

/// Options for opening a file through the fd-first API.
///
/// Mirrors the relevant subset of [`std::fs::OpenOptions`].
#[derive(Debug, Clone, Default)]
pub struct OpenOptions {
    pub(crate) read: bool,
    pub(crate) write: bool,
    pub(crate) append: bool,
    pub(crate) truncate: bool,
    pub(crate) create: bool,
    pub(crate) create_new: bool,
    pub(crate) no_symlinks: bool,
}

impl OpenOptions {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn read(mut self, v: bool) -> Self {
        self.read = v;
        self
    }
    pub fn write(mut self, v: bool) -> Self {
        self.write = v;
        self
    }
    pub fn append(mut self, v: bool) -> Self {
        self.append = v;
        self
    }
    pub fn truncate(mut self, v: bool) -> Self {
        self.truncate = v;
        self
    }
    /// Create the file if it does not exist (requires `write` or `append`).
    pub fn create(mut self, v: bool) -> Self {
        self.create = v;
        self
    }
    /// Fail if the file already exists (`O_CREAT | O_EXCL`).
    pub fn create_new(mut self, v: bool) -> Self {
        self.create_new = v;
        self
    }
    /// Reject any symlinks inside the jail (Linux: `RESOLVE_NO_SYMLINKS`).
    pub fn no_symlinks(mut self, v: bool) -> Self {
        self.no_symlinks = v;
        self
    }
}

// ── Linux implementation ──────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use crate::openat2::{
        kernel_version, openat2, probe_openat2, Errno, KernelVersion, OpenHow, MIN_OPENAT2_KERNEL,
        O_APPEND, O_CLOEXEC, O_CREAT, O_EXCL, O_RDONLY, O_TRUNC, O_WRONLY, RESOLVE_BENEATH,
        RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS,
    };
    use std::ffi::CString;
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

    /// Implementation of `Jail::open_file` on Linux using `openat2`.
    pub(crate) fn jail_open(
        dirfd: &OwnedFd,
        jail_root: &Path,
        root_inode: u64,
        rel_path: &Path,
        opts: &OpenOptions,
    ) -> Result<JailFile, JailError> {
        // Build the relative CStr path (openat2 requires relative for RESOLVE_BENEATH)
        let path_str = rel_path
            .to_str()
            .ok_or_else(|| JailError::InvalidPath("path contains invalid UTF-8".into()))?;
        if path_str.contains('\0') {
            return Err(JailError::InvalidPath("null bytes not allowed".into()));
        }
        let cpath = CString::new(path_str)
            .map_err(|_| JailError::InvalidPath("could not convert path to C string".into()))?;

        // Build O_* flags
        let mut flags: u64 = O_CLOEXEC;
        if opts.read && !opts.write && !opts.append {
            flags |= O_RDONLY;
        }
        if opts.write {
            flags |= O_WRONLY;
        }
        if opts.append {
            flags |= O_APPEND | O_WRONLY;
        }
        if opts.create {
            flags |= O_CREAT;
        }
        if opts.create_new {
            flags |= O_CREAT | O_EXCL;
        }
        if opts.truncate {
            flags |= O_TRUNC;
        }
        // Default: read-only
        if flags == O_CLOEXEC {
            flags |= O_RDONLY;
        }

        // Build RESOLVE_* flags
        let mut resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
        if opts.no_symlinks {
            resolve |= RESOLVE_NO_SYMLINKS;
        }

        let how = OpenHow {
            flags,
            mode: 0o666,
            resolve,
        };

        let owned_fd = openat2(dirfd.as_raw_fd(), &cpath, &how)
            .map_err(|e| map_errno_to_jail_error(e, rel_path))?;

        // fstat the opened fd for attestation
        let file_stat = fstat(owned_fd.as_raw_fd()).map_err(JailError::Io)?;
        let file: File = unsafe { File::from_raw_fd(owned_fd.into_raw_fd()) };

        let attestation = Attestation {
            jail_root: jail_root.to_path_buf(),
            opened_path: rel_path.to_path_buf(),
            root_inode,
            file_inode: file_stat.ino,
            device: file_stat.dev,
            nlink: file_stat.nlink,
            toctou_safe: true,
            opened_at: SystemTime::now(),
            signature: None,
        };

        Ok(JailFile { file, attestation })
    }

    fn map_errno_to_jail_error(e: Errno, path: &Path) -> JailError {
        match e {
            Errno::EXDEV => JailError::Escape { requested: path.to_path_buf() },
            Errno::ELOOP => JailError::SymlinkRejected { requested: path.to_path_buf() },
            _ if e.raw() == 105 /* ENOLINK — magic link on some kernels */ =>
                JailError::MagicLink { requested: path.to_path_buf() },
            _ => JailError::Io(e.into()),
        }
    }

    // ── stat(2) without libc ───────────────────────────────────────────────────

    pub(crate) struct StatResult {
        pub dev: u64,
        pub ino: u64,
        pub nlink: u64,
    }

    /// `fstat(2)` via raw syscall — avoids libc.
    pub(crate) fn fstat(fd: i32) -> std::io::Result<StatResult> {
        // stat64 layout (x86-64 / aarch64)
        #[repr(C)]
        struct Stat64 {
            st_dev: u64,
            st_ino: u64,
            st_nlink: u64,
            st_mode: u32,
            st_uid: u32,
            st_gid: u32,
            _pad0: u32,
            st_rdev: u64,
            st_size: i64,
            st_blksize: i64,
            st_blocks: i64,
            st_atime: i64,
            st_atime_ns: i64,
            st_mtime: i64,
            st_mtime_ns: i64,
            st_ctime: i64,
            st_ctime_ns: i64,
            _unused: [i64; 3],
        }

        let mut stat = std::mem::MaybeUninit::<Stat64>::zeroed();
        let ret: i64;
        unsafe {
            std::arch::asm!(
                "syscall",
                inlateout("rax") 5i64 /* SYS_fstat */ => ret,
                in("rdi") fd,
                in("rsi") stat.as_mut_ptr(),
                out("rcx") _,
                out("r11") _,
                options(nostack),
            );
        }
        if ret < 0 {
            return Err(std::io::Error::from_raw_os_error(-ret as i32));
        }
        let s = unsafe { stat.assume_init() };
        Ok(StatResult {
            dev: s.st_dev,
            ino: s.st_ino,
            nlink: s.st_nlink,
        })
    }

    /// fstat the dirfd at Jail::new time to pin the root inode.
    pub(crate) fn stat_dirfd(fd: &OwnedFd) -> std::io::Result<StatResult> {
        fstat(fd.as_raw_fd())
    }
}

// ── macOS / BSD fallback ──────────────────────────────────────────────────────

#[cfg(not(target_os = "linux"))]
mod fallback_impl {
    use super::*;
    use std::os::unix::fs::OpenOptionsExt;

    // O_NOFOLLOW — protects the final path component only
    #[cfg(target_os = "macos")]
    const O_NOFOLLOW: i32 = 0x0100;
    #[cfg(not(target_os = "macos"))]
    const O_NOFOLLOW: i32 = 0x0100; // same on *BSDs

    pub(crate) fn jail_open(
        jail_root: &Path,
        root_inode: u64,
        rel_path: &Path,
        opts: &OpenOptions,
    ) -> Result<JailFile, JailError> {
        // Validate via existing path-walking logic first
        let abs_path = {
            let jail = crate::jail::Jail::new(jail_root)?;
            jail.join(rel_path)?
        };

        let mut oo = std::fs::OpenOptions::new();
        if opts.read {
            oo.read(true);
        }
        if opts.write {
            oo.write(true);
        }
        if opts.append {
            oo.append(true);
        }
        if opts.truncate {
            oo.truncate(true);
        }
        if opts.create {
            oo.create(true);
        }
        if opts.create_new {
            oo.create_new(true);
        }
        if !opts.read && !opts.write && !opts.append {
            oo.read(true);
        }
        oo.custom_flags(O_NOFOLLOW);

        let file = oo.open(&abs_path).map_err(JailError::Io)?;

        // fstat via std::fs::metadata on the file
        let meta = file.metadata().map_err(JailError::Io)?;
        use std::os::unix::fs::MetadataExt;

        let attestation = Attestation {
            jail_root: jail_root.to_path_buf(),
            opened_path: rel_path.to_path_buf(),
            root_inode,
            file_inode: meta.ino(),
            device: meta.dev(),
            nlink: meta.nlink(),
            toctou_safe: false, // macOS fallback is not TOCTOU-safe
            opened_at: SystemTime::now(),
            signature: None,
        };

        Ok(JailFile { file, attestation })
    }
}

// ── Jail fd-first methods ─────────────────────────────────────────────────────

// (macOS fallback uses crate::jail::Jail internally in fallback_impl)

/// Returns the O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC flags for opening a directory fd.
/// Used when pinning the jail root dirfd on Linux.
#[cfg(target_os = "linux")]
fn libc_open_directory_flags() -> i32 {
    // O_RDONLY=0, O_NOFOLLOW=0x20000 (linux), O_DIRECTORY=0x10000, O_CLOEXEC=0x80000
    0o0_200000 | 0o0_400000 | 0o2_000000 // O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
}

/// State held by the fd-first `Jail` extension (stored alongside the path-based Jail).
///
/// On Linux this holds an open `dirfd` pinned at `Jail::new` time; on other
/// platforms we derive the root inode from `std::fs::metadata`.
pub struct FdJail {
    /// Canonicalized jail root (same as `Jail::root()`).
    pub(crate) root: PathBuf,
    /// Root inode pinned at construction time.
    pub(crate) root_inode: u64,
    /// Open directory fd (Linux only).
    #[cfg(target_os = "linux")]
    pub(crate) dirfd: std::os::unix::io::OwnedFd,
}

impl FdJail {
    /// Open the jail root directory and pin its inode.
    ///
    /// On Linux 5.6+ this also verifies that `openat2` is available.
    /// Returns `JailError::UnsupportedKernel` if the kernel is too old
    /// and the `fd-first-fallback` feature is not enabled.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, JailError> {
        let root = root.as_ref().canonicalize().map_err(JailError::Io)?;

        if root.parent().is_none() || !root.is_dir() {
            return Err(JailError::InvalidJailRoot {
                path: root,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "not a directory or is filesystem root",
                ),
            });
        }

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::{AsRawFd, FromRawFd};

            // Check kernel version first for a friendly error message.
            if let Some(kv) = crate::openat2::kernel_version() {
                if kv < MIN_OPENAT2_KERNEL {
                    return Err(JailError::UnsupportedKernel { version: kv });
                }
            }
            // Probe via actual syscall — authoritative even in containers that
            // hide the kernel version.
            crate::openat2::probe_openat2().map_err(|_| {
                let version = crate::openat2::kernel_version().unwrap_or(KernelVersion {
                    major: 0,
                    minor: 0,
                    patch: 0,
                });
                JailError::UnsupportedKernel { version }
            })?;

            // Open the jail root directory with O_DIRECTORY so the fd is a
            // directory fd we can use as `dirfd` for subsequent openat2 calls.
            // We use std::fs::File for the open itself to avoid duplicating
            // another raw path-to-fd helper.
            use std::os::unix::fs::OpenOptionsExt;
            let dir_file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc_open_directory_flags())
                .open(&root)
                .map_err(JailError::Io)?;

            // SAFETY: dir_file is open and valid; we immediately wrap it.
            let raw_fd = dir_file.as_raw_fd();
            let stat = linux_impl::fstat(raw_fd).map_err(JailError::Io)?;
            // Transfer ownership into OwnedFd (File will not close it).
            let dirfd = unsafe {
                std::os::unix::io::OwnedFd::from_raw_fd(std::os::unix::io::IntoRawFd::into_raw_fd(
                    dir_file,
                ))
            };
            return Ok(FdJail {
                root,
                root_inode: stat.ino,
                dirfd,
            });
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Emit a compile-time note (not an error — fallback is allowed)
            let meta = std::fs::metadata(&root).map_err(JailError::Io)?;
            use std::os::unix::fs::MetadataExt;
            Ok(FdJail {
                root,
                root_inode: meta.ino(),
            })
        }
    }

    /// Opens a file relative to the jail root.
    ///
    /// On Linux 5.6+ this is a single `openat2(RESOLVE_BENEATH)` syscall and is
    /// **TOCTOU-safe by construction**. On macOS/BSD the fallback path validates
    /// with `O_NOFOLLOW` on the final component; `attestation().toctou_safe` will
    /// be `false`.
    ///
    /// Returns a [`JailFile`] containing both the open [`File`] and attestation data.
    pub fn open(&self, path: impl AsRef<Path>, opts: OpenOptions) -> Result<JailFile, JailError> {
        let rel = self.validate_relative(path.as_ref())?;

        #[cfg(target_os = "linux")]
        return linux_impl::jail_open(&self.dirfd, &self.root, self.root_inode, &rel, &opts);

        #[cfg(not(target_os = "linux"))]
        return fallback_impl::jail_open(&self.root, self.root_inode, &rel, &opts);
    }

    /// Creates a new file relative to the jail root.
    ///
    /// Uses `O_CREAT | O_EXCL` — fails if the file already exists.
    /// The parent directory **must** already exist; this method does not create
    /// intermediate directories.
    pub fn create(&self, path: impl AsRef<Path>) -> Result<JailFile, JailError> {
        self.open(path, OpenOptions::new().write(true).create_new(true))
    }

    /// Validates a path without opening a file descriptor.
    ///
    /// Returns the validated relative path if it is safe. This is **weaker** than
    /// [`open`](Self::open) because it does not hold an fd. Use it only for
    /// logging or display purposes.
    ///
    /// # ⚠ Warning
    ///
    /// The returned `PathBuf` **MUST NOT** be passed to a subsequent `open` call.
    /// Doing so reintroduces the TOCTOU window that `open` eliminates. Use
    /// `open` if you intend to access the file.
    pub fn check(&self, path: impl AsRef<Path>) -> Result<PathBuf, JailError> {
        self.validate_relative(path.as_ref())
    }

    /// Returns the canonicalized jail root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    /// Normalise and basic-validate a relative path before handing it to the
    /// kernel. This is not the security check — `openat2` is — but it keeps
    /// userspace errors (absolute paths, null bytes) out of the kernel.
    fn validate_relative(&self, path: &Path) -> Result<PathBuf, JailError> {
        let s = path
            .to_str()
            .ok_or_else(|| JailError::InvalidPath("path contains invalid UTF-8".into()))?;
        if s.contains('\0') {
            return Err(JailError::InvalidPath("null bytes not allowed".into()));
        }
        if path.is_absolute() {
            return Err(JailError::InvalidPath("path must be relative".into()));
        }
        Ok(path.to_path_buf())
    }
}

impl std::fmt::Debug for FdJail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FdJail")
            .field("root", &self.root)
            .field("root_inode", &self.root_inode)
            .field("toctou_safe", &cfg!(target_os = "linux"))
            .finish()
    }
}
