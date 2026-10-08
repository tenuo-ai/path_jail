//! fd-first jail operations backed by `openat2(RESOLVE_BENEATH)` on Linux 5.6+.
//!
//! On macOS/BSDs the same API surface falls back to a `openat(O_NOFOLLOW)` chain
//! (equivalent to what cap-std does on older kernels). The fallback is *not*
//! TOCTOU-safe under concurrent rename attacks; this is reflected in
//! `Attestation::toctou_safe = false`.
//!
//! # Feature flag
//!
//! Enable the `guard` feature to opt into this API:
//!
//! ```toml
//! [dependencies]
//! path_jail = { version = "0.4", features = ["guard"] }
//! ```

use crate::error::JailError;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

// "openat2-capable" platforms: Linux on x86_64 or aarch64.
// All other platforms (macOS, BSD, Windows, and Linux on other arches such as
// riscv64/s390x/loongarch64) use the O_NOFOLLOW fallback with toctou_safe=false.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use crate::openat2::{kernel_version as openat2_kernel_version, probe_openat2, MIN_OPENAT2_KERNEL};

// ── Public types ──────────────────────────────────────────────────────────────

/// A file opened through [`FdJail::open`] or [`FdJail::create`] (guard API).
///
/// Holds both the open file descriptor and attestation data recorded at open
/// time. On Linux 5.6+ the open is performed by a single `openat2` syscall and
/// is therefore TOCTOU-safe by construction; on other platforms a fallback path
/// is used and `attestation().toctou_safe` will be `false`.
///
/// See [`JailedFile`](crate::JailedFile) for the lighter `secure-open` variant
/// that uses `O_NOFOLLOW` without an `Attestation`.
pub struct GuardedFile {
    pub(crate) file: File,
    pub(crate) attestation: Attestation,
}

impl GuardedFile {
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
    /// # use path_jail::guard::{FdJail, OpenOptions};
    /// # let jail = FdJail::new("/var/uploads").unwrap();
    /// let jf = jail.open("report.pdf", OpenOptions::new().read(true)).unwrap();
    /// if jf.has_hard_links() {
    ///     // Reject — policy violation
    ///     return;
    /// }
    /// ```
    pub fn has_hard_links(&self) -> bool {
        self.attestation.nlink > 1
    }

    /// Signs this file's attestation with the given signer and returns a
    /// new [`Attestation`] with `signature` populated.
    ///
    /// The signature covers [`Attestation::signing_bytes`] — the canonical
    /// fixed-layout encoding of every attestation field including `opened_at`.
    ///
    /// path_jail does not vendor a signing implementation; provide one by
    /// implementing the [`Signer`](crate::guard::Signer) trait. See the
    /// [`signing`](crate::guard) module docs for an `ed25519-dalek` example.
    pub fn sign_attestation<S: crate::guard::Signer>(
        &self,
        signer: &S,
    ) -> Result<Attestation, S::Error> {
        let mut att = self.attestation.clone();
        att.signature = Some(signer.sign(&att.signing_bytes())?);
        Ok(att)
    }
}

impl std::fmt::Debug for GuardedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardedFile")
            .field("attestation", &self.attestation)
            .finish_non_exhaustive()
    }
}

impl std::ops::Deref for GuardedFile {
    type Target = File;
    fn deref(&self) -> &File {
        &self.file
    }
}

impl std::ops::DerefMut for GuardedFile {
    fn deref_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

impl std::io::Read for GuardedFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl std::io::Write for GuardedFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl std::io::Seek for GuardedFile {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.file.seek(pos)
    }
}

#[cfg(unix)]
impl std::os::unix::io::AsFd for GuardedFile {
    fn as_fd(&self) -> std::os::unix::io::BorrowedFd<'_> {
        self.file.as_fd()
    }
}

#[cfg(unix)]
impl std::os::unix::io::AsRawFd for GuardedFile {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.file.as_raw_fd()
    }
}

// ── Attestation ───────────────────────────────────────────────────────────────

/// Attestation data recorded at the moment a file is opened through the jail.
///
/// This struct is `#[non_exhaustive]`: new fields may be added in future minor
/// releases. Construct attestations only via [`FdJail::open`] / [`FdJail::create`];
/// do not construct them in struct-literal syntax in your own code.
///
/// The Ed25519 signature (when present) is the **trust anchor** for all other
/// fields — an attacker who can forge an attestation struct can claim any inode
/// values. Enforcement points **MUST** verify the signature before reading any
/// other field.
///
/// # Signing
///
/// Sign an attestation by calling [`GuardedFile::sign_attestation`] with any type
/// that implements the [`Signer`](crate::guard::Signer) trait. The library does
/// not vendor a crypto implementation — bring your own (`ed25519-dalek`,
/// `ring`, HSM, KMS, etc.). See the [`signing`](crate::guard) module for
/// examples.
///
/// Verify a received attestation with [`Attestation::verify`]. Unsigned
/// attestations are valid for logging and debugging but **MUST NOT** be
/// accepted by the Tenuo enforcement point as proof of guard execution.
///
/// # Determinism
///
/// [`content_bytes`](Attestation::content_bytes) returns a canonical serialization
/// of all fields *except* `opened_at` and `signature`. Two calls to `Jail::open`
/// for the same path in the same jail will produce identical `content_bytes`.
/// `opened_at` intentionally differs and is excluded from `content_bytes`.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
    /// Hard link count (`st_nlink`). Caller decides policy; see [`GuardedFile::has_hard_links`].
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
    /// This is the exact byte slice that a [`Signer`](crate::guard::Signer)
    /// produces a signature over, and that a
    /// [`Verifier`](crate::guard::Verifier) must replay during verification.
    /// Exposed publicly so enforcement points outside this crate can perform
    /// their own verification without going through [`Attestation::verify`].
    ///
    /// Format: [`content_bytes`](Self::content_bytes) followed by
    /// `opened_at` (nanoseconds since UNIX_EPOCH) as `u64 LE`.
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

    /// Verifies this attestation's signature with the given verifier.
    ///
    /// Returns `Ok(())` only if a signature is present **and** the verifier
    /// accepts it. Unsigned attestations return
    /// [`VerifyError::NotSigned`](crate::guard::VerifyError::NotSigned);
    /// signed-but-invalid attestations return
    /// [`VerifyError::Invalid`](crate::guard::VerifyError::Invalid) wrapping
    /// the verifier's own error.
    ///
    /// Enforcement points should call this **before** trusting any other
    /// attestation field — see the type-level docs for the rationale.
    pub fn verify<V: crate::guard::Verifier>(
        &self,
        verifier: &V,
    ) -> Result<(), crate::guard::VerifyError<V::Error>> {
        let sig = self.signature.ok_or(crate::guard::VerifyError::NotSigned)?;
        verifier
            .verify(&self.signing_bytes(), &sig)
            .map_err(crate::guard::VerifyError::Invalid)
    }
}

fn encode_path_field(buf: &mut Vec<u8>, path: &Path) {
    let bytes = path.as_os_str().as_encoded_bytes();
    let len = bytes.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

// ── OpenOptions ───────────────────────────────────────────────────────────────

/// Options for opening a file through the guard API.
///
/// Mirrors the relevant subset of [`std::fs::OpenOptions`].
///
/// # Mount-point containment
///
/// By default the kernel allows traversal across mount points inside the jail
/// root (bind mounts, overlayfs layers, etc. that have been mounted into the
/// jail directory tree are reachable). If your threat model requires strict
/// filesystem-volume containment — e.g., to defend against a privileged process
/// bind-mounting external content into the jail — opt in via
/// [`no_xdev`](Self::no_xdev). On Linux this maps to `RESOLVE_NO_XDEV`; on the
/// macOS/BSD fallback it is a no-op (the fallback has no equivalent
/// kernel-enforced flag).
#[derive(Debug, Clone, Default)]
pub struct OpenOptions {
    pub(crate) read: bool,
    pub(crate) write: bool,
    pub(crate) append: bool,
    pub(crate) truncate: bool,
    pub(crate) create: bool,
    pub(crate) create_new: bool,
    pub(crate) no_symlinks: bool,
    pub(crate) no_xdev: bool,
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
    ///
    /// On the macOS/BSD fallback this is a no-op — `O_NOFOLLOW` protects only
    /// the final path component; intermediate symlinks are not blocked.
    pub fn no_symlinks(mut self, v: bool) -> Self {
        self.no_symlinks = v;
        self
    }

    /// Block traversal across mount points (Linux: `RESOLVE_NO_XDEV`).
    ///
    /// When enabled, `openat2` returns `EXDEV` (mapped to [`JailError::Escape`])
    /// if any path component crosses a mount point. Use this to defend against
    /// bind-mount escapes when an attacker may have mounted external content
    /// inside the jail directory.
    ///
    /// On the macOS/BSD fallback this is a no-op — the fallback has no
    /// equivalent flag and cannot enforce mount-point containment.
    pub fn no_xdev(mut self, v: bool) -> Self {
        self.no_xdev = v;
        self
    }

    fn validate(&self) -> Result<(), JailError> {
        let can_write = self.write || self.append;
        if (self.create || self.create_new) && !can_write {
            return Err(JailError::InvalidPath(
                "create/create_new requires write or append access".into(),
            ));
        }
        if self.truncate && !self.write {
            return Err(JailError::InvalidPath(
                "truncate requires write access".into(),
            ));
        }
        if self.truncate && self.append {
            return Err(JailError::InvalidPath(
                "truncate cannot be combined with append".into(),
            ));
        }
        Ok(())
    }
}

// ── ResolveOptions ────────────────────────────────────────────────────────────

/// Path-resolution options for the guard mutation operations
/// (`FdJail::create_dir_with`, `remove_file_with`, `remove_dir_with` and
/// `rename_with`; Linux x86_64/aarch64 only).
///
/// These apply to resolving the parent directory of each path. The final
/// component is never followed: `unlinkat` and `renameat2` act on a symlink
/// itself, and `mkdirat` fails if the name already exists.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResolveOptions {
    pub(crate) no_symlinks: bool,
    pub(crate) no_xdev: bool,
}

impl ResolveOptions {
    /// Default options: symlinks and mount crossings inside the jail are allowed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reject any symlink in the parent path (`RESOLVE_NO_SYMLINKS`).
    pub fn no_symlinks(mut self, v: bool) -> Self {
        self.no_symlinks = v;
        self
    }

    /// Reject parent paths that cross a mount point (`RESOLVE_NO_XDEV`).
    ///
    /// Same bind-mount defense as [`OpenOptions::no_xdev`].
    pub fn no_xdev(mut self, v: bool) -> Self {
        self.no_xdev = v;
        self
    }
}

// ── Linux implementation ──────────────────────────────────────────────────────

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux_impl {
    use super::*;
    use crate::openat2::{
        mkdirat, openat2, renameat2, unlinkat, Errno, OpenHow, AT_REMOVEDIR, O_APPEND, O_CLOEXEC,
        O_CREAT, O_DIRECTORY, O_EXCL, O_PATH, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, RESOLVE_BENEATH,
        RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS, RESOLVE_NO_XDEV,
    };
    use std::ffi::CString;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};

    /// Implementation of [`FdJail::open`] on Linux using `openat2`.
    pub(crate) fn jail_open(
        dirfd: &OwnedFd,
        jail_root: &Path,
        root_inode: u64,
        rel_path: &Path,
        opts: &OpenOptions,
    ) -> Result<GuardedFile, JailError> {
        // Build the relative CStr path (openat2 requires relative for RESOLVE_BENEATH)
        use std::os::unix::ffi::OsStrExt;
        let cpath = CString::new(rel_path.as_os_str().as_bytes())
            .map_err(|_| JailError::InvalidPath("could not convert path to C string".into()))?;

        // Build the access mode independently from O_APPEND. This matches
        // std::fs::OpenOptions: read+write/append means O_RDWR, not O_WRONLY.
        let mut flags: u64 = O_CLOEXEC;
        let wants_write = opts.write || opts.append;
        flags |= match (opts.read, wants_write) {
            (true, true) => O_RDWR,
            (false, true) => O_WRONLY,
            _ => O_RDONLY,
        };
        if opts.append {
            flags |= O_APPEND;
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

        // Build RESOLVE_* flags
        let mut resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
        if opts.no_symlinks {
            resolve |= RESOLVE_NO_SYMLINKS;
        }
        if opts.no_xdev {
            resolve |= RESOLVE_NO_XDEV;
        }

        // Per openat2(2): `mode` MUST be 0 unless O_CREAT or O_TMPFILE is set,
        // otherwise the kernel returns EINVAL. We do not use O_TMPFILE.
        let mode: u64 = if flags & O_CREAT != 0 { 0o666 } else { 0 };

        let how = OpenHow {
            flags,
            mode,
            resolve,
        };

        let owned_fd = openat2(dirfd.as_raw_fd(), &cpath, &how)
            .map_err(|e| map_errno_to_jail_error(e, rel_path))?;

        // Read attestation fields via File::metadata — uses std's portable stat
        // wrapper and avoids arch-specific struct stat layouts. The fd ownership
        // moves into File so it closes when the JailFile drops.
        let file: File = unsafe { File::from_raw_fd(owned_fd.into_raw_fd()) };
        let meta = file.metadata().map_err(JailError::Io)?;

        let attestation = Attestation {
            jail_root: jail_root.to_path_buf(),
            opened_path: rel_path.to_path_buf(),
            root_inode,
            file_inode: meta.ino(),
            device: meta.dev(),
            nlink: meta.nlink(),
            toctou_safe: true,
            opened_at: SystemTime::now(),
            signature: None,
        };

        Ok(GuardedFile { file, attestation })
    }

    fn map_errno_to_jail_error(e: Errno, path: &Path) -> JailError {
        // openat2(2) consolidates magic-link rejection (RESOLVE_NO_MAGICLINKS)
        // and symlink rejection (RESOLVE_NO_SYMLINKS / symlink loop) into the
        // SAME errno: ELOOP. Userspace cannot distinguish a magic-link
        // rejection from an ordinary symlink rejection from the errno alone.
        // We therefore map ELOOP to `SymlinkRejected` uniformly; the
        // `MagicLink` variant is reserved for a future kernel ABI change that
        // separates the two (e.g., a distinct ENOLINK or new errno).
        match e {
            Errno::EXDEV => JailError::Escape {
                requested: path.to_path_buf(),
            },
            Errno::ELOOP => JailError::SymlinkRejected {
                requested: path.to_path_buf(),
            },
            _ => JailError::Io(e.into()),
        }
    }

    /// Resolve `path` exactly as `open` would (`RESOLVE_BENEATH |
    /// RESOLVE_NO_MAGICLINKS`) without opening the file for I/O.
    ///
    /// Returns `Ok(true)` if it resolves, `Ok(false)` if a component does not
    /// exist yet, and the mapped jail error for any kernel rejection.
    pub(crate) fn resolves_beneath(dirfd: &OwnedFd, path: &Path) -> Result<bool, JailError> {
        use std::os::unix::ffi::OsStrExt;

        let target = if path.as_os_str().is_empty() {
            Path::new(".")
        } else {
            path
        };
        let cpath = CString::new(target.as_os_str().as_bytes())
            .map_err(|_| JailError::InvalidPath("null bytes not allowed".into()))?;
        let how = OpenHow {
            flags: O_PATH | O_CLOEXEC,
            mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
        };
        match openat2(dirfd.as_raw_fd(), &cpath, &how) {
            Ok(_) => Ok(true),
            Err(Errno::ENOENT) => Ok(false),
            Err(e) => Err(map_errno_to_jail_error(e, path)),
        }
    }

    fn path_component(path: &Path) -> Result<(&Path, CString), JailError> {
        use std::os::unix::ffi::OsStrExt;

        // `Path::file_name` normalizes away a trailing "/" or "/.", which would
        // turn `remove_file("link/")` into unlinking the symlink itself and
        // `remove_dir("sub/.")` into removing `sub`. Reject them instead.
        let last = path
            .as_os_str()
            .as_bytes()
            .rsplit(|b| *b == b'/')
            .next()
            .unwrap_or_default();
        if last.is_empty() || last == b"." || last == b".." {
            return Err(JailError::InvalidPath(
                "final path component cannot be empty, '.' or '..'".into(),
            ));
        }

        let name = path.file_name().ok_or_else(|| {
            JailError::InvalidPath("operation requires a final path component".into())
        })?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let name = CString::new(name.as_bytes())
            .map_err(|_| JailError::InvalidPath("null bytes not allowed".into()))?;
        Ok((parent, name))
    }

    fn open_parent(
        dirfd: &OwnedFd,
        parent: &Path,
        opts: &ResolveOptions,
    ) -> Result<OwnedFd, JailError> {
        use std::os::unix::ffi::OsStrExt;

        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        let cpath = CString::new(parent.as_os_str().as_bytes())
            .map_err(|_| JailError::InvalidPath("null bytes not allowed".into()))?;
        let mut resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
        if opts.no_symlinks {
            resolve |= RESOLVE_NO_SYMLINKS;
        }
        if opts.no_xdev {
            resolve |= RESOLVE_NO_XDEV;
        }
        let how = OpenHow {
            flags: O_PATH | O_DIRECTORY | O_CLOEXEC,
            mode: 0,
            resolve,
        };
        openat2(dirfd.as_raw_fd(), &cpath, &how).map_err(|e| map_errno_to_jail_error(e, parent))
    }

    pub(crate) fn create_dir(
        dirfd: &OwnedFd,
        path: &Path,
        mode: u32,
        opts: &ResolveOptions,
    ) -> Result<(), JailError> {
        let (parent, name) = path_component(path)?;
        let parent = open_parent(dirfd, parent, opts)?;
        mkdirat(parent.as_raw_fd(), &name, mode & 0o7777).map_err(|e| JailError::Io(e.into()))
    }

    pub(crate) fn remove_file(
        dirfd: &OwnedFd,
        path: &Path,
        opts: &ResolveOptions,
    ) -> Result<(), JailError> {
        let (parent, name) = path_component(path)?;
        let parent = open_parent(dirfd, parent, opts)?;
        unlinkat(parent.as_raw_fd(), &name, 0).map_err(|e| JailError::Io(e.into()))
    }

    pub(crate) fn remove_dir(
        dirfd: &OwnedFd,
        path: &Path,
        opts: &ResolveOptions,
    ) -> Result<(), JailError> {
        let (parent, name) = path_component(path)?;
        let parent = open_parent(dirfd, parent, opts)?;
        unlinkat(parent.as_raw_fd(), &name, AT_REMOVEDIR).map_err(|e| JailError::Io(e.into()))
    }

    pub(crate) fn rename(
        dirfd: &OwnedFd,
        from: &Path,
        to: &Path,
        opts: &ResolveOptions,
    ) -> Result<(), JailError> {
        let (from_parent, from_name) = path_component(from)?;
        let (to_parent, to_name) = path_component(to)?;
        let from_parent = open_parent(dirfd, from_parent, opts)?;
        let to_parent = open_parent(dirfd, to_parent, opts)?;
        renameat2(
            from_parent.as_raw_fd(),
            &from_name,
            to_parent.as_raw_fd(),
            &to_name,
            0,
        )
        .map_err(|e| JailError::Io(e.into()))
    }
}

// ── macOS / BSD fallback ──────────────────────────────────────────────────────

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
mod fallback_impl {
    use super::*;
    use std::os::unix::fs::OpenOptionsExt;

    // O_NOFOLLOW differs between the Linux ABI and macOS/BSD. This fallback
    // also serves Linux architectures without an openat2 asm shim, so using
    // the Darwin value unconditionally would silently follow final symlinks.
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "m68k"
        )
    ))]
    const O_NOFOLLOW: i32 = 0x8000;

    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "csky",
            target_arch = "hexagon",
            target_arch = "loongarch64",
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "s390x",
            target_arch = "sparc",
            target_arch = "sparc64"
        )
    ))]
    const O_NOFOLLOW: i32 = 0o0400000;

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    const O_NOFOLLOW: i32 = 0x0100;

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    compile_error!(
        "path_jail guard: O_NOFOLLOW is unknown for this Unix target; refusing to build an unsafe fallback"
    );

    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        not(any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "m68k",
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "csky",
            target_arch = "hexagon",
            target_arch = "loongarch64",
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "s390x",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ))]
    compile_error!("path_jail guard: O_NOFOLLOW is unknown for this Linux architecture");

    pub(crate) fn jail_open(
        jail_root: &Path,
        root_inode: u64,
        rel_path: &Path,
        opts: &OpenOptions,
    ) -> Result<GuardedFile, JailError> {
        // Validate via existing path-walking logic first
        let abs_path = {
            let jail = crate::jail::Jail::from_canonical(jail_root.to_path_buf());
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

        Ok(GuardedFile { file, attestation })
    }
}

// ── Jail fd-first methods ─────────────────────────────────────────────────────

// (macOS fallback uses crate::jail::Jail internally in fallback_impl)

/// Returns the O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC flags for opening a directory fd.
/// Used when pinning the jail root dirfd on Linux.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn libc_open_directory_flags() -> i32 {
    use crate::openat2::{O_CLOEXEC, O_DIRECTORY, O_NOFOLLOW};
    // Use the per-arch constants: on aarch64 the x86_64 O_DIRECTORY/O_NOFOLLOW
    // bits mean O_DIRECT/O_LARGEFILE.
    (O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) as i32
}

/// State held by the fd-first `Jail` extension (stored alongside the path-based Jail).
///
/// On Linux this holds an open `dirfd` pinned at `Jail::new` time; on other
/// platforms we derive the root inode from `std::fs::metadata`.
///
/// # Thread safety
///
/// `FdJail` is `Send + Sync` and can be shared across threads via `Arc<FdJail>`.
/// `Clone` is supported: on Linux it `dup(2)`s the pinned directory fd so each
/// clone holds its own independent fd.
pub struct FdJail {
    /// Canonicalized jail root (same as `Jail::root()`).
    pub(crate) root: PathBuf,
    /// Root inode pinned at construction time.
    pub(crate) root_inode: u64,
    /// Device of the pinned root; inode numbers are only unique per device.
    pub(crate) root_dev: u64,
    /// Open directory fd (Linux only).
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub(crate) dirfd: std::os::unix::io::OwnedFd,
}

impl Clone for FdJail {
    fn clone(&self) -> Self {
        self.try_clone()
            .expect("failed to duplicate the pinned jail directory descriptor")
    }
}

impl FdJail {
    /// Creates an independent clone of this jail without panicking on fd exhaustion.
    ///
    /// Prefer this over [`Clone::clone`] in long-running services where `dup(2)`
    /// can fail because the process has reached its file-descriptor limit.
    pub fn try_clone(&self) -> std::io::Result<Self> {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            use std::os::unix::io::AsFd;
            Ok(Self {
                root: self.root.clone(),
                root_inode: self.root_inode,
                root_dev: self.root_dev,
                dirfd: self.dirfd.as_fd().try_clone_to_owned()?,
            })
        }

        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            Ok(Self {
                root: self.root.clone(),
                root_inode: self.root_inode,
                root_dev: self.root_dev,
            })
        }
    }

    /// Open the jail root directory and pin its inode.
    ///
    /// On Linux 5.6+ this also verifies that `openat2` is available and returns
    /// `JailError::UnsupportedKernel` on older kernels.
    ///
    /// # Platform behavior
    ///
    /// | Platform | Mechanism | TOCTOU-safe |
    /// |---|---|---|
    /// | Linux 5.6+ | `openat2(RESOLVE_BENEATH)` — single atomic syscall | **Yes** |
    /// | macOS / BSD | `O_NOFOLLOW` on the final path component | **No** |
    ///
    /// On macOS and BSD this constructor always succeeds (there is no kernel
    /// version gate), but every subsequent [`open`](Self::open) call uses the
    /// same `O_NOFOLLOW`-based fallback as the `secure-open` feature. A race
    /// window exists between path validation and the `open(2)` syscall.
    ///
    /// **Always check [`Attestation::toctou_safe`] if your threat model
    /// requires kernel-enforced atomicity.** If `toctou_safe` is `false` and
    /// you need stronger guarantees, run on Linux 5.6+ or use OS-level
    /// isolation (container, chroot).
    pub fn new(root: impl AsRef<Path>) -> Result<Self, JailError> {
        let root_input = root.as_ref().to_path_buf();
        let root = root_input
            .canonicalize()
            .map_err(|e| JailError::InvalidRoot {
                path: root_input.clone(),
                source: Some(e),
            })?;
        let root_meta = std::fs::metadata(&root).map_err(|e| JailError::InvalidRoot {
            path: root.clone(),
            source: Some(e),
        })?;

        if root.parent().is_none() || !root_meta.is_dir() {
            return Err(JailError::InvalidRoot {
                path: root,
                source: Some(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "not a directory or is filesystem root",
                )),
            });
        }

        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            use std::os::unix::io::FromRawFd;

            // Check kernel version first for a friendly error message.
            if let Some(kv) = openat2_kernel_version() {
                if kv < MIN_OPENAT2_KERNEL {
                    return Err(JailError::UnsupportedKernel { version: Some(kv) });
                }
            }
            // Probe via actual syscall — authoritative even in containers that
            // hide the kernel version.
            probe_openat2().map_err(|_| JailError::UnsupportedKernel {
                version: openat2_kernel_version(),
            })?;

            // Open the jail root directory with O_DIRECTORY so the fd is a
            // directory fd we can use as `dirfd` for subsequent openat2 calls.
            // We use std::fs::File for the open itself to avoid duplicating
            // another raw path-to-fd helper.
            let dir_file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc_open_directory_flags())
                .open(&root)
                .map_err(JailError::Io)?;

            let opened_meta = dir_file.metadata().map_err(JailError::Io)?;
            if opened_meta.dev() != root_meta.dev() || opened_meta.ino() != root_meta.ino() {
                return Err(JailError::InvalidRoot {
                    path: root,
                    source: Some(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "jail root changed while it was being opened",
                    )),
                });
            }
            let root_inode = opened_meta.ino();
            // Transfer ownership into OwnedFd (File will not close it).
            let dirfd = unsafe {
                std::os::unix::io::OwnedFd::from_raw_fd(std::os::unix::io::IntoRawFd::into_raw_fd(
                    dir_file,
                ))
            };
            Ok(FdJail {
                root,
                root_inode,
                root_dev: opened_meta.dev(),
                dirfd,
            })
        }

        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            // Emit a compile-time note (not an error — fallback is allowed)
            use std::os::unix::fs::MetadataExt;
            Ok(FdJail {
                root,
                root_inode: root_meta.ino(),
                root_dev: root_meta.dev(),
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
    /// Returns a [`GuardedFile`] containing both the open [`File`] and attestation data.
    pub fn open(
        &self,
        path: impl AsRef<Path>,
        opts: OpenOptions,
    ) -> Result<GuardedFile, JailError> {
        opts.validate()?;
        let rel = self.validate_relative(path.as_ref())?;

        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        return linux_impl::jail_open(&self.dirfd, &self.root, self.root_inode, &rel, &opts);

        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        return fallback_impl::jail_open(&self.root, self.root_inode, &rel, &opts);
    }

    /// Creates a new file relative to the jail root.
    ///
    /// Uses `O_CREAT | O_EXCL` — fails if the file already exists.
    /// The parent directory **must** already exist; this method does not create
    /// intermediate directories.
    pub fn create(&self, path: impl AsRef<Path>) -> Result<GuardedFile, JailError> {
        self.open(path, OpenOptions::new().write(true).create_new(true))
    }

    /// Atomically creates a directory beneath the pinned jail root.
    ///
    /// Available on Linux x86_64/aarch64. The parent path is resolved with
    /// `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` and pinned before
    /// `mkdirat(2)` executes, so concurrent parent renames cannot redirect it.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub fn create_dir(&self, path: impl AsRef<Path>) -> Result<(), JailError> {
        self.create_dir_with(path, ResolveOptions::default())
    }

    /// [`create_dir`](Self::create_dir) with explicit [`ResolveOptions`].
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub fn create_dir_with(
        &self,
        path: impl AsRef<Path>,
        opts: ResolveOptions,
    ) -> Result<(), JailError> {
        let path = self.validate_relative(path.as_ref())?;
        linux_impl::create_dir(&self.dirfd, &path, 0o777, &opts)
    }

    /// Removes a non-directory entry beneath the pinned jail root.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub fn remove_file(&self, path: impl AsRef<Path>) -> Result<(), JailError> {
        self.remove_file_with(path, ResolveOptions::default())
    }

    /// [`remove_file`](Self::remove_file) with explicit [`ResolveOptions`].
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub fn remove_file_with(
        &self,
        path: impl AsRef<Path>,
        opts: ResolveOptions,
    ) -> Result<(), JailError> {
        let path = self.validate_relative(path.as_ref())?;
        linux_impl::remove_file(&self.dirfd, &path, &opts)
    }

    /// Removes an empty directory beneath the pinned jail root.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub fn remove_dir(&self, path: impl AsRef<Path>) -> Result<(), JailError> {
        self.remove_dir_with(path, ResolveOptions::default())
    }

    /// [`remove_dir`](Self::remove_dir) with explicit [`ResolveOptions`].
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub fn remove_dir_with(
        &self,
        path: impl AsRef<Path>,
        opts: ResolveOptions,
    ) -> Result<(), JailError> {
        let path = self.validate_relative(path.as_ref())?;
        linux_impl::remove_dir(&self.dirfd, &path, &opts)
    }

    /// Atomically renames an entry between two locations beneath the jail root.
    ///
    /// This has normal Linux rename semantics: an existing destination may be
    /// replaced. Both parent directories are independently pinned beneath the
    /// jail before `renameat2(2)` executes.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub fn rename(&self, from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<(), JailError> {
        self.rename_with(from, to, ResolveOptions::default())
    }

    /// [`rename`](Self::rename) with explicit [`ResolveOptions`], applied to
    /// both parent directories.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub fn rename_with(
        &self,
        from: impl AsRef<Path>,
        to: impl AsRef<Path>,
        opts: ResolveOptions,
    ) -> Result<(), JailError> {
        let from = self.validate_relative(from.as_ref())?;
        let to = self.validate_relative(to.as_ref())?;
        linux_impl::rename(&self.dirfd, &from, &to, &opts)
    }

    /// Validates a path without opening a file descriptor — for display or logging only.
    ///
    /// Returns the caller's relative path (not a symlink-resolved one) if it
    /// passes the same format checks as [`open`](Self::open) and a
    /// point-in-time containment check. On Linux, existing paths are resolved
    /// by the kernel with the same `openat2` rules as `open` (via a transient
    /// `O_PATH` descriptor), so absolute symlinks and magic links are rejected
    /// just as `open` rejects them; paths with a missing component fall back to
    /// [`Jail::join`](crate::Jail::join). Fails if the directory at the root
    /// path is no longer the pinned root (device and inode). This is
    /// **weaker** than `open` because no fd is held: the path can change
    /// between this call and any subsequent filesystem operation.
    ///
    /// # ⚠ Do not open after `check_path`
    ///
    /// The returned `PathBuf` **MUST NOT** be passed to a subsequent `open` or
    /// `create` call. Doing so reintroduces the TOCTOU window that `open`
    /// eliminates atomically. Call `open` directly when you need to access the
    /// file — use `check_path` only when you need a safe string for a log
    /// entry, an error message, or an audit record.
    pub fn check_path(&self, path: impl AsRef<Path>) -> Result<PathBuf, JailError> {
        use std::os::unix::fs::MetadataExt;

        let rel = self.validate_relative(path.as_ref())?;
        let root_meta = std::fs::metadata(&self.root).map_err(|e| JailError::InvalidRoot {
            path: self.root.clone(),
            source: Some(e),
        })?;
        if root_meta.dev() != self.root_dev || root_meta.ino() != self.root_inode {
            return Err(JailError::InvalidRoot {
                path: self.root.clone(),
                source: Some(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "jail root was replaced after it was pinned",
                )),
            });
        }
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        if linux_impl::resolves_beneath(&self.dirfd, &rel)? {
            return Ok(rel);
        }
        crate::jail::Jail::from_canonical(self.root.clone()).join(&rel)?;
        Ok(rel)
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
        use std::os::unix::ffi::OsStrExt;
        if path.as_os_str().as_bytes().contains(&0) {
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
            .field("root_dev", &self.root_dev)
            .field("toctou_safe", &cfg!(target_os = "linux"))
            .finish()
    }
}
