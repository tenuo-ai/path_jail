use std::error::Error;
use std::fmt;
use std::path::PathBuf;

/// Errors returned by path_jail operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum JailError {
    // ── Original variants (path-based API) ────────────────────────────────────
    /// Path would escape the jail root.
    ///
    /// Returned by the path-based API (`Jail::join` and friends) and by the
    /// `guard` fallback, which validates with `Jail::join` before opening.
    /// The openat2 path reports the same condition as `Escape`.
    EscapedRoot {
        /// The path, built from the caller's input, that resolved outside the root.
        attempted: PathBuf,
        /// The jail's canonical root.
        root: PathBuf,
    },
    /// Path contains a broken symlink (cannot verify target is safe).
    BrokenSymlink(PathBuf),
    /// Path is invalid (e.g., contains absolute components or null bytes).
    InvalidPath(String),
    /// Jail root is invalid (filesystem root, not a directory, or inaccessible).
    ///
    /// `source` is `Some` when an I/O error was the proximate cause (e.g.,
    /// permission denied opening the directory). It is `None` when the root
    /// was rejected on structural grounds (e.g., the path is `/` or `C:\`).
    InvalidRoot {
        /// The root that was rejected (canonicalized when canonicalization succeeded).
        path: PathBuf,
        /// The I/O error that caused the rejection, if any.
        source: Option<std::io::Error>,
    },

    // ── guard API variants ─────────────────────────────────────────────────
    /// `openat2` returned `EXDEV` — path escapes jail or traverses above root.
    ///
    /// Covers symlink escapes, `..` traversal above the root, absolute
    /// symlinks, and (with `no_xdev`) mount-point crossings. Absolute input
    /// paths are rejected earlier as [`Self::InvalidPath`]. This is the primary
    /// security error; one audit log entry covers the entire class of
    /// containment failures.
    #[cfg(feature = "guard")]
    Escape {
        /// The relative path the caller asked to open.
        requested: PathBuf,
    },

    /// `openat2` returned `ELOOP` — symlink loop, or `RESOLVE_NO_SYMLINKS` was
    /// set via [`OpenOptions::no_symlinks`](crate::guard::OpenOptions::no_symlinks).
    #[cfg(feature = "guard")]
    SymlinkRejected {
        /// The relative path the caller asked to open.
        requested: PathBuf,
    },

    /// A `/proc/self/fd`-style magic link was detected (`RESOLVE_NO_MAGICLINKS`).
    /// These links can escape the jail regardless of `RESOLVE_BENEATH`.
    ///
    /// # Deprecation
    ///
    /// **This variant is currently unreachable.** The Linux kernel returns the
    /// same errno (`ELOOP`) for both `RESOLVE_NO_MAGICLINKS` and
    /// `RESOLVE_NO_SYMLINKS` rejections; userspace cannot distinguish them.
    /// Magic-link rejections therefore surface as [`Self::SymlinkRejected`].
    ///
    /// Match on `SymlinkRejected` instead. This variant is preserved so
    /// existing `match` arms are not broken; it will be removed in a future
    /// major version if the kernel introduces a distinct errno.
    #[cfg(feature = "guard")]
    #[deprecated(
        since = "0.4.0",
        note = "unreachable: the kernel maps magic-link rejections to ELOOP, \
                which surfaces as `SymlinkRejected`. Match on `SymlinkRejected` instead."
    )]
    MagicLink {
        /// The relative path the caller asked to open.
        requested: PathBuf,
    },

    /// `openat2(2)` is not available on this kernel (Linux < 5.6).
    ///
    /// `version` is `Some` when the kernel version was readable from
    /// `/proc/sys/kernel/osrelease`, and `None` when `/proc` is unavailable
    /// (some hardened containers). In both cases the live `openat2` probe
    /// confirmed the syscall is not supported.
    #[cfg(all(
        feature = "guard",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    UnsupportedKernel {
        /// The running kernel's version, when `/proc/sys/kernel/osrelease` was readable.
        version: Option<crate::openat2::KernelVersion>,
    },

    /// The opened file is not a regular file and
    /// [`OpenOptions::require_regular_file`](crate::guard::OpenOptions::require_regular_file)
    /// was set. The type comes from `fstat` on the opened handle.
    #[cfg(all(feature = "guard", unix))]
    FileTypeRejected {
        /// The relative path the caller asked to open.
        requested: PathBuf,
        /// The type `fstat` reported for the opened handle.
        file_type: crate::guard::FileKind,
    },

    /// The opened file has more than one hard link and
    /// [`OpenOptions::reject_hard_links`](crate::guard::OpenOptions::reject_hard_links)
    /// was set. The link count comes from `fstat` on the opened handle.
    #[cfg(all(feature = "guard", unix))]
    HardLinkRejected {
        /// The relative path the caller asked to open.
        requested: PathBuf,
        /// The link count `fstat` reported for the opened handle.
        nlink: u64,
    },

    // ── Shared ────────────────────────────────────────────────────────────────
    /// Underlying I/O error.
    Io(std::io::Error),
}

impl fmt::Display for JailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Path-based variants
            Self::EscapedRoot { attempted, root } => write!(
                f,
                "path '{}' escapes jail root '{}'",
                attempted.display(),
                root.display()
            ),
            Self::BrokenSymlink(path) => write!(
                f,
                "broken symlink at '{}' (cannot verify target)",
                path.display()
            ),
            Self::InvalidPath(reason) => write!(f, "invalid path: {}", reason),
            Self::InvalidRoot {
                path,
                source: Some(src),
            } => {
                write!(f, "invalid jail root '{}': {}", path.display(), src)
            }
            Self::InvalidRoot { path, source: None } => {
                let reason = if path.parent().is_none() {
                    "cannot use filesystem root"
                } else if !path.is_dir() {
                    "not a directory"
                } else {
                    "invalid"
                };
                write!(f, "invalid jail root '{}' ({})", path.display(), reason)
            }

            // guard variants
            #[cfg(feature = "guard")]
            Self::Escape { requested } => write!(
                f,
                "path '{}' escapes jail (openat2 EXDEV)",
                requested.display()
            ),
            #[cfg(feature = "guard")]
            Self::SymlinkRejected { requested } => write!(
                f,
                "symlink rejected for path '{}' (ELOOP / no_symlinks policy)",
                requested.display()
            ),
            #[cfg(feature = "guard")]
            #[allow(deprecated)]
            Self::MagicLink { requested } => write!(
                f,
                "magic link detected for path '{}' (RESOLVE_NO_MAGICLINKS)",
                requested.display()
            ),
            #[cfg(all(
                feature = "guard",
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            Self::UnsupportedKernel { version: Some(v) } => {
                write!(f, "openat2 not available on kernel {} (requires >= 5.6)", v)
            }
            #[cfg(all(
                feature = "guard",
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            Self::UnsupportedKernel { version: None } => write!(
                f,
                "openat2 not available on this kernel (requires >= 5.6; \
                 kernel version unreadable)"
            ),
            #[cfg(all(feature = "guard", unix))]
            Self::FileTypeRejected {
                requested,
                file_type,
            } => write!(
                f,
                "'{}' is a {} (regular file required)",
                requested.display(),
                file_type
            ),
            #[cfg(all(feature = "guard", unix))]
            Self::HardLinkRejected { requested, nlink } => write!(
                f,
                "'{}' has {} hard links (hard links rejected)",
                requested.display(),
                nlink
            ),
            Self::Io(err) => write!(f, "io error: {}", err),
        }
    }
}

impl std::error::Error for JailError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::InvalidRoot {
                source: Some(src), ..
            } => Some(src),
            _ => None,
        }
    }
}

impl From<std::io::Error> for JailError {
    fn from(err: std::io::Error) -> Self {
        JailError::Io(err)
    }
}
