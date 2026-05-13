use std::error::Error;
use std::fmt;
use std::path::PathBuf;

/// Errors returned by path_jail operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum JailError {
    // ── Original variants (path-based API) ────────────────────────────────────
    /// Path would escape the jail root (path-based API).
    EscapedRoot { attempted: PathBuf, root: PathBuf },
    /// Path contains a broken symlink (cannot verify target is safe).
    BrokenSymlink(PathBuf),
    /// Path is invalid (e.g., contains absolute components or null bytes).
    InvalidPath(String),
    /// Jail root is invalid (path-based API).
    InvalidRoot(PathBuf),

    // ── guard API variants ─────────────────────────────────────────────────
    /// `openat2` returned `EXDEV` — path escapes jail or traverses above root.
    ///
    /// Covers symlink escapes, `..` traversal, and absolute path injection.
    /// This is the primary security error; one audit log entry covers the entire
    /// class of containment failures.
    #[cfg(feature = "guard")]
    Escape { requested: PathBuf },

    /// `openat2` returned `ELOOP` — symlink loop, or `RESOLVE_NO_SYMLINKS` was
    /// set via [`OpenOptions::no_symlinks`](crate::guard::OpenOptions::no_symlinks).
    #[cfg(feature = "guard")]
    SymlinkRejected { requested: PathBuf },

    /// A `/proc/self/fd`-style magic link was detected (`RESOLVE_NO_MAGICLINKS`).
    /// These links can escape the jail regardless of `RESOLVE_BENEATH`.
    ///
    /// # Currently unreachable
    ///
    /// The Linux kernel returns the same errno (`ELOOP`) for both
    /// `RESOLVE_NO_MAGICLINKS` and `RESOLVE_NO_SYMLINKS` rejections, and
    /// userspace cannot tell them apart. As of v0.5, magic-link rejections
    /// surface as [`Self::SymlinkRejected`] rather than this variant. The
    /// variant is preserved (and not yet deprecated) so callers can match on
    /// it if a future kernel ABI separates the two errnos.
    #[cfg(feature = "guard")]
    MagicLink { requested: PathBuf },

    /// `openat2(2)` is not available on this kernel (Linux < 5.6).
    ///
    /// `version` is `Some` when the kernel version was readable from
    /// `/proc/sys/kernel/osrelease`, and `None` when `/proc` is unavailable
    /// (some hardened containers). In both cases the live `openat2` probe
    /// confirmed the syscall is not supported.
    #[cfg(all(feature = "guard", target_os = "linux"))]
    UnsupportedKernel {
        version: Option<crate::openat2::KernelVersion>,
    },

    /// Invalid root in the guard API (not a directory, filesystem root, or inaccessible).
    #[cfg(feature = "guard")]
    InvalidJailRoot {
        path: PathBuf,
        source: std::io::Error,
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
            Self::InvalidRoot(path) => {
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
            Self::MagicLink { requested } => write!(
                f,
                "magic link detected for path '{}' (RESOLVE_NO_MAGICLINKS)",
                requested.display()
            ),
            #[cfg(all(feature = "guard", target_os = "linux"))]
            Self::UnsupportedKernel { version: Some(v) } => {
                write!(f, "openat2 not available on kernel {} (requires >= 5.6)", v)
            }
            #[cfg(all(feature = "guard", target_os = "linux"))]
            Self::UnsupportedKernel { version: None } => write!(
                f,
                "openat2 not available on this kernel (requires >= 5.6; \
                 kernel version unreadable)"
            ),
            #[cfg(feature = "guard")]
            Self::InvalidJailRoot { path, source } => {
                write!(f, "invalid jail root '{}': {}", path.display(), source)
            }

            Self::Io(err) => write!(f, "io error: {}", err),
        }
    }
}

impl std::error::Error for JailError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            #[cfg(feature = "guard")]
            Self::InvalidJailRoot { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<std::io::Error> for JailError {
    fn from(err: std::io::Error) -> Self {
        JailError::Io(err)
    }
}
