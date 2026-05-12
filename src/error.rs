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

    // ── fd-first API variants ─────────────────────────────────────────────────

    /// `openat2` returned `EXDEV` — path escapes jail or traverses above root.
    ///
    /// Covers symlink escapes, `..` traversal, and absolute path injection.
    /// This is the primary security error; one audit log entry covers the entire
    /// class of containment failures.
    #[cfg(feature = "fd-first")]
    Escape { requested: PathBuf },

    /// `openat2` returned `ELOOP` — symlink loop, or `RESOLVE_NO_SYMLINKS` was
    /// set via [`OpenOptions::no_symlinks`](crate::fd_first::OpenOptions::no_symlinks).
    #[cfg(feature = "fd-first")]
    SymlinkRejected { requested: PathBuf },

    /// A `/proc/self/fd`-style magic link was detected (`RESOLVE_NO_MAGICLINKS`).
    /// These links can escape the jail regardless of `RESOLVE_BENEATH`.
    #[cfg(feature = "fd-first")]
    MagicLink { requested: PathBuf },

    /// `openat2(2)` is not available on this kernel (Linux < 5.6).
    ///
    /// Upgrade the kernel or use the path-based API (which is not TOCTOU-safe).
    #[cfg(all(feature = "fd-first", target_os = "linux"))]
    UnsupportedKernel { version: crate::openat2::KernelVersion },

    /// Invalid root in the fd-first API (not a directory, filesystem root, or inaccessible).
    #[cfg(feature = "fd-first")]
    InvalidJailRoot { path: PathBuf, source: std::io::Error },

    // ── Shared ────────────────────────────────────────────────────────────────

    /// Underlying I/O error.
    Io(std::io::Error),
}

impl fmt::Display for JailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Path-based variants
            Self::EscapedRoot { attempted, root } => write!(
                f, "path '{}' escapes jail root '{}'",
                attempted.display(), root.display()
            ),
            Self::BrokenSymlink(path) => write!(
                f, "broken symlink at '{}' (cannot verify target)", path.display()
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

            // fd-first variants
            #[cfg(feature = "fd-first")]
            Self::Escape { requested } => write!(
                f, "path '{}' escapes jail (openat2 EXDEV)", requested.display()
            ),
            #[cfg(feature = "fd-first")]
            Self::SymlinkRejected { requested } => write!(
                f, "symlink rejected for path '{}' (ELOOP / no_symlinks policy)", requested.display()
            ),
            #[cfg(feature = "fd-first")]
            Self::MagicLink { requested } => write!(
                f, "magic link detected for path '{}' (RESOLVE_NO_MAGICLINKS)", requested.display()
            ),
            #[cfg(all(feature = "fd-first", target_os = "linux"))]
            Self::UnsupportedKernel { version } => write!(
                f, "openat2 not available on kernel {} (requires >= 5.6)", version
            ),
            #[cfg(feature = "fd-first")]
            Self::InvalidJailRoot { path, source } => write!(
                f, "invalid jail root '{}': {}", path.display(), source
            ),

            Self::Io(err) => write!(f, "io error: {}", err),
        }
    }
}

impl std::error::Error for JailError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            #[cfg(feature = "fd-first")]
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
