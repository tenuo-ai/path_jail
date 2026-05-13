//! A zero-dependency filesystem sandbox for Rust.
//!
//! Restricts paths to a root directory, preventing traversal attacks
//! while supporting files that don't exist yet.
//!
//! # Quick Start
//!
//! For one-off validation, use the [`join`] function:
//!
//! ```no_run
//! let safe_path = path_jail::join("/var/uploads", "user/file.txt")?;
//! std::fs::write(&safe_path, b"hello")?;
//! # Ok::<(), path_jail::JailError>(())
//! ```
//!
//! For validating multiple paths, create a [`Jail`] and reuse it:
//!
//! ```no_run
//! use path_jail::Jail;
//!
//! let jail = Jail::new("/var/uploads")?;
//! let path1 = jail.join("report.pdf")?;
//! let path2 = jail.join("data.csv")?;
//! # Ok::<(), path_jail::JailError>(())
//! ```
//!
//! # TOCTOU-Safe File Operations (guard API)
//!
//! Enable the `guard` feature for kernel-enforced containment via
//! `openat2(RESOLVE_BENEATH)` on Linux 5.6+:
//!
//! ```toml
//! [dependencies]
//! path_jail = { version = "0.4", features = ["guard"] }
//! ```
//!
//! ```no_run
//! # #[cfg(feature = "guard")] {
//! use path_jail::guard::{FdJail, OpenOptions};
//!
//! let jail = FdJail::new("/var/uploads")?;
//! let mut jf = jail.open("report.pdf", OpenOptions::new().read(true))?;
//! if jf.has_hard_links() {
//!     // Enforce hard-link policy here
//! }
//! use std::io::Read;
//! let mut buf = Vec::new();
//! jf.read_to_end(&mut buf)?;
//! # }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Type-Safe Paths
//!
//! For compile-time guarantees, use [`JailedPath`]:
//!
//! ```no_run
//! use path_jail::{Jail, JailedPath};
//!
//! fn save_upload(path: JailedPath, data: &[u8]) -> std::io::Result<()> {
//!     // path is guaranteed to be inside the jail
//!     std::fs::write(&path, data)
//! }
//!
//! let jail = Jail::new("/var/uploads")?;
//! let path = jail.join_typed("report.pdf")?;
//! save_upload(path, b"data")?;
//! # Ok::<(), path_jail::JailError>(())
//! ```
//!
//! # Security
//!
//! This crate blocks:
//! - Path traversal (`../../etc/passwd`)
//! - Symlink escapes (symlinks pointing outside the jail)
//! - Absolute path injection (`/etc/passwd`)
//! - Null byte injection (`file\x00.txt`)
//! - Broken symlinks (cannot verify target)
//!
//! With `guard`: all of the above plus TOCTOU races, magic links
//! (`/proc/self/fd`), and intermediate directory attacks (Linux 5.6+).
//!
//! See [`Jail`] and [`guard::FdJail`] for details.

mod error;
mod jail;
mod jailed_path;

#[cfg(feature = "secure-open")]
mod open;

#[cfg(all(feature = "guard", target_os = "linux"))]
pub(crate) mod openat2;

// `guard` is Unix-only — the implementation uses `OwnedFd`, `MetadataExt`,
// `OpenOptionsExt::custom_flags`, etc., which only exist on `cfg(unix)`.
// Windows is explicitly out of scope (see SECURITY.md). Compiling
// `--features guard` on Windows is a no-op rather than a build failure.
#[cfg(all(feature = "guard", unix))]
pub mod guard;

use std::path::{Path, PathBuf};

pub use error::JailError;
pub use jail::Jail;
pub use jailed_path::JailedPath;

#[cfg(feature = "secure-open")]
pub use open::JailedFile;

/// Validate a path in one shot.
///
/// This is a convenience wrapper around [`Jail::new`] and [`Jail::join`].
/// For validating multiple paths against the same root, create a [`Jail`]
/// and reuse it for better performance.
///
/// # Arguments
///
/// * `root` : The jail root directory (must exist and be a directory)
/// * `path` : A relative path to validate and join to the root
///
/// # Returns
///
/// The canonicalized safe path, or an error if:
/// - The root doesn't exist or isn't a directory
/// - The path would escape the jail
/// - The path is absolute
///
/// # Example
///
/// ```no_run
/// // Validate user input before saving a file
/// # let user_input = "report.pdf";
/// # let data = b"contents";
/// let safe = path_jail::join("/var/uploads", user_input)?;
/// std::fs::write(&safe, data)?;
/// # Ok::<(), path_jail::JailError>(())
/// ```
pub fn join<R, P>(root: R, path: P) -> Result<PathBuf, JailError>
where
    R: AsRef<Path>,
    P: AsRef<Path>,
{
    Jail::new(root)?.join(path)
}
