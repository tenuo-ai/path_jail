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
//! # Security
//!
//! This crate blocks:
//! - Path traversal (`../../etc/passwd`)
//! - Symlink escapes (symlinks pointing outside the jail)
//! - Absolute path injection (`/etc/passwd`)
//!
//! See [`Jail`] for details on the security model.

mod error;
mod jail;

use std::path::{Path, PathBuf};

pub use error::JailError;
pub use jail::Jail;

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