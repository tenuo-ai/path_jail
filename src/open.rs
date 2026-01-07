//! TOCTOU-safe file operations using `O_NOFOLLOW`.
//!
//! This module provides hardened file open operations that prevent symlink attacks
//! between path validation and file open. Only available on Unix with the
//! `secure-open` feature.
//!
//! # Limitations
//!
//! This uses `O_NOFOLLOW` on the final open, which protects against symlink swaps
//! on the target file. It does NOT protect against symlink swaps on intermediate
//! directories (that would require `openat()` walking, which needs `libc`).
//!
//! For full TOCTOU protection against local attackers, use [`cap-std`](https://docs.rs/cap-std).

#![cfg(all(feature = "secure-open", unix))]

use crate::{Jail, JailError, JailedPath};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

// O_NOFOLLOW values by platform (from POSIX/system headers)
#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o0400000;

#[cfg(target_os = "macos")]
const O_NOFOLLOW: i32 = 0x0100;

#[cfg(target_os = "freebsd")]
const O_NOFOLLOW: i32 = 0x0100;

#[cfg(target_os = "openbsd")]
const O_NOFOLLOW: i32 = 0x0100;

#[cfg(target_os = "netbsd")]
const O_NOFOLLOW: i32 = 0x0100;

#[cfg(target_os = "dragonfly")]
const O_NOFOLLOW: i32 = 0x0100;

// Fallback for other Unix-like systems
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
const O_NOFOLLOW: i32 = 0;

/// A file opened with TOCTOU-safe semantics.
///
/// This is a thin wrapper around [`std::fs::File`] that guarantees the file
/// was opened with `O_NOFOLLOW`, preventing symlink attacks on the final path
/// component.
#[derive(Debug)]
pub struct JailedFile {
    inner: File,
}

impl JailedFile {
    /// Returns the underlying [`File`].
    #[inline]
    pub fn into_inner(self) -> File {
        self.inner
    }
}

impl std::ops::Deref for JailedFile {
    type Target = File;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::ops::DerefMut for JailedFile {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl io::Read for JailedFile {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl io::Write for JailedFile {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl io::Seek for JailedFile {
    #[inline]
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

impl Jail {
    /// Open a file for reading with `O_NOFOLLOW` protection.
    ///
    /// This is TOCTOU-safe for the final path component: even if an attacker
    /// swaps the file with a symlink between validation and open, the open
    /// will fail with an error.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use path_jail::Jail;
    /// use std::io::Read;
    ///
    /// let jail = Jail::new("/var/uploads")?;
    /// let mut file = jail.open("config.txt")?;
    /// let mut contents = String::new();
    /// file.read_to_string(&mut contents)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path would escape the jail
    /// - The file doesn't exist
    /// - The file is a symlink (blocked by `O_NOFOLLOW`)
    /// - Permission denied
    pub fn open<P: AsRef<Path>>(&self, relative: P) -> Result<JailedFile, JailError> {
        let path = self.join(relative)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(&path)?;
        Ok(JailedFile { inner: file })
    }

    /// Create a new file with `O_NOFOLLOW | O_CREAT | O_EXCL`.
    ///
    /// The file must not exist. This prevents symlink attacks where an attacker
    /// creates a symlink at the target path between validation and creation.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use path_jail::Jail;
    /// use std::io::Write;
    ///
    /// let jail = Jail::new("/var/uploads")?;
    /// let mut file = jail.create("new_file.txt")?;
    /// file.write_all(b"hello")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path would escape the jail
    /// - The file already exists
    /// - Parent directory doesn't exist
    /// - Permission denied
    pub fn create<P: AsRef<Path>>(&self, relative: P) -> Result<JailedFile, JailError> {
        let path = self.join(relative)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true) // O_CREAT | O_EXCL
            .custom_flags(O_NOFOLLOW)
            .open(&path)?;
        Ok(JailedFile { inner: file })
    }

    /// Open a file for writing, truncating if it exists.
    ///
    /// Uses `O_NOFOLLOW` to prevent symlink attacks.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use path_jail::Jail;
    /// use std::io::Write;
    ///
    /// let jail = Jail::new("/var/uploads")?;
    /// let mut file = jail.create_or_truncate("data.txt")?;
    /// file.write_all(b"overwritten")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn create_or_truncate<P: AsRef<Path>>(&self, relative: P) -> Result<JailedFile, JailError> {
        let path = self.join(relative)?;
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(O_NOFOLLOW)
            .open(&path)?;
        Ok(JailedFile { inner: file })
    }

    /// Open a file for appending.
    ///
    /// Uses `O_NOFOLLOW` to prevent symlink attacks.
    pub fn open_append<P: AsRef<Path>>(&self, relative: P) -> Result<JailedFile, JailError> {
        let path = self.join(relative)?;
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .custom_flags(O_NOFOLLOW)
            .open(&path)?;
        Ok(JailedFile { inner: file })
    }
}

impl JailedPath {
    /// Open this path for reading with `O_NOFOLLOW` protection.
    ///
    /// See [`Jail::open`] for details.
    pub fn open(&self) -> Result<JailedFile, JailError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(self.as_path())?;
        Ok(JailedFile { inner: file })
    }

    /// Create a new file at this path with `O_NOFOLLOW | O_CREAT | O_EXCL`.
    ///
    /// See [`Jail::create`] for details.
    pub fn create(&self) -> Result<JailedFile, JailError> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(O_NOFOLLOW)
            .open(self.as_path())?;
        Ok(JailedFile { inner: file })
    }
}

