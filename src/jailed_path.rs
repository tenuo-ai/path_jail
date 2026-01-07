//! A validated path guaranteed to be inside a [`Jail`](crate::Jail).

use std::ffi::OsStr;
use std::fmt;
use std::ops::Deref;
use std::path::{Path, PathBuf};

/// A path verified to be inside a [`Jail`](crate::Jail).
///
/// This is a zero-cost wrapper that provides compile-time guarantees:
/// - Can only be constructed via [`Jail::join_typed`](crate::Jail::join_typed)
///   or [`Jail::segments`](crate::Jail::segments)
/// - Prevents "confused deputy" bugs where unvalidated paths are accidentally used
///
/// # Example
///
/// ```no_run
/// use path_jail::{Jail, JailedPath};
///
/// fn save_file(path: JailedPath, data: &[u8]) -> std::io::Result<()> {
///     // path is guaranteed to be inside the jail - no runtime check needed
///     std::fs::write(&path, data)
/// }
///
/// let jail = Jail::new("/var/uploads")?;
/// let path: JailedPath = jail.join_typed("report.pdf")?;
/// save_file(path, b"data")?;
/// # Ok::<(), path_jail::JailError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JailedPath {
    inner: PathBuf,
}

impl JailedPath {
    /// Create from a validated PathBuf.
    ///
    /// This is crate-internal only. External code must use
    /// [`Jail::join_typed`](crate::Jail::join_typed) or
    /// [`Jail::segments`](crate::Jail::segments).
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { inner: path }
    }

    /// Consumes the `JailedPath` and returns the underlying [`PathBuf`].
    ///
    /// Use this when you need ownership of the path.
    #[inline]
    pub fn into_inner(self) -> PathBuf {
        self.inner
    }

    /// Returns a reference to the underlying [`Path`].
    #[inline]
    pub fn as_path(&self) -> &Path {
        &self.inner
    }
}

impl Deref for JailedPath {
    type Target = Path;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AsRef<Path> for JailedPath {
    #[inline]
    fn as_ref(&self) -> &Path {
        &self.inner
    }
}

impl AsRef<OsStr> for JailedPath {
    #[inline]
    fn as_ref(&self) -> &OsStr {
        self.inner.as_os_str()
    }
}

impl fmt::Display for JailedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.display())
    }
}

impl From<JailedPath> for PathBuf {
    #[inline]
    fn from(path: JailedPath) -> Self {
        path.inner
    }
}

