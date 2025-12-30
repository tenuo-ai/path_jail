use crate::error::JailError;
use std::path::{Component, Path, PathBuf};

/// A filesystem sandbox that restricts paths to a root directory.
#[derive(Debug, Clone)]
pub struct Jail {
    root: PathBuf,
}

impl Jail {
    /// Create a jail rooted at the given directory.
    ///
    /// Canonicalizes the root immediately. Errors if:
    /// - Root does not exist
    /// - Root is not a directory
    /// - Root is a filesystem root (`/`, `C:\`, `\\server\share`)
    pub fn new<P: AsRef<Path>>(root: P) -> Result<Self, JailError> {
        let root = root.as_ref().canonicalize()?;
        // Reject filesystem roots (/, C:\) - they have no parent
        // Reject non-directories (files, etc.)
        if root.parent().is_none() || !root.is_dir() {
            return Err(JailError::InvalidRoot(root));
        }
        Ok(Self { root })
    }

    /// Returns the canonicalized root path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Safely join a relative path to the jail root.
    ///
    /// Resolves `..` components, follows symlinks, verifies containment.
    /// Works even if the final path does not exist.
    #[must_use = "use the returned path, not the original input"]
    pub fn join<P: AsRef<Path>>(&self, relative: P) -> Result<PathBuf, JailError> {
        let path = relative.as_ref();

        // Reject null bytes (C string terminator attack)
        // These would be truncated by the OS, causing path confusion
        if path.to_string_lossy().contains('\0') {
            return Err(JailError::InvalidPath("null bytes not allowed".into()));
        }

        if path.is_absolute() {
            return Err(JailError::InvalidPath("absolute paths not allowed".into()));
        }

        let mut current = self.root.clone();
        for component in path.components() {
            match component {
                Component::Normal(name) => {
                    current.push(name);
                    // If it exists, resolve symlinks and check bounds
                    if current.exists() {
                        current = self.verify_inside(current)?;
                    } else if current.is_symlink() {
                        return Err(JailError::BrokenSymlink(current));
                    }
                }
                Component::ParentDir => {
                    current.pop();
                    // Check we haven't escaped the jail
                    if !current.starts_with(&self.root) {
                        return Err(JailError::EscapedRoot {
                            attempted: path.to_path_buf(),
                            root: self.root.clone(),
                        });
                    }
                    // Re-verify after pop (parent might be a symlink)
                    if current.exists() {
                        current = self.verify_inside(current)?;
                    } else if current.is_symlink() {
                        return Err(JailError::BrokenSymlink(current));
                    }
                }
                Component::CurDir => {} // Ignore "."
                Component::RootDir | Component::Prefix(_) => {
                    return Err(JailError::InvalidPath(
                        "absolute components not allowed".into(),
                    ));
                }
            }
        }

        Ok(current)
    }

    /// Verify a path is inside the jail.
    fn verify_inside(&self, path: PathBuf) -> Result<PathBuf, JailError> {
        let canonical = path.canonicalize()?;
        if !canonical.starts_with(&self.root) {
            return Err(JailError::EscapedRoot {
                attempted: path,
                root: self.root.clone(),
            });
        }
        Ok(canonical)
    }

    /// Verify an absolute path is inside the jail.
    /// Returns the canonicalized path if it's inside, otherwise an error.
    /// The path must exist.
    #[must_use = "use the returned path, not the original input"]
    pub fn contains<P: AsRef<Path>>(&self, absolute: P) -> Result<PathBuf, JailError> {
        let absolute = absolute.as_ref();
        if !absolute.is_absolute() {
            return Err(JailError::InvalidPath("path must be absolute".into()));
        }
        self.verify_inside(absolute.to_path_buf())
    }

    /// Get the relative path from an absolute path inside the jail.
    ///
    /// This is the inverse of [`join`](Self::join): it takes an absolute path
    /// and returns the relative portion within the jail. Useful for storing
    /// portable paths in a database.
    ///
    /// The path must exist (for symlink resolution). For non-existent paths,
    /// keep the original relative path you passed to [`join`](Self::join).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use path_jail::Jail;
    ///
    /// let jail = Jail::new("/var/uploads")?;
    /// let abs = jail.join("2025/report.pdf")?;
    /// std::fs::write(&abs, b"data")?;  // Create the file
    ///
    /// // Get the relative path for database storage
    /// let rel = jail.relative(&abs)?;
    /// assert_eq!(rel, std::path::Path::new("2025/report.pdf"));
    /// # Ok::<(), path_jail::JailError>(())
    /// ```
    pub fn relative<P: AsRef<Path>>(&self, absolute: P) -> Result<PathBuf, JailError> {
        let path = absolute.as_ref();

        let resolved = if path.is_absolute() {
            // Absolute paths must exist (for symlink verification)
            self.verify_inside(path.to_path_buf())?
        } else {
            // Relative paths: resolve via join() to normalize
            self.join(path)?
        };

        // Strip the jail root to get the relative path
        resolved
            .strip_prefix(&self.root)
            .map(|p| p.to_path_buf())
            .map_err(|_| JailError::EscapedRoot {
                attempted: path.to_path_buf(),
                root: self.root.clone(),
            })
    }
}

impl AsRef<Path> for Jail {
    fn as_ref(&self) -> &Path {
        &self.root
    }
}
