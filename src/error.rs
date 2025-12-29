use std::fmt;
use std::error::Error;
use std::path::PathBuf;

#[derive(Debug)]
pub enum JailError {
    /// Path would escape the jail root.
    EscapedRoot { attempted: PathBuf, root: PathBuf },
    /// Path contains a broken symlink (cannot verify target is safe).
    BrokenSymlink(PathBuf),
    /// Path is invalid (e.g., contains absolute components).
    InvalidPath(String),
    /// Underlying I/O error.
    Io(std::io::Error),
}

impl fmt::Display for JailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EscapedRoot { attempted, root } => {
                write!(f, "path '{}' escapes jail root '{}'", 
                       attempted.display(), root.display())
            }
            Self::BrokenSymlink(path) => {
                write!(f, "broken symlink at '{}' (cannot verify target)", path.display())
            }
            Self::InvalidPath(reason) => write!(f, "invalid path: {}", reason),
            Self::Io(err) => write!(f, "io error: {}", err),
        }
    }
}

impl std::error::Error for JailError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for JailError {
    fn from(err: std::io::Error) -> Self {
        JailError::Io(err)
    }
}