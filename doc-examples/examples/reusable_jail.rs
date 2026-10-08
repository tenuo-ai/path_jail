use std::path::{Path, PathBuf};

fn main() -> Result<(), path_jail::JailError> {
    // ANCHOR: readme
    use path_jail::Jail;

    // Create a jail (root must exist, be a directory, and not be filesystem root)
    let jail = Jail::new("/var/uploads")?;

    // Get the canonicalized root
    let root: &Path = jail.root();

    // Safely join a relative path
    let path: PathBuf = jail.join("subdir/file.txt")?;

    // Check if an absolute path is inside the jail (the path must exist)
    let verified: PathBuf = jail.contains("/var/uploads/file.txt")?;

    // Get relative path for database storage (the path must exist)
    let rel: PathBuf = jail.relative(&verified)?; // "file.txt"
                                                  // ANCHOR_END: readme
    let _ = (root, path, rel);
    Ok(())
}
