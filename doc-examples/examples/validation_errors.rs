fn main() -> Result<(), Box<dyn std::error::Error>> {
    let user_input = "report.pdf";
    let data = b"contents";
    // ANCHOR: readme
    use path_jail::{Jail, JailError};

    let jail = Jail::new("/var/uploads")?;

    match jail.join(user_input) {
        Ok(path) => {
            // Validated. The write is a separate lookup; see TOCTOU-Safe File
            // Operations if other processes can change the tree concurrently.
            std::fs::write(&path, data)?;
        }
        Err(JailError::EscapedRoot { attempted, root }) => {
            // Path traversal or symlink escape
            eprintln!(
                "Blocked: {} escapes {}",
                attempted.display(),
                root.display()
            );
        }
        Err(JailError::BrokenSymlink(path)) => {
            // Symlink target doesn't exist (can't verify it's safe)
            eprintln!("Broken symlink: {}", path.display());
        }
        Err(JailError::InvalidPath(reason)) => {
            // Absolute path, null byte, or other invalid input
            eprintln!("Invalid: {}", reason);
        }
        Err(JailError::Io(e)) => {
            // A component couldn't be inspected (e.g. permission denied).
            // Fail closed: treat it as a rejection, not as a missing file.
            eprintln!("I/O error: {}", e);
        }
        Err(e) => eprintln!("Error: {}", e), // Future-proof (non_exhaustive)
    }
    // ANCHOR_END: readme
    Ok(())
}
