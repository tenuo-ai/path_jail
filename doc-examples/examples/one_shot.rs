use std::path::PathBuf;

fn main() -> Result<(), path_jail::JailError> {
    // ANCHOR: readme
    // Validate and join in one call
    let safe: PathBuf = path_jail::join("/var/uploads", "subdir/file.txt")?;
    // ANCHOR_END: readme
    let _ = safe;
    Ok(())
}
