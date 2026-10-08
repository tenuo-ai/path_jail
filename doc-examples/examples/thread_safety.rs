fn main() -> Result<(), path_jail::JailError> {
    // ANCHOR: readme
    use path_jail::Jail;
    use std::sync::Arc;

    let jail = Arc::new(Jail::new("/var/uploads")?);

    let jail_clone = Arc::clone(&jail);
    let handle = std::thread::spawn(move || jail_clone.join("file.txt"));
    let path = handle.join().expect("thread panicked")?;
    // ANCHOR_END: readme
    let _ = path;
    Ok(())
}
