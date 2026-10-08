fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ANCHOR: readme
    use path_jail::{Jail, JailedPath};

    fn save_upload(path: JailedPath, data: &[u8]) -> std::io::Result<()> {
        // Validated against untrusted input when constructed. It is not pinned:
        // concurrent filesystem changes need the `guard` API.
        std::fs::write(&path, data)
    }

    let jail = Jail::new("/var/uploads")?;
    let path: JailedPath = jail.join_typed("report.pdf")?;
    save_upload(path, b"data")?;
    // ANCHOR_END: readme
    Ok(())
}
