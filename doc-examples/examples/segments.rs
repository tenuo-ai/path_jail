fn main() -> Result<(), path_jail::JailError> {
    // ANCHOR: readme
    use path_jail::{Jail, JailedPath};

    let jail = Jail::new("/var/uploads")?;
    let user_id = "alice";
    let filename = "photo.jpg";

    // Each segment must be one name: no `/`, `\`, `..`, or null bytes
    let path = jail.join_segments([user_id, "files", filename])?;

    // These fail:
    assert!(jail.join_segments(["../etc", "passwd"]).is_err()); // ".." rejected
    assert!(jail.join_segments(["users/files"]).is_err()); // "/" in a segment rejected

    // Type-safe version:
    let typed: JailedPath = jail.segments([user_id, "files", filename])?;
    // ANCHOR_END: readme
    let _ = (path, typed);
    Ok(())
}
