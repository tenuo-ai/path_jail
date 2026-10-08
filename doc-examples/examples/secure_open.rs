fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ANCHOR: readme
    use path_jail::Jail;
    use std::io::{Read, Write};

    let jail = Jail::new("/var/uploads")?;

    // Open with O_NOFOLLOW - fails if the final component is a symlink
    let mut file = jail.open("config.txt")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Create with O_CREAT | O_EXCL | O_NOFOLLOW - fails if the file exists or is a symlink
    let mut file = jail.create("new.txt")?;
    file.write_all(b"hello")?;

    // Other options
    let data_file = jail.create_or_truncate("data.txt")?; // Truncate if exists
    let log_file = jail.open_append("log.txt")?; // Append mode
                                                 // ANCHOR_END: readme
    let _ = (data_file, log_file);
    Ok(())
}
