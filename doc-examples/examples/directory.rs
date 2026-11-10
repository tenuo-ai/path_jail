#![allow(dead_code)]

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn inspect(
    jail: &path_jail::guard::FdJail,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    use path_jail::guard::OpenOptions;
    use std::io::Read;

    // ANCHOR: iterate
    let directory = jail.open_dir("incoming")?;
    let mut contents = Vec::new();
    for entry in directory.read_dir()? {
        let entry = entry?;
        let mut file = directory.open(
            entry.file_name(),
            OpenOptions::new()
                .read(true)
                .require_regular_file(true)
                .reject_hard_links(true),
        )?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        contents.push(bytes);
    }
    // ANCHOR_END: iterate
    Ok(contents)
}

fn main() {}
