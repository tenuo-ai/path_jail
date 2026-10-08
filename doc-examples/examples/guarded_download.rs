#![allow(dead_code)]

// ANCHOR: readme
use path_jail::guard::{FdJail, OpenOptions};
use path_jail::JailError;
use std::io::Write;

/// Stream an untrusted relative path from the jail into `out`.
fn download(jail: &FdJail, name: &str, out: &mut impl Write) -> Result<u64, JailError> {
    let mut file = jail.open(
        name,
        OpenOptions::new()
            .read(true)
            .require_regular_file(true) // a FIFO or device is rejected, not read
            .reject_hard_links(true), // a link to an inode outside the jail is rejected
    )?;
    // Read from the handle that was checked. Never reopen the path.
    Ok(std::io::copy(&mut file, out)?)
}
// ANCHOR_END: readme

fn main() {}
