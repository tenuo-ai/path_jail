#![allow(dead_code)]

use path_jail::guard::{FdJail, OpenOptions};
use path_jail::JailError;
use std::io::{Read, Write};

fn read(jail: &FdJail, name: &str) -> Result<String, JailError> {
    // ANCHOR: read
    let mut file = jail.open(
        name,
        OpenOptions::new()
            .read(true)
            .require_regular_file(true)
            .reject_hard_links(true),
    )?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    // ANCHOR_END: read
    Ok(text)
}

fn create(jail: &FdJail, name: &str, data: &[u8]) -> Result<(), JailError> {
    // ANCHOR: create
    // `FdJail::create` is `write(true).create_new(true)`: it fails if the
    // file already exists, so it never follows or clobbers anything.
    let mut file = jail.create(name)?;
    file.write_all(data)?;
    // ANCHOR_END: create
    Ok(())
}

fn overwrite(jail: &FdJail, name: &str, data: &[u8]) -> Result<(), JailError> {
    // ANCHOR: overwrite
    let mut file = jail.open(
        name,
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true) // deferred until the handle checks pass
            .require_regular_file(true)
            .reject_hard_links(true),
    )?;
    file.write_all(data)?;
    // ANCHOR_END: overwrite
    Ok(())
}

fn append(jail: &FdJail, name: &str, line: &str) -> Result<(), JailError> {
    // ANCHOR: append
    let mut file = jail.open(
        name,
        OpenOptions::new()
            .append(true)
            .create(true)
            .require_regular_file(true)
            .reject_hard_links(true),
    )?;
    writeln!(file, "{line}")?;
    // ANCHOR_END: append
    Ok(())
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn mutate(jail: &FdJail) -> Result<(), JailError> {
    // ANCHOR: mutate
    jail.create_dir("staging")?;
    jail.rename("incoming/report.pdf", "staging/report.pdf")?;
    jail.remove_file("staging/report.pdf")?;
    jail.remove_dir("staging")?;
    // ANCHOR_END: mutate
    Ok(())
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn replace(jail: &FdJail, name: &str, tmp: &str, data: &[u8]) -> Result<(), JailError> {
    // ANCHOR: replace
    // Write a fresh file, then move it into place. Unlike an in-place
    // truncate, nothing that already exists at `name` is ever written to.
    let mut file = jail.create(tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    jail.rename(tmp, name)?;
    // ANCHOR_END: replace
    Ok(())
}

fn main() {}
