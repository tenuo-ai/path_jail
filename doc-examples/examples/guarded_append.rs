#![allow(dead_code)]

// ANCHOR: readme
use path_jail::guard::{FdJail, OpenOptions};
use path_jail::JailError;
use std::io::Write;

/// Append one line to a per-job log inside the jail.
fn append_line(jail: &FdJail, log: &str, line: &str) -> Result<(), JailError> {
    let mut file = jail.open(
        log,
        OpenOptions::new()
            .append(true)
            .create(true)
            .require_regular_file(true)
            .reject_hard_links(true),
    )?;
    writeln!(file, "{line}")?;
    Ok(())
}
// ANCHOR_END: readme

fn main() {}
