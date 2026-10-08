#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn run(jail: &path_jail::guard::FdJail) -> Result<(), path_jail::JailError> {
    // ANCHOR: readme
    jail.create_dir("work")?;
    jail.rename("incoming/report.pdf", "work/report.pdf")?;
    jail.remove_file("work/report.pdf")?;
    jail.remove_dir("work")?;
    // ANCHOR_END: readme
    Ok(())
}

fn main() {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    let _ = run;
}
