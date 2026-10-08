fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ANCHOR: readme
    use path_jail::guard::{FdJail, OpenOptions};
    use std::io::{Read, Write};

    // Pin the jail root as a file descriptor — renames of the root after this
    // point are invisible to the jail.
    let jail = FdJail::new("/var/uploads")?;

    // On Linux 5.6+ x86_64/aarch64: one openat2 syscall, kernel-enforced containment
    let mut jf = jail.open("report.pdf", OpenOptions::new().read(true))?;
    let mut buf = Vec::new();
    jf.read_to_end(&mut buf)?;

    // Every open captures an Attestation with inode, device, nlink, and timestamp
    let att = jf.attestation();
    println!("kernel-enforced: {}", att.toctou_safe); // false on the O_NOFOLLOW fallback
    assert!(att.signature.is_none()); // None until you sign it with your own Signer

    // Untrusted trees: require a regular file and refuse hard links. Both checks
    // run on the opened handle (fstat), not on a re-resolved path.
    let upload = jail.open(
        "incoming/data.csv",
        OpenOptions::new()
            .read(true)
            .require_regular_file(true) // FIFOs, devices, dirs → FileTypeRejected
            .reject_hard_links(true), // nlink > 1 → HardLinkRejected
    )?;

    // Create a new file — fails if it already exists
    let mut out = jail.create("output.bin")?;
    out.write_all(b"processed")?;
    // ANCHOR_END: readme
    let _ = upload;
    Ok(())
}
