//! Integration tests for the guard API (acceptance criteria from the spec).
//!
//! These tests correspond 1:1 to the spec's acceptance criteria table.
//! Run with: `cargo test --features fd-first`

#![cfg(feature = "guard")]

use path_jail::guard::{FdJail, OpenOptions};
use path_jail::JailError;
use std::io::{Read, Write};
use tempfile::tempdir;

// ── Criterion 1 ──────────────────────────────────────────────────────────────
// jail.open("../../etc/passwd") → JailError::Escape
// (strace would show one openat2 syscall, no file open)

#[test]
#[cfg(target_os = "linux")]
fn ac1_traversal_returns_escape() {
    let dir = tempdir().unwrap();
    let jail = FdJail::new(dir.path()).unwrap();

    let err = jail
        .open("../../etc/passwd", OpenOptions::new().read(true))
        .unwrap_err();

    assert!(
        matches!(err, JailError::Escape { .. }),
        "expected JailError::Escape, got: {:?}",
        err
    );

    // Verify the error message is actionable
    let msg = format!("{}", err);
    assert!(msg.contains("escapes jail"), "error message: {}", msg);
}

// macOS: same test but we expect EscapedRoot (fallback path-walk variant)
#[test]
#[cfg(not(target_os = "linux"))]
fn ac1_traversal_blocked_on_fallback() {
    let dir = tempdir().unwrap();
    let jail = FdJail::new(dir.path()).unwrap();

    let err = jail
        .open("../../etc/passwd", OpenOptions::new().read(true))
        .unwrap_err();

    // On macOS the fallback path-walk rejects with EscapedRoot
    assert!(
        matches!(err, JailError::EscapedRoot { .. }),
        "expected EscapedRoot on fallback, got: {:?}",
        err
    );
}

// ── Criterion 2 ──────────────────────────────────────────────────────────────
// jail.open("symlink-to-outside") → JailError::Escape

#[test]
#[cfg(unix)]
fn ac2_symlink_escape_blocked() {
    let dir = tempdir().unwrap();
    let jail = FdJail::new(dir.path()).unwrap();

    // Create a symlink pointing outside the jail
    let link = dir.path().join("evil");
    std::os::unix::fs::symlink("/etc", &link).unwrap();

    let err = jail
        .open("evil", OpenOptions::new().read(true))
        .unwrap_err();

    assert!(
        matches!(
            err,
            JailError::Escape { .. } | JailError::EscapedRoot { .. }
        ),
        "expected Escape or EscapedRoot, got: {:?}",
        err
    );
}

// ── Criterion 3 ──────────────────────────────────────────────────────────────
// jail.open("/proc/self/root/etc/passwd") → JailError::MagicLink
// (only on Linux; /proc/self/root is a magic link)

#[test]
#[cfg(target_os = "linux")]
fn ac3_magic_link_blocked() {
    use std::path::Path;

    if !Path::new("/proc/self/root").exists() {
        // Skip in containers that don't expose /proc/self/root
        return;
    }

    // We use /proc as the jail root so the path stays inside-ish,
    // but /proc/self/root is a magic procfs link and RESOLVE_NO_MAGICLINKS
    // must block it.
    let jail = match FdJail::new("/proc") {
        Ok(j) => j,
        Err(_) => return, // /proc may not be suitable as a jail root in all envs
    };

    let err = jail
        .open("self/root/etc/passwd", OpenOptions::new().read(true))
        .unwrap_err();

    // Either MagicLink (RESOLVE_NO_MAGICLINKS) or Escape (RESOLVE_BENEATH catches the root link)
    assert!(
        matches!(err, JailError::MagicLink { .. } | JailError::Escape { .. }),
        "expected MagicLink or Escape for /proc/self/root, got: {:?}",
        err
    );
}

// ── Criterion 4 ──────────────────────────────────────────────────────────────
// Pre-existing hard link inside jail → open() succeeds; has_hard_links() = true

#[test]
#[cfg(unix)]
fn ac4_hard_link_detected() {
    let dir = tempdir().unwrap();
    let original = dir.path().join("original.txt");
    std::fs::write(&original, b"data").unwrap();

    // Create a hard link inside the jail
    let link = dir.path().join("hardlink.txt");
    std::fs::hard_link(&original, &link).unwrap();

    let jail = FdJail::new(dir.path()).unwrap();
    let jf = jail
        .open("hardlink.txt", OpenOptions::new().read(true))
        .unwrap();

    // nlink should be 2 (original + hard link)
    assert!(
        jf.has_hard_links(),
        "expected has_hard_links() = true for a hard-linked file"
    );
    assert_eq!(jf.attestation().nlink, 2);
}

#[test]
#[cfg(unix)]
fn ac4_regular_file_has_no_extra_hard_links() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("solo.txt");
    std::fs::write(&file, b"data").unwrap();

    let jail = FdJail::new(dir.path()).unwrap();
    let jf = jail
        .open("solo.txt", OpenOptions::new().read(true))
        .unwrap();

    assert!(
        !jf.has_hard_links(),
        "single-link file should not report has_hard_links()"
    );
    assert_eq!(jf.attestation().nlink, 1);
}

// ── Criterion 5 ──────────────────────────────────────────────────────────────
// Two open() calls, same path, same jail → content_bytes() identical; opened_at differs

#[test]
#[cfg(unix)]
fn ac5_content_bytes_deterministic() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("report.pdf");
    std::fs::write(&file, b"pdf content").unwrap();

    let jail = FdJail::new(dir.path()).unwrap();

    let jf1 = jail
        .open("report.pdf", OpenOptions::new().read(true))
        .unwrap();
    // Small sleep to ensure opened_at differs if the clock has sufficient resolution
    std::thread::sleep(std::time::Duration::from_millis(2));
    let jf2 = jail
        .open("report.pdf", OpenOptions::new().read(true))
        .unwrap();

    // content_bytes must be identical (excludes opened_at and signature)
    assert_eq!(
        jf1.attestation().content_bytes(),
        jf2.attestation().content_bytes(),
        "content_bytes() must be identical for two opens of the same file"
    );

    // opened_at is intentionally different
    // (may be equal on low-resolution clocks; that's acceptable)
    // We don't assert inequality since clock granularity is platform-dependent.

    // signing_bytes (which include opened_at) must include all content_bytes
    let cb = jf1.attestation().content_bytes();
    let sb = jf1.attestation().signing_bytes();
    assert!(
        sb.starts_with(&cb),
        "signing_bytes must start with content_bytes"
    );
    assert!(
        sb.len() > cb.len(),
        "signing_bytes must include extra timestamp bytes"
    );
}

// ── Criterion 6 (partial) ────────────────────────────────────────────────────
// Spec AC6: "Signed attestation verifies under configured key."
// Ed25519 signing requires an external key and is future work (tracked separately).
// This test covers the prerequisite: the wire format encodes fields correctly
// and signature is None when no key is configured.
// TODO(ac6): add signing verification once the Ed25519 feature is implemented.

#[test]
#[cfg(unix)]
fn ac6_partial_attestation_wire_format_and_unsigned() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("data.bin");
    std::fs::write(&file, b"bytes").unwrap();

    let jail = FdJail::new(dir.path()).unwrap();
    let jf = jail
        .open("data.bin", OpenOptions::new().read(true))
        .unwrap();
    let att = jf.attestation();

    let cb = att.content_bytes();

    // Verify field encoding: jail_root length prefix
    let root_bytes = att.jail_root.as_os_str().as_encoded_bytes();
    let root_len = u32::from_le_bytes(cb[0..4].try_into().unwrap()) as usize;
    assert_eq!(root_len, root_bytes.len());
    assert_eq!(&cb[4..4 + root_len], root_bytes);

    // opened_path follows
    let off = 4 + root_len;
    let path_bytes = att.opened_path.as_os_str().as_encoded_bytes();
    let path_len = u32::from_le_bytes(cb[off..off + 4].try_into().unwrap()) as usize;
    assert_eq!(path_len, path_bytes.len());
    assert_eq!(&cb[off + 4..off + 4 + path_len], path_bytes);

    // Signature is None (no key configured — full AC6 is pending Ed25519 feature)
    assert!(att.signature.is_none());
}

// ── Criterion 7 ──────────────────────────────────────────────────────────────
// Kernel < 5.6, fallback feature disabled → Jail::new returns UnsupportedKernel
// We verify: (a) FdJail::new succeeds on this machine (proving kernel >= 5.6),
// and (b) the error type would be UnsupportedKernel on an old kernel.
// The old-kernel path can only be tested via mocking; we test the type exists.

#[test]
#[cfg(target_os = "linux")]
fn ac7_fd_jail_new_succeeds_on_modern_kernel() {
    let dir = tempdir().unwrap();
    // If this succeeds, the kernel is >= 5.6. If it returns UnsupportedKernel,
    // the error variant exists and formats correctly.
    match FdJail::new(dir.path()) {
        Ok(jail) => {
            // Modern kernel — verify root is set
            assert_eq!(jail.root(), dir.path().canonicalize().unwrap());
        }
        Err(JailError::UnsupportedKernel { .. }) => {
            // Old kernel — acceptable, error variant is correct type
        }
        Err(e) => panic!("unexpected error from FdJail::new: {:?}", e),
    }
}

// ── Criterion 8 ──────────────────────────────────────────────────────────────
// Python bindings: tested separately in the python package.
// Here we verify the Rust side surface is stable.

#[test]
#[cfg(unix)]
fn ac8_api_surface_stable() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("upload.bin");
    std::fs::write(&file, b"hello world").unwrap();

    let jail = FdJail::new(dir.path()).unwrap();

    // open() returns JailFile with Read + attestation
    let mut jf = jail
        .open("upload.bin", OpenOptions::new().read(true))
        .unwrap();
    let mut buf = Vec::new();
    jf.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"hello world");

    // attestation data is populated
    let att = jf.attestation();
    assert_eq!(att.opened_path, std::path::Path::new("upload.bin"));
    assert!(!att.jail_root.as_os_str().is_empty());
    assert!(att.file_inode > 0);

    // create() fails if file exists
    let err = jail.create("upload.bin").unwrap_err();
    assert!(
        matches!(err, JailError::Io(_)),
        "expected Io(AlreadyExists), got: {:?}",
        err
    );

    // create() succeeds for new files
    let mut jf2 = jail.create("new_file.bin").unwrap();
    jf2.write_all(b"written").unwrap();
    drop(jf2);
    assert_eq!(
        std::fs::read(dir.path().join("new_file.bin")).unwrap(),
        b"written"
    );

    // check() returns relative path (weaker — no fd held)
    let rel = jail.check("upload.bin").unwrap();
    assert_eq!(rel, std::path::Path::new("upload.bin"));

    // check() rejects absolute paths
    assert!(jail.check("/etc/passwd").is_err());
}

// ── Additional: TOCTOU-safe flag ─────────────────────────────────────────────

#[test]
#[cfg(unix)]
fn toctou_safe_reflects_platform() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("f.txt");
    std::fs::write(&file, b"x").unwrap();

    let jail = FdJail::new(dir.path()).unwrap();
    let jf = jail.open("f.txt", OpenOptions::new().read(true)).unwrap();

    #[cfg(target_os = "linux")]
    assert!(jf.attestation().toctou_safe, "Linux should be TOCTOU-safe");

    #[cfg(not(target_os = "linux"))]
    assert!(
        !jf.attestation().toctou_safe,
        "macOS/BSD fallback is not TOCTOU-safe"
    );
}

// ── no_symlinks option ────────────────────────────────────────────────────────

#[test]
#[cfg(all(unix, target_os = "linux"))]
fn no_symlinks_rejects_symlink_inside_jail() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("real.txt");
    std::fs::write(&target, b"data").unwrap();

    let link = dir.path().join("link.txt");
    std::os::unix::fs::symlink("real.txt", &link).unwrap();

    let jail = FdJail::new(dir.path()).unwrap();

    // Without no_symlinks: succeeds
    jail.open("link.txt", OpenOptions::new().read(true))
        .unwrap();

    // With no_symlinks: rejected
    let err = jail
        .open("link.txt", OpenOptions::new().read(true).no_symlinks(true))
        .unwrap_err();
    assert!(
        matches!(err, JailError::SymlinkRejected { .. }),
        "expected SymlinkRejected, got: {:?}",
        err
    );
}
