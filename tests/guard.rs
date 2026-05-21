//! Integration tests for the guard API (acceptance criteria from the spec).
//!
//! These tests correspond 1:1 to the spec's acceptance criteria table.
//! Run with: `cargo test --features guard`

#![cfg(all(feature = "guard", unix))]

use path_jail::guard::{FdJail, OpenOptions, Signer, Verifier, VerifyError};
use path_jail::JailError;
use std::io::{Read, Write};
use tempfile::tempdir;

// ── Test signer/verifier ─────────────────────────────────────────────────────
// A deterministic stand-in for an Ed25519 signer. NOT cryptographically secure;
// only used to verify the trait surface end-to-end without pulling in a
// crypto dep. Real callers wire up ed25519-dalek / ring / KMS.

#[derive(Debug)]
struct TestSigner {
    key: [u8; 32],
}

#[derive(Debug)]
struct TestVerifier {
    key: [u8; 32],
}

#[derive(Debug)]
struct BadSignature;
impl std::fmt::Display for BadSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "test verifier rejected signature")
    }
}
impl std::error::Error for BadSignature {}

fn test_signature(key: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    // First 32 bytes: key XOR rolling-checksum of msg.
    // Last 32 bytes: msg length, repeated.
    let mut sig = [0u8; 64];
    let mut acc: u8 = 0;
    for (i, b) in msg.iter().enumerate() {
        acc = acc.wrapping_add(*b).wrapping_add(i as u8);
    }
    for i in 0..32 {
        sig[i] = key[i] ^ acc.wrapping_add(i as u8);
    }
    let len = msg.len() as u64;
    let len_bytes = len.to_le_bytes();
    for i in 0..32 {
        sig[32 + i] = len_bytes[i % 8];
    }
    sig
}

impl Signer for TestSigner {
    type Error = std::convert::Infallible;
    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], Self::Error> {
        Ok(test_signature(&self.key, msg))
    }
}

impl Verifier for TestVerifier {
    type Error = BadSignature;
    fn verify(&self, msg: &[u8], signature: &[u8; 64]) -> Result<(), Self::Error> {
        let expected = test_signature(&self.key, msg);
        if expected == *signature {
            Ok(())
        } else {
            Err(BadSignature)
        }
    }
}

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

    // The kernel returns ELOOP for RESOLVE_NO_MAGICLINKS rejections, which
    // we map to SymlinkRejected — userspace cannot distinguish a magic-link
    // rejection from a regular symlink rejection (see JailError::MagicLink
    // docs). Escape (EXDEV) is also acceptable if the kernel resolved
    // /proc/self/root as a regular link before noticing the cross-mount.
    #[allow(deprecated)]
    let is_expected = matches!(
        err,
        JailError::MagicLink { .. } | JailError::Escape { .. } | JailError::SymlinkRejected { .. }
    );
    assert!(
        is_expected,
        "expected MagicLink, Escape, or SymlinkRejected for /proc/self/root, got: {:?}",
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

// ── Criterion 6 ──────────────────────────────────────────────────────────────
// Spec AC6: "Signed attestation verifies under configured key."

#[test]
#[cfg(unix)]
fn ac6_attestation_wire_format() {
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

    // Unsigned by default
    assert!(att.signature.is_none());
}

#[test]
#[cfg(unix)]
fn ac6_signed_attestation_verifies_under_configured_key() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("payload.bin");
    std::fs::write(&file, b"x").unwrap();

    let jail = FdJail::new(dir.path()).unwrap();
    let jf = jail
        .open("payload.bin", OpenOptions::new().read(true))
        .unwrap();

    let key = [7u8; 32];
    let signer = TestSigner { key };
    let verifier = TestVerifier { key };

    // Sign produces a signature populated attestation.
    let signed = jf.sign_attestation(&signer).expect("signer infallible");
    assert!(signed.signature.is_some());

    // Verify under the same key succeeds.
    signed
        .verify(&verifier)
        .expect("signature must verify under matching key");
}

#[test]
#[cfg(unix)]
fn ac6_signature_rejected_under_wrong_key() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("payload.bin");
    std::fs::write(&file, b"x").unwrap();

    let jail = FdJail::new(dir.path()).unwrap();
    let jf = jail
        .open("payload.bin", OpenOptions::new().read(true))
        .unwrap();

    let signer = TestSigner { key: [1u8; 32] };
    let wrong_verifier = TestVerifier { key: [2u8; 32] };

    let signed = jf.sign_attestation(&signer).unwrap();
    let err = signed
        .verify(&wrong_verifier)
        .expect_err("verification under a different key must fail");
    assert!(matches!(err, VerifyError::Invalid(_)));
}

#[test]
#[cfg(unix)]
fn ac6_unsigned_attestation_verify_returns_notsigned() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("payload.bin");
    std::fs::write(&file, b"x").unwrap();

    let jail = FdJail::new(dir.path()).unwrap();
    let jf = jail
        .open("payload.bin", OpenOptions::new().read(true))
        .unwrap();

    let verifier = TestVerifier { key: [0u8; 32] };
    let err = jf
        .attestation()
        .verify(&verifier)
        .expect_err("unsigned attestation must not verify");
    assert!(matches!(err, VerifyError::NotSigned));
}

#[test]
#[cfg(unix)]
fn ac6_signature_rejected_on_tampered_field() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("payload.bin");
    std::fs::write(&file, b"x").unwrap();

    let jail = FdJail::new(dir.path()).unwrap();
    let jf = jail
        .open("payload.bin", OpenOptions::new().read(true))
        .unwrap();

    let key = [42u8; 32];
    let signer = TestSigner { key };
    let verifier = TestVerifier { key };

    let mut signed = jf.sign_attestation(&signer).unwrap();
    // Tamper after signing.
    signed.file_inode = signed.file_inode.wrapping_add(1);
    let err = signed
        .verify(&verifier)
        .expect_err("tampered attestation must fail verification");
    assert!(matches!(err, VerifyError::Invalid(_)));
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

    // open() returns GuardedFile with Read + attestation
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

    // check_path() returns relative path (weaker — no fd held)
    let rel = jail.check_path("upload.bin").unwrap();
    assert_eq!(rel, std::path::Path::new("upload.bin"));

    // check_path() rejects absolute paths
    assert!(jail.check_path("/etc/passwd").is_err());
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

// ── no_xdev option ───────────────────────────────────────────────────────────

// TODO(no_xdev): the test below only proves the builder type-checks. The
// real EXDEV-on-mount-crossing assertion needs a bind mount, which requires
// CAP_SYS_ADMIN and is not available in the default GitHub Actions runner.
// Plan: add a separate workflow (e.g. .github/workflows/privileged-tests.yml)
// that runs under `sudo unshare -m` or a privileged container and includes a
// `#[ignore]`d test marked `#[cfg(target_os = "linux")]` that:
//   1. mkdir jail/mnt && mkdir external
//   2. mount --bind external jail/mnt
//   3. assert FdJail::new(jail).open("mnt/foo", OpenOptions::new().read(true)
//        .no_xdev(true)) returns JailError::Escape
//   4. umount jail/mnt
// Until that workflow exists, this builder test is the only signal we have.
#[test]
#[cfg(unix)]
fn no_xdev_option_compiles_and_is_chainable() {
    let opts = OpenOptions::new().read(true).no_xdev(true);
    let _ = opts;
}

#[test]
#[cfg(target_os = "linux")]
fn no_xdev_succeeds_when_no_mount_crossing() {
    // Without a mount-point crossing, no_xdev must not produce a spurious EXDEV.
    let dir = tempdir().unwrap();
    let file = dir.path().join("a.txt");
    std::fs::write(&file, b"x").unwrap();

    let jail = FdJail::new(dir.path()).unwrap();
    jail.open("a.txt", OpenOptions::new().read(true).no_xdev(true))
        .expect("open with no_xdev should succeed when no mount is crossed");
}

// ── Clone / Send / Sync for FdJail ───────────────────────────────────────────

#[test]
#[cfg(unix)]
fn fd_jail_clone_is_independent() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("shared.txt");
    std::fs::write(&file, b"hello").unwrap();

    let jail = FdJail::new(dir.path()).unwrap();
    let jail2 = jail.clone();

    // Both clones should be able to open the same file independently.
    let mut jf1 = jail
        .open("shared.txt", OpenOptions::new().read(true))
        .unwrap();
    let mut jf2 = jail2
        .open("shared.txt", OpenOptions::new().read(true))
        .unwrap();

    let mut buf1 = Vec::new();
    let mut buf2 = Vec::new();
    jf1.read_to_end(&mut buf1).unwrap();
    jf2.read_to_end(&mut buf2).unwrap();

    assert_eq!(buf1, b"hello");
    assert_eq!(buf2, b"hello");
    // The two opens are independent fds pointing to the same inode.
    assert_eq!(jf1.attestation().file_inode, jf2.attestation().file_inode);
}

#[test]
#[cfg(unix)]
fn fd_jail_is_send_sync() {
    // Compile-time assertion: FdJail and GuardedFile can be sent across threads.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FdJail>();
    // GuardedFile is not Send/Sync (it wraps a raw File which has platform-specific rules),
    // but FdJail, which is shared to produce GuardedFiles, is.
}

#[test]
#[cfg(unix)]
fn fd_jail_clone_shared_via_arc() {
    use std::sync::Arc;

    let dir = tempdir().unwrap();
    let file = dir.path().join("arc.txt");
    std::fs::write(&file, b"arc content").unwrap();

    let jail = Arc::new(FdJail::new(dir.path()).unwrap());
    let jail2 = Arc::clone(&jail);

    let handle = std::thread::spawn(move || {
        let mut jf = jail2
            .open("arc.txt", OpenOptions::new().read(true))
            .unwrap();
        let mut buf = Vec::new();
        jf.read_to_end(&mut buf).unwrap();
        buf
    });

    let buf = handle.join().unwrap();
    assert_eq!(buf, b"arc content");
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
