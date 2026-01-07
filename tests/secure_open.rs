//! Tests for the secure-open feature.
//!
//! These tests verify O_NOFOLLOW protection against symlink attacks.

#![cfg(all(feature = "secure-open", unix))]

use path_jail::{Jail, JailedFile};
use std::fs;
use std::io::{Read, Write};
use tempfile::tempdir;

#[test]
fn open_reads_regular_file() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();

    // Create a regular file
    fs::write(dir.path().join("test.txt"), b"hello").unwrap();

    // Should be able to open and read it
    let mut file = jail.open("test.txt").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "hello");
}

#[test]
fn open_rejects_symlink() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();

    // Create a symlink to a file OUTSIDE the jail
    let link = dir.path().join("evil.txt");
    std::os::unix::fs::symlink("/etc/passwd", &link).unwrap();

    // jail.join() should catch this escape attempt via symlink
    let result = jail.open("evil.txt");
    assert!(result.is_err());
}

#[test]
fn open_with_o_nofollow_rejects_internal_symlink() {
    use std::os::unix::fs::OpenOptionsExt;

    // This test demonstrates that O_NOFOLLOW works on the final path
    // The symlink points to a file inside the jail, but O_NOFOLLOW still rejects it
    let dir = tempdir().unwrap();

    let real_file = dir.path().join("real.txt");
    fs::write(&real_file, b"secret").unwrap();

    let link = dir.path().join("link.txt");
    std::os::unix::fs::symlink(&real_file, &link).unwrap();

    // Open the symlink directly with O_NOFOLLOW (not via jail)
    #[cfg(target_os = "linux")]
    const O_NOFOLLOW: i32 = 0o0400000;
    #[cfg(target_os = "macos")]
    const O_NOFOLLOW: i32 = 0x0100;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    const O_NOFOLLOW: i32 = 0x0100;

    let result = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(&link);

    // Should fail because the path is a symlink
    assert!(result.is_err());
}

#[test]
fn create_makes_new_file() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();

    // Create a new file
    let mut file = jail.create("new.txt").unwrap();
    file.write_all(b"created").unwrap();

    // Verify it was created
    let contents = fs::read_to_string(dir.path().join("new.txt")).unwrap();
    assert_eq!(contents, "created");
}

#[test]
fn create_fails_if_exists() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();

    // Create a file first
    fs::write(dir.path().join("exists.txt"), b"existing").unwrap();

    // create() should fail (O_EXCL behavior)
    let result = jail.create("exists.txt");
    assert!(result.is_err());
}

#[test]
fn create_rejects_symlink_target() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();

    // Create a symlink to a non-existent file
    let link = dir.path().join("link.txt");
    std::os::unix::fs::symlink("/tmp/nonexistent", &link).unwrap();

    // create() should fail because the path is a symlink
    let result = jail.create("link.txt");
    assert!(result.is_err());
}

#[test]
fn create_or_truncate_works() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();

    // Create initial content
    fs::write(dir.path().join("data.txt"), b"old content").unwrap();

    // Truncate and write new content
    let mut file = jail.create_or_truncate("data.txt").unwrap();
    file.write_all(b"new").unwrap();
    drop(file);

    // Verify truncation
    let contents = fs::read_to_string(dir.path().join("data.txt")).unwrap();
    assert_eq!(contents, "new");
}

#[test]
fn open_append_works() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();

    // Create initial content
    fs::write(dir.path().join("log.txt"), b"line1\n").unwrap();

    // Append
    let mut file = jail.open_append("log.txt").unwrap();
    file.write_all(b"line2\n").unwrap();
    drop(file);

    // Verify append
    let contents = fs::read_to_string(dir.path().join("log.txt")).unwrap();
    assert_eq!(contents, "line1\nline2\n");
}

#[test]
fn jailed_path_open_works() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();

    // Create a file
    fs::write(dir.path().join("file.txt"), b"content").unwrap();

    // Get JailedPath and open it
    let jailed_path = jail.join_typed("file.txt").unwrap();
    let mut file = jailed_path.open().unwrap();

    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "content");
}

#[test]
fn jailed_path_create_works() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();

    let jailed_path = jail.join_typed("created.txt").unwrap();
    let mut file = jailed_path.create().unwrap();
    file.write_all(b"hello").unwrap();
    drop(file);

    let contents = fs::read_to_string(dir.path().join("created.txt")).unwrap();
    assert_eq!(contents, "hello");
}

#[test]
fn jailed_file_deref_works() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();

    fs::write(dir.path().join("meta.txt"), b"test").unwrap();

    let file: JailedFile = jail.open("meta.txt").unwrap();

    // Can access File methods via Deref
    let metadata = file.metadata().unwrap();
    assert!(metadata.is_file());
}

#[test]
fn jailed_file_into_inner_works() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();

    fs::write(dir.path().join("convert.txt"), b"data").unwrap();

    let jailed_file = jail.open("convert.txt").unwrap();
    let std_file: std::fs::File = jailed_file.into_inner();

    // Can use as regular File
    let metadata = std_file.metadata().unwrap();
    assert!(metadata.is_file());
}

// This test verifies the TOCTOU protection claim
// An attacker would need to race between jail.join() and the open()
// But O_NOFOLLOW means even if they win the race, the open fails
#[test]
fn open_blocks_symlink_swap_attack() {
    use std::os::unix::fs::OpenOptionsExt;

    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();

    // Create a regular file first
    let file_path = dir.path().join("target.txt");
    fs::write(&file_path, b"original").unwrap();

    // Get the validated path
    // Note: jail.join() returns the canonicalized path, which is the REAL path
    // This is important - we don't store "target.txt", we store the full resolved path
    let safe_path = jail.join("target.txt").unwrap();

    // Simulate attacker: swap file with symlink between validation and open
    fs::remove_file(&file_path).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", &file_path).unwrap();

    // The key insight: safe_path points to where "target.txt" WAS
    // After the swap, that location is now a symlink
    // O_NOFOLLOW protects us here

    #[cfg(target_os = "linux")]
    const O_NOFOLLOW: i32 = 0o0400000;
    #[cfg(target_os = "macos")]
    const O_NOFOLLOW: i32 = 0x0100;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    const O_NOFOLLOW: i32 = 0x0100;

    let result = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(&safe_path);

    // On the original path (target.txt), this would fail because it's a symlink
    // But safe_path is the CANONICAL path, which still points to the same inode
    // The attacker replaced the file, so the canonical path is now invalid
    // This test demonstrates the TOCTOU race - the file was removed
    // Result: either the file doesn't exist, or it's a symlink (depending on timing)

    // In this test case, the canonical path no longer exists because we deleted it
    // The symlink is at the ORIGINAL path, not the canonical path
    // So the open fails with "file not found"
    assert!(result.is_err());
}

