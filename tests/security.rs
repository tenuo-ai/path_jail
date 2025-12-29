use path_jail::Jail;
use tempfile::tempdir;
use std::fs;

// Test the convenience function
#[test]
fn join_function_works() {
    let dir = tempdir().unwrap();
    
    // Should work for valid paths
    let path = path_jail::join(dir.path(), "file.txt").unwrap();
    assert!(path.ends_with("file.txt"));
    
    // Should block traversal
    assert!(path_jail::join(dir.path(), "../secret").is_err());
    
    // Should block absolute paths
    assert!(path_jail::join(dir.path(), "/etc/passwd").is_err());
}

#[test]
fn blocks_traversal() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();

    // Try to escape
    assert!(jail.join("../secret").is_err());
    assert!(jail.join("../../etc/passwd").is_err());
    assert!(jail.join("foo/../../secret").is_err());
}

#[test]
fn allows_safe_new_files() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();

    // "new_file.txt" doesn't exist yet, but should be valid
    let path = jail.join("subdir/new_file.txt").unwrap();
    
    // It should be absolute and start with the jail root (which is canonicalized)
    assert!(path.starts_with(jail.root()));
    assert!(path.ends_with("new_file.txt"));
}

#[test]
fn blocks_absolute_input() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();
    
    let err = jail.join("/etc/passwd");
    assert!(err.is_err());
}

#[test]
fn allows_internal_parent_navigation() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();
    
    // Create a/b directory structure
    fs::create_dir_all(dir.path().join("a/b")).unwrap();
    
    // Navigate with .. but stay inside jail
    let path = jail.join("a/b/../c").unwrap();
    assert!(path.starts_with(jail.root()));
    assert!(path.ends_with("a/c"));
}

#[test]
#[cfg(unix)]
fn catches_symlink_escape() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();
    
    // Create a symlink pointing outside the jail
    let link = dir.path().join("evil");
    std::os::unix::fs::symlink("/etc", &link).unwrap();
    
    // Attempting to traverse through the symlink should fail
    assert!(jail.join("evil/passwd").is_err());
}

#[test]
#[cfg(unix)]
fn rejects_broken_symlinks() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();
    
    // Create a broken symlink (target doesn't exist)
    let link = dir.path().join("broken");
    std::os::unix::fs::symlink("/nonexistent/target", &link).unwrap();
    
    // Broken symlinks should be rejected (can't verify they're safe)
    assert!(jail.join("broken").is_err());
}

#[test]
#[cfg(unix)]
fn allows_internal_symlinks() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();
    
    // Create a real directory and a symlink pointing to it (inside jail)
    fs::create_dir(dir.path().join("real")).unwrap();
    std::os::unix::fs::symlink(
        dir.path().join("real"),
        dir.path().join("link")
    ).unwrap();
    
    // Symlink inside jail should be allowed
    let path = jail.join("link").unwrap();
    assert!(path.starts_with(jail.root()));
}

#[test]
fn blocks_dot_dot_at_root() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();
    
    // Even a single .. at root should fail
    assert!(jail.join("..").is_err());
}

#[test]
fn handles_dot_components() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();
    
    // Current dir components should be ignored
    let path = jail.join("./foo/./bar").unwrap();
    assert!(path.ends_with("foo/bar"));
}

#[test]
fn relative_extracts_path() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();
    
    // Create the file first (relative requires existence for absolute paths)
    let abs = jail.join("2025/report.pdf").unwrap();
    fs::create_dir_all(abs.parent().unwrap()).unwrap();
    fs::write(&abs, b"test").unwrap();
    
    // Now get relative - should round-trip
    let rel = jail.relative(&abs).unwrap();
    assert_eq!(rel, std::path::Path::new("2025/report.pdf"));
}

#[test]
fn relative_rejects_outside_paths() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();
    
    // Path outside jail should fail
    assert!(jail.relative("/etc/passwd").is_err());
}

#[test]
fn relative_works_with_relative_input() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();
    
    // Can also pass a relative path directly
    let rel = jail.relative("subdir/file.txt").unwrap();
    assert_eq!(rel, std::path::Path::new("subdir/file.txt"));
}

#[test]
fn relative_normalizes_path() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();
    
    // Create directory structure
    fs::create_dir_all(dir.path().join("foo")).unwrap();
    
    // foo/../bar should normalize to bar
    let rel = jail.relative("foo/../bar").unwrap();
    assert_eq!(rel, std::path::Path::new("bar"));
    
    // ./subdir/./file should normalize to subdir/file
    let rel = jail.relative("./subdir/./file").unwrap();
    assert_eq!(rel, std::path::Path::new("subdir/file"));
}

// === Edge case tests ===

#[test]
fn handles_empty_path() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();
    
    // Empty path should return the root
    let path = jail.join("").unwrap();
    assert_eq!(path, jail.root());
}

#[test]
fn handles_double_slashes() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();
    
    // Double slashes should be normalized
    let path = jail.join("foo//bar").unwrap();
    assert!(path.ends_with("foo/bar"));
}

#[test]
fn handles_trailing_slash() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();
    
    let path = jail.join("subdir/").unwrap();
    assert!(path.ends_with("subdir"));
}

#[test]
#[cfg(unix)]
fn catches_symlink_chain_escape() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();
    
    // Create a chain: link1 -> link2 -> /etc
    let link2 = dir.path().join("link2");
    std::os::unix::fs::symlink("/etc", &link2).unwrap();
    
    let link1 = dir.path().join("link1");
    std::os::unix::fs::symlink(&link2, &link1).unwrap();
    
    // Following the chain should still be caught
    assert!(jail.join("link1/passwd").is_err());
}

#[test]
#[cfg(unix)]
fn jail_root_can_be_symlink() {
    let dir = tempdir().unwrap();
    let real_dir = dir.path().join("real");
    fs::create_dir(&real_dir).unwrap();
    
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real_dir, &link).unwrap();
    
    // Jail root as symlink should work (resolved on creation)
    let jail = Jail::new(&link).unwrap();
    
    // Root should be the resolved path, not the symlink
    assert_eq!(jail.root(), real_dir.canonicalize().unwrap());
    
    // Should still work normally
    let path = jail.join("file.txt").unwrap();
    assert!(path.starts_with(jail.root()));
}

#[test]
fn contains_verifies_paths() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();
    
    // Create a file inside
    let file = dir.path().join("test.txt");
    fs::write(&file, b"test").unwrap();
    
    // contains() should accept paths inside
    assert!(jail.contains(&file).is_ok());
    
    // contains() should reject paths outside
    assert!(jail.contains("/etc/passwd").is_err());
    
    // contains() should reject relative paths
    assert!(jail.contains("relative/path").is_err());
}

#[test]
fn rejects_triple_dots() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();
    
    // "..." is a valid filename, should be allowed
    let path = jail.join("...").unwrap();
    assert!(path.ends_with("..."));
    
    // But it shouldn't enable any escapes
    let path = jail.join(".../foo").unwrap();
    assert!(path.starts_with(jail.root()));
}

#[test]
fn relative_rejects_nonexistent_absolute() {
    let dir = tempdir().unwrap();
    let jail = Jail::new(dir.path()).unwrap();
    
    // Non-existent absolute paths should fail
    let abs = jail.join("does/not/exist.txt").unwrap();
    assert!(jail.relative(&abs).is_err());
}