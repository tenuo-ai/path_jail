# path_jail

[![CI](https://github.com/aimable100/path_jail/actions/workflows/ci.yml/badge.svg)](https://github.com/aimable100/path_jail/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/path_jail.svg)](https://crates.io/crates/path_jail)
[![docs.rs](https://img.shields.io/docsrs/path_jail)](https://docs.rs/path_jail)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/aimable100/path_jail#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.80-blue.svg)](https://github.com/aimable100/path_jail)

A zero-dependency filesystem sandbox for Rust. Restricts paths to a root directory, preventing traversal attacks while supporting files that don't exist yet.

**Python bindings:** [`path-jail`](https://github.com/aimable100/path-jail-python) on PyPI

## Installation

```bash
cargo add path_jail
```

## The Problem

The standard approach fails for new files:

```rust
// This breaks if the file doesn't exist yet!
let path = root.join(user_input).canonicalize()?;
if !path.starts_with(&root) {
    return Err("escape attempt");
}
```

## The Solution

```rust
// One-liner for simple cases
let path = path_jail::join("/var/uploads", user_input)?;
std::fs::write(&path, data)?;

// Blocked: returns Err(EscapedRoot)
path_jail::join("/var/uploads", "../../etc/passwd")?;
```

For multiple paths, create a `Jail` and reuse it:

```rust
use path_jail::Jail;

let jail = Jail::new("/var/uploads")?;
let path1 = jail.join("report.pdf")?;
let path2 = jail.join("data.csv")?;
```

## Features

- **Zero dependencies** - only stdlib
- **Symlink-safe** - resolves and validates symlinks
- **Works for new files** - validates paths that don't exist yet
- **Helpful errors** - tells you what went wrong and why

## Security

| Attack | Example | Blocked |
|--------|---------|---------|
| Path traversal | `../../etc/passwd` | Yes |
| Symlink escape | `link -> /etc` | Yes |
| Symlink chains | `a -> b -> /etc` | Yes |
| Broken symlinks | `link -> /nonexistent` | Yes |
| Absolute injection | `/etc/passwd` | Yes |
| Parent escape | `foo/../../secret` | Yes |
| Null byte injection | `file\x00.txt` | Yes |

### Limitations

This library validates paths. It does not hold file descriptors.

**Rejected at construction:**
- Filesystem roots (`/`, `C:\`, `\\server\share`) are rejected because they defeat the purpose of jailing.

**Defends against:**
- Logic errors in path construction
- Confused deputy attacks from untrusted input

**Does not defend against:**
- Malicious local processes racing your I/O

For kernel-enforced sandboxing, use [`cap-std`](https://docs.rs/cap-std).

### Platform-Specific Edge Cases

#### Hard Links

Hard links cannot be detected by path inspection. If an attacker has shell access and creates a hard link to a sensitive file inside your jail, path_jail will allow access.

**Mitigations:**
- Use a separate partition for the jail (hard links cannot cross partitions)
- Use container isolation

#### Mount Points

If an attacker can mount a filesystem inside the jail, they can escape:

```rust
let jail = Jail::new("/var/uploads")?;
// Attacker (with root): mount /dev/sda1 /var/uploads/mnt
jail.join("mnt/etc/passwd")?;  // Passes check, but accesses root filesystem!
```

Detecting mount points would require `stat()` on every path component (expensive) or parsing `/proc/mounts` (Linux-only).

**Mitigations:**
- Mounting requires root privileges. If attacker has root, path validation is moot.
- Use container isolation (separate mount namespace)

#### TOCTOU Race Conditions

path_jail validates paths at call time. A symlink could be created between validation and use:

```rust
let path = jail.join("file.txt")?;  // Validated
// Attacker creates symlink here
std::fs::write(&path, data)?;        // Escapes!
```

**Mitigations:**
- Use `O_NOFOLLOW` when opening files
- Use container/chroot isolation

#### Windows Reserved Device Names

On Windows, filenames like `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9` are special device names.

```rust
let path = jail.join("CON.txt")?;   // Returns C:\uploads\CON.txt
std::fs::File::open(&path)?;         // Opens console device, not file!
```

**Impact:** Denial of Service (not a filesystem escape).

**Mitigation:** Validate filenames against a blocklist before calling path_jail, or use UUIDs for stored filenames.

#### Unicode Normalization (macOS)

macOS automatically converts filenames to NFD (decomposed) form. A file saved as `café.txt` (NFC) may be stored as `café.txt` (NFD).

path_jail handles this correctly (all paths are canonicalized). The issue arises when storing paths externally:

```rust
let user_input = "café";  // NFC from web form
let jail = Jail::new(format!("/uploads/{}", user_input))?;

// Wrong: storing original input
db.insert("root", user_input);  // NFC bytes

// Later: comparison fails
db.get("root") == jail.root().to_str();  // NFC != NFD
```

**Mitigation:** Always store `jail.root()` or `jail.relative()`, never the original input. These are already canonicalized.

#### Case Sensitivity (Windows/macOS)

Windows and macOS (by default) have case-insensitive filesystems.

path_jail handles this correctly for existing paths because `canonicalize()` normalizes case to what's on disk:

```rust
let jail = Jail::new("/var/Uploads")?;           // Canonicalized
jail.contains("/var/uploads/file.txt")?;          // Also canonicalized - works!
```

The issue is for blocklist checks on user input before calling path_jail:

```rust
let blocklist = ["secret.txt"];
let input = "SECRET.TXT";

// Wrong: case-sensitive comparison
if blocklist.contains(&input) { /* won't match */ }

// Right: normalize first
if blocklist.contains(&input.to_lowercase().as_str()) { /* matches */ }
```

**Mitigation:** Normalize case before blocklist checks.

#### Trailing Dots and Spaces (Windows)

Windows silently strips trailing dots and spaces:

```rust
jail.join("file.txt.")?;   // Becomes "file.txt"
jail.join("file.txt ")?;   // Becomes "file.txt"
```

**Mitigation:** Strip trailing dots/spaces before validation.

#### Alternate Data Streams (Windows NTFS)

NTFS supports alternate data streams: `file.txt:hidden`. Consider rejecting filenames containing `:`.

#### Unicode Display Attacks

Filenames can contain Unicode control characters that manipulate display:

```rust
jail.join("\u{202E}txt.exe")?;  // Right-to-left override: displays as "exe.txt"
```

path_jail passes these through (they're valid filenames). This is a UI attack, not a path attack. Sanitize filenames before displaying to users.

#### Special Filesystems (Linux)

`/proc` and `/dev` contain symlinks that can escape any jail:

```rust
let jail = Jail::new("/proc")?;
jail.join("self/root/etc/passwd")?;  // /proc/self/root → /
```

path_jail catches this via symlink resolution (the above returns `EscapedRoot`). However, these filesystems have many such escape vectors. Avoid using them as jail roots.

### Path Canonicalization

All returned paths are canonicalized (symlinks resolved, `..` eliminated):

```rust
// macOS: /var is a symlink to /private/var
let jail = Jail::new("/var/uploads")?;
assert!(jail.root().starts_with("/private/var"));

// Windows: Long paths (>260 chars) use \\?\ prefix
let long_name = "a".repeat(300);
let path = jail.join(&long_name)?;
assert!(path.to_string_lossy().starts_with(r"\\?\"));
```

When comparing paths, always canonicalize your expected values.

## API

### One-shot validation

```rust
// Validate and join in one call
let safe: PathBuf = path_jail::join("/var/uploads", "subdir/file.txt")?;
```

### Reusable jail

```rust
use path_jail::Jail;

// Create a jail (root must exist, be a directory, and not be filesystem root)
let jail = Jail::new("/var/uploads")?;

// Get the canonicalized root
let root: &Path = jail.root();

// Safely join a relative path
let path: PathBuf = jail.join("subdir/file.txt")?;

// Check if an absolute path is inside the jail
let verified: PathBuf = jail.contains("/var/uploads/file.txt")?;

// Get relative path for database storage
let rel: PathBuf = jail.relative(&path)?;  // "subdir/file.txt"
```

## Error Handling

### Construction errors

```rust
use path_jail::{Jail, JailError};

match Jail::new("/var/uploads") {
    Ok(jail) => { /* use jail */ }
    Err(JailError::InvalidRoot(path)) => {
        // Tried to use filesystem root (/, C:\) as jail
        panic!("Config error: {} is filesystem root", path.display());
    }
    Err(JailError::Io(e)) => {
        // Root doesn't exist or isn't a directory
        panic!("Config error: {}", e);
    }
    Err(_) => unreachable!(),
}
```

### Path validation errors

```rust
use path_jail::{Jail, JailError};

let jail = Jail::new("/var/uploads")?;

match jail.join(user_input) {
    Ok(path) => {
        // Safe to use
        std::fs::write(&path, data)?;
    }
    Err(JailError::EscapedRoot { attempted, root }) => {
        // Path traversal attempt
        eprintln!("Blocked: {} escapes {}", attempted.display(), root.display());
    }
    Err(JailError::BrokenSymlink(path)) => {
        // Symlink target doesn't exist (can't verify it's safe)
        eprintln!("Broken symlink: {}", path.display());
    }
    Err(JailError::InvalidPath(reason)) => {
        // Absolute path or other invalid input
        eprintln!("Invalid: {}", reason);
    }
    Err(JailError::Io(e)) => {
        // Filesystem error (e.g., permission denied)
        eprintln!("I/O error: {}", e);
    }
    Err(JailError::InvalidRoot(_)) => unreachable!(), // Only from Jail::new
}
```

## Example: File Uploads

```rust
use path_jail::Jail;
use std::path::PathBuf;

struct UploadService {
    jail: Jail,
}

impl UploadService {
    fn new(root: &str) -> Result<Self, path_jail::JailError> {
        Ok(Self { jail: Jail::new(root)? })
    }

    fn save(&self, user_id: &str, filename: &str, data: &[u8]) -> std::io::Result<PathBuf> {
        let path = self.jail.join(format!("{}/{}", user_id, filename))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, data)?;
        Ok(path)
    }
}
```

## Framework Integration

### Axum

```rust
use axum::{extract::Path, http::StatusCode, response::IntoResponse};
use bytes::Bytes;
use path_jail::Jail;
use std::sync::LazyLock;

static UPLOADS: LazyLock<Jail> = LazyLock::new(|| {
    Jail::new("/var/uploads").expect("uploads dir must exist")
});

async fn upload(
    Path(filename): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let path = UPLOADS.join(&filename).map_err(|_| StatusCode::BAD_REQUEST)?;
    
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    std::fs::write(&path, &body).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(StatusCode::CREATED)
}
```

### Actix-web

```rust
use actix_web::{web, HttpResponse, Result};
use path_jail::Jail;
use std::sync::LazyLock;

static UPLOADS: LazyLock<Jail> = LazyLock::new(|| {
    Jail::new("/var/uploads").expect("uploads dir must exist")
});

async fn upload(
    path: web::Path<String>,
    body: web::Bytes,
) -> Result<HttpResponse> {
    let safe_path = UPLOADS.join(path.as_str())
        .map_err(|_| actix_web::error::ErrorBadRequest("invalid path"))?;
    
    std::fs::write(&safe_path, &body)?;
    Ok(HttpResponse::Created().finish())
}
```

## Want Type-Safe Paths?

If you want to enforce validated paths at compile time, use the newtype pattern:

```rust
use path_jail::{Jail, JailError};
use std::path::{Path, PathBuf};

/// A path verified to be inside a jail.
pub struct JailedPath(PathBuf);

impl JailedPath {
    pub fn new(jail: &Jail, path: impl AsRef<Path>) -> Result<Self, JailError> {
        jail.join(path).map(Self)
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

// Now your functions can require JailedPath
fn save_upload(path: JailedPath, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path.as_path(), data)
}
```

This makes "confused deputy" bugs a compile error: you cannot accidentally pass an unvalidated `PathBuf` where a `JailedPath` is expected.

This pattern has **zero runtime cost** - it's a newtype wrapper that compiles away.

## Alternatives

| | path_jail | strict-path | cap-std |
|-|-----------|-------------|---------|
| Approach | Path validation | Type-safe path system | File descriptors |
| Returns | `std::path::PathBuf` | Custom `StrictPath<T>` | Custom `Dir`/`File` |
| Dependencies | 0 | ~5 | ~10 |
| TOCTOU-safe | Path-only* | No | Yes |
| Best for | Simple file sandboxing | Complex type-safe paths | Kernel-enforced security |

- [`strict-path`](https://crates.io/crates/strict-path) - More comprehensive, uses marker types for compile-time guarantees
- [`cap-std`](https://docs.rs/cap-std) - Capability-based, TOCTOU-safe, but different API than `std::fs`

*Path-only: Safe against remote attackers (who can't race the filesystem). Not safe against local attackers with write access to the jail directory. See [TOCTOU Race Conditions](#toctou-race-conditions).

## Thread Safety

`Jail` implements `Clone`, `Send`, and `Sync`. It can be safely shared across threads:

```rust
use std::sync::Arc;
use path_jail::Jail;

let jail = Arc::new(Jail::new("/var/uploads")?);

let jail_clone = Arc::clone(&jail);
std::thread::spawn(move || {
    let path = jail_clone.join("file.txt").unwrap();
    // ...
});
```

## MSRV

Minimum Supported Rust Version: **1.80**

This crate tracks recent stable Rust. We use `LazyLock` for ergonomic static initialization in examples.

## Development

```bash
git clone https://github.com/aimable100/path_jail.git
cd path_jail
cargo test
cargo clippy
```

## License

MIT OR Apache-2.0

