# path_jail

[![CI](https://github.com/tenuo-ai/path_jail/actions/workflows/ci.yml/badge.svg)](https://github.com/tenuo-ai/path_jail/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/path_jail.svg)](https://crates.io/crates/path_jail)
[![docs.rs](https://img.shields.io/docsrs/path_jail)](https://docs.rs/path_jail)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/tenuo-ai/path_jail#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](https://github.com/tenuo-ai/path_jail)

A zero-dependency filesystem sandbox for Rust. Restricts paths to a root directory, preventing traversal attacks while supporting files that don't exist yet.

Maintained by **[Tenuo](https://tenuo.ai)**.

**Python bindings:** [`path-jail`](https://github.com/tenuo-ai/path-jail-python) on PyPI

## Installation

```bash
cargo add path_jail
```

## The Problem

The standard approach fails for new files:

```rust,ignore
// This breaks if the file doesn't exist yet!
let path = root.join(user_input).canonicalize()?;
if !path.starts_with(&root) {
    return Err("escape attempt");
}
```

## The Solution

```rust,ignore
// One-liner for simple cases: validates the untrusted string
let path = path_jail::join("/var/uploads", user_input)?;
// The write is a separate lookup. If other processes can change the tree,
// use the `guard` feature instead (see TOCTOU below).
std::fs::write(&path, data)?;

// Blocked: returns Err(EscapedRoot)
path_jail::join("/var/uploads", "../../etc/passwd")?;
```

For multiple paths, create a `Jail` and reuse it:

```rust,ignore
use path_jail::Jail;

let jail = Jail::new("/var/uploads")?;
let path1 = jail.join("report.pdf")?;
let path2 = jail.join("data.csv")?;
```

## Choosing an API

path_jail has three layers. Each one adds to the one before it; pick the
strongest your platform supports. The [threat model](SECURITY.md#what-each-api-defends-against)
lists exactly what each layer does and does not defend against.

| Layer | You get | Guarantee | Use when |
|-------|---------|-----------|----------|
| [`Jail`](#api) (default) | A validated `PathBuf` | The **string** resolves inside the root at the moment you call `join`. You open it later with `std::fs`, so another process can swap a symlink in between. | Only your service writes to the tree, or you need a path for logging, storage keys, or display |
| [`secure-open`](#secure-open--o_nofollow-protection-all-unix) | A `JailedFile` | Validation, then an open with `O_NOFOLLOW`: the **final component** cannot be a swapped-in symlink. Intermediate directories can still be swapped. | Unix without the `guard` feature |
| [`guard`](#guard--kernel-enforced-toctou-safety-linux-56) | A `GuardedFile` (a descriptor, not a path) | Linux 5.6+ x86_64/aarch64: **one `openat2` call** resolves and opens beneath a pinned root, so nothing can race it. Elsewhere: the `secure-open` guarantee, reported as `attestation().toctou_safe == false`. Optional checks on the opened handle reject FIFOs, devices, directories, and hard links. | Untrusted users or processes can modify the tree |

Moving existing code over? See [Migrating to the guard API](docs/guides/migrating.md).
Using Tokio? See [Async (Tokio)](docs/guides/tokio.md).

## Platform support

This is the single support matrix for the crate; other documents link here.

| | Linux 5.6+, x86_64/aarch64 | Linux < 5.6 (or `openat2` blocked by seccomp), x86_64/aarch64 | Other Linux architectures¹, Android | macOS, FreeBSD, NetBSD, OpenBSD, DragonFly | Windows | Other Unix (illumos, Solaris, …) |
|---|---|---|---|---|---|---|
| `Jail` (default) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `secure-open` | ✅ | ✅ | ✅ | ✅ | feature is a no-op | compile error² |
| `guard`: `FdJail::open` / `create` | ✅ atomic (`toctou_safe = true`) | `FdJail::new` → `UnsupportedKernel` | fallback (`toctou_safe = false`) | fallback (`toctou_safe = false`) | not available | compile error² |
| `guard`: `create_dir`, `remove_file`, `remove_dir`, `rename` | ✅ | — | not available³ | not available³ | — | — |
| `guard`: `require_regular_file`, `reject_hard_links` | ✅ | — | ✅ | ✅ | — | — |
| `guard`: `no_symlinks`, `no_xdev` | ✅ enforced | — | no-op | no-op | — | — |

1. armv7, i686, riscv64, powerpc, powerpc64, s390x, loongarch64, mips, sparc and other Linux targets with a known `O_NOFOLLOW` value.
2. The `O_*` flag values are unknown there, so the crate refuses to build an unsafe fallback rather than guess.
3. A pathname-based fallback would reintroduce the race these methods exist to avoid, so they are compiled only where they are kernel-enforced.

CI runs the full test suite on Linux x86_64 and aarch64, macOS, Windows, and
FreeBSD, and under QEMU on armv7, i686, powerpc, powerpc64le, riscv64, and
s390x. Android, NetBSD, loongarch64, sparc64, and illumos are compile-checked.

## Features

- **Zero dependencies** - only stdlib
- **Symlink-safe** - resolves and validates symlinks
- **Works for new files** - validates paths that don't exist yet
- **Type-safe paths** - optional `JailedPath` newtype prevents confused deputy bugs
- **Segment joining** - safely build paths from user IDs, filenames, etc.
- **Helpful errors** - tells you what went wrong and why
- **`secure-open` feature** (Unix) - `O_NOFOLLOW`-protected opens; zero extra deps
- **`guard` feature** (Unix) - fd-pinned opens with handle checks; kernel-enforced via `openat2(RESOLVE_BENEATH)` on Linux 5.6+ x86_64/aarch64, `O_NOFOLLOW` fallback elsewhere ([support matrix](#platform-support))

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

The path-based `Jail` API validates paths; it does not hold file descriptors,
so the limitations below apply to it. The `guard` feature's `FdJail` pins the
root as a descriptor and closes several of them (see
[TOCTOU-Safe File Operations](#toctou-safe-file-operations)).

**Rejected at construction:**
- Filesystem roots (`/`, `C:\`, `\\server\share`) are rejected because they defeat the purpose of jailing.

**Defends against:**
- Logic errors in path construction
- Confused deputy attacks from untrusted input

**Does not defend against:**
- Malicious local processes racing your I/O (use the `guard` feature for kernel-enforced protection on Linux 5.6+)

For kernel-enforced sandboxing without leaving the `path_jail` API, enable the [`guard` feature](#guard--kernel-enforced-toctou-safety-linux-56). For a
capability-based alternative that replaces `std::fs` entirely, see [`cap-std`](https://docs.rs/cap-std).

### Platform-Specific Edge Cases

#### Hard Links

Hard links cannot be detected by path inspection. If an attacker has shell access and creates a hard link to a sensitive file inside your jail, path_jail will allow access.

**Mitigations:**
- With the `guard` feature, open with `OpenOptions::reject_hard_links(true)`
  (checked on the opened handle)
- Use a separate partition for the jail (hard links cannot cross partitions)
- Use container isolation

#### Mount Points

If an attacker can mount a filesystem inside the jail, they can escape:

```rust,ignore
let jail = Jail::new("/var/uploads")?;
// Attacker (with root): mount /dev/sda1 /var/uploads/mnt
jail.join("mnt/etc/passwd")?;  // Passes check, but accesses root filesystem!
```

Detecting mount points would require `stat()` on every path component (expensive) or parsing `/proc/mounts` (Linux-only).

**Mitigations:**
- With the `guard` feature on Linux, open with `OpenOptions::no_xdev(true)`
  (`RESOLVE_NO_XDEV` rejects any mount crossing)
- Mounting requires root privileges. If attacker has root, path validation is moot.
- Use container isolation (separate mount namespace)

#### TOCTOU Race Conditions

path_jail validates paths at call time. A symlink could be created between validation and use:

```rust,ignore
let path = jail.join("file.txt")?;  // Validated
// Attacker creates symlink here
std::fs::write(&path, data)?;        // Escapes!
```

**Mitigations:**
- Enable the `guard` feature on Linux 5.6+: a single `openat2(RESOLVE_BENEATH)` syscall makes the validate-and-open atomic (see [below](#guard--kernel-enforced-toctou-safety-linux-56))
- Enable the `secure-open` feature for `O_NOFOLLOW`-protected file operations (protects the final component only)
- Use container/chroot isolation

#### Windows Reserved Device Names

On Windows, filenames like `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9` are special device names.

```rust,ignore
let path = jail.join("CON.txt")?;   // Returns C:\uploads\CON.txt
std::fs::File::open(&path)?;         // Opens console device, not file!
```

**Impact:** Denial of Service (not a filesystem escape).

**Mitigation:** Validate filenames against a blocklist before calling path_jail, or use UUIDs for stored filenames.

#### Unicode Normalization (macOS)

macOS automatically converts filenames to NFD (decomposed) form. A file saved as `café.txt` (NFC) may be stored as `café.txt` (NFD).

path_jail handles this correctly (all paths are canonicalized). The issue arises when storing paths externally:

```rust,ignore
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

```rust,ignore
let jail = Jail::new("/var/Uploads")?;           // Canonicalized
jail.contains("/var/uploads/file.txt")?;          // Also canonicalized - works!
```

The issue is for blocklist checks on user input before calling path_jail:

```rust,ignore
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

```rust,ignore
jail.join("file.txt.")?;   // Becomes "file.txt"
jail.join("file.txt ")?;   // Becomes "file.txt"
```

**Mitigation:** Strip trailing dots/spaces before validation.

#### Alternate Data Streams (Windows NTFS)

NTFS supports alternate data streams: `file.txt:hidden`. Consider rejecting filenames containing `:`.

#### Unicode Display Attacks

Filenames can contain Unicode control characters that manipulate display:

```rust,ignore
jail.join("\u{202E}txt.exe")?;  // Right-to-left override: displays as "exe.txt"
```

path_jail passes these through (they're valid filenames). This is a UI attack, not a path attack. Sanitize filenames before displaying to users.

#### Special Filesystems (Linux)

`/proc` and `/dev` contain symlinks that can escape any jail:

```rust,ignore
let jail = Jail::new("/proc")?;
jail.join("self/root/etc/passwd")?;  // /proc/self/root → /
```

path_jail catches this via symlink resolution (the above returns `EscapedRoot`). However, these filesystems have many such escape vectors. Avoid using them as jail roots.

### Path Canonicalization

All returned paths are canonicalized (symlinks resolved, `..` eliminated):

```rust,ignore
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

<!-- example: doc-examples/examples/one_shot.rs#readme -->
```rust
// Validate and join in one call
let safe: PathBuf = path_jail::join("/var/uploads", "subdir/file.txt")?;
```

### Reusable jail

<!-- example: doc-examples/examples/reusable_jail.rs#readme -->
```rust
use path_jail::Jail;

// Create a jail (root must exist, be a directory, and not be filesystem root)
let jail = Jail::new("/var/uploads")?;

// Get the canonicalized root
let root: &Path = jail.root();

// Safely join a relative path
let path: PathBuf = jail.join("subdir/file.txt")?;

// Check if an absolute path is inside the jail (the path must exist)
let verified: PathBuf = jail.contains("/var/uploads/file.txt")?;

// Get relative path for database storage (the path must exist)
let rel: PathBuf = jail.relative(&verified)?; // "file.txt"
```

### Type-safe paths

Use `JailedPath` for compile-time guarantees:

<!-- example: doc-examples/examples/typed_paths.rs#readme -->
```rust
use path_jail::{Jail, JailedPath};

fn save_upload(path: JailedPath, data: &[u8]) -> std::io::Result<()> {
    // Validated against untrusted input when constructed. It is not pinned:
    // concurrent filesystem changes need the `guard` API.
    std::fs::write(&path, data)
}

let jail = Jail::new("/var/uploads")?;
let path: JailedPath = jail.join_typed("report.pdf")?;
save_upload(path, b"data")?;
```

### Segment joining

Safely build paths from multiple user inputs:

<!-- example: doc-examples/examples/segments.rs#readme -->
```rust
use path_jail::{Jail, JailedPath};

let jail = Jail::new("/var/uploads")?;
let user_id = "alice";
let filename = "photo.jpg";

// Each segment must be one name: no `/`, `\`, `..`, or null bytes
let path = jail.join_segments([user_id, "files", filename])?;

// These fail:
assert!(jail.join_segments(["../etc", "passwd"]).is_err()); // ".." rejected
assert!(jail.join_segments(["users/files"]).is_err()); // "/" in a segment rejected

// Type-safe version:
let typed: JailedPath = jail.segments([user_id, "files", filename])?;
```

## Error Handling

### Construction errors

<!-- example: doc-examples/examples/construction_errors.rs#readme -->
```rust
use path_jail::{Jail, JailError};

match Jail::new("/var/uploads") {
    Ok(jail) => {
        /* use jail */
        let _ = jail;
    }
    Err(JailError::InvalidRoot { path, .. }) => {
        // Filesystem root (/, C:\) or not a directory
        panic!("Config error: {}", path.display());
    }
    Err(JailError::Io(e)) => {
        // Root doesn't exist or can't be canonicalized. (`guard::FdJail::new`
        // reports this case as `InvalidRoot` with `source: Some(e)` instead.)
        panic!("Config error: {}", e);
    }
    Err(e) => panic!("Unexpected error: {}", e), // Future-proof (non_exhaustive)
}
```

### Path validation errors

<!-- example: doc-examples/examples/validation_errors.rs#readme -->
```rust
use path_jail::{Jail, JailError};

let jail = Jail::new("/var/uploads")?;

match jail.join(user_input) {
    Ok(path) => {
        // Validated. The write is a separate lookup; see TOCTOU-Safe File
        // Operations if other processes can change the tree concurrently.
        std::fs::write(&path, data)?;
    }
    Err(JailError::EscapedRoot { attempted, root }) => {
        // Path traversal or symlink escape
        eprintln!(
            "Blocked: {} escapes {}",
            attempted.display(),
            root.display()
        );
    }
    Err(JailError::BrokenSymlink(path)) => {
        // Symlink target doesn't exist (can't verify it's safe)
        eprintln!("Broken symlink: {}", path.display());
    }
    Err(JailError::InvalidPath(reason)) => {
        // Absolute path, null byte, or other invalid input
        eprintln!("Invalid: {}", reason);
    }
    Err(JailError::Io(e)) => {
        // A component couldn't be inspected (e.g. permission denied).
        // Fail closed: treat it as a rejection, not as a missing file.
        eprintln!("I/O error: {}", e);
    }
    Err(e) => eprintln!("Error: {}", e), // Future-proof (non_exhaustive)
}
```

## Example: File Uploads

With the `guard` feature, the untrusted name is resolved and opened beneath the
pinned root, and the checks run on the handle that was opened. On Linux 5.6+
x86_64/aarch64 that is one `openat2` call; elsewhere it is the `O_NOFOLLOW`
fallback (see [Platform support](#platform-support)), and `create_dir` is not
compiled, so create per-user directories out of band there.

<!-- example: doc-examples/examples/guarded_upload.rs#readme -->
```rust
use path_jail::guard::{FdJail, OpenOptions};
use path_jail::JailError;
use std::io::Write;

struct UploadService {
    jail: FdJail,
}

/// Accept one path segment only, so `user_id`/`filename` cannot reach into
/// another user's directory with `..` or `/`.
fn plain_name(s: &str) -> Result<&str, JailError> {
    if s.is_empty() || s == "." || s == ".." || s.contains('/') || s.contains('\0') {
        return Err(JailError::InvalidPath(format!(
            "not a plain file name: {s:?}"
        )));
    }
    Ok(s)
}

impl UploadService {
    fn new(root: &str) -> Result<Self, JailError> {
        Ok(Self {
            jail: FdJail::new(root)?,
        })
    }

    fn save(&self, user_id: &str, filename: &str, data: &[u8]) -> Result<(), JailError> {
        let user_dir = plain_name(user_id)?;
        // fd-relative mkdir exists only where the open is kernel-enforced.
        // Elsewhere, create per-user directories out of band.
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        match self.jail.create_dir(user_dir) {
            Ok(()) => {}
            Err(JailError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }

        let mut file = self.jail.open(
            format!("{user_dir}/{}", plain_name(filename)?),
            OpenOptions::new()
                .write(true)
                .create_new(true) // never overwrite an existing upload
                .no_symlinks(true) // no symlinked user directories (Linux)
                .require_regular_file(true)
                .reject_hard_links(true),
        )?;
        file.write_all(data)?;
        Ok(())
    }
}
```

Without `guard`, `Jail::join` validates the untrusted string, but the write
that follows is a separate pathname lookup. That is fine when only your
service writes to the tree; see [TOCTOU Race Conditions](#toctou-race-conditions)
otherwise.

## Example: File Downloads

Read from the handle that was checked. Never validate a path and then reopen it.

<!-- example: doc-examples/examples/guarded_download.rs#readme -->
```rust
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
```

## Example: Appending to a Log

<!-- example: doc-examples/examples/guarded_append.rs#readme -->
```rust
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
```

To replace a file without writing through whatever currently sits at its name,
write a new file and `rename` it into place; see
[Migrating to the guard API](docs/guides/migrating.md#replace-a-file).

## Framework Integration

These examples use the `guard` feature
(`path_jail = { version = "0.5", features = ["guard"] }`) and compile on any
Unix. The open is atomic and kernel-enforced on Linux 5.6+ x86_64/aarch64; on
other Unix targets it uses the `O_NOFOLLOW` fallback, which protects only the
final component. Guarded opens and writes are blocking calls, so they run off
the async executor. The [Tokio guide](docs/guides/tokio.md) covers streaming,
timeouts, and error mapping.

### Axum

<!-- example: doc-examples/examples/axum_upload.rs#readme -->
```rust
use axum::{extract::Path, http::StatusCode, response::IntoResponse};
use bytes::Bytes;
use path_jail::guard::{FdJail, OpenOptions};
use path_jail::JailError;
use std::io::Write;
use std::sync::LazyLock;

static UPLOADS: LazyLock<FdJail> =
    LazyLock::new(|| FdJail::new("/var/uploads").expect("uploads dir must exist"));

async fn upload(
    Path(filename): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let result = tokio::task::spawn_blocking(move || -> Result<(), JailError> {
        let mut file = UPLOADS.open(
            &filename,
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .require_regular_file(true)
                .reject_hard_links(true),
        )?;
        file.write_all(&body)?;
        Ok(())
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match result {
        Ok(()) => Ok(StatusCode::CREATED),
        Err(JailError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(StatusCode::CONFLICT)
        }
        Err(JailError::Io(_)) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        // Escape, symlink, special file, hard link, invalid path.
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}
```

### Actix-web

<!-- example: doc-examples/examples/actix_upload.rs#readme -->
```rust
use actix_web::{error, web, HttpResponse, Result};
use path_jail::guard::{FdJail, OpenOptions};
use path_jail::JailError;
use std::io::Write;
use std::sync::LazyLock;

static UPLOADS: LazyLock<FdJail> =
    LazyLock::new(|| FdJail::new("/var/uploads").expect("uploads dir must exist"));

async fn upload(path: web::Path<String>, body: web::Bytes) -> Result<HttpResponse> {
    let filename = path.into_inner();
    let result = web::block(move || -> Result<(), JailError> {
        let mut file = UPLOADS.open(
            &filename,
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .require_regular_file(true)
                .reject_hard_links(true),
        )?;
        file.write_all(&body)?;
        Ok(())
    })
    .await?;

    match result {
        Ok(()) => Ok(HttpResponse::Created().finish()),
        Err(JailError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(error::ErrorConflict("file already exists"))
        }
        Err(JailError::Io(e)) => Err(error::ErrorInternalServerError(e)),
        Err(e) => Err(error::ErrorBadRequest(e)),
    }
}
```

## TOCTOU-Safe File Operations

### `secure-open` — O_NOFOLLOW protection (all Unix)

Enable the `secure-open` feature for `O_NOFOLLOW`-protected file operations:

```toml
[dependencies]
path_jail = { version = "0.5", features = ["secure-open"] }
```

<!-- example: doc-examples/examples/secure_open.rs#readme -->
```rust
use path_jail::Jail;
use std::io::{Read, Write};

let jail = Jail::new("/var/uploads")?;

// Open with O_NOFOLLOW - fails if the final component is a symlink
let mut file = jail.open("config.txt")?;
let mut contents = String::new();
file.read_to_string(&mut contents)?;

// Create with O_CREAT | O_EXCL | O_NOFOLLOW - fails if the file exists or is a symlink
let mut file = jail.create("new.txt")?;
file.write_all(b"hello")?;

// Other options
let data_file = jail.create_or_truncate("data.txt")?; // Truncate if exists
let log_file = jail.open_append("log.txt")?; // Append mode
```

This protects against symlink swap attacks on the **final path component**. Zero additional dependencies.

**Limitation:** Protects the final path component only. An attacker who can swap an intermediate directory between path validation and the open call can still escape.

---

### `guard` — Kernel-enforced TOCTOU safety (Linux 5.6+)

On Linux 5.6+ x86_64/aarch64, the `guard` feature resolves and opens with a single `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` syscall. Because the validate-and-open is **atomic at the kernel level**, there is no window for a race condition. Other Unix targets use the `O_NOFOLLOW` fallback; see [Platform support](#platform-support).

```toml
[dependencies]
path_jail = { version = "0.5", features = ["guard"] }
```

<!-- example: doc-examples/examples/guard_open.rs#readme -->
```rust
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
```

**On macOS/BSD and Linux architectures without an `openat2` shim:** falls back
to an `O_NOFOLLOW`-based open (same protection as `secure-open`).
`attestation().toctou_safe` will be `false`.

On Linux x86_64/aarch64, guarded mutations stay fd-relative as well:

<!-- example: doc-examples/examples/guard_mutations.rs#readme -->
```rust
jail.create_dir("work")?;
jail.rename("incoming/report.pdf", "work/report.pdf")?;
jail.remove_file("work/report.pdf")?;
jail.remove_dir("work")?;
```

These methods are intentionally unavailable on fallback platforms because a
pathname-based fallback would reintroduce the race they are designed to avoid.

**Blocked by `openat2`:**
- Symlink escapes (`/etc` link inside jail) → `JailError::Escape`
- `..` traversal → `JailError::Escape`
- `/proc/self/root` and other magic links → `JailError::SymlinkRejected`
  (Linux reports `ELOOP` for both magic-link and ordinary symlink rejection)
- Symlinks when `no_symlinks(true)` → `JailError::SymlinkRejected`

**Not blocked by `openat2` — opt in with `OpenOptions` handle policies:**
- Hard links: a hard link inside the jail can name an inode that also lives
  outside it. `reject_hard_links(true)` → `JailError::HardLinkRejected`, and a
  requested `truncate` is deferred until the check passes. The check is
  point-in-time: a link added between the check and the truncate still sees the
  file emptied, so write-then-rename when that race matters.
- FIFOs, directories and device nodes: `require_regular_file(true)` →
  `JailError::FileTypeRejected`. Sockets, and write-only opens of a FIFO with no
  reader, fail in the kernel before a handle exists and return `JailError::Io`. The open uses `O_NONBLOCK`, so a planted FIFO
  is rejected instead of hanging the caller.

**Returns `JailError::UnsupportedKernel`** on Linux kernels older than 5.6. Zero additional dependencies — raw syscall, no libc.

## Alternatives

| | path_jail | strict-path | cap-std |
|-|-----------|-------------|---------|
| Approach | Path validation + guard | Type-safe path system | File descriptors |
| Returns | `PathBuf` / `JailedPath` / `GuardedFile` | Custom `StrictPath<T>` | Custom `Dir`/`File` |
| Dependencies | 0 | ~5 | ~10 |
| TOCTOU-safe | `guard` (Linux 5.6+ x86_64/aarch64, kernel-enforced) / `secure-open` (final component, all Unix) | No | Yes |
| Best for | File sandboxing with optional kernel enforcement | Complex type-safe paths | Full capability-based security |

- [`strict-path`](https://crates.io/crates/strict-path) - More comprehensive, uses marker types for compile-time guarantees
- [`cap-std`](https://docs.rs/cap-std) - Capability-based, TOCTOU-safe, but replaces `std::fs` entirely

*`guard` on Linux 5.6+ x86_64/aarch64: the validate-and-open is a single `openat2` syscall — truly atomic, no race window. On macOS/BSD and other Linux architectures the same API falls back to `O_NOFOLLOW` (final component only).*

## Thread Safety

`Jail` implements `Clone`, `Send`, and `Sync`. It can be safely shared across threads.
`guard::FdJail` is `Send + Sync` too; share it with `Arc`, or use
`FdJail::try_clone` to duplicate the pinned descriptor without panicking when
the process is out of file descriptors.

<!-- example: doc-examples/examples/thread_safety.rs#readme -->
```rust
use path_jail::Jail;
use std::sync::Arc;

let jail = Arc::new(Jail::new("/var/uploads")?);

let jail_clone = Arc::clone(&jail);
let handle = std::thread::spawn(move || jail_clone.join("file.txt"));
let path = handle.join().expect("thread panicked")?;
```

## MSRV

Minimum Supported Rust Version: **1.85**

This crate tracks recent stable Rust. The MSRV is bumped to 1.85 to accommodate transitive dev-dependencies that require edition 2024.

## Development

This crate is maintained by [Tenuo](https://tenuo.ai). Contributions are welcome!

```bash
git clone https://github.com/tenuo-ai/path_jail.git
cd path_jail
cargo test --all-features
cargo clippy --all-features --all-targets -- -D warnings
```

Rust examples in this README and in `docs/guides/` are compiled from
`doc-examples/examples/`. Edit the example file, then sync and check:

```bash
python3 scripts/check_doc_examples.py --fix
cargo build --manifest-path doc-examples/Cargo.toml --examples
```

## License

MIT OR Apache-2.0
