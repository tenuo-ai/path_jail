# path_jail

> **Work in Progress** - Core functionality works, API may change.

A zero-dependency filesystem sandbox for Rust. Restricts paths to a root directory, preventing traversal attacks while supporting files that don't exist yet.

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

### Limitations

This library validates paths. It does not hold file descriptors.

There is a **TOCTOU (time-of-check time-of-use)** race condition. If an attacker has write access to the jail directory, they could swap a directory with a symlink between validation and use.

**Defends against:**
- Logic errors in path construction
- Confused deputy attacks from untrusted input

**Does not defend against:**
- Malicious local processes racing your I/O

For kernel-enforced sandboxing, use [`cap-std`](https://docs.rs/cap-std).

## API

### One-shot validation

```rust
// Validate and join in one call
let safe: PathBuf = path_jail::join("/var/uploads", "subdir/file.txt")?;
```

### Reusable jail

```rust
use path_jail::Jail;

// Create a jail (root must exist and be a directory)
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

## Alternatives

| | path_jail | strict-path | cap-std |
|-|-----------|-------------|---------|
| Approach | Path validation | Type-safe path system | File descriptors |
| Returns | `std::path::PathBuf` | Custom `StrictPath<T>` | Custom `Dir`/`File` |
| Dependencies | 0 | ~5 | ~10 |
| TOCTOU-safe | No | No | Yes |
| Best for | Simple file sandboxing | Complex type-safe paths | Kernel-enforced security |

- [`strict-path`](https://crates.io/crates/strict-path) - More comprehensive, uses marker types for compile-time guarantees
- [`cap-std`](https://docs.rs/cap-std) - Capability-based, TOCTOU-safe, but different API than `std::fs`

## Roadmap

- [x] Core path validation (`join`, `contains`, `relative`)
- [x] Symlink resolution (including chains and broken symlinks)
- [x] Error types with context
- [x] Comprehensive security tests (22 tests)
- [ ] I/O helpers (`read`, `write`, `create_dir_all`)

## License

MIT OR Apache-2.0

