# path_jail Design Document

This document captures design decisions and rationale for `path_jail`. For usage, see `README.md`.

## 1. The Problem

### 1.1 The New File Paradox

The standard approach:

```rust
let path = root.join(user_input).canonicalize()?;
if !path.starts_with(&root) {
    return Err("escape attempt");
}
```

The bug: `canonicalize()` fails if the file does not exist. You cannot validate paths for files you
intend to create.

### 1.2 The Symlink Trap

An attacker creates:
```
uploads/innocent_link -> /etc
```

Writing to `uploads/innocent_link/passwd` overwrites system files. String-based `..` removal does
not catch this.

### 1.3 The Broken Symlink Trap

An attacker creates:
```
uploads/evil -> /etc/shadow  (target does not exist yet)
```

`Path::exists()` returns false for broken symlinks. If verification is skipped, a later write could
follow the symlink to an external location.

### 1.4 The Traversal Trap

Lexical path cleaning is insufficient:
- `foo/../bar` vs `foo/bar`
- Windows: `C:\Users` vs `\\?\C:\Users`

OS-level path resolution is required.

### 1.5 The TOCTOU Trap

Even a correctly validated path is unsafe if anything changes between validation and use:

```rust
let path = jail.join("file.txt")?;  // validated here
// attacker swaps directory for symlink here
std::fs::write(&path, data)?;        // follows symlink — escapes jail
```

The only complete defence is making validation and open a single atomic kernel operation.

---

## 2. Architecture: Three Capability Layers

`path_jail` is organized as three feature layers, each building on the previous:

```
┌────────────────────────────────────────────────────────────┐
│  guard (Linux 5.6+)                                        │
│  openat2(RESOLVE_BENEATH) — atomic validate + open         │
│  Attestation: inode, device, nlink, timestamp, signature   │
├────────────────────────────────────────────────────────────┤
│  secure-open (Unix)                                        │
│  O_NOFOLLOW on the final path component                    │
├────────────────────────────────────────────────────────────┤
│  default (all platforms)                                   │
│  Jail + JailedPath — path validation, no file I/O          │
└────────────────────────────────────────────────────────────┘
```

Callers opt into exactly the level they need; the default has zero feature overhead.

---

## 3. Security Model

### 3.1 Default API (`Jail`)

`path_jail` guarantees the returned path was physically inside the jail at the moment of
verification.

| Attack | Example | Blocked |
|--------|---------|---------|
| Path traversal | `../../etc/passwd` | Yes |
| Symlink escape | `link -> /etc` | Yes |
| Symlink chains | `a -> b -> /etc` | Yes |
| Broken symlinks | `link -> /nonexistent` | Yes |
| Absolute injection | `/etc/passwd` | Yes |
| Parent escape | `foo/../../secret` | Yes |
| Null byte injection | `file\x00.txt` | Yes |

**Limitation:** TOCTOU race between `join()` and a subsequent filesystem call. See §3.3.

### 3.2 `secure-open` Feature

Adds `O_NOFOLLOW` protection to the final path component of every open. Closes the symlink-swap
window on the **last** component only. Intermediate directory swaps remain unprotected.

### 3.3 `guard` Feature

Uses `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` on Linux 5.6+. The validate-and-open is a
single kernel syscall — there is no userspace window between them.

| Mechanism | Protection | Platforms |
|---|---|---|
| `openat2` | Atomic; covers all components + magic links | Linux 5.6+ |
| `O_NOFOLLOW` fallback | Final component only | macOS / BSD |

The fallback path on macOS/BSD is intentionally equivalent to `secure-open`. Callers can detect
which path was used at runtime via `Attestation::toctou_safe`.

---

## 4. API Design Decisions

### 4.1 `#[must_use]` on `join()` and friends

Prevents confused deputy attacks where a caller validates a path but then uses the original
untrusted input:

```rust
// WRONG: validates but ignores result
jail.join(user_input)?;
std::fs::write(user_input, data)?;  // uses unvalidated path!

// RIGHT
let safe = jail.join(user_input)?;
std::fs::write(&safe, data)?;
```

### 4.2 `JailedPath` newtype

Prevents "confused deputy" bugs at compile time. Functions can require `JailedPath` parameters,
making it impossible to accidentally pass an unvalidated `PathBuf`:

```rust
fn save_upload(path: JailedPath, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(&path, data)
}

// Won't compile — PathBuf is not JailedPath
save_upload(user_input, data);  // Error!

// Must validate first
let safe = jail.join_typed(user_input)?;
save_upload(safe, data);  // OK
```

### 4.3 `join_segments()`

Common pattern: building paths from multiple user inputs such as
`format!("{}/{}", user_id, filename)`. This is error-prone because separators and `..` in a segment
can still escape. `join_segments()` validates each segment independently, rejecting `/`, `\`, `..`,
and null bytes. Empty segments are silently skipped (consistent with how most shells and URL
normalizers treat empty components).

### 4.4 Why reject broken symlinks?

A broken symlink's target cannot be verified. If the path were returned, and the target were later
created (or exists but is inaccessible), the symlink could point outside the jail. Rejection is the
safe default.

### 4.5 Why canonicalize the root immediately?

Ensures `starts_with()` comparisons are reliable. Without canonicalization:
- `/var/uploads` vs `/var/./uploads` — fails on string comparison
- macOS: `/var` vs `/private/var` — `var` is a symlink, comparison would fail

### 4.6 Why no runtime dependencies?

`openat2` is invoked via a hand-rolled syscall wrapper in `src/openat2.rs` rather than through
`libc`. This keeps the default feature set free of any runtime dependency and the `guard` feature
free of any new ones.

### 4.7 Pluggable signing (`Signer` / `Verifier`)

The `Attestation` struct records inode, device, nlink, and timestamp at open time. path_jail does
not vendor a crypto implementation — callers bring their own by implementing `Signer` and
`Verifier`. This keeps the crate zero-dependency while supporting `ed25519-dalek`, `ring`, HSM
clients, AWS KMS, GCP KMS, or any other backend.

### 4.8 `FdJail` does not implement `Clone`/`Send`/`Sync` by default

`Clone` would require `dup(2)` on the pinned `dirfd`. On Linux, `OwnedFd` is `Send + Sync`, so
sharing an `FdJail` across threads via `Arc<FdJail>` is safe once those traits are derived. They
are added as part of v0.4.0 (see `fd_jail.rs`).

---

## 5. Project Structure

```
path_jail/
├── src/
│   ├── lib.rs          # Re-exports, join() convenience function
│   ├── jail.rs         # Jail struct and methods
│   ├── jailed_path.rs  # JailedPath newtype
│   ├── error.rs        # JailError enum
│   ├── open.rs         # secure-open feature (O_NOFOLLOW helpers)
│   ├── openat2.rs      # Raw openat2 syscall wrapper (Linux)
│   └── guard/
│       ├── mod.rs      # Re-exports
│       ├── fd_jail.rs  # FdJail, JailFile, Attestation, OpenOptions
│       └── signing.rs  # Signer, Verifier, VerifyError traits
├── tests/
│   ├── security.rs     # Core path-validation tests
│   ├── secure_open.rs  # secure-open feature tests
│   └── guard.rs        # guard feature tests
├── docs/
│   └── (empty — design specs live in DESIGN.md)
├── README.md           # User guide
├── DESIGN.md           # This file
├── SECURITY.md         # Threat model
├── CHANGELOG.md
├── LICENSE-MIT
└── LICENSE-APACHE
```

---

## 6. Feature Flags

### `default` — no flags

Zero dependencies. Provides `Jail`, `JailedPath`, `JailError`, and the `join()` convenience
function. Works on all platforms including Windows.

### `secure-open` (Unix only)

Adds `O_NOFOLLOW`-protected file operations to `Jail`:

```rust
let file = jail.open("config.txt")?;     // O_NOFOLLOW
let file = jail.create("new.txt")?;      // O_CREAT | O_EXCL | O_NOFOLLOW
let file = jail.create_or_truncate(...); // O_TRUNC | O_NOFOLLOW
let file = jail.open_append("log.txt")?; // O_APPEND | O_NOFOLLOW
```

Zero additional dependencies — uses `std::os::unix::fs::OpenOptionsExt::custom_flags()`.

**Limitation:** Protects the final path component only.

### `guard` (Unix API surface; full protection on Linux 5.6+)

Adds `FdJail` with atomic kernel-enforced containment on Linux 5.6+, and the O_NOFOLLOW fallback
on macOS/BSD. Also adds `Attestation`, `Signer`/`Verifier` traits, and new `JailError` variants.

Enabling `guard` on Windows compiles without error but is a no-op (all items are
`#[cfg(unix)]`-gated).

---

## 7. Platform Support Matrix

| Feature | Linux 5.6+ | Linux < 5.6 | macOS / BSD | Windows |
|---|---|---|---|---|
| `default` | ✓ | ✓ | ✓ | ✓ |
| `secure-open` | ✓ | ✓ | ✓ | no-op |
| `guard` (TOCTOU-safe) | ✓ | `UnsupportedKernel` error | fallback (`toctou_safe=false`) | no-op |

---

## 8. Known Limitations

See `README.md` § Limitations and `SECURITY.md` for the full threat model. Key points:

- **Hard links** cannot be detected by path inspection alone. `JailFile::has_hard_links()` checks
  `nlink` after the fd is open — use it to enforce hard-link policy.
- **Mount points** — use `OpenOptions::no_xdev()` on Linux to block cross-mount traversal.
- **Windows reserved device names** (`CON`, `NUL`, etc.) — validate before calling path_jail.
- **Unicode normalization** (macOS NFD) — always store `jail.root()`, never the raw input.
- **TOCTOU on macOS** — the `guard` fallback is not atomic; use Linux 5.6+ or OS isolation for
  the strongest guarantees.

---

## 9. Future Considerations

Not planned, but possible extensions if there is demand:

- **Async support** — feature-gated async wrappers around `FdJail::open`
- **Serde support** — deserializing `Jail` from config files
- **Windows `secure-open`** — reparse-point detection via `FILE_FLAG_OPEN_REPARSE_POINT`
- **`FdJail` directory operations** — `mkdir`, `readdir`, `rename` via the pinned `dirfd`
