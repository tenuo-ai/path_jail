# path_jail Design

This document explains why `path_jail` is built the way it is. It is for
contributors and for users who want to understand the guarantees before relying
on them. For usage, see [README.md](README.md); for exactly what each API
defends against, see the [threat model](SECURITY.md).

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

For symlink and rename races, the only complete defense is making validation and open a single
atomic kernel operation. Hard links, FIFOs, and device nodes are a separate problem: no path
resolution flag stops them, so they have to be checked on the opened handle (§4.9).

---

## 2. Architecture: Three Layers

`path_jail` offers three layers, each stronger than the last. They are independent Cargo features:
enabling `guard` does not require `secure-open`.

```
┌──────────────────────────────────────────────────────────────────┐
│  guard (Unix)                                                    │
│  FdJail: root pinned at construction, returns descriptors        │
│  Linux 5.6+ x86_64/aarch64: openat2(RESOLVE_BENEATH), atomic     │
│  Other Unix: O_NOFOLLOW fallback (toctou_safe = false)           │
│  Handle checks: file type, hard links  ·  Attestation            │
├──────────────────────────────────────────────────────────────────┤
│  secure-open (Unix)                                              │
│  Path validation, then O_NOFOLLOW on the final component         │
├──────────────────────────────────────────────────────────────────┤
│  default (all platforms)                                         │
│  Jail + JailedPath: path validation, no file I/O                 │
└──────────────────────────────────────────────────────────────────┘
```

Callers opt into exactly the layer they need. The default build compiles none of the `secure-open`
or `guard` code.

---

## 3. Security Model

The [threat model](SECURITY.md#what-each-api-defends-against) is the authoritative, threat-by-threat
list. This section summarizes the reasoning.

### 3.1 Default API (`Jail`)

`Jail::join` guarantees that, at the moment of the call, every existing component of the path
resolved inside the root. Components that do not exist yet are checked lexically, which is what
makes new files possible (§1.1).

| Attack | Example | Blocked |
|--------|---------|---------|
| Path traversal | `../../etc/passwd` | Yes |
| Symlink escape | `link -> /etc` | Yes |
| Symlink chains | `a -> b -> /etc` | Yes |
| Broken symlinks | `link -> /nonexistent` | Yes |
| Absolute injection | `/etc/passwd` | Yes |
| Parent escape | `foo/../../secret` | Yes |
| Null byte injection | `file\x00.txt` | Yes |

**Fail closed on unreadable components.** If an existing component cannot be inspected (for
example, permission denied), `join` returns `JailError::Io`. Before 0.5 it treated such a component
as missing, which let an unreadable symlink pass as a not-yet-created file. A security check must
not turn "I could not look" into "nothing is there."

**Limitation:** `join` returns a path, so there is a TOCTOU window between `join()` and any
later filesystem call. See §3.3.

### 3.2 `secure-open` Feature

Validates with `Jail::join`, then opens with `O_NOFOLLOW`. This closes the symlink-swap window on
the **last** component only. Intermediate directory swaps remain possible, and the open follows
hard links and blocks on a FIFO.

### 3.3 `guard` Feature

`FdJail::new` pins the root. Every guard operation then resolves relative to that pinned root:

| Mechanism | Protection | Platforms |
|---|---|---|
| `openat2(RESOLVE_BENEATH \| RESOLVE_NO_MAGICLINKS)` | Atomic; covers every component and magic links | Linux 5.6+ on x86_64 and aarch64 |
| `O_NOFOLLOW` fallback | Path validation, then final component only (as `secure-open`) | macOS, the BSDs, Android, and other Linux architectures |

On the openat2 path, validation and open are one syscall; there is no userspace window between
them. Callers can see which mechanism was used through `Attestation::toctou_safe`. The
[platform support matrix](README.md#platform-support) lists every combination.

**No fallback on old Linux kernels.** On x86_64 and aarch64, `FdJail::new` returns
`JailError::UnsupportedKernel` when `openat2` is missing (Linux < 5.6) or when a seccomp or LSM
policy answers it with `EPERM`. It does not silently fall back to the weaker path: on an
architecture where the strong guarantee exists, a caller who asked for `guard` should find out
that it is unavailable rather than get less than they expect. The probe treats `EPERM` as
unavailable for the same reason: otherwise construction would succeed and every later call would
fail.

---

## 4. API Design Decisions

### 4.1 `#[must_use]` on `join()` and friends

`join`, `join_typed`, `join_segments`, `segments`, and `contains` are `#[must_use]`, so discarding
the validated result outright is a compiler warning:

```rust
// Warns: "unused return value of `Jail::join` that must be used"
jail.join(user_input);
std::fs::write(user_input, data)?;  // uses the unvalidated input

// RIGHT
let safe = jail.join(user_input)?;
std::fs::write(&safe, data)?;
```

The lint is a partial guard. It does **not** fire for `jail.join(user_input)?;` or
`jail.join(user_input).ok();`, because the result is consumed. For a compile-time guarantee that a
path was validated, take a `JailedPath` (§4.2).

### 4.2 `JailedPath` newtype

`JailedPath` can only be constructed by `Jail::join_typed` and `Jail::segments`. Functions that
take a `JailedPath` therefore cannot be handed an unvalidated `PathBuf`:

```rust
fn save_upload(path: JailedPath, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(&path, data)
}

// Won't compile — PathBuf is not JailedPath
save_upload(user_input, data)?;

// Must validate first
let safe = jail.join_typed(user_input)?;
save_upload(safe, data)?;
```

`JailedPath` records that the path was validated, not that it is still safe: it does not pin
anything, so the TOCTOU limitation of §3.1 still applies.

### 4.3 `join_segments()`

Common pattern: building paths from multiple user inputs such as
`format!("{}/{}", user_id, filename)`. This is error-prone because separators and `..` in a segment
can still escape. `join_segments()` validates each segment independently, rejecting `/`, `\`, `..`,
and null bytes. Empty segments are silently skipped (consistent with how most shells and URL
normalizers treat empty components).

### 4.4 Why reject broken symlinks?

A broken symlink's target cannot be verified. If the path were returned, and the target were later
created (or exists but is inaccessible), the symlink could point outside the jail. Rejection is the
safe default. Symlink loops are rejected the same way.

### 4.5 Why canonicalize the root immediately?

Ensures `starts_with()` comparisons are reliable. Without canonicalization:
- `/var/uploads` vs `/var/./uploads` — fails on string comparison
- macOS: `/var` vs `/private/var` — `var` is a symlink, comparison would fail

### 4.6 Why no runtime dependencies?

A sandboxing crate is part of its users' trusted computing base, so it should add as little to it
as possible. `path_jail` has no runtime dependencies in any feature set:

- On Linux x86_64 and aarch64, `openat2`, `mkdirat`, `unlinkat`, `renameat2`, and `fcntl` are
  invoked through a small inline-assembly syscall wrapper (`src/openat2.rs`), not through `libc`.
- The `O_NOFOLLOW` fallback uses `std::os::unix::fs::OpenOptionsExt::custom_flags`, and declares
  `fcntl` with `extern "C"` from the platform C library that `std` already links.
- `O_*` flag values differ by OS and, on Linux, by architecture (for example, `O_NOFOLLOW` is
  `0x8000` on ARM and PowerPC but `0o400000` on x86). The crate carries a table per target and
  **refuses to compile** (`compile_error!`) on a target whose values it does not know, rather than
  guess and silently follow symlinks.

### 4.7 Pluggable signing (`Signer` / `Verifier`)

The `Attestation` struct records inode, device, nlink, and timestamp at open time. path_jail does
not vendor a crypto implementation — callers bring their own by implementing `Signer` and
`Verifier`. This keeps the crate zero-dependency while supporting `ed25519-dalek`, `ring`, HSM
clients, or any other backend.

Version 1 attestations carry no verifier challenge, audience, key identifier, or expiry, so a
signed attestation can be replayed. Do not use one as an authorization token; see the
[threat model](SECURITY.md#what-each-api-defends-against) and the planned
[v2 format](https://github.com/tenuo-ai/path_jail/issues/10).

### 4.8 `FdJail` cloning and thread safety

`FdJail` is `Send + Sync` (its fields are a path, two integers, and, on Linux, an `OwnedFd`), so
the usual way to share one is `Arc<FdJail>`.

It also implements `Clone`. On Linux, cloning `dup(2)`s the pinned directory descriptor, so each
clone owns an independent descriptor. `dup` can fail when the process is out of file descriptors,
and `Clone::clone` cannot return an error, so `clone` panics in that case. `FdJail::try_clone`
returns the error instead; prefer it in long-running services.

### 4.9 Handle checks: file type and hard links

`openat2(RESOLVE_BENEATH)` controls **how a name is resolved**. It cannot see that a regular-looking
name is a FIFO (opening it blocks until a writer appears), a device node, or a hard link whose inode
also lives outside the jail. Those can only be decided by looking at what was opened, so
`OpenOptions` offers two checks on the opened handle:

- `require_regular_file(true)` rejects directories, FIFOs, and device nodes with
  `JailError::FileTypeRejected`.
- `reject_hard_links(true)` rejects a non-directory with `nlink > 1` with
  `JailError::HardLinkRejected`.

Design choices:

- **Check the handle, never the path.** Both checks use `fstat` on the descriptor the caller then
  reads or writes. A second lookup by path could be raced.
- **Non-blocking open.** With either check set, the open uses `O_NONBLOCK`, so a planted FIFO is
  rejected instead of hanging the caller. The flag is cleared before the handle is returned, so
  callers get an ordinary blocking descriptor.
- **Deferred truncate.** `O_TRUNC` takes effect inside `open`, before any check could run. With a
  check set, the crate opens without `O_TRUNC` and truncates only after the checks pass, so a file
  that is already hard-linked is not emptied. The check is a point-in-time sample: a link added
  between the check and the truncate is not caught, so write a new file and rename it into place
  when that matters.
- **Opt-in.** Both checks are off by default to keep existing `open` calls behaving as they did,
  and because some callers (a content-addressed store, a tool that reads devices) legitimately need
  hard links or special files. Every guarded example in the documentation turns them on.
- **No controlling terminal.** Guarded opens pass `O_NOCTTY`, so a terminal reached through the
  jail never becomes the process's controlling terminal.

Opening a device node can still trigger driver side effects before it is rejected. Creating a
device node requires `CAP_MKNOD`, so this matters mainly when the jail tree is shared with
privileged processes.

### 4.10 Guarded mutations

On Linux x86_64 and aarch64, `FdJail` also provides `create_dir`, `remove_file`, `remove_dir`, and
`rename`. Each one opens the parent directory with `openat2(O_PATH | O_DIRECTORY, RESOLVE_BENEATH)`
and then issues the matching `*at` syscall on that pinned parent, so a concurrent rename of a
parent directory cannot redirect the operation. The `_with` variants take `ResolveOptions` to also
reject symlinks or mount crossings in the parent path.

- **Not provided on the fallback.** A pathname-based `create_dir` or `rename` would reintroduce
  exactly the race these methods exist to close, so they are not compiled where they cannot be
  kernel-enforced. Callers on macOS and the BSDs handle directory setup out of band.
- **No path normalization on the final component.** `Path::file_name` silently drops a trailing
  `/` or `/.`, which would turn `remove_file("link/")` into unlinking the symlink itself. The
  mutation methods reject a trailing `/`, `/.`, or `/..` instead of acting on a different name than
  the caller wrote.
- **Retry `EAGAIN`.** With `RESOLVE_BENEATH`, the kernel returns `EAGAIN` when a rename races `..`
  resolution. The wrapper retries a bounded number of times rather than surface a transient error.

### 4.11 `check_path` is for display, not for opening

`FdJail::check_path` validates a path without returning a descriptor, for log lines, error
messages, and audit records. On Linux it resolves existing paths with the same `openat2` rules as
`open`, so it does not approve a path that `open` would reject, and it checks that the root path
still names the pinned directory (device and inode). It returns the caller's path rather than a
resolved one, so the log shows what was asked for.

Its answer is point-in-time. The tree can change before any later operation, so a `check_path`
result is never proof that a later open is safe: open with `FdJail::open` on the original input,
and never open a `check_path` result with `std::fs`, which would be a second, unchecked lookup.

---

## 5. Project Structure

```
path_jail/
├── src/
│   ├── lib.rs           # Re-exports, join() convenience function, crate docs
│   ├── jail.rs          # Jail: path validation
│   ├── jailed_path.rs   # JailedPath newtype
│   ├── error.rs         # JailError
│   ├── open.rs          # secure-open: JailedFile, O_NOFOLLOW opens
│   ├── openat2.rs       # Linux x86_64/aarch64 syscall wrappers (openat2, *at, fcntl)
│   └── guard/
│       ├── mod.rs       # Re-exports
│       ├── fd_jail.rs   # FdJail, GuardedFile, Attestation, OpenOptions, ResolveOptions, FileKind
│       └── signing.rs   # Signer, Verifier, VerifyError
├── tests/
│   ├── security.rs      # Path validation
│   ├── secure_open.rs   # secure-open
│   └── guard.rs         # guard
├── fuzz/                # cargo-fuzz target for arbitrary path bytes (not published)
├── doc-examples/        # Compiled copies of the README and guide examples (not published)
├── scripts/             # check_doc_examples.py: keeps doc blocks identical to doc-examples/
├── docs/guides/         # Migrating to the guard API; using it with Tokio
├── README.md            # User guide and platform support matrix
├── DESIGN.md            # This file
├── SECURITY.md          # Threat model and vulnerability reporting
├── CHANGELOG.md
├── LICENSE-MIT
└── LICENSE-APACHE
```

---

## 6. Feature Flags

### `default` — no flags

Zero dependencies. Provides `Jail`, `JailedPath`, `JailError`, and the `join()` convenience
function. Works on every platform, including Windows.

### `secure-open` (Unix)

Adds `O_NOFOLLOW`-protected file operations to `Jail`:

```rust
let file = jail.open("config.txt")?;              // O_NOFOLLOW
let file = jail.create("new.txt")?;               // O_CREAT | O_EXCL | O_NOFOLLOW
let file = jail.create_or_truncate("data.txt")?;  // O_CREAT | O_TRUNC | O_NOFOLLOW
let file = jail.open_append("log.txt")?;          // O_CREAT | O_APPEND | O_NOFOLLOW
```

**Limitation:** protects the final path component only (§3.2). On Windows the feature compiles to
nothing.

### `guard` (Unix)

Adds `FdJail`, `GuardedFile`, `OpenOptions` (with the handle checks of §4.9), `ResolveOptions`,
`FileKind`, `Attestation`, the `Signer`/`Verifier` traits, and the guard `JailError` variants.
Opens are atomic and kernel-enforced on Linux 5.6+ x86_64/aarch64 and use the `O_NOFOLLOW`
fallback on other Unix targets; the guarded mutations of §4.10 exist only on the former.

On Windows the `guard` module is not compiled, so code that uses it does not build there; enabling
the feature itself is harmless.

---

## 7. Platform Support Matrix

The matrix (features × kernel × architecture × OS, plus what CI runs and compile-checks) is in
[README.md § Platform support](README.md#platform-support). Other documents link to it rather than
keep their own copy.

---

## 8. Known Limitations

See [README.md § Limitations](README.md#limitations) and the [threat model](SECURITY.md) for the
full list. Key points:

- **Hard links** cannot be detected by path inspection alone. `OpenOptions::reject_hard_links(true)`
  checks `nlink` on the opened handle and fails the open (`GuardedFile::has_hard_links()` reports
  it for callers with their own policy). The check is point-in-time.
- **Mount points** — use `OpenOptions::no_xdev()` on Linux to block cross-mount traversal.
- **Windows reserved device names** (`CON`, `NUL`, etc.) — validate before calling path_jail.
- **Unicode normalization** (macOS NFD) — always store `jail.root()`, never the raw input.
- **TOCTOU on the fallback** (macOS, the BSDs, and Linux architectures other than x86_64/aarch64) —
  the `guard` fallback is not atomic; use Linux 5.6+ on x86_64/aarch64 or OS isolation for the
  strongest guarantees.

---

## 9. Possible Future Work

Open proposals, each tracked in an issue:

- [Guarded `openat2` on more Linux architectures](https://github.com/tenuo-ai/path_jail/issues/5)
- [A guarded Windows backend](https://github.com/tenuo-ai/path_jail/issues/6) built on directory handles
- [Race-safe recursive directory creation](https://github.com/tenuo-ai/path_jail/issues/7) (`create_dir_all`)
- [A versioned (v2) attestation wire format](https://github.com/tenuo-ai/path_jail/issues/10) with freshness and context
- [Handle-relative directory access and iteration](https://github.com/tenuo-ai/path_jail/issues/11)
- [Atomic guarded file replacement](https://github.com/tenuo-ai/path_jail/issues/13)

Decided against:

- **Async wrappers.** Running a guarded open on Tokio is `spawn_blocking` plus
  `tokio::fs::File::from_std`; a helper would add an async runtime to every user's dependency tree
  to save a few lines. See [docs/guides/tokio.md](docs/guides/tokio.md).
