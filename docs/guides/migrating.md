# Migrating to the guard API

This guide moves file access from `std::fs` (or from `Jail::join` followed by
`std::fs`) to `path_jail::guard`. It is for code that opens files named by
untrusted input in a directory that other users or processes can modify.

If only your service writes to the tree, `Jail::join` alone may be enough; see
[Choosing an API](../../README.md#choosing-an-api) and the
[threat model](../../SECURITY.md#what-each-api-defends-against).

## Why the path-only pattern is not enough

```rust,ignore
// Before: validate a string, then open it in a separate lookup.
let path = jail.join(user_input)?;   // checked now
std::fs::write(&path, data)?;        // resolved again here
```

Between those two calls, another process can replace a directory on the path
with a symlink, and the write follows it. `Jail::join` cannot prevent that:
it returns a path, and a path is looked up again every time it is used.

The guard API returns a **file descriptor** instead. On Linux 5.6+ x86_64 and
aarch64, resolution and open are one `openat2(RESOLVE_BENEATH)` call beneath a
directory descriptor pinned when the jail was created. There is no second
lookup to race. On other Unix targets, the same API falls back to an
`O_NOFOLLOW` open and reports `attestation().toctou_safe == false`; see the
[support matrix](../../README.md#platform-support).

## Setup

```toml
[dependencies]
path_jail = { version = "0.5", features = ["guard"] }
```

Create one `FdJail` per root at startup and share it (`Arc<FdJail>` or a
`static`). `FdJail::new` pins the root directory; renaming or replacing the
root path afterwards does not move the jail.

```rust,ignore
use path_jail::guard::{FdJail, OpenOptions};
let jail = FdJail::new("/var/uploads")?;
```

Every operation below takes the untrusted **relative** path directly. Do not
call `Jail::join` or `FdJail::check_path` first and pass the result on:
`check_path` is for logging and display only.

## Read a file

```rust,ignore
// Before
let text = std::fs::read_to_string(jail.join(name)?)?;
```

<!-- example: doc-examples/examples/migration.rs#read -->
```rust
let mut file = jail.open(
    name,
    OpenOptions::new()
        .read(true)
        .require_regular_file(true)
        .reject_hard_links(true),
)?;
let mut text = String::new();
file.read_to_string(&mut text)?;
```

`require_regular_file` rejects FIFOs, devices, and directories (a FIFO is
opened non-blocking, so it cannot hang the caller). `reject_hard_links`
rejects a file whose inode has another name, which may be outside the jail.
Both checks run with `fstat` on the descriptor you then read from.

## Create a new file

```rust,ignore
// Before
std::fs::write(jail.join(name)?, data)?;
```

<!-- example: doc-examples/examples/migration.rs#create -->
```rust
// `FdJail::create` is `write(true).create_new(true)`: it fails if the
// file already exists, so it never follows or clobbers anything.
let mut file = jail.create(name)?;
file.write_all(data)?;
```

## Overwrite an existing file

```rust,ignore
// Before
std::fs::write(jail.join(name)?, data)?; // follows a symlink at `name`
```

<!-- example: doc-examples/examples/migration.rs#overwrite -->
```rust
let mut file = jail.open(
    name,
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true) // deferred until the handle checks pass
        .require_regular_file(true)
        .reject_hard_links(true),
)?;
file.write_all(data)?;
```

With a handle check enabled, the truncate happens only after the checks pass,
so a file that is already hard-linked is not emptied. The check is a
point-in-time sample: a process that adds a link in between still sees the
file emptied. When that matters, [replace the file](#replace-a-file) instead.

## Append to a file

```rust,ignore
// Before
std::fs::OpenOptions::new().append(true).create(true).open(jail.join(name)?)?;
```

<!-- example: doc-examples/examples/migration.rs#append -->
```rust
let mut file = jail.open(
    name,
    OpenOptions::new()
        .append(true)
        .create(true)
        .require_regular_file(true)
        .reject_hard_links(true),
)?;
writeln!(file, "{line}")?;
```

## Directories, rename, and remove (Linux x86_64/aarch64)

```rust,ignore
// Before
std::fs::create_dir(jail.join("staging")?)?;
std::fs::rename(jail.join(from)?, jail.join(to)?)?;
```

<!-- example: doc-examples/examples/migration.rs#mutate -->
```rust
jail.create_dir("staging")?;
jail.rename("incoming/report.pdf", "staging/report.pdf")?;
jail.remove_file("staging/report.pdf")?;
jail.remove_dir("staging")?;
```

Each call pins the parent directory beneath the jail before the `*at` syscall
runs. `create_dir_with`, `remove_file_with`, `remove_dir_with`, and
`rename_with` take `ResolveOptions` to also reject symlinks (`no_symlinks`) or
mount crossings (`no_xdev`) in the parent path. A trailing `/`, `/.`, or `/..`
is rejected rather than normalized away.

These methods are not compiled on the fallback platforms, because a
pathname-based version would reintroduce the race. On macOS and BSD, create
directories out of band or with `std::fs` from trusted code.

## Replace a file

To replace a file without ever writing through whatever currently sits at its
name, write a new file and rename it into place (Linux x86_64/aarch64):

<!-- example: doc-examples/examples/migration.rs#replace -->
```rust
// Write a fresh file, then move it into place. Unlike an in-place
// truncate, nothing that already exists at `name` is ever written to.
let mut file = jail.create(tmp)?;
file.write_all(data)?;
file.sync_all()?;
drop(file);
jail.rename(tmp, name)?;
```

## Error mapping

| `std::fs` error you handled before | guard error |
|---|---|
| `NotFound`, `PermissionDenied`, `AlreadyExists` | `JailError::Io(e)` with the same `e.kind()` |
| (none: the open escaped silently) | Linux openat2 path: `JailError::Escape` (path leaves the jail), `JailError::SymlinkRejected` (symlink with `no_symlinks`, a symlink loop, or a magic link). Fallback: `JailError::EscapedRoot` or `JailError::BrokenSymlink` from the path check |
| (none: a FIFO blocked, a device opened) | `JailError::FileTypeRejected { file_type, .. }` |
| (none: a hard link was followed) | `JailError::HardLinkRejected { nlink, .. }` |
| invalid input you checked by hand | `JailError::InvalidPath` (absolute path, null byte, invalid flag combination) |

Treat every variant other than `Io` as a policy rejection (for an HTTP API, a
4xx), and `Io` as an operational error. `JailError` is `#[non_exhaustive]`, so
keep a catch-all arm.

## Checklist

- [ ] No `std::fs` call takes a path built from untrusted input.
- [ ] No code validates with `join`/`check_path` and then opens the result.
- [ ] Reads use `require_regular_file(true)` and `reject_hard_links(true)`.
- [ ] New files use `create` / `create_new(true)`; overwrites are deliberate.
- [ ] Blocking guard calls run off the async executor ([Tokio guide](tokio.md)).
- [ ] Deployments that need the race-free guarantee check `toctou_safe` or
      run on Linux 5.6+ x86_64/aarch64.
