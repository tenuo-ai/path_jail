# Async (Tokio)

path_jail has no async API and no Tokio dependency. Guarded opens are a few
blocking syscalls, and the result is an ordinary `std::fs::File`, so the
pattern is: open on the blocking pool, then convert the descriptor with
`tokio::fs::File::from_std`. This page shows that pattern for uploads and
downloads, with timeouts and error handling.

Add Tokio to your own crate (path_jail does not need it):

```toml
[dependencies]
path_jail = { version = "0.5", features = ["guard"] }
tokio = { version = "1", features = ["fs", "io-util", "rt-multi-thread", "time"] }
```

## What blocks

Every path_jail call touches the filesystem and blocks the calling thread:

- `Jail::new`, `join`, `contains`, `relative`, `join_segments` (canonicalize and `lstat`)
- `FdJail::new`, `open`, `create`, `check_path`
- `FdJail::create_dir`, `remove_file`, `remove_dir`, `rename` and their `_with` variants
- reads, writes, and `sync_all` on a `GuardedFile` or `JailedFile`

Run them with `tokio::task::spawn_blocking` (or `actix_web::web::block`), never
directly in an async task.

## Errors

One error type keeps policy rejections apart from operational failures:

<!-- example: doc-examples/examples/tokio_guarded.rs#errors -->
```rust
use path_jail::guard::{FdJail, OpenOptions};
use path_jail::JailError;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

#[derive(Debug)]
enum FileError {
    /// Rejected by the jail: escape, symlink, special file, hard link, bad path.
    Rejected(JailError),
    /// The open or a later read/write failed at the OS level.
    Io(std::io::Error),
    /// The open did not finish in time. The blocking open itself keeps running.
    TimedOut,
    /// The blocking task panicked.
    Panicked,
}

impl From<JailError> for FileError {
    fn from(err: JailError) -> Self {
        match err {
            JailError::Io(e) => FileError::Io(e),
            other => FileError::Rejected(other),
        }
    }
}

impl From<std::io::Error> for FileError {
    fn from(err: std::io::Error) -> Self {
        FileError::Io(err)
    }
}
```

## Open on the blocking pool

<!-- example: doc-examples/examples/tokio_guarded.rs#open -->
```rust
/// Run the guarded open on Tokio's blocking pool and hand back an async file.
///
/// `FdJail::open` makes blocking syscalls, so it must not run on an executor
/// worker. The returned `tokio::fs::File` wraps the checked descriptor; the
/// path is never reopened through `tokio::fs`.
async fn open_guarded(
    jail: Arc<FdJail>,
    name: String,
    options: OpenOptions,
    timeout: Duration,
) -> Result<tokio::fs::File, FileError> {
    let task = tokio::task::spawn_blocking(move || jail.open(name, options));
    let guarded = match tokio::time::timeout(timeout, task).await {
        Err(_elapsed) => return Err(FileError::TimedOut),
        Ok(Err(_join_error)) => return Err(FileError::Panicked),
        Ok(Ok(result)) => result?,
    };
    Ok(tokio::fs::File::from_std(guarded.into_file()))
}
```

The returned `tokio::fs::File` is the descriptor that passed the jail's
checks. Do **not** open the same name again with `tokio::fs::File::open` or
`tokio::fs::write`: that is a second, unchecked lookup.

### Cancellation

- If the timeout fires, or the caller's future is dropped, `open_guarded`
  returns or is dropped, but the blocking `open` already started keeps running
  until the syscall finishes. Tokio cannot interrupt it. When it completes,
  the `GuardedFile` it produced is dropped and the descriptor closed.
- For `create_new`, that means a timed-out upload may still have created an
  empty file. Retry with the same name and you get `AlreadyExists`; pick a new
  name or clean up out of band.
- After the open, the `tokio::fs::File` operations are ordinary async I/O and
  stop at the next `.await` when the future is dropped, leaving a partially
  written file.

## Upload

<!-- example: doc-examples/examples/tokio_guarded.rs#upload -->
```rust
/// Store an upload under an untrusted name. Never overwrites.
async fn upload(
    jail: Arc<FdJail>,
    name: String,
    mut body: impl AsyncRead + Unpin,
) -> Result<u64, FileError> {
    let options = OpenOptions::new()
        .write(true)
        .create_new(true)
        .require_regular_file(true)
        .reject_hard_links(true);
    let mut file = open_guarded(jail, name, options, Duration::from_secs(5)).await?;
    let written = tokio::io::copy(&mut body, &mut file).await?;
    file.flush().await?;
    Ok(written)
}
```

## Download

<!-- example: doc-examples/examples/tokio_guarded.rs#download -->
```rust
/// Stream a file named by an untrusted path to `out`.
async fn download(
    jail: Arc<FdJail>,
    name: String,
    mut out: impl AsyncWrite + Unpin,
) -> Result<u64, FileError> {
    let options = OpenOptions::new()
        .read(true)
        .require_regular_file(true)
        .reject_hard_links(true);
    let mut file = open_guarded(jail, name, options, Duration::from_secs(5)).await?;
    Ok(tokio::io::copy(&mut file, &mut out).await?)
}
```

## Why there is no async helper in the crate

The whole adapter is `spawn_blocking` plus `File::from_std`, as above. A
helper in path_jail would add Tokio to the dependency tree of every user,
including the many who do not use it, to save a few lines. The examples on
this page are compiled in CI against Tokio 1, from
[`doc-examples/examples/tokio_guarded.rs`](../../doc-examples/examples/tokio_guarded.rs).
