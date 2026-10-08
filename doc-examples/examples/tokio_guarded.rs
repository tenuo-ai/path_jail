#![allow(dead_code)]

// ANCHOR: errors
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
// ANCHOR_END: errors

// ANCHOR: open
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
// ANCHOR_END: open

// ANCHOR: upload
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
// ANCHOR_END: upload

// ANCHOR: download
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
// ANCHOR_END: download

#[tokio::main]
async fn main() {}
