#![allow(dead_code)]

// ANCHOR: readme
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
// ANCHOR_END: readme

fn main() {}
