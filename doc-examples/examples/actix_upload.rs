#![allow(dead_code)]

// ANCHOR: readme
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
// ANCHOR_END: readme

fn main() {}
