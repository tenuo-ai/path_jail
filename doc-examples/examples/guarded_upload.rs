#![allow(dead_code)]

// ANCHOR: readme
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
// ANCHOR_END: readme

fn main() {}
