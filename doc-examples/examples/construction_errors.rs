fn main() {
    // ANCHOR: readme
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
    // ANCHOR_END: readme
}
