#![no_main]

use libfuzzer_sys::fuzz_target;
use path_jail::Jail;
use std::path::PathBuf;
use std::sync::OnceLock;

fn fuzz_root() -> &'static PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        let path = std::env::temp_dir().join(format!("path-jail-fuzz-{}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create fuzz root");
        path.canonicalize().expect("canonicalize fuzz root")
    })
}

#[cfg(unix)]
fn input_path(data: &[u8]) -> PathBuf {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    PathBuf::from(OsString::from_vec(data.to_vec()))
}

#[cfg(not(unix))]
fn input_path(data: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(data).into_owned())
}

fuzz_target!(|data: &[u8]| {
    let jail = Jail::new(fuzz_root()).expect("stable fuzz root");
    let candidate = input_path(data);

    match jail.join(&candidate) {
        Ok(joined) => {
            assert!(joined.starts_with(jail.root()));
            assert!(!joined.is_absolute() || joined.starts_with(fuzz_root()));
        }
        Err(_) => {}
    }
});
