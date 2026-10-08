#![no_main]

use libfuzzer_sys::fuzz_target;
use path_jail::guard::FdJail;
use path_jail::Jail;
use std::path::PathBuf;
use std::sync::OnceLock;

struct Jails {
    path: Jail,
    fd: FdJail,
}

fn jails() -> &'static Jails {
    static JAILS: OnceLock<Jails> = OnceLock::new();
    JAILS.get_or_init(|| {
        let root = std::env::temp_dir().join(format!("path-jail-fuzz-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("create fuzz root");
        Jails {
            path: Jail::new(&root).expect("stable fuzz root"),
            fd: FdJail::new(&root).expect("stable fuzz root"),
        }
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
    let jails = jails();
    let candidate = input_path(data);

    let joined = jails.path.join(&candidate);
    if let Ok(joined) = &joined {
        assert!(joined.starts_with(jails.path.root()));
    }

    // check_path must agree with join and hand back the caller's path unchanged.
    let checked = jails.fd.check_path(&candidate);
    assert_eq!(checked.is_ok(), joined.is_ok());
    if let Ok(checked) = checked {
        assert_eq!(checked, candidate);
    }
});
