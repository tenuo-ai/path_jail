# path_jail fd-first rewrite: mini spec

## Objective

Replace path_jail's validate-then-return-PathBuf architecture with an fd-first design using `openat2(RESOLVE_BENEATH)`. The result is TOCTOU-safe by construction. Zero new dependencies. Linux 5.6+ required; macOS gets a documented fallback with weaker guarantees.

---

## Syscall layer

The core primitive is `openat2` with `resolve` flags:

```rust
// Raw syscall — no libc, no rustix
// linux/openat2.h
#[repr(C)]
struct OpenHow {
    flags:   u64,  // O_RDONLY, O_WRONLY, etc.
    mode:    u64,  // creation mode, 0 for reads
    resolve: u64,  // RESOLVE_* flags
}

const RESOLVE_BENEATH:       u64 = 0x08; // no escape from dirfd subtree
const RESOLVE_NO_SYMLINKS:   u64 = 0x04; // optional: reject all symlinks
const RESOLVE_NO_MAGICLINKS: u64 = 0x02; // reject /proc/self/fd style links
const SYS_OPENAT2:           i64 = 437;

fn openat2_beneath(dirfd: RawFd, path: &CStr, flags: i32) -> Result<OwnedFd, Errno> {
    let how = OpenHow {
        flags:   flags as u64,
        mode:    0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
    };
    let fd = unsafe {
        syscall(SYS_OPENAT2, dirfd, path.as_ptr(), &how, size_of::<OpenHow>())
    };
    if fd < 0 {
        // Linux syscall errors are in [-4095, -1]. The cast is safe in practice,
        // but assert the range explicitly to catch unexpected values on unusual targets.
        debug_assert!(fd >= i32::MIN as i64, "syscall errno out of expected range");
        Err(Errno(-fd as i32))
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }
}
```

`RESOLVE_BENEATH` is the key flag. The kernel enforces jail containment — no userspace path parsing required. Symlinks that escape the jail return `EXDEV`. Path components that traverse above the jail root return `EXDEV`. This is not a check followed by an open; it is a single atomic operation.

`RESOLVE_NO_MAGICLINKS` blocks `/proc/self/fd/N` and similar kernel magic links that can escape the jail regardless of `RESOLVE_BENEATH`. On by default.

`RESOLVE_NO_SYMLINKS` is opt-in. Default off — most legitimate tool use involves symlinks inside the jail. Available as `JailOptions::no_symlinks()`.

---

## API surface

```rust
pub struct Jail {
    dirfd: OwnedFd,   // open directory fd for the jail root, pinned at Jail::new time
    root:  PathBuf,   // stored for attestation and error messages only
}

pub struct JailFile {
    file:        File,
    jail_root:   PathBuf,
    opened_path: PathBuf,  // relative, as requested
    root_inode:  u64,      // from fstat on dirfd at Jail::new time
    file_inode:  u64,      // from fstat on the opened fd
    device:      u64,      // st_dev — same device = hard link detection basis
    nlink:       u64,      // hard link count
}

pub struct Attestation {
    pub jail_root:    PathBuf,
    pub opened_path:  PathBuf,
    pub root_inode:   u64,
    pub file_inode:   u64,
    pub device:       u64,
    pub nlink:        u64,         // hard link count — caller decides policy
    pub toctou_safe:  bool,        // false on macOS fallback path
    pub opened_at:    SystemTime,
    pub signature:    Option<[u8; 64]>,  // Ed25519, if key configured
}

impl Jail {
    /// Opens the jail root directory and pins its inode.
    /// `dirfd` is held open for the lifetime of the Jail. Subsequent renames
    /// or replacements of the root path do not affect the jail — all operations
    /// remain scoped to the original directory regardless of what happens to
    /// the path string used to create it.
    /// Fails if path does not exist or is not a directory.
    /// Fails on Linux < 5.6 unless fallback feature is enabled.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, JailError>;

    /// Opens a file relative to the jail root.
    /// Returns JailFile containing the fd and attestation data.
    /// Single syscall on Linux 5.6+ (openat2). TOCTOU-safe.
    pub fn open(&self, path: impl AsRef<Path>, options: OpenOptions)
        -> Result<JailFile, JailError>;

    /// Creates a file relative to the jail root.
    /// Uses O_CREAT | O_EXCL relative to dirfd. No path string in critical section.
    /// The parent directory MUST already exist inside the jail. This method does
    /// not create intermediate directories. Callers needing mkdir-p semantics
    /// must create parent directories explicitly via a separate jail operation
    /// before calling create(). Automatic parent creation is out of scope for
    /// this spec — it introduces recursive openat chains with their own TOCTOU
    /// surface that deserves separate treatment.
    pub fn create(&self, path: impl AsRef<Path>)
        -> Result<JailFile, JailError>;

    /// Validates a path without opening. Returns the relative path if safe.
    /// Weaker than open() — does not hold an fd. Provided for callers
    /// that need a validated path string for logging or display purposes only.
    /// MUST NOT be used as the basis for a subsequent open() call.
    pub fn check(&self, path: impl AsRef<Path>)
        -> Result<PathBuf, JailError>;
}

impl Attestation {
    /// Returns the canonical byte representation of all fields except `opened_at`
    /// and `signature`. Used for content-equality checks across calls to the same
    /// path, and for implementations that need to compare attestations without
    /// caring about when they were produced.
    /// The full signing input (including `opened_at`) is what the Ed25519
    /// signature covers; this helper is not a substitute for signature verification.
    pub fn content_bytes(&self) -> Vec<u8>;
}
    pub fn file(&self) -> &File;
    pub fn into_file(self) -> File;
    pub fn attestation(&self) -> &Attestation;
    pub fn sign_attestation(&self, key: &SigningKey) -> Attestation;

    // Hard link policy helper — caller decides whether nlink > 1 is acceptable
    pub fn has_hard_links(&self) -> bool {
        self.nlink > 1
    }
}
```

The `check()` method is a deliberate design decision. Some callers need a path string for logging or display. Providing `check()` with a strong warning makes the safe/unsafe choice explicit rather than having callers call `open()` and immediately extract the path. The docstring MUST state that the result of `check()` MUST NOT be passed to any subsequent `open()` call.

---

## Attestation signing

The attestation struct is serialized canonically before signing:

```
attestation_bytes :=
    len(jail_root_bytes)      as u32 LE
    || jail_root_bytes
    || len(opened_path_bytes) as u32 LE
    || opened_path_bytes
    || root_inode             as u64 LE
    || file_inode             as u64 LE
    || device                 as u64 LE
    || nlink                  as u64 LE
    || toctou_safe            as u8 (1 = true, 0 = false)
    || unix_timestamp_nanos   as u64 LE
```

No JSON, no CBOR — fixed-layout binary. Deterministic without a serialization library. Ed25519 signature over these bytes. The signing key is optionally configured at `Jail::new` time; unsigned attestations are valid for logging and debugging but MUST NOT be accepted by the Tenuo enforcement point as proof of guard execution.

The Ed25519 signature is the trust anchor for all attestation fields. `root_inode` and `file_inode` are informational without it — an attacker who can forge an attestation struct can claim any inode values. The signature is what binds the attestation to the guard's key, which must match the key named in the warrant's `guard` claim. Enforcement points MUST verify the signature before reading any other attestation field.

The Tenuo enforcement point verifies:

1. Attestation signature valid under the guard key named in the warrant
2. `attestation.jail_root` matches the `Subpath` constraint root in the warrant
3. `attestation.opened_path` is within `jail_root`
4. `attestation.toctou_safe` is `true`, unless the warrant explicitly permits otherwise
5. `attestation.opened_at` is within the PoP JWT timestamp window

---

## Error taxonomy

```rust
pub enum JailError {
    /// openat2 returned EXDEV — path escapes jail or traverses above root.
    /// Covers symlink escapes, .. traversal, and absolute path attempts.
    Escape { requested: PathBuf },

    /// openat2 returned ELOOP — symlink loop or RESOLVE_NO_SYMLINKS triggered.
    SymlinkRejected { requested: PathBuf },

    /// /proc/self/fd or similar magic link detected (RESOLVE_NO_MAGICLINKS).
    MagicLink { requested: PathBuf },

    /// Jail root does not exist or is not a directory.
    InvalidRoot { path: PathBuf, source: io::Error },

    /// openat2 not available (Linux < 5.6) and fallback feature not enabled.
    UnsupportedKernel { version: KernelVersion },

    /// Standard I/O error (file not found, permission denied, etc.)
    Io(io::Error),
}
```

`Escape` is the critical variant. It covers the entire class of attacks the map/territory post describes — path traversal, symlink escape, absolute path injection. One error variant, one audit log entry, unambiguous meaning.

---

## Hard link policy

Hard links cannot be detected before open. After open they are visible via `nlink > 1` on the `fstat` result. The library surfaces this as `JailFile::has_hard_links()` and includes `nlink` in the attestation. Policy is the caller's responsibility:

```rust
let jf = jail.open("report.pdf", OpenOptions::new().read(true))?;
if jf.has_hard_links() {
    return Err(SecurityError::HardLinkDetected);
}
// proceed
```

This is the correct layering. The library cannot know whether hard links are acceptable for a given use case — a content-addressed store might legitimately use them. The enforcement point can treat `nlink > 1` as a denial condition by checking the attestation.

Callers that require hard link rejection MUST check `has_hard_links()` before reading. This MUST be documented prominently, not buried in caveats.

---

## macOS fallback

macOS has no `openat2`. The fallback uses `open(O_NOFOLLOW)` on each path component via `openat` chain, which is what cap-std does on older kernels. This is userspace path resolution and is therefore not TOCTOU-safe under concurrent rename attacks.

The fallback:

- Is gated behind `#[cfg(not(target_os = "linux"))]`
- Emits a compile-time warning: `path_jail: using fallback path resolution — not TOCTOU-safe`
- Sets `Attestation::toctou_safe = false`
- The Tenuo enforcement point MUST reject attestations with `toctou_safe: false` unless the warrant explicitly permits it via a `guard_options` claim

This makes the weaker guarantee visible in the attestation rather than silently degrading.

---

## What does not change

- The Python bindings surface. `Jail`, `jail.open()`, `ValueError` on escape. Same ergonomics.
- The zero-dependency commitment. All of the above uses only `std` and raw syscalls. No libc, no rustix.
- `safe_unzip`'s dependency on path_jail. It inherits the TOCTOU fix automatically — `jail.join()` on the write path becomes `jail.open()`.

---

## Scope explicitly excluded

- **Windows.** `CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT` approximates some of this but the semantics differ enough to deserve its own spec.
- **Directory traversal / `read_dir`.** Iterating jail contents has its own TOCTOU surface (rename-during-walk). Document as a known limitation.
- **Network jails.** `url_jail` is a separate crate. This spec is filesystem only.

---

## Acceptance criteria

| # | Condition | Expected result |
|---|-----------|-----------------|
| 1 | `jail.open("../../etc/passwd")` on Linux 5.6+ | `JailError::Escape`; `strace` shows one `openat2` syscall, no file open |
| 2 | `jail.open("symlink-to-outside")` | `JailError::Escape` |
| 3 | `jail.open("/proc/self/root/etc/passwd")` | `JailError::MagicLink` |
| 4 | Pre-existing hard link inside jail | `open()` succeeds; `jf.has_hard_links()` returns `true` |
| 5 | Two `open()` calls to same path, same jail | `attestation.content_bytes()` identical; `opened_at` differs and is excluded from content bytes by design |
| 6 | Signed attestation | Verifies under configured key |
| 7 | Kernel < 5.6, fallback feature disabled | `Jail::new` returns `JailError::UnsupportedKernel` |
| 8 | Python bindings | `jail.open()` returns file object and attestation bytes; `ValueError` on escape |
