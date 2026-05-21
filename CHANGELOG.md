# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-05-21

### Added

- **`guard` feature** (Linux 5.6+ / macOS-BSD fallback): kernel-enforced TOCTOU-safe file access
  - `FdJail::new()` — pins the jail root as a live directory fd at construction time; subsequent opens cannot be raced by renames of the root
  - `FdJail::open()` — single `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` syscall on Linux 5.6+; `O_NOFOLLOW` fallback on macOS/BSD (`attestation().toctou_safe` will be `false` on the fallback path)
  - `FdJail::create()` — `O_CREAT | O_EXCL` atomic creation
  - `FdJail::check_path()` — validate a path without opening (for logging/display only; re-opening reintroduces TOCTOU)
  - `OpenOptions` — mirrors the relevant subset of `std::fs::OpenOptions`; adds `no_symlinks` (`RESOLVE_NO_SYMLINKS`) and `no_xdev` (`RESOLVE_NO_XDEV`)
  - `JailFile` — wraps the opened `File` alongside an `Attestation` snapshot; implements `Read`, `Write`, `Seek`, `Deref<Target=File>`
  - `GuardedFile` — wraps the opened `File` alongside an `Attestation` snapshot; implements `Read`, `Write`, `Seek`, `Deref<Target=File>`, `AsFd`, `AsRawFd` (Unix)
  - `GuardedFile::has_hard_links()` — detects hard links (data-exfiltration vector) via `nlink` from `fstat`
  - `Attestation` (`#[non_exhaustive]`) — records `jail_root`, `opened_path`, `root_inode`, `file_inode`, `device`, `nlink`, `toctou_safe`, `opened_at`, and an optional 64-byte signature
  - `Attestation::content_bytes()` — canonical serialization of all fields except `opened_at` and `signature` (stable for content-equality checks)
  - `Attestation::signing_bytes()` — `content_bytes` + `opened_at` nanos; the exact bytes a `Signer` signs and a `Verifier` replays
  - `Attestation::verify()` — signature verification against a `Verifier`
  - `GuardedFile::sign_attestation()` — returns a new `Attestation` with `signature` populated
  - `Signer` trait — pluggable 64-byte signature production (`ed25519-dalek`, `ring`, HSM, KMS, etc.)
  - `Verifier` trait — pluggable signature verification
  - `VerifyError<E>` — distinguishes `NotSigned` from `Invalid(E)`

- **aarch64 Linux support** — cross-compilation and tests verified on `aarch64-unknown-linux-gnu` and `armv7-unknown-linux-gnueabihf`

- **`guard` feature — architecture support expanded**: Linux on `riscv64`, `s390x`, `loongarch64`, and all other architectures without a raw `openat2` syscall shim now fall through to the `O_NOFOLLOW` fallback (same as macOS/BSD) instead of emitting a compile error. `attestation().toctou_safe` will be `false` on these platforms.

- New `JailError` variants (all `#[cfg(feature = "guard")]`):
  - `Escape { requested }` — `openat2` returned `EXDEV`; covers symlink escapes, `..` traversal, and absolute injection
  - `SymlinkRejected { requested }` — `openat2` returned `ELOOP`; covers symlink loops and `no_symlinks` policy rejections; also surfaces magic-link rejections because the kernel maps both to `ELOOP`
  - `MagicLink { requested }` — reserved for a future kernel ABI that separates magic-link errno; currently unreachable (see deprecation note)
  - `UnsupportedKernel { version }` — `openat2` not available on kernel < 5.6 (`#[cfg(target_os = "linux")]`)
  - `InvalidJailRoot { path, source }` — invalid root in the guard API

### Changed

- MSRV bumped from 1.80 to **1.85** (accommodates edition-2024 transitive dev-dependencies)
- `guard` feature flag replaces the earlier `fd-first` name (internal rename; no API was previously published)
- **`JailError::InvalidRoot`** is now a struct variant `{ path: PathBuf, source: Option<std::io::Error> }` instead of a tuple variant `(PathBuf)`. The `source` field is `Some` when an I/O error was the proximate cause (e.g., `FdJail::new` failing to open the directory) and `None` for structural rejections (e.g., path is `/`). `JailError::InvalidJailRoot` (guard-only) is removed; `InvalidRoot` now covers both APIs.
- **`guard::JailFile`** renamed to **`guard::GuardedFile`** to distinguish it clearly from `crate::JailedFile` (the `secure-open` type).
- **`FdJail::check`** renamed to **`FdJail::check_path`** to make the "no fd held, for display only" semantics visible at the call site.
- `KernelVersion` is now `#[non_exhaustive]`.
- `secure-open` on an unknown Unix platform now produces a `compile_error!` instead of silently setting `O_NOFOLLOW = 0` (which would have followed symlinks without any error).
- `FdJail::new` canonicalize failure now returns `JailError::InvalidRoot` (with `source: Some(io_error)`) instead of `JailError::Io`.

### Deprecated

- `JailError::MagicLink` — the Linux kernel currently returns `ELOOP` for both magic-link and symlink rejections, making this variant unreachable. Match on `SymlinkRejected` instead. The variant is preserved so callers are not broken if a future kernel release introduces a distinct errno.

## [0.3.1] - 2026-01-06

### Fixed

- Formatting issues (rustfmt)

## [0.3.0] - 2026-01-05

### Added

- **`JailedPath` newtype**: Compile-time guarantee that a path is validated
  - `Jail::join_typed()` returns `JailedPath` instead of `PathBuf`
  - `Jail::segments()` returns `JailedPath` from iterator of segments
  - Implements `Deref<Target=Path>`, `AsRef<Path>`, `Display`, `From<JailedPath> for PathBuf`
  - Prevents confused deputy bugs at compile time

- **Segment joining**: Safely build paths from multiple user inputs
  - `Jail::join_segments()` validates each segment (rejects `/`, `\`, `..`, null bytes)
  - `Jail::segments()` returns type-safe `JailedPath`
  - Safer than `format!("{}/{}", user_id, filename)` patterns

- **`secure-open` feature** (Unix only): TOCTOU-safe file operations using `O_NOFOLLOW`
  - `Jail::open()` - open for reading with symlink protection
  - `Jail::create()` - create new file with `O_CREAT | O_EXCL | O_NOFOLLOW`
  - `Jail::create_or_truncate()` - truncate if exists
  - `Jail::open_append()` - append mode
  - `JailedPath::open()` and `JailedPath::create()` methods
  - `JailedFile` wrapper with `Read`, `Write`, `Seek`, `Deref<Target=File>`
  - Zero additional dependencies (uses `std::os::unix::fs::OpenOptionsExt`)
  - Protects against symlink swap attacks between validation and open

### Changed

- Documentation updated with new API examples
- Test suite expanded to 61 tests

## [0.2.0] - 2024-12-29

### Added

- **Security**: Reject null bytes in paths (prevents C string terminator attacks)
- `InvalidRoot` error variant for filesystem root and non-directory detection
- `#[non_exhaustive]` on `JailError` for future compatibility
- Comprehensive edge case tests (38 total)
- Documentation for platform-specific security considerations

### Changed

- **Breaking**: `JailError` is now `#[non_exhaustive]` - add a catch-all arm to matches
- **Breaking**: MSRV bumped from 1.70 to 1.80 (for `LazyLock` in examples)
- `InvalidRoot` provides context-aware error messages ("filesystem root" vs "not a directory")
- Improved documentation with framework examples (Axum, Actix-web)

### Security

- Null byte injection is now blocked (previously passed through for non-existent paths)
- Filesystem roots (`/`, `C:\`) are now rejected at construction

## [0.1.0] - 2024-12-28

### Added

- Initial release
- `Jail` struct for filesystem sandboxing
- `join()` convenience function
- Symlink escape detection
- Broken symlink rejection
- Path traversal prevention

