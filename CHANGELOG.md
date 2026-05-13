# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-05-13

### Added

- **`guard` feature** (formerly `fd-first`): kernel-enforced TOCTOU-safe file access via `openat2(RESOLVE_BENEATH)` on Linux 5.6+
  - `guard::FdJail` pins a directory fd at construction; root renames after `FdJail::new` are ignored
  - `FdJail::open()` / `FdJail::create()` perform a single TOCTOU-safe syscall on Linux
  - `FdJail::check()` validates a path without opening (logging/display only — must not be used as the basis for a subsequent open)
  - `Attestation` records `jail_root`, `opened_path`, `root_inode`, `file_inode`, `device`, `nlink`, `toctou_safe`, `opened_at`
  - `Attestation::content_bytes()` for deterministic comparison; `Attestation::signing_bytes()` now public for external verifiers
  - `OpenOptions` with `read`/`write`/`append`/`truncate`/`create`/`create_new`/`no_symlinks`/`no_xdev`
  - `JailFile::has_hard_links()` exposes hard-link policy; library does not enforce, caller decides
  - macOS/BSD fallback via `O_NOFOLLOW`; `Attestation::toctou_safe` is `false` on the fallback path
- **Pluggable attestation signing** (`guard::Signer`, `guard::Verifier`, `guard::VerifyError`)
  - `JailFile::sign_attestation(&signer)` returns a signed `Attestation`
  - `Attestation::verify(&verifier)` checks the signature on the enforcement side
  - Zero vendored crypto — bring your own (`ed25519-dalek`, `ring`, HSM, KMS, etc.)
- **`OpenOptions::no_xdev`** — opt in to `RESOLVE_NO_XDEV` for mount-point containment (defends against bind-mount escapes)
- **aarch64 Linux support** for the `guard` feature (alongside x86_64); riscv64 is still gated by `compile_error!`
- New error variants (guarded by `guard` feature): `Escape`, `SymlinkRejected`, `MagicLink`, `UnsupportedKernel`, `InvalidJailRoot`

### Changed

- **Breaking**: MSRV bumped from 1.80 to 1.85 to accommodate transitive dev-dependencies that require Cargo edition 2024
- Attestation fields are now read via `File::metadata()` instead of an inline-asm `fstat` syscall (portable across architectures, eliminates the arch-specific struct-stat layout problem)
- Crate package now `exclude`s `docs/`, `.claude/`, `.github/`, `tests/`

### Notes

- The `guard` feature uses only `std` and raw syscalls — zero new runtime dependencies
- `guard` supports x86_64 and aarch64 Linux for the raw-asm `openat2` path; riscv64 support is planned

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

