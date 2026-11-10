//! guard API for TOCTOU-safe file access via `openat2(RESOLVE_BENEATH)`.
//!
//! This module is only available with the `guard` feature enabled.
//!
//! See the [crate-level documentation](crate) for a quick-start example.

mod fd_jail;
mod signing;

pub use fd_jail::{
    Attestation, FdJail, FileKind, GuardCapabilities, GuardedFile, OpenOptions, ResolveOptions,
};
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub use fd_jail::{ReplaceError, ReplaceMode, ReplaceOptions};
pub use signing::{Signer, Verifier, VerifyError};
