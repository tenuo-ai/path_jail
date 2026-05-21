//! guard API for TOCTOU-safe file access via `openat2(RESOLVE_BENEATH)`.
//!
//! This module is only available with the `guard` feature enabled.
//!
//! See the [crate-level documentation](crate) for a quick-start example.

mod fd_jail;
mod signing;

pub use fd_jail::{Attestation, FdJail, GuardedFile, OpenOptions};
pub use signing::{Signer, Verifier, VerifyError};
