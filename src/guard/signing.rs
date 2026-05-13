//! Pluggable signing for [`Attestation`](super::Attestation) structs.
//!
//! path_jail does not vendor a crypto implementation — bring your own by
//! implementing [`Signer`] (and [`Verifier`] on the enforcement side). This
//! keeps the crate zero-dependency while letting callers wire up
//! `ed25519-dalek`, `ring`, an HSM client, AWS KMS, GCP KMS, etc.
//!
//! # Wire format
//!
//! The signature covers the bytes returned by
//! [`Attestation::signing_bytes`](super::Attestation::signing_bytes), which is
//! the canonical fixed-layout encoding of every attestation field including
//! `opened_at`. The format is deterministic and free of length-ambiguity:
//! see the doc on `signing_bytes` for the exact layout.
//!
//! # Example: ed25519-dalek
//!
//! ```ignore
//! use ed25519_dalek::{Signature, Signer as DalekSigner, SigningKey, Verifier as DalekVerifier, VerifyingKey};
//! use path_jail::guard::{Signer, Verifier};
//!
//! struct DalekS(SigningKey);
//! impl Signer for DalekS {
//!     type Error = std::convert::Infallible;
//!     fn sign(&self, msg: &[u8]) -> Result<[u8; 64], Self::Error> {
//!         Ok(self.0.sign(msg).to_bytes())
//!     }
//! }
//!
//! struct DalekV(VerifyingKey);
//! impl Verifier for DalekV {
//!     type Error = ed25519_dalek::SignatureError;
//!     fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> Result<(), Self::Error> {
//!         self.0.verify(msg, &Signature::from_bytes(sig))
//!     }
//! }
//! ```

/// Produces a 64-byte signature over a byte slice.
///
/// Implementations typically wrap a key handle (in-process key material, an
/// HSM session, a KMS client, etc.). Failures may come from the underlying
/// crypto provider (network errors talking to KMS, HSM unavailable, etc.).
pub trait Signer {
    /// Signing-failure type — usually the underlying provider's error.
    /// Use [`std::convert::Infallible`] for in-process signers that cannot fail.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Sign `msg` and return the 64-byte signature.
    ///
    /// The signature MUST cover all of `msg`. Truncating or pre-hashing
    /// without authentication weakens the attestation chain.
    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], Self::Error>;
}

/// Verifies a 64-byte signature over a byte slice.
///
/// On the enforcement-point side. Implementations wrap a verifying key.
pub trait Verifier {
    /// Verification-failure type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Returns `Ok(())` if `signature` is valid over `msg` under the
    /// implementation's verifying key; otherwise returns the provider error.
    fn verify(&self, msg: &[u8], signature: &[u8; 64]) -> Result<(), Self::Error>;
}

/// Error returned by [`Attestation::verify`](super::Attestation::verify).
///
/// Distinguishes "attestation is unsigned" from "signature is invalid", so
/// enforcement points can choose to reject both or only the latter.
#[derive(Debug)]
pub enum VerifyError<E> {
    /// The attestation has no signature attached.
    ///
    /// Per the spec, enforcement points MUST NOT accept unsigned attestations
    /// as proof of guard execution.
    NotSigned,
    /// The signature was present but failed verification.
    Invalid(E),
}

impl<E: std::fmt::Display> std::fmt::Display for VerifyError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSigned => write!(f, "attestation has no signature"),
            Self::Invalid(e) => write!(f, "signature verification failed: {}", e),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for VerifyError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(e) => Some(e),
            Self::NotSigned => None,
        }
    }
}
