//! ZeroCaptcha error type. Every failure mode maps to a machine-readable
//! `reason` string on the wire (see `VerifyResult::reason`), so the HTTP layer
//! only decides status codes, never semantics.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZerocaptchaError {
    #[error("ZeroCaptcha not configured: {0}")]
    NotConfigured(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Proof-of-work computation failed: {0}")]
    Crypto(String),

    #[error("Challenge store unavailable: {0}")]
    StoreUnavailable(String),
}

pub type Result<T> = std::result::Result<T, ZerocaptchaError>;
