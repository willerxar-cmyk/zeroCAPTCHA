//! zeroCAPTCHA © 2026 Willer Xavier Reis and SID6. See LICENSE.
//!
//! Privacy-preserving proof-of-work challenges.
//!
//! A trusted application requests a signed challenge, passes it to the
//! browser, and verifies the solution server-side before performing its action.
//! Each proof expires, is bound to a purpose and client pseudonym, and is
//! consumed atomically on successful verification.

pub mod challenge;
pub mod config;
pub mod error;
pub mod evidence;
pub mod http;
pub mod kdf;
pub mod limiter;
mod memo;
pub mod precision;
pub mod service;
pub mod store;

pub use challenge::{Algorithm, Challenge, ChallengeKind, Difficulty, Purpose, Solution};
pub use evidence::EvidenceMode;
pub use service::{ChallengeService, CreateChallengeRequest, VerifySolutionRequest};
