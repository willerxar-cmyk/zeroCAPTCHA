//! Proof-of-work key-derivation — the PLUGGABLE crypto module.
//!
//! Every algorithm derives a 32-byte key from `(salt, counter)`:
//!
//! - `Pbkdf2Sha256`: `PBKDF2-HMAC-SHA256(password = LE64(counter), salt,
//!   iterations = cost)` — the default; WebCrypto accelerates the exact same
//!   construction in browsers, so widget and server agree by construction
//!   (and we need no WASM — a real efficiency win over WASM-PoW systems).
//! - `Sha256`: iterative hashing — `state = SHA256(salt || LE64(counter))`,
//!   then `state = SHA256(state)` `cost - 1` more times; key = state.
//! - `Argon2id` / `Scrypt`: memory-hard variants, feature-gated.
//!
//! The counter is the 8-byte little-endian encoding of the integer, identical
//! on both sides (Rust `u64::to_le_bytes`, widget `DataView.setBigUint64(LE)`).
//!
//! The service depends on the [`KdfProvider`] trait and ships a built-in provider.

use hmac::Hmac;
use sha2::{Digest, Sha256};

use crate::challenge::{Algorithm, KEY_LENGTH};
use crate::error::{Result, ZerocaptchaError};

/// Argon2id memory cost, protocol-fixed (KiB) — see module docs.
#[cfg(feature = "argon2")]
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
/// Argon2id parallelism, protocol-fixed.
#[cfg(feature = "argon2")]
const ARGON2_PARALLELISM: u32 = 1;
/// scrypt block size factor `r`, protocol-fixed.
#[cfg(feature = "scrypt")]
const SCRYPT_R: u32 = 8;
/// scrypt parallelism `p`, protocol-fixed.
#[cfg(feature = "scrypt")]
const SCRYPT_P: u32 = 1;

/// Fixed KDF parameters carried by a challenge.
#[derive(Clone, Copy, Debug)]
pub struct KdfSpec {
    pub algorithm: Algorithm,
    pub cost: u32,
}

/// The pluggable derivation surface. Implementations must be deterministic:
/// the same `(spec, salt, counter)` must always yield the same key, since the
/// server re-derives the key the client found.
pub trait KdfProvider: Send + Sync {
    fn derive(&self, spec: &KdfSpec, salt: &[u8], counter: u64) -> Result<[u8; KEY_LENGTH]>;
}

/// The built-in provider: PBKDF2-HMAC-SHA-256, iterative SHA-256, and
/// (feature-gated) Argon2id and scrypt.
pub struct BuiltinKdfProvider;

impl KdfProvider for BuiltinKdfProvider {
    fn derive(&self, spec: &KdfSpec, salt: &[u8], counter: u64) -> Result<[u8; KEY_LENGTH]> {
        derive_key(spec, salt, counter)
    }
}

/// Derive the 32-byte key for `(salt, counter)` under the given algorithm.
pub fn derive_key(spec: &KdfSpec, salt: &[u8], counter: u64) -> Result<[u8; KEY_LENGTH]> {
    let mut out = [0u8; KEY_LENGTH];
    let password = counter.to_le_bytes();
    match spec.algorithm {
        Algorithm::Pbkdf2Sha256 => {
            let iterations = spec.cost.max(1);
            pbkdf2::pbkdf2_hmac::<Sha256>(&password, salt, iterations, &mut out);
        }
        Algorithm::Sha256 => {
            let rounds = spec.cost.max(1) as usize;
            let mut state = Sha256::new();
            state.update(salt);
            state.update(password);
            let mut digest = state.finalize();
            for _ in 1..rounds {
                let mut next = Sha256::new();
                next.update(digest);
                digest = next.finalize();
            }
            out.copy_from_slice(&digest);
        }
        Algorithm::Argon2id => {
            #[cfg(feature = "argon2")]
            {
                use argon2::{Algorithm as Argon2Alg, Argon2, Params, Version};
                let params = Params::new(
                    ARGON2_MEMORY_KIB,
                    spec.cost.max(1),
                    ARGON2_PARALLELISM,
                    Some(KEY_LENGTH),
                )
                .map_err(|e| ZerocaptchaError::Crypto(format!("argon2 params: {e}")))?;
                let argon2 = Argon2::new(Argon2Alg::Argon2id, Version::V0x13, params);
                argon2
                    .hash_password_into(&password, salt, &mut out)
                    .map_err(|e| ZerocaptchaError::Crypto(format!("argon2id: {e}")))?;
            }
            #[cfg(not(feature = "argon2"))]
            {
                return Err(ZerocaptchaError::UnsupportedAlgorithm(
                    "S6-ARGON2ID requires the 'argon2' cargo feature".into(),
                ));
            }
        }
        Algorithm::Scrypt => {
            #[cfg(feature = "scrypt")]
            {
                use scrypt::Params;
                let log_n = spec.cost.clamp(1, 20) as u8;
                let scrypt_params = Params::new(log_n, SCRYPT_R, SCRYPT_P, KEY_LENGTH)
                    .map_err(|e| ZerocaptchaError::Crypto(format!("scrypt params: {e}")))?;
                scrypt::scrypt(&password, salt, &scrypt_params, &mut out)
                    .map_err(|e| ZerocaptchaError::Crypto(format!("scrypt: {e}")))?;
            }
            #[cfg(not(feature = "scrypt"))]
            {
                return Err(ZerocaptchaError::UnsupportedAlgorithm(
                    "S6-SCRYPT requires the 'scrypt' cargo feature".into(),
                ));
            }
        }
    }
    Ok(out)
}

/// Hex form of a derived key (lowercase) — the wire representation checked
/// against the challenge prefix.
pub fn key_hex(key: &[u8; KEY_LENGTH]) -> String {
    hex::encode(key)
}

/// Constant-time key comparison. The prefix check runs AFTER the comparison,
/// so a wrong key never leaks prefix timing.
pub fn keys_match(left: &[u8; KEY_LENGTH], right: &[u8; KEY_LENGTH]) -> bool {
    use subtle::ConstantTimeEq;
    left.ct_eq(right).into()
}

/// HMAC type used by the challenge signer/verifier (single source of truth).
pub type ChallengeMac = Hmac<Sha256>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The widget computes PBKDF2 via WebCrypto with the SAME construction;
    /// this vector is the server-side golden value for a deterministic
    /// `(salt, counter, cost)` triple.
    #[test]
    fn pbkdf2_sha256_known_vector() {
        let salt = [0xABu8; 16];
        let spec = KdfSpec {
            algorithm: Algorithm::Pbkdf2Sha256,
            cost: 100,
        };
        let key = derive_key(&spec, &salt, 42).unwrap();
        let mut expected = [0u8; KEY_LENGTH];
        pbkdf2::pbkdf2_hmac::<Sha256>(&42u64.to_le_bytes(), &salt, 100, &mut expected);
        assert_eq!(key, expected);
        assert_eq!(key_hex(&key).len(), 64);
        assert!(
            key_hex(&key)
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn sha256_iterative_matches_manual_loop() {
        let salt = b"zerocaptcha-salt";
        let spec = KdfSpec {
            algorithm: Algorithm::Sha256,
            cost: 5,
        };
        let key = derive_key(&spec, salt, 7).unwrap();
        let mut state = Sha256::new();
        state.update(salt);
        state.update(7u64.to_le_bytes());
        let mut digest = state.finalize();
        for _ in 1..5 {
            let mut next = Sha256::new();
            next.update(digest);
            digest = next.finalize();
        }
        assert_eq!(key.as_slice(), digest.as_slice());
    }

    #[test]
    fn counter_changes_key() {
        let salt = [0u8; 16];
        let spec = KdfSpec {
            algorithm: Algorithm::Pbkdf2Sha256,
            cost: 50,
        };
        let k1 = derive_key(&spec, &salt, 1).unwrap();
        let k2 = derive_key(&spec, &salt, 2).unwrap();
        assert_ne!(k1, k2, "different counters must yield different keys");
    }

    #[test]
    fn keys_match_is_constant_time_correct() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let c = [2u8; 32];
        assert!(keys_match(&a, &b));
        assert!(!keys_match(&a, &c));
    }

    #[cfg(feature = "argon2")]
    #[test]
    fn argon2id_derives_and_differs() {
        let salt = [0x42u8; 16];
        let spec = KdfSpec {
            algorithm: Algorithm::Argon2id,
            cost: 2,
        };
        let a = derive_key(&spec, &salt, 9).unwrap();
        let a2 = derive_key(&spec, &salt, 9).unwrap();
        assert_eq!(a, a2, "deterministic");
        let pbkdf2 = derive_key(
            &KdfSpec {
                algorithm: Algorithm::Pbkdf2Sha256,
                cost: 100,
            },
            &salt,
            9,
        )
        .unwrap();
        assert_ne!(a, pbkdf2);
    }

    #[cfg(feature = "scrypt")]
    #[test]
    fn scrypt_derives_and_differs() {
        let salt = [0x42u8; 16];
        let spec = KdfSpec {
            algorithm: Algorithm::Scrypt,
            cost: 12,
        };
        let s = derive_key(&spec, &salt, 9).unwrap();
        let s2 = derive_key(&spec, &salt, 9).unwrap();
        assert_eq!(s, s2, "deterministic");
        let pbkdf2 = derive_key(
            &KdfSpec {
                algorithm: Algorithm::Pbkdf2Sha256,
                cost: 100,
            },
            &salt,
            9,
        )
        .unwrap();
        assert_ne!(s, pbkdf2);
    }

    #[cfg(not(feature = "argon2"))]
    #[test]
    fn argon2_without_feature_is_unsupported() {
        let spec = KdfSpec {
            algorithm: Algorithm::Argon2id,
            cost: 2,
        };
        assert!(matches!(
            derive_key(&spec, &[0u8; 16], 1),
            Err(ZerocaptchaError::UnsupportedAlgorithm(_))
        ));
    }
}
