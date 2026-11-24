//! Challenge lifecycle: create (sign) and verify (validate + single-use).
//!
//! ## Verify path (cheapest first — the efficiency core)
//! 1. **Expiration** — `expires_at` in the past → reject (`expired`).
//! 2. **Signature** — recomputed HMAC vs `sig`, constant-time → reject.
//! 3. **Purpose and client binding** — must equal the calling flow and current
//!    edge-derived client pseudonym → reject.
//! 4. **Memo fast-path** — if this challenge id was already successfully
//!    verified (spent), answer `replayed` in µs WITHOUT re-deriving the KDF
//!    (mCaptcha-style spent-solution caching; bounds replay-flood CPU).
//! 5. **Proof** — re-derive the KDF once with the supplied counter off the
//!    async executor, then check the key in constant time and enforce the prefix.
//! 6. **Evidence** — optional Cap-style human-interaction scoring when the
//!    operator enabled `lenient`/`strict` mode.
//! 7. **Single-use** — atomic claim (Redis or in-memory); on success the id is
//!    memoized so every subsequent replay attempt costs µs.
//!
//! The KDF re-derivation is a single call, never a search: verification cost
//! is approximately one honest attempt. Each extra hex digit multiplies
//! the expected number of client attempts by sixteen.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use hmac::{Mac, SimpleHmac};
use rand::{Rng, RngCore};
use sha2::Sha256;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::warn;
use uuid::Uuid;

#[cfg(test)]
use crate::challenge::Evidence;
use crate::challenge::{
    Algorithm, Challenge, ChallengeKind, ChallengeParameters, Difficulty, KEY_LENGTH, MAX_TTL_SECS,
    MIN_TTL_SECS, PROTOCOL_DOMAIN, Purpose, SALT_LENGTH, Solution, VerifyResult, is_valid_binding,
    reasons,
};
use crate::error::{Result, ZerocaptchaError};
use crate::evidence::EvidenceMode;
use crate::kdf::{KdfProvider, KdfSpec, key_hex, keys_match};
use crate::memo::SpentMemo;
use crate::precision::{PrecisionParameters, PrecisionPolicy};
use crate::store::ChallengeStore;

mod precision;

/// Inputs for challenge creation. Difficulty/purpose/ttl are decided by the
/// CALLING service (e.g. an identity provider reading its admin policy),
/// never by the client.
#[derive(Clone, Debug)]
pub struct CreateChallengeRequest {
    pub algorithm: Algorithm,
    pub difficulty: Difficulty,
    pub purpose: Purpose,
    /// Challenge lifetime in seconds; clamped to [MIN_TTL_SECS, MAX_TTL_SECS].
    pub ttl_secs: u64,
    /// HMAC pseudonym derived by the trusted edge/identity boundary.
    pub client_binding: String,
    /// Trusted application policy; a browser cannot select an easier timing
    /// mode or remove a signed requirement after challenge issuance.
    pub precision: Option<PrecisionPolicy>,
}

/// Inputs for verification. `purpose` is the flow the CALLER is serving; the
/// challenge's own purpose must match it.
#[derive(Clone, Debug)]
pub struct VerifySolutionRequest {
    pub solution: Solution,
    pub purpose: Purpose,
    /// Trusted application policy can override the service default.
    pub evidence_mode: Option<EvidenceMode>,
    /// Must match the binding covered by the challenge HMAC.
    pub client_binding: String,
}

/// Runtime collaborators are grouped so constructor growth never needs lint
/// suppression and tests can inject deterministic, production-shaped parts.
pub struct ChallengeServiceDependencies {
    pub clock: Arc<dyn Clock>,
    pub store: Arc<dyn ChallengeStore>,
    pub kdf: Arc<dyn KdfProvider>,
}

/// Security policy loaded from environment or live identity settings.
#[derive(Clone, Copy, Debug)]
pub struct ChallengeServiceOptions {
    pub evidence_mode: EvidenceMode,
    pub adaptive: bool,
    pub memo_max_entries: usize,
    pub memo_ttl_secs: u64,
}

/// Clock abstraction so verification expiry can be tested deterministically
/// (production uses the system clock; tests inject a deterministic fixture).
pub trait Clock: Send + Sync {
    fn now_unix(&self) -> i64;
    fn now_unix_ms(&self) -> u64 {
        (self.now_unix().max(0) as u64).saturating_mul(1000)
    }
}

/// System clock — production default.
#[derive(Clone, Copy, Debug)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs() as i64
    }
    fn now_unix_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis()
            .min(u64::MAX as u128) as u64
    }
}

/// The ZeroCaptcha engine. Cheap to clone (`Arc` inside); one instance per
/// process, shared by the HTTP handlers.
pub struct ChallengeService {
    /// HMAC signing key. `None` ⇒ issuance/verification refuse to operate
    /// (fail-closed: never serve unsigned challenges).
    secret: Option<Arc<[u8]>>,
    clock: Arc<dyn Clock>,
    store: Arc<dyn ChallengeStore>,
    /// Proof-of-work key derivation.
    kdf: Arc<dyn KdfProvider>,
    /// Human-evidence scoring mode (Cap-inspired; default off).
    evidence_mode: EvidenceMode,
    /// Escalate difficulty when per-client issuance pressure exceeds 50% of the
    /// window quota (mCaptcha lesson: variable difficulty under attack).
    adaptive: bool,
    /// Spent-challenge memo (replay fast-path).
    memo: SpentMemo,
    /// Counter for minted challenges (observability).
    minted: AtomicU64,
    /// Counter for verified solutions (observability).
    verified: AtomicU64,
}

impl ChallengeService {
    pub fn new(
        secret: Option<Vec<u8>>,
        dependencies: ChallengeServiceDependencies,
        options: ChallengeServiceOptions,
    ) -> Self {
        Self {
            secret: secret.map(Arc::from),
            clock: dependencies.clock,
            store: dependencies.store,
            kdf: dependencies.kdf,
            evidence_mode: options.evidence_mode,
            adaptive: options.adaptive,
            memo: SpentMemo::new(options.memo_max_entries, options.memo_ttl_secs),
            minted: AtomicU64::new(0),
            verified: AtomicU64::new(0),
        }
    }

    /// Whether issuance is configured (surfaced to the HTTP layer for a clean
    /// "not configured" answer instead of a generic error).
    pub fn is_configured(&self) -> bool {
        self.secret.is_some()
    }

    /// Challenges minted since boot (observability/metrics).
    pub fn minted_count(&self) -> u64 {
        self.minted.load(Ordering::Relaxed)
    }

    /// Solutions verified since boot.
    pub fn verified_count(&self) -> u64 {
        self.verified.load(Ordering::Relaxed)
    }

    /// Mint and sign a challenge. When `adaptive` is enabled and the calling
    /// flow passes a pressure hint ≥ 0.5, the difficulty is escalated one
    /// step (cheap clients are unaffected — they get the standard tier).
    pub fn create_challenge(
        &self,
        req: &CreateChallengeRequest,
        pressure: f64,
    ) -> Result<Challenge> {
        let secret = self.secret.as_deref().ok_or_else(|| {
            ZerocaptchaError::NotConfigured(
                "ZEROCAPTCHA_SECRET is not set; challenge issuance disabled".to_string(),
            )
        })?;

        validate_binding("client_binding", &req.client_binding)?;
        let difficulty = if self.adaptive && pressure >= 0.5 {
            req.difficulty.escalate()
        } else {
            req.difficulty
        };

        let mut salt = [0u8; SALT_LENGTH];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let now = self.clock.now_unix();
        let ttl = req.ttl_secs.clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        let precision = match req.precision {
            Some(policy) if policy.validate(ttl) => Some(PrecisionParameters {
                hold_ms: rand::rngs::OsRng.gen_range(policy.min_hold_ms..=policy.max_hold_ms),
                release_window_ms: policy.release_window_ms,
            }),
            Some(_) => {
                return Err(ZerocaptchaError::InvalidInput(
                    "invalid precision policy".into(),
                ));
            }
            None => None,
        };
        let params = ChallengeParameters {
            id: Uuid::now_v7().to_string(),
            alg: req.algorithm,
            salt: BASE64_STANDARD.encode(salt),
            cost: difficulty.cost(),
            prefix: difficulty.prefix().to_string(),
            expires_at: now.saturating_add(ttl as i64),
            purpose: req.purpose,
            kind: ChallengeKind::ProofOfWork,
            client_binding: req.client_binding.clone(),
            precision,
        };

        let sig = sign_params(secret, &params)?;
        self.minted.fetch_add(1, Ordering::Relaxed);
        Ok(Challenge { params, sig })
    }

    /// Verify a client solution. Returns a structured [`VerifyResult`]; any
    /// failure (including store unavailability) maps to `valid == false`.
    pub async fn verify_solution(&self, req: &VerifySolutionRequest) -> VerifyResult {
        let Some(secret) = self.secret.as_deref() else {
            warn!("ZeroCaptcha verify called without a configured secret (fail-closed)");
            return VerifyResult::reject(reasons::NOT_CONFIGURED);
        };

        let now = self.clock.now_unix();

        // 1. Expiration (cheapest; no crypto).
        if now >= req.solution.challenge.params.expires_at {
            return VerifyResult::reject(reasons::EXPIRED);
        }

        // 2. Signature over the canonical parameters (constant-time compare).
        match verify_params_signature(secret, &req.solution.challenge) {
            Ok(true) => {}
            Ok(false) => return VerifyResult::reject(reasons::INVALID_SIGNATURE),
            Err(e) => {
                warn!("ZeroCaptcha signature check failed: {e}");
                return VerifyResult::reject(reasons::INVALID_SIGNATURE);
            }
        }

        // 3. Purpose binding.
        if req.solution.challenge.params.purpose != req.purpose {
            return VerifyResult::reject(reasons::PURPOSE_MISMATCH);
        }

        if !bindings_match(
            &req.solution.challenge.params.client_binding,
            &req.client_binding,
        ) {
            return VerifyResult::reject(reasons::CLIENT_BINDING_MISMATCH);
        }

        let params = &req.solution.challenge.params;

        // 4. Memo fast-path: a previously-verified (spent) challenge is
        //    answered `replayed` without touching the KDF — an attacker
        //    replaying one solution thousands of times costs µs, not ms.
        if self.memo.is_spent(&params.id) {
            return VerifyResult::reject(reasons::REPLAYED);
        }

        // Timing is authenticated before expensive work. Final submission may
        // follow a slow solve; the signed receipt fixes the earlier release.
        if let Err(reason) = self.verify_precision_receipt(&req.solution) {
            return VerifyResult::reject(reason);
        }

        // 5. Re-derive the key from the submitted counter (ONE KDF call,
        //    off the async executor so memory-hard algorithms never block
        //    request handling), then constant-time compare + prefix check.
        let Ok(salt) = BASE64_STANDARD.decode(&params.salt) else {
            return VerifyResult::reject(reasons::INVALID_SOLUTION);
        };
        let Ok(alg) = Algorithm::from_str(params.alg.as_str()) else {
            return VerifyResult::reject(reasons::UNSUPPORTED_ALGORITHM);
        };
        let spec = KdfSpec {
            algorithm: alg,
            cost: params.cost,
        };
        let counter = req.solution.counter;
        let kdf = Arc::clone(&self.kdf);
        let derive = tokio::task::spawn_blocking(move || kdf.derive(&spec, &salt, counter));
        let derived = match derive.await {
            Ok(Ok(key)) => key,
            _ => return VerifyResult::reject(reasons::INVALID_SOLUTION),
        };
        let Ok(submitted_key) = decode_hex_key(&req.solution.key) else {
            return VerifyResult::reject(reasons::INVALID_SOLUTION);
        };
        if !keys_match(&derived, &submitted_key) {
            return VerifyResult::reject(reasons::INVALID_SOLUTION);
        }
        if !key_hex(&derived).starts_with(&params.prefix) {
            return VerifyResult::reject(reasons::INVALID_SOLUTION);
        }

        // 6. Apply the trusted request policy or the service default.
        let evidence_mode = req.evidence_mode.unwrap_or(self.evidence_mode);
        if !evidence_mode.accepts(&req.solution.evidence) {
            return VerifyResult::reject(reasons::EVIDENCE_REJECTED);
        }

        self.consume(params).await
    }

    /// Atomically spend a capability. Store failures reject because accepting
    /// without global single-use state would turn retries into replay tokens.
    async fn consume(&self, params: &ChallengeParameters) -> VerifyResult {
        // A real KDF can cross expiry after the initial cheap check. Renew
        // the clock at consumption so completed work never revives a token.
        let now = self.clock.now_unix();
        if now >= params.expires_at {
            return VerifyResult::reject(reasons::EXPIRED);
        }
        let remaining = (params.expires_at - now).max(0) as u64;
        match self.store.consume_once(&params.id, remaining.max(1)).await {
            Ok(true) => {
                self.memo.record(&params.id);
                self.verified.fetch_add(1, Ordering::Relaxed);
                VerifyResult::ok()
            }
            Ok(false) => VerifyResult::reject(reasons::REPLAYED),
            Err(_) => {
                warn!("zeroCAPTCHA single-use store unavailable");
                VerifyResult::reject(reasons::STORE_UNAVAILABLE)
            }
        }
    }
}

fn validate_binding(name: &str, value: &str) -> Result<()> {
    if is_valid_binding(value) {
        return Ok(());
    }
    Err(ZerocaptchaError::InvalidInput(format!(
        "{name} must be a lowercase SHA-256 hex pseudonym"
    )))
}

fn bindings_match(expected: &str, provided: &str) -> bool {
    use subtle::ConstantTimeEq;
    expected.as_bytes().ct_eq(provided.as_bytes()).into()
}

/// Sign canonical challenge parameters. The MAC input is
/// `domain || canonical_json(params)`.
fn sign_params(secret: &[u8], params: &ChallengeParameters) -> Result<String> {
    let canonical = canonical_params(params)?;
    let mut mac = <SimpleHmac<Sha256> as Mac>::new_from_slice(secret)
        .map_err(|e| ZerocaptchaError::Crypto(format!("hmac key: {e}")))?;
    mac.update(PROTOCOL_DOMAIN);
    mac.update(&canonical);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Recompute and constant-time-compare the challenge signature.
fn verify_params_signature(secret: &[u8], challenge: &Challenge) -> Result<bool> {
    use subtle::ConstantTimeEq;
    let canonical = canonical_params(&challenge.params)?;
    let mut mac = <SimpleHmac<Sha256> as Mac>::new_from_slice(secret)
        .map_err(|e| ZerocaptchaError::Crypto(format!("hmac key: {e}")))?;
    mac.update(PROTOCOL_DOMAIN);
    mac.update(&canonical);
    let expected = mac.finalize().into_bytes();
    let Ok(provided) = hex::decode(&challenge.sig) else {
        return Ok(false);
    };
    Ok(provided.ct_eq(expected.as_slice()).into())
}

/// Canonical JSON of the parameters — deterministic because serde_json
/// serializes struct fields in declaration order with no whitespace.
fn canonical_params(params: &ChallengeParameters) -> Result<Vec<u8>> {
    serde_json::to_vec(params)
        .map_err(|e| ZerocaptchaError::InvalidInput(format!("canonical serialization: {e}")))
}

/// Decode a hex key of exactly `KEY_LENGTH` bytes.
fn decode_hex_key(hex_str: &str) -> std::result::Result<[u8; KEY_LENGTH], ()> {
    let bytes = hex::decode(hex_str).map_err(|_| ())?;
    <[u8; KEY_LENGTH]>::try_from(bytes.as_slice()).map_err(|_| ())
}

#[cfg(test)]
mod tests;
