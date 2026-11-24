//! ZeroCaptcha protocol domain types.
//!
//! Everything the wire format carries lives here, with deterministic,
//! versioned serialization under `PROTOCOL_DOMAIN`. Field order of
//! `ChallengeParameters` IS the canonical signing order — do not reorder
//! without bumping the protocol version, or every outstanding challenge
//! signature breaks.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Protocol domain separator used as HMAC context: every signature is computed
/// over `PROTOCOL_DOMAIN || canonical_json(parameters)` so a signature from
/// this protocol can never be confused with any other HMAC usage (defense
/// against cross-protocol confusion).
pub const PROTOCOL_DOMAIN: &[u8] = b"zerocaptcha:public:challenge:v1";

/// A client binding is an HMAC-SHA-256 pseudonym encoded as lowercase hex.
/// Raw network addresses never cross the ZeroCaptcha service boundary.
pub const CLIENT_BINDING_HEX_LENGTH: usize = 64;

pub fn is_valid_binding(value: &str) -> bool {
    value.len() == CLIENT_BINDING_HEX_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Derived-key length in bytes (protocol constant; 256-bit keys).
pub const KEY_LENGTH: usize = 32;
/// Salt length in bytes (protocol constant).
pub const SALT_LENGTH: usize = 16;
/// Hard ceiling for challenge validity (defense against a misconfigured
/// operator turning a challenge into a long-lived replay token).
pub const MAX_TTL_SECS: u64 = 3600;
/// Floor so a challenge cannot be issued already-expired.
pub const MIN_TTL_SECS: u64 = 30;

/// Difficulty tiers map to (prefix length in hex digits, PBKDF2 cost). The
/// prefix length is the security parameter: expected solve attempts =
/// `16^prefix_len` (4 bits per hex digit). Cost is the per-attempt KDF cost.
///
/// Mapping (chosen so a WebCrypto PBKDF2-SHA256 solver lands in a human
/// pleasant window):
/// - `low`    → prefix `0`   (4 bits ≈ 16 attempts, ~0.05–0.2 s)
/// - `medium` → prefix `00`  (8 bits ≈ 256 attempts, ~0.3–1 s) ← default
/// - `high`   → prefix `000` (12 bits ≈ 4096 attempts, ~5–15 s; used by
///   escalation when a client is already rate-limited)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Difficulty {
    Low,
    Medium,
    High,
}

impl Difficulty {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Difficulty::Low => "low",
            Difficulty::Medium => "medium",
            Difficulty::High => "high",
        }
    }

    /// Hex prefix the derived key must start with.
    pub const fn prefix(&self) -> &'static str {
        match self {
            Difficulty::Low => "0",
            Difficulty::Medium => "00",
            Difficulty::High => "000",
        }
    }

    /// PBKDF2/iterative-SHA iteration cost per attempt at this tier.
    pub const fn cost(&self) -> u32 {
        match self {
            Difficulty::Low => 2_000,
            Difficulty::Medium => 5_000,
            Difficulty::High => 5_000,
        }
    }

    /// Bits of work: 4 per hex digit of the prefix.
    pub const fn bits(&self) -> u32 {
        self.prefix().len() as u32 * 4
    }

    /// Cap on solver iterations: 16× the expected value never cuts a
    /// legitimate solve short (P(needing >16×E) ≈ 0) while bounding loops.
    pub const fn max_attempts(&self) -> u64 {
        16u64 << self.bits()
    }

    /// One step harder (used by adaptive difficulty — see service module).
    pub const fn escalate(self) -> Difficulty {
        match self {
            Difficulty::Low => Difficulty::Medium,
            Difficulty::Medium => Difficulty::High,
            Difficulty::High => Difficulty::High,
        }
    }
}

impl std::str::FromStr for Difficulty {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Ok(Difficulty::Low),
            "medium" => Ok(Difficulty::Medium),
            "high" => Ok(Difficulty::High),
            other => Err(format!(
                "unknown difficulty '{other}' (expected low|medium|high)"
            )),
        }
    }
}

impl Serialize for Difficulty {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Difficulty {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The flow a challenge was minted for. Verification rejects a solution whose
/// challenge purpose does not match the calling flow, so a challenge farmed on
/// one form cannot be spent on another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Login,
    Register,
    /// Password recovery / account recovery flows (2026-08-08): gated by the
    /// same admin policy as login (the recovery form is part of the login
    /// surface) but purpose-bound so a recovery challenge is not spendable on
    /// login and vice-versa.
    Recovery,
    /// Public appointment or reservation booking.
    Booking,
}

impl Purpose {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Purpose::Login => "login",
            Purpose::Register => "register",
            Purpose::Recovery => "recovery",
            Purpose::Booking => "booking",
        }
    }
}

impl std::str::FromStr for Purpose {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "login" => Ok(Purpose::Login),
            "register" => Ok(Purpose::Register),
            "recovery" => Ok(Purpose::Recovery),
            "booking" => Ok(Purpose::Booking),
            other => Err(format!(
                "unknown purpose '{other}' (expected login|register|recovery|booking)"
            )),
        }
    }
}

impl Serialize for Purpose {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Purpose {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Proof channel represented by a signed, single-use challenge.
///
/// The standalone edition issues proof-of-work challenges.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    ProofOfWork,
}

/// Proof-of-work key-derivation algorithm. The wire identifiers are stable.
/// The bundled widget uses Web Crypto for `S6-PBKDF2-SHA256`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// PBKDF2-HMAC-SHA-256; `cost` = iteration count. Default.
    Pbkdf2Sha256,
    /// Iterative SHA-256; `cost` = number of rounds. No dependencies.
    Sha256,
    /// Argon2id (memory-hard); `cost` = time cost, memory fixed at 64 MiB,
    /// parallelism 1. Feature `argon2`; the default widget does not solve it.
    Argon2id,
    /// scrypt (memory-hard); `cost` = log2(N), r = 8, p = 1. Feature `scrypt`.
    Scrypt,
}

impl Algorithm {
    pub const DEFAULT: Self = Algorithm::Pbkdf2Sha256;

    pub const fn as_str(&self) -> &'static str {
        match self {
            Algorithm::Pbkdf2Sha256 => "S6-PBKDF2-SHA256",
            Algorithm::Sha256 => "S6-SHA256",
            Algorithm::Argon2id => "S6-ARGON2ID",
            Algorithm::Scrypt => "S6-SCRYPT",
        }
    }

    /// All algorithms the engine can verify (used to give a precise error
    /// instead of a generic parse failure).
    pub const ALL: [Algorithm; 4] = [
        Algorithm::Pbkdf2Sha256,
        Algorithm::Sha256,
        Algorithm::Argon2id,
        Algorithm::Scrypt,
    ];
}

impl std::str::FromStr for Algorithm {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "S6-PBKDF2-SHA256" => Ok(Algorithm::Pbkdf2Sha256),
            "S6-SHA256" => Ok(Algorithm::Sha256),
            "S6-ARGON2ID" => Ok(Algorithm::Argon2id),
            "S6-SCRYPT" => Ok(Algorithm::Scrypt),
            other => Err(format!("unknown algorithm '{other}'")),
        }
    }
}

impl Serialize for Algorithm {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Algorithm {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The signed parameter set of a challenge. Field order IS the canonical
/// signing order — treat as frozen for protocol v2.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChallengeParameters {
    /// Unique challenge id (uuid v7). Also the single-use store key.
    pub id: String,
    /// KDF algorithm identifier.
    pub alg: Algorithm,
    /// Salt, base64 (standard alphabet, padded).
    pub salt: String,
    /// Per-attempt KDF cost (iterations / Argon2 time cost / scrypt log-N).
    pub cost: u32,
    /// Required hex prefix of the derived key (lowercase).
    pub prefix: String,
    /// Unix seconds after which the challenge is invalid.
    pub expires_at: i64,
    /// Flow this challenge is bound to.
    pub purpose: Purpose,
    /// Proof-of-work challenge kind.
    pub kind: ChallengeKind,
    /// Edge-derived, privacy-preserving client pseudonym.
    pub client_binding: String,
    /// Optional signed timing requirement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precision: Option<crate::precision::PrecisionParameters>,
}

/// A signed challenge as sent to the client. The signature covers the
/// canonical JSON of the embedded parameters.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Challenge {
    #[serde(flatten)]
    pub params: ChallengeParameters,
    /// `hex(HMAC-SHA256(secret, PROTOCOL_DOMAIN || canonical(params)))`.
    pub sig: String,
}

/// Optional client-asserted interaction and focus signals. The server applies
/// its configured evidence policy. These signals do not establish identity.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Count of user interactions observed by the widget (clicks, keys,
    /// pointer moves). A fully automated solver typically produces 0.
    pub interactions: u32,
    /// Whether the document held focus while the solve ran.
    pub focus: bool,
    /// Wall-clock time the browser spent solving, in milliseconds. Solves
    /// far below the expected window hint at headless/optimized solvers.
    pub solve_ms: u64,
}

/// A client solution: the challenge it solved plus the winning counter and
/// the derived key (hex), and optional human evidence. Verification
/// re-derives the key from `counter` (ONE KDF call) and compares in constant
/// time.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Solution {
    pub challenge: Challenge,
    /// The counter whose derived key matched the prefix.
    pub counter: u64,
    /// Derived key, hex (lowercase) — 64 hex chars for a 32-byte key.
    pub key: String,
    /// Optional human-evidence signals (see `Evidence`). Absent → ignored
    /// unless `strict` mode is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
    /// Only the engine can attest release timing; client event durations are
    /// never accepted as a substitute for this domain-separated signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precision_receipt: Option<crate::precision::PrecisionReceipt>,
}

/// Machine-readable verification outcome. `reason` is always present when
/// `valid == false` and is safe to surface to clients (no secret material).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifyResult {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl VerifyResult {
    pub fn ok() -> Self {
        Self {
            valid: true,
            reason: None,
        }
    }

    pub fn reject(reason: &str) -> Self {
        Self {
            valid: false,
            reason: Some(reason.to_string()),
        }
    }
}

/// Human-readable rejection reasons (stable identifiers, keep in sync with
/// the widget's error mapping).
pub mod reasons {
    pub const EXPIRED: &str = "expired";
    pub const INVALID_SIGNATURE: &str = "invalid_signature";
    pub const PURPOSE_MISMATCH: &str = "purpose_mismatch";
    pub const CLIENT_BINDING_MISMATCH: &str = "client_binding_mismatch";
    pub const INVALID_SOLUTION: &str = "invalid_solution";
    pub const REPLAYED: &str = "replayed";
    pub const UNSUPPORTED_ALGORITHM: &str = "unsupported_algorithm";
    pub const STORE_UNAVAILABLE: &str = "store_unavailable";
    pub const NOT_CONFIGURED: &str = "not_configured";
    pub const EVIDENCE_REJECTED: &str = "evidence_rejected";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn difficulty_mapping_is_sane() {
        assert_eq!(Difficulty::Low.prefix(), "0");
        assert_eq!(Difficulty::Medium.prefix(), "00");
        assert_eq!(Difficulty::High.prefix(), "000");
        assert_eq!(Difficulty::Low.bits(), 4);
        assert_eq!(Difficulty::Medium.bits(), 8);
        assert_eq!(Difficulty::High.bits(), 12);
        assert_eq!(Difficulty::Medium.max_attempts(), 4096);
        assert_eq!(Difficulty::High.max_attempts(), 65536);
        // Escalation ladder never gets easier.
        assert_eq!(Difficulty::Low.escalate(), Difficulty::Medium);
        assert_eq!(Difficulty::Medium.escalate(), Difficulty::High);
        assert_eq!(Difficulty::High.escalate(), Difficulty::High);
    }

    #[test]
    fn difficulty_roundtrip() {
        for d in [Difficulty::Low, Difficulty::Medium, Difficulty::High] {
            let json = serde_json::to_string(&d).unwrap();
            assert_eq!(json, format!("\"{}\"", d.as_str()));
            let parsed: Difficulty = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, d);
        }
        assert!(serde_json::from_str::<Difficulty>("\"extreme\"").is_err());
    }

    #[test]
    fn purpose_and_algorithm_roundtrip() {
        for p in [
            Purpose::Login,
            Purpose::Register,
            Purpose::Recovery,
            Purpose::Booking,
        ] {
            let json = serde_json::to_string(&p).unwrap();
            let parsed: Purpose = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, p);
        }
        assert_eq!(Purpose::Recovery.as_str(), "recovery");
        for a in Algorithm::ALL {
            let json = serde_json::to_string(&a).unwrap();
            let parsed: Algorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, a);
        }
        // Third-party algorithm identifiers must not parse.
        assert!(Algorithm::from_str("PBKDF2/SHA-256").is_err());
    }

    #[test]
    fn canonical_json_is_deterministic() {
        use base64::Engine;
        let params = ChallengeParameters {
            id: "0195f0a1-0000-7000-8000-000000000001".to_string(),
            alg: Algorithm::Pbkdf2Sha256,
            salt: base64::engine::general_purpose::STANDARD.encode([0u8; 16]),
            cost: 5000,
            prefix: "00".to_string(),
            expires_at: 1_754_640_000,
            purpose: Purpose::Login,
            kind: ChallengeKind::ProofOfWork,
            client_binding: "ab".repeat(32),
            precision: None,
        };
        let a = serde_json::to_string(&params).unwrap();
        let b = serde_json::to_string(&params).unwrap();
        assert_eq!(a, b, "canonical params JSON must be byte-stable");
        assert!(!a.contains(' '), "no whitespace in the signing input");
    }

    #[test]
    fn v2_solution_without_evidence_parses() {
        let raw = r#"{"challenge":{"id":"x","alg":"S6-PBKDF2-SHA256","salt":"QUJD","cost":100,"prefix":"0","expires_at":2000000000,"purpose":"login","kind":"proof_of_work","client_binding":"abababababababababababababababababababababababababababababababab","sig":"ab"},"counter":1,"key":"00"}"#;
        let sol: Solution = serde_json::from_str(raw).unwrap();
        assert_eq!(sol.evidence, None);
    }
}
