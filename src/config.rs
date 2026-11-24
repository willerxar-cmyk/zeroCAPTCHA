//! ZeroCaptcha service configuration — every knob comes from the environment
//! (zero hardcoded operational values; only documented safe defaults).
//!
//! Startup requires a fresh 32-byte signing key supplied as hexadecimal.

use std::env;
use std::str::FromStr;

use crate::challenge::Difficulty;
use crate::evidence::EvidenceMode;

#[derive(Clone)]
pub struct ZeroCaptchaConfig {
    /// HMAC signing key. `None` ⇒ the service refuses to operate.
    pub secret: Option<[u8; 32]>,
    pub host: String,
    pub port: u16,
    /// Redis URL for the single-use store; `None` ⇒ in-memory store
    /// (single-instance deployments need no external state).
    pub redis_url: Option<String>,
    /// Human-evidence scoring mode (off|lenient|strict).
    pub evidence_mode: EvidenceMode,
    /// Escalate difficulty when per-client issuance pressure exceeds 50%.
    pub adaptive_difficulty: bool,
    /// Default difficulty when a caller omits one.
    pub default_difficulty: Difficulty,
    /// Default challenge lifetime in seconds (clamped by the service).
    pub default_ttl_secs: u64,
    /// Per-client challenge issuance quota per window.
    pub issue_per_window: u32,
    /// Per-client verification quota per window.
    pub verify_per_window: u32,
    /// Rate-limit window length in seconds.
    pub window_secs: u64,
    /// Hard cap on in-process client buckets under identifier floods.
    pub rate_limit_max_keys: usize,
    /// Spent-challenge memo size (replay fast-path).
    pub memo_max_entries: usize,
    /// Spent-challenge memo TTL in seconds.
    pub memo_ttl_secs: u64,
    /// Maximum public HTTP request body accepted by the standalone API.
    pub http_max_body_bytes: usize,
    /// Enable the challenge and verification routes.
    pub http_api_enabled: bool,
}

impl ZeroCaptchaConfig {
    pub fn from_env() -> Result<Self, &'static str> {
        Ok(Self {
            secret: env_secret("ZEROCAPTCHA_SECRET"),
            host: env::var("ZEROCAPTCHA_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: env::var("ZEROCAPTCHA_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3028),
            redis_url: env_nonempty("ZEROCAPTCHA_REDIS_URL"),
            evidence_mode: EvidenceMode::parse(
                &env::var("ZEROCAPTCHA_EVIDENCE_MODE").unwrap_or_else(|_| "strict".to_string()),
            )?,
            adaptive_difficulty: env_bool("ZEROCAPTCHA_ADAPTIVE_DIFFICULTY", true),
            default_difficulty: env::var("ZEROCAPTCHA_DIFFICULTY_DEFAULT")
                .ok()
                .and_then(|v| Difficulty::from_str(&v).ok())
                .unwrap_or(Difficulty::Medium),
            default_ttl_secs: env_u64("ZEROCAPTCHA_CHALLENGE_TTL_DEFAULT_SECS", 600),
            issue_per_window: env_u32("ZEROCAPTCHA_ISSUE_PER_WINDOW", 20),
            verify_per_window: env_u32("ZEROCAPTCHA_VERIFY_PER_WINDOW", 60),
            window_secs: env_u64("ZEROCAPTCHA_WINDOW_SECS", 60),
            rate_limit_max_keys: env_usize("ZEROCAPTCHA_RATE_LIMIT_MAX_KEYS", 100_000),
            memo_max_entries: env_usize("ZEROCAPTCHA_MEMO_MAX_ENTRIES", 10_000),
            memo_ttl_secs: env_u64("ZEROCAPTCHA_MEMO_TTL_SECS", 120),
            http_max_body_bytes: env_usize("ZEROCAPTCHA_HTTP_MAX_BODY_BYTES", 16_384)
                .clamp(1_024, 1_048_576),
            http_api_enabled: env_bool("ZEROCAPTCHA_HTTP_API_ENABLED", true),
        })
    }
}

fn env_secret(key: &str) -> Option<[u8; 32]> {
    let value = env::var(key).ok()?;
    let mut secret = [0u8; 32];
    hex::decode_to_slice(value.trim(), &mut secret).ok()?;
    secret.iter().any(|byte| *byte != 0).then_some(secret)
}

fn env_nonempty(key: &str) -> Option<String> {
    env::var(key).ok().filter(|s| !s.trim().is_empty())
}

fn env_bool(key: &str, default: bool) -> bool {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u32(key: &str, default: u32) -> u32 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_usize(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialized env mutation guard: tests that set env vars run one at a
    /// time (the standard Rust test runner runs them in parallel threads).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn secret_policy_rejects_empty_and_placeholders() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("ZEROCAPTCHA_SECRET");
        }
        assert!(
            env_secret("ZEROCAPTCHA_SECRET").is_none(),
            "unset ⇒ unconfigured"
        );

        unsafe {
            std::env::set_var("ZEROCAPTCHA_SECRET", "change-me-123");
        }
        assert!(
            env_secret("ZEROCAPTCHA_SECRET").is_none(),
            "placeholder ⇒ unconfigured"
        );

        unsafe {
            std::env::set_var("ZEROCAPTCHA_SECRET", "ab".repeat(32));
        }
        assert!(
            env_secret("ZEROCAPTCHA_SECRET").is_some(),
            "real value accepted"
        );
        unsafe {
            std::env::remove_var("ZEROCAPTCHA_SECRET");
        }
    }

    #[test]
    fn defaults_are_safe() {
        let _guard = ENV_LOCK.lock().unwrap();
        for k in [
            "ZEROCAPTCHA_HOST",
            "ZEROCAPTCHA_PORT",
            "ZEROCAPTCHA_EVIDENCE_MODE",
            "ZEROCAPTCHA_ADAPTIVE_DIFFICULTY",
            "ZEROCAPTCHA_DIFFICULTY_DEFAULT",
        ] {
            unsafe {
                std::env::remove_var(k);
            }
        }
        let cfg = ZeroCaptchaConfig::from_env().unwrap();
        assert_eq!(cfg.host, "127.0.0.1");
        assert_eq!(cfg.port, 3028);
        assert_eq!(
            cfg.evidence_mode,
            EvidenceMode::Strict,
            "unset environment defaults to strict"
        );
        assert!(cfg.adaptive_difficulty);
        assert_eq!(cfg.default_difficulty, Difficulty::Medium);
    }

    #[test]
    fn invalid_evidence_policy_fails_configuration() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("ZEROCAPTCHA_EVIDENCE_MODE", "typo");
        }
        let result = ZeroCaptchaConfig::from_env();
        unsafe {
            std::env::remove_var("ZEROCAPTCHA_EVIDENCE_MODE");
        }
        assert!(result.is_err());
    }
}
