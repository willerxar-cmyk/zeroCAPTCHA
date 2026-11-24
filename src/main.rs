//! ZeroCaptcha — self-hosted, privacy-first proof-of-work CAPTCHA service.
//!
//! Standalone binary: reads `ZEROCAPTCHA_*` env vars, serves
//! `GET /health`, `POST /v1/challenge` and `POST /v1/verify`. See
//! `README.md` for the full operator guide (config table, API, widget,
//! and scaling) and `src/lib.rs` for the protocol design.

use std::sync::Arc;

use rand::RngCore;
use tracing_subscriber::EnvFilter;
use zerocaptcha::config::ZeroCaptchaConfig;
use zerocaptcha::http::AppState;
use zerocaptcha::kdf::{BuiltinKdfProvider, KdfProvider};
use zerocaptcha::limiter::IssuanceLimiter;
use zerocaptcha::service::{
    ChallengeService, ChallengeServiceDependencies, ChallengeServiceOptions, SystemClock,
};
use zerocaptcha::store::{ChallengeStore, InMemoryStore};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = ZeroCaptchaConfig::from_env()?;

    let Some(secret) = config.secret else {
        return Err(
            "ZEROCAPTCHA_SECRET must be a freshly generated 32-byte hexadecimal key".into(),
        );
    };
    let kdf: Arc<dyn KdfProvider> = Arc::new(BuiltinKdfProvider);

    // ── Single-use store ─────────────────────────────────────────────────────
    // Redis for multi-instance deployments; the built-in in-memory store for
    // single instances (no external state needed).
    let store: Arc<dyn ChallengeStore> = match config.redis_url.as_deref() {
        Some(_url) => {
            #[cfg(feature = "redis")]
            {
                // Redis URLs commonly contain passwords; never place the
                // configured endpoint in logs or telemetry attributes.
                tracing::info!("Single-use store: Redis.");
                Arc::new(zerocaptcha::store::RedisStore::new(
                    config.redis_url.clone(),
                ))
            }
            #[cfg(not(feature = "redis"))]
            {
                return Err("ZEROCAPTCHA_REDIS_URL requires the redis build feature".into());
            }
        }
        None => Arc::new(InMemoryStore::new()),
    };

    let mut signing_key = secret.to_vec();
    if config.redis_url.is_none() {
        // A restart loses in-memory claims. Scope the HMAC key to this process
        // so proofs from before a restart cannot be accepted again.
        let mut boot_nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut boot_nonce);
        signing_key.extend_from_slice(&boot_nonce);
    }
    let service = Arc::new(ChallengeService::new(
        Some(signing_key),
        ChallengeServiceDependencies {
            clock: Arc::new(SystemClock),
            store,
            kdf,
        },
        ChallengeServiceOptions {
            evidence_mode: config.evidence_mode,
            adaptive: config.adaptive_difficulty,
            memo_max_entries: config.memo_max_entries,
            memo_ttl_secs: config.memo_ttl_secs,
        },
    ));

    let state = AppState {
        service: Arc::clone(&service),
        limiter: Arc::new(IssuanceLimiter::new(
            config.issue_per_window,
            config.verify_per_window,
            config.window_secs,
            config.rate_limit_max_keys,
        )),
        default_difficulty: config.default_difficulty,
        default_ttl_secs: config.default_ttl_secs,
        http_max_body_bytes: config.http_max_body_bytes,
        http_api_enabled: config.http_api_enabled,
    };

    let app = zerocaptcha::http::router(state);

    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(
        "ZeroCaptcha listening on {addr} (configured={})",
        service.is_configured()
    );
    axum::serve(listener, app).await?;
    Ok(())
}
