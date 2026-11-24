//! ZeroCaptcha HTTP API (public, self-contained).
//!
//! Endpoints:
//! - `GET  /health`        — liveness probe.
//! - `POST /v1/challenge`  — mint a signed challenge
//!   body: `{ purpose, difficulty?, algorithm?, ttl_secs?, client_binding }`
//!   200 `{ challenge: {…} }` · 429 `{ error, retry_after_secs }` ·
//!   400/503 `{ error }`.
//! - `POST /v1/verify`     — verify a client solution
//!   body: `{ solution: {…}, purpose, evidence_mode?, client_binding }`
//!   200 `{ valid, reason? }` · 429 `{ valid: false, reason: "rate_limited" }`.
//!
//! Bind this API behind a trusted application server.

use axum::Json;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;

use crate::challenge::{Algorithm, Challenge, Difficulty, Purpose, Solution, is_valid_binding};
use crate::evidence::EvidenceMode;
use crate::limiter::{IssuanceLimiter, LimitDecision};
use crate::precision::{PrecisionPolicy, PrecisionRequest, PrecisionResponse};
use crate::service::{ChallengeService, VerifySolutionRequest};

/// State shared by the HTTP handlers.
#[derive(Clone)]
pub struct AppState {
    pub service: Arc<ChallengeService>,
    pub limiter: Arc<IssuanceLimiter>,
    pub default_difficulty: Difficulty,
    pub default_ttl_secs: u64,
    pub http_max_body_bytes: usize,
    pub http_api_enabled: bool,
}

// ============ Health ============

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub configured: bool,
    pub minted: u64,
    pub verified: u64,
}

pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "zerocaptcha",
        configured: state.service.is_configured(),
        minted: state.service.minted_count(),
        verified: state.service.verified_count(),
    })
}

// ============ Challenge creation ============

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateChallengeHttpRequest {
    /// Flow this challenge is bound to: `login` | `register` | `recovery`.
    pub purpose: String,
    /// Optional difficulty id (`low|medium|high`); defaults to the service
    /// default (config). The CALLER decides difficulty — never the client
    /// widget (a client-chosen difficulty would let bots pick easy tiers).
    #[serde(default)]
    pub difficulty: Option<String>,
    /// Optional algorithm id; defaults to `S6-PBKDF2-SHA256`.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// Optional challenge lifetime in seconds (clamped server-side).
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    /// Privacy-preserving caller key. Public integrations derive this from
    /// their trusted edge context; raw IP addresses are rejected by design.
    pub client_binding: String,
    /// Precision selection belongs to the trusted application policy, just
    /// like difficulty. The standalone API must stay behind that boundary.
    #[serde(default)]
    pub precision: Option<PrecisionPolicy>,
}

#[derive(Debug, Serialize)]
pub struct CreateChallengeResponse {
    pub success: bool,
    pub challenge: Option<Challenge>,
    pub error: Option<String>,
    pub retry_after_secs: Option<u64>,
}

pub async fn create_challenge(
    State(state): State<AppState>,
    Json(req): Json<CreateChallengeHttpRequest>,
) -> impl IntoResponse {
    if !state.http_api_enabled {
        return unavailable_http_api();
    }
    if !is_valid_binding(&req.client_binding) {
        return bad_request("client_binding must be a lowercase SHA-256 hex pseudonym".into());
    }
    // Rate limit first — the cheapest possible rejection.
    if let LimitDecision::Denied { retry_after_secs } =
        state.limiter.check_issue(&req.client_binding)
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(CreateChallengeResponse {
                success: false,
                challenge: None,
                error: Some("challenge issuance rate limit exceeded".to_string()),
                retry_after_secs: Some(retry_after_secs),
            }),
        )
            .into_response();
    }

    let purpose = match Purpose::from_str(&req.purpose) {
        Ok(p) => p,
        Err(e) => return bad_request(e),
    };
    let difficulty = match req
        .difficulty
        .as_deref()
        .map(Difficulty::from_str)
        .transpose()
    {
        Ok(d) => d.unwrap_or(state.default_difficulty),
        Err(e) => return bad_request(e),
    };
    let algorithm = match req
        .algorithm
        .as_deref()
        .map(Algorithm::from_str)
        .transpose()
    {
        Ok(a) => a.unwrap_or(Algorithm::DEFAULT),
        Err(e) => return bad_request(e),
    };

    match state.service.create_challenge(
        &crate::service::CreateChallengeRequest {
            algorithm,
            difficulty,
            purpose,
            ttl_secs: req.ttl_secs.unwrap_or(state.default_ttl_secs),
            client_binding: req.client_binding.clone(),
            precision: req.precision,
        },
        state.limiter.issue_pressure(&req.client_binding),
    ) {
        Ok(challenge) => Json(CreateChallengeResponse {
            success: true,
            challenge: Some(challenge),
            error: None,
            retry_after_secs: None,
        })
        .into_response(),
        Err(e) => {
            tracing::warn!("zerocaptcha challenge creation failed: {e}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(CreateChallengeResponse {
                    success: false,
                    challenge: None,
                    error: Some(e.to_string()),
                    retry_after_secs: None,
                }),
            )
                .into_response()
        }
    }
}

// ============ Verification ============

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    pub solution: Solution,
    pub purpose: String,
    /// Trusted application evidence policy (`off`|`lenient`|`strict`).
    /// Absent → the service env default (`ZEROCAPTCHA_EVIDENCE_MODE`).
    #[serde(default)]
    pub evidence_mode: Option<String>,
    pub client_binding: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum VerifyOperationRequest {
    Precision(PrecisionRequest),
    Solution(VerifyRequest),
}
pub type VerifyResponse = PrecisionResponse;

pub async fn verify_challenge(
    State(state): State<AppState>,
    Json(req): Json<VerifyOperationRequest>,
) -> impl IntoResponse {
    if !state.http_api_enabled {
        return unavailable_http_api();
    }
    let req = match req {
        VerifyOperationRequest::Precision(request) => {
            return Json(crate::precision::execute_request(&state, request).await).into_response();
        }
        VerifyOperationRequest::Solution(request) => request,
    };
    if !is_valid_binding(&req.client_binding) {
        return bad_request("client_binding must be a lowercase SHA-256 hex pseudonym".into());
    }
    if let LimitDecision::Denied { .. } = state.limiter.check_verify(&req.client_binding) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(VerifyResponse::reject("rate_limited")),
        )
            .into_response();
    }

    let purpose = match Purpose::from_str(&req.purpose) {
        Ok(p) => p,
        Err(e) => return bad_request(e),
    };
    let evidence_mode = match req
        .evidence_mode
        .as_deref()
        .map(EvidenceMode::parse)
        .transpose()
    {
        Ok(mode) => mode,
        Err(error) => return bad_request(error.into()),
    };
    let result = state
        .service
        .verify_solution(&VerifySolutionRequest {
            solution: req.solution,
            purpose,
            evidence_mode,
            client_binding: req.client_binding,
        })
        .await;
    Json(VerifyResponse {
        valid: result.valid,
        reason: result.reason,
        precision_ticket: None,
        precision_receipt: None,
    })
    .into_response()
}

/// Assemble the full HTTP router (used by `main` and by the integration
/// tests, so the tests exercise the exact production surface).
pub fn router(state: AppState) -> Router {
    let max_body_bytes = state.http_max_body_bytes;
    Router::new()
        .route("/health", get(health))
        .route("/v1/challenge", post(create_challenge))
        .route("/v1/verify", post(verify_challenge))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .with_state(state)
}

fn bad_request(message: String) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": message, "status": "error" })),
    )
        .into_response()
}

fn unavailable_http_api() -> axum::response::Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "http challenge API disabled",
            "status": "error"
        })),
    )
        .into_response()
}
