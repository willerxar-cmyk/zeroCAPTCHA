//! ZeroCaptcha HTTP API integration tests — the real production surface
//! (`/health`, `/v1/challenge`, `/v1/verify`) exercised in-process with
//! `tower::ServiceExt::oneshot` (no network, no mocks: real crypto, real
//! stores, real rate limits).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;

use std::str::FromStr;
use zerocaptcha::challenge::{Algorithm, Difficulty, Purpose, Solution};
use zerocaptcha::evidence::EvidenceMode;
use zerocaptcha::http::{AppState, router};
use zerocaptcha::kdf::{BuiltinKdfProvider, KdfProvider, KdfSpec, derive_key, key_hex};
use zerocaptcha::limiter::IssuanceLimiter;
use zerocaptcha::service::{
    ChallengeService, ChallengeServiceDependencies, ChallengeServiceOptions, SystemClock,
};
use zerocaptcha::store::{ChallengeStore, InMemoryStore};

const SECRET: &str = "integration-test-secret-at-least-32-bytes!!";
const CLIENT_BINDING: &str = "abababababababababababababababababababababababababababababababab";
const OTHER_BINDING: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

/// Production-shaped app: real service + real in-memory store + real limiter.
fn app(secret: Option<&str>, issue_quota: u32, verify_quota: u32) -> axum::Router {
    app_with_http_api(secret, issue_quota, verify_quota, true)
}

fn app_with_http_api(
    secret: Option<&str>,
    issue_quota: u32,
    verify_quota: u32,
    http_api_enabled: bool,
) -> axum::Router {
    let store: Arc<dyn ChallengeStore> = Arc::new(InMemoryStore::new());
    let kdf: Arc<dyn KdfProvider> = Arc::new(BuiltinKdfProvider);
    let service = Arc::new(ChallengeService::new(
        secret.map(|s| s.as_bytes().to_vec()),
        ChallengeServiceDependencies {
            clock: Arc::new(SystemClock),
            store,
            kdf,
        },
        ChallengeServiceOptions {
            evidence_mode: EvidenceMode::Off,
            adaptive: false,
            memo_max_entries: 10_000,
            memo_ttl_secs: 120,
        },
    ));
    let state = AppState {
        service,
        limiter: Arc::new(IssuanceLimiter::new(issue_quota, verify_quota, 60, 100)),
        default_difficulty: Difficulty::Low, // fast tests
        default_ttl_secs: 600,
        http_max_body_bytes: 16_384,
        http_api_enabled,
    };
    router(state)
}

/// Solve the way the widget does: iterate counters until the prefix matches.
fn solve(challenge: &zerocaptcha::challenge::Challenge) -> Solution {
    use base64::Engine;
    let params = &challenge.params;
    let alg = Algorithm::from_str(params.alg.as_str()).unwrap();
    let salt = base64::engine::general_purpose::STANDARD
        .decode(&params.salt)
        .unwrap();
    let spec = KdfSpec {
        algorithm: alg,
        cost: params.cost,
    };
    let max = Difficulty::Low.max_attempts().min(1 << 20);
    for counter in 0..max {
        let key = derive_key(&spec, &salt, counter).unwrap();
        let hex_key = key_hex(&key);
        if hex_key.starts_with(&params.prefix) {
            return Solution {
                challenge: challenge.clone(),
                counter,
                key: hex_key,
                evidence: None,
                precision_receipt: None,
            };
        }
    }
    panic!("no solution found within attempt cap");
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn precision_policy_is_signed_into_real_pow_challenge() {
    let response = app(Some(SECRET), 20, 60)
        .oneshot(Request::builder().method("POST").uri("/v1/challenge")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::json!({
                "purpose": "login", "client_binding": CLIENT_BINDING,
                "precision": {"min_hold_ms": 3000, "max_hold_ms": 6000, "release_window_ms": 500}
            }).to_string())).unwrap())
        .await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let hold_ms = json["challenge"]["precision"]["hold_ms"].as_u64().unwrap();
    assert!((3000..=6000).contains(&hold_ms));
    assert_eq!(json["challenge"]["precision"]["release_window_ms"], 500);
    assert!(json["challenge"]["cost"].as_u64().unwrap() > 0);
    assert!(!json["challenge"]["prefix"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn health_reports_ok_and_configured() {
    let app = app(Some(SECRET), 20, 60);
    let res = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let json = body_json(res).await;
    assert_eq!(json["status"], "ok");
    assert_eq!(json["configured"], true);
}

#[tokio::test]
async fn full_flow_challenge_solve_verify() {
    let app = app(Some(SECRET), 20, 60);
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/challenge")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"purpose":"login","client_binding":"{CLIENT_BINDING}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let json = body_json(res).await;
    let challenge: zerocaptcha::challenge::Challenge =
        serde_json::from_value(json["challenge"].clone()).unwrap();
    assert_eq!(challenge.params.purpose, Purpose::Login);

    let solution = solve(&challenge);
    let invalid_policy = app
        .clone()
        .oneshot(
            Request::post("/v1/verify")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "solution": solution,
                        "purpose": "login",
                        "client_binding": CLIENT_BINDING,
                        "evidence_mode": "typo"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_policy.status(), StatusCode::BAD_REQUEST);

    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/verify")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "solution": solution,
                        "purpose": "login",
                        "client_binding": CLIENT_BINDING
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let json = body_json(res).await;
    assert_eq!(json["valid"], true, "honest solution must verify");
}

#[tokio::test]
async fn unconfigured_service_refuses_challenge() {
    let app = app(None, 20, 60);
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/challenge")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"purpose":"login","client_binding":"{CLIENT_BINDING}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    let json = body_json(res).await;
    assert_eq!(json["success"], false);
}

#[tokio::test]
async fn tampered_challenge_is_rejected() {
    let app = app(Some(SECRET), 20, 60);
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/challenge")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"purpose":"register","client_binding":"{CLIENT_BINDING}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(res).await;
    let mut challenge: zerocaptcha::challenge::Challenge =
        serde_json::from_value(json["challenge"].clone()).unwrap();
    challenge.params.cost += 1; // tamper a signed field

    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/verify")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "solution": { "challenge": challenge, "counter": 0, "key": "00".repeat(32) },
                        "purpose": "register",
                        "client_binding": CLIENT_BINDING
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(res).await;
    assert_eq!(json["valid"], false);
    assert_eq!(json["reason"], "invalid_signature");
}

#[tokio::test]
async fn replay_after_verify_is_rejected() {
    let app = app(Some(SECRET), 20, 60);
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/challenge")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"purpose":"login","client_binding":"{CLIENT_BINDING}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(res).await;
    let challenge: zerocaptcha::challenge::Challenge =
        serde_json::from_value(json["challenge"].clone()).unwrap();
    let solution = solve(&challenge);
    let payload = serde_json::json!({
        "solution": &solution,
        "purpose": "login",
        "client_binding": CLIENT_BINDING
    })
    .to_string();

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/verify")
                .header("content-type", "application/json")
                .body(Body::from(payload.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(first).await;
    assert_eq!(json["valid"], true);

    let second = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/verify")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(second).await;
    assert_eq!(json["valid"], false);
    assert_eq!(json["reason"], "replayed");
}

#[tokio::test]
async fn issuance_rate_limit_returns_429() {
    let app = app(Some(SECRET), 2, 60); // tiny quota: 2 challenges per window
    for _ in 0..2 {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"purpose":"login","client_binding":"{CLIENT_BINDING}"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/challenge")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"purpose":"login","client_binding":"{CLIENT_BINDING}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    let json = body_json(res).await;
    assert!(json["retry_after_secs"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn wrong_purpose_is_rejected() {
    let app = app(Some(SECRET), 20, 60);
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/challenge")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"purpose":"recovery","client_binding":"{CLIENT_BINDING}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(res).await;
    let challenge: zerocaptcha::challenge::Challenge =
        serde_json::from_value(json["challenge"].clone()).unwrap();
    assert_eq!(challenge.params.purpose, Purpose::Recovery);

    let solution = solve(&challenge);
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/verify")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "solution": solution,
                        "purpose": "login",
                        "client_binding": CLIENT_BINDING
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(res).await;
    assert_eq!(json["valid"], false);
    assert_eq!(json["reason"], "purpose_mismatch");
}

#[tokio::test]
async fn solved_challenge_cannot_be_transferred_to_another_client() {
    let app = app(Some(SECRET), 20, 60);
    let issued = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/challenge")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"purpose":"login","client_binding":"{CLIENT_BINDING}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let challenge: zerocaptcha::challenge::Challenge =
        serde_json::from_value(body_json(issued).await["challenge"].clone()).unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/verify")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "solution": solve(&challenge),
                        "purpose": "login",
                        "client_binding": OTHER_BINDING
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(response).await;
    assert_eq!(json["valid"], false);
    assert_eq!(json["reason"], "client_binding_mismatch");
}

#[tokio::test]
async fn challenge_endpoint_rejects_unknown_fields() {
    let response = app(Some(SECRET), 20, 60)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/challenge")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"purpose":"login","client_binding":"{CLIENT_BINDING}","kind":"unknown"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn disabled_http_mode_rejects_challenge_issuance() {
    let response = app_with_http_api(Some(SECRET), 20, 60, false)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/challenge")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"purpose":"login","client_binding":"{CLIENT_BINDING}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
