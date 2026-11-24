use super::*;
use crate::kdf::derive_key;
use crate::store::InMemoryStore;
use std::sync::atomic::{AtomicI64, Ordering as AtOrdering};

struct FixtureClock(AtomicI64);
impl FixtureClock {
    fn at(ts: i64) -> Self {
        Self(AtomicI64::new(ts))
    }
    fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, AtOrdering::SeqCst);
    }
}
impl Clock for FixtureClock {
    fn now_unix(&self) -> i64 {
        self.0.load(AtOrdering::SeqCst)
    }
}

const SECRET: &str = "test-zerocaptcha-secret-at-least-32-bytes!!";
const T0: i64 = 1_754_640_000;
const CLIENT_BINDING: &str = "abababababababababababababababababababababababababababababababab";

fn service() -> (ChallengeService, Arc<FixtureClock>) {
    service_with_mode(EvidenceMode::Off, false)
}

fn service_with_mode(
    evidence_mode: EvidenceMode,
    adaptive: bool,
) -> (ChallengeService, Arc<FixtureClock>) {
    let clock = Arc::new(FixtureClock::at(T0));
    (
        ChallengeService::new(
            Some(SECRET.as_bytes().to_vec()),
            ChallengeServiceDependencies {
                clock: clock.clone(),
                store: Arc::new(InMemoryStore::new()),
                kdf: Arc::new(crate::kdf::BuiltinKdfProvider),
            },
            ChallengeServiceOptions {
                evidence_mode,
                adaptive,
                memo_max_entries: 10_000,
                memo_ttl_secs: 120,
            },
        ),
        clock,
    )
}

fn create_request(purpose: Purpose) -> CreateChallengeRequest {
    CreateChallengeRequest {
        algorithm: Algorithm::Pbkdf2Sha256,
        difficulty: Difficulty::Low, // 4 bits ≈ 16 attempts ⇒ fast tests
        purpose,
        ttl_secs: 600,
        client_binding: CLIENT_BINDING.to_string(),
        precision: None,
    }
}

fn verify_request(solution: Solution, purpose: Purpose) -> VerifySolutionRequest {
    VerifySolutionRequest {
        solution,
        purpose,
        evidence_mode: None,
        client_binding: CLIENT_BINDING.to_string(),
    }
}

fn solve(challenge: &Challenge) -> Solution {
    let params = &challenge.params;
    let alg = Algorithm::from_str(params.alg.as_str()).unwrap();
    let salt = BASE64_STANDARD.decode(&params.salt).unwrap();
    let spec = KdfSpec {
        algorithm: alg,
        cost: params.cost,
    };
    let max = Difficulty::from_str("low")
        .unwrap()
        .max_attempts()
        .min(1 << 20);
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

#[tokio::test]
async fn honest_solution_verifies() {
    let (svc, _clock) = service();
    let challenge = svc
        .create_challenge(&create_request(Purpose::Login), 0.0)
        .unwrap();
    let solution = solve(&challenge);
    let res = svc
        .verify_solution(&verify_request(solution, Purpose::Login))
        .await;
    assert!(res.valid, "honest solution must verify: {:?}", res.reason);
}

#[tokio::test]
async fn tampered_params_rejected() {
    let (svc, _clock) = service();
    let challenge = svc
        .create_challenge(&create_request(Purpose::Login), 0.0)
        .unwrap();
    let mut tampered = challenge.clone();
    tampered.params.cost += 1; // alter a signed field
    let res = svc
        .verify_solution(&verify_request(
            Solution {
                challenge: tampered,
                counter: 0,
                key: "00".repeat(32),
                evidence: None,
                precision_receipt: None,
            },
            Purpose::Login,
        ))
        .await;
    assert_eq!(res.reason.as_deref(), Some(reasons::INVALID_SIGNATURE));
}

#[tokio::test]
async fn wrong_purpose_rejected() {
    let (svc, _clock) = service();
    let challenge = svc
        .create_challenge(&create_request(Purpose::Login), 0.0)
        .unwrap();
    let res = svc
        .verify_solution(&verify_request(solve(&challenge), Purpose::Register))
        .await;
    assert_eq!(res.reason.as_deref(), Some(reasons::PURPOSE_MISMATCH));
}

#[tokio::test]
async fn expired_challenge_rejected() {
    let (svc, clock) = service();
    let challenge = svc
        .create_challenge(&create_request(Purpose::Login), 0.0)
        .unwrap();
    let solution = solve(&challenge);
    clock.advance(600); // expiry is exclusive at the exact deadline
    let res = svc
        .verify_solution(&verify_request(solution, Purpose::Login))
        .await;
    assert_eq!(res.reason.as_deref(), Some(reasons::EXPIRED));
}

#[tokio::test]
async fn replayed_solution_rejected_and_memoized() {
    let (svc, _clock) = service();
    let challenge = svc
        .create_challenge(&create_request(Purpose::Login), 0.0)
        .unwrap();
    let solution = solve(&challenge);
    assert!(
        svc.verify_solution(&verify_request(solution.clone(), Purpose::Login))
            .await
            .valid
    );
    // The second submission is a replay — via the memo fast-path.
    let res = svc
        .verify_solution(&verify_request(solution, Purpose::Login))
        .await;
    assert_eq!(res.reason.as_deref(), Some(reasons::REPLAYED));
}

#[tokio::test]
async fn wrong_key_rejected_even_with_valid_counter() {
    let (svc, _clock) = service();
    let challenge = svc
        .create_challenge(&create_request(Purpose::Login), 0.0)
        .unwrap();
    let res = svc
        .verify_solution(&verify_request(
            Solution {
                challenge,
                counter: 0,
                key: "ff".repeat(32),
                evidence: None,
                precision_receipt: None,
            },
            Purpose::Login,
        ))
        .await;
    assert_eq!(res.reason.as_deref(), Some(reasons::INVALID_SOLUTION));
}

#[tokio::test]
async fn unconfigured_service_fails_closed() {
    let svc = ChallengeService::new(
        None,
        ChallengeServiceDependencies {
            clock: Arc::new(FixtureClock::at(T0)),
            store: Arc::new(InMemoryStore::new()),
            kdf: Arc::new(crate::kdf::BuiltinKdfProvider),
        },
        ChallengeServiceOptions {
            evidence_mode: EvidenceMode::Off,
            adaptive: false,
            memo_max_entries: 100,
            memo_ttl_secs: 60,
        },
    );
    assert!(!svc.is_configured());
    assert!(
        svc.create_challenge(&create_request(Purpose::Login), 0.0)
            .is_err()
    );
    let res = svc
        .verify_solution(&VerifySolutionRequest {
            solution: Solution {
                challenge: Challenge {
                    params: ChallengeParameters {
                        id: "x".into(),
                        alg: Algorithm::Pbkdf2Sha256,
                        salt: BASE64_STANDARD.encode([0u8; 16]),
                        cost: 1,
                        prefix: "00".into(),
                        expires_at: T0 + 600,
                        purpose: Purpose::Login,
                        kind: ChallengeKind::ProofOfWork,
                        client_binding: CLIENT_BINDING.to_string(),
                        precision: None,
                    },
                    sig: "00".to_string(),
                },
                counter: 0,
                key: "00".repeat(32),
                evidence: None,
                precision_receipt: None,
            },
            purpose: Purpose::Login,
            evidence_mode: None,
            client_binding: CLIENT_BINDING.to_string(),
        })
        .await;
    assert_eq!(res.reason.as_deref(), Some(reasons::NOT_CONFIGURED));
}

#[tokio::test]
async fn sha256_algorithm_roundtrip() {
    let (svc, _clock) = service();
    let mut req = create_request(Purpose::Recovery);
    req.algorithm = Algorithm::Sha256;
    let challenge = svc.create_challenge(&req, 0.0).unwrap();
    let res = svc
        .verify_solution(&verify_request(solve(&challenge), Purpose::Recovery))
        .await;
    assert!(res.valid, "iterative SHA-256 must verify: {:?}", res.reason);
}

#[tokio::test]
async fn ttl_is_clamped() {
    let (svc, _clock) = service();
    let mut req = create_request(Purpose::Login);
    req.ttl_secs = 1; // below floor
    let c = svc.create_challenge(&req, 0.0).unwrap();
    assert!(c.params.expires_at <= T0 + 30);
    let mut req = create_request(Purpose::Login);
    req.ttl_secs = 999_999; // above ceiling
    let c = svc.create_challenge(&req, 0.0).unwrap();
    assert!(c.params.expires_at <= T0 + 3600);
}

#[tokio::test]
async fn adaptive_difficulty_escalates_under_pressure() {
    let (svc, _) = service_with_mode(EvidenceMode::Off, true);
    let c = svc
        .create_challenge(&create_request(Purpose::Login), 0.9)
        .unwrap();
    assert_eq!(c.params.prefix, "00");
    let c = svc
        .create_challenge(&create_request(Purpose::Login), 0.1)
        .unwrap();
    assert_eq!(c.params.prefix, "0");
}

#[tokio::test]
async fn evidence_strict_rejects_bots_accepts_humans() {
    let (svc, _) = service_with_mode(EvidenceMode::Strict, false);
    let challenge = svc
        .create_challenge(&create_request(Purpose::Login), 0.0)
        .unwrap();

    let mut bot = solve(&challenge);
    bot.evidence = None;
    let res = svc
        .verify_solution(&verify_request(bot, Purpose::Login))
        .await;
    assert_eq!(res.reason.as_deref(), Some(reasons::EVIDENCE_REJECTED));

    let challenge2 = svc
        .create_challenge(&create_request(Purpose::Login), 0.0)
        .unwrap();
    let mut human = solve(&challenge2);
    human.evidence = Some(Evidence {
        interactions: 3,
        focus: true,
        solve_ms: 900,
    });
    let res = svc
        .verify_solution(&verify_request(human, Purpose::Login))
        .await;
    assert!(res.valid, "human evidence must pass strict mode");
}

#[tokio::test]
async fn per_request_evidence_mode_overrides_service_default() {
    let (svc, _) = service_with_mode(EvidenceMode::Off, false);
    let challenge = svc
        .create_challenge(&create_request(Purpose::Login), 0.0)
        .unwrap();
    let mut bot = solve(&challenge);
    bot.evidence = None;
    let res = svc
        .verify_solution(&VerifySolutionRequest {
            solution: bot,
            purpose: Purpose::Login,
            evidence_mode: Some(EvidenceMode::Strict),
            client_binding: CLIENT_BINDING.to_string(),
        })
        .await;
    assert_eq!(res.reason.as_deref(), Some(reasons::EVIDENCE_REJECTED));
}

#[tokio::test]
async fn evidence_lenient_rejects_clearly_bot_evidence() {
    let (svc, _) = service_with_mode(EvidenceMode::Lenient, false);
    let challenge = svc
        .create_challenge(&create_request(Purpose::Login), 0.0)
        .unwrap();
    let mut bot = solve(&challenge);
    bot.evidence = Some(Evidence {
        interactions: 0,
        focus: false,
        solve_ms: 1,
    });
    let res = svc
        .verify_solution(&verify_request(bot, Purpose::Login))
        .await;
    assert_eq!(res.reason.as_deref(), Some(reasons::EVIDENCE_REJECTED));

    let challenge2 = svc
        .create_challenge(&create_request(Purpose::Login), 0.0)
        .unwrap();
    let mut no_evidence = solve(&challenge2);
    no_evidence.evidence = None;
    let res = svc
        .verify_solution(&verify_request(no_evidence, Purpose::Login))
        .await;
    assert!(res.valid, "lenient accepts missing evidence");
}
