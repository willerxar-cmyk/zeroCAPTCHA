//! Native behavioral regressions use the real signing/KDF/store path with an
//! explicit millisecond clock fixture; no wall-clock sleeps affect precision.
use base64::Engine;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use zerocaptcha::evidence::EvidenceMode;
use zerocaptcha::kdf::{BuiltinKdfProvider, KdfProvider, KdfSpec, derive_key, key_hex};
use zerocaptcha::precision::{PrecisionPolicy, PrecisionReceipt};
use zerocaptcha::service::{
    ChallengeService, ChallengeServiceDependencies, ChallengeServiceOptions, Clock,
    CreateChallengeRequest, VerifySolutionRequest,
};
use zerocaptcha::store::InMemoryStore;
use zerocaptcha::{Algorithm, Challenge, Difficulty, Purpose, Solution};

const CLIENT: &str = "abababababababababababababababababababababababababababababababab";
const NOW_MS: u64 = 1_800_000_000_000;
struct FixtureClock(AtomicU64);
impl FixtureClock {
    fn set(&self, value: u64) {
        self.0.store(value, Ordering::SeqCst);
    }
}
impl Clock for FixtureClock {
    fn now_unix(&self) -> i64 {
        (self.now_unix_ms() / 1000) as i64
    }
    fn now_unix_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
fn fixture() -> (ChallengeService, Arc<FixtureClock>) {
    let clock = Arc::new(FixtureClock(AtomicU64::new(NOW_MS)));
    (
        ChallengeService::new(
            Some(b"precision-test-signing-secret-at-least-32-bytes".to_vec()),
            ChallengeServiceDependencies {
                clock: clock.clone(),
                store: Arc::new(InMemoryStore::new()),
                kdf: Arc::new(BuiltinKdfProvider),
            },
            ChallengeServiceOptions {
                evidence_mode: EvidenceMode::Off,
                adaptive: false,
                memo_max_entries: 100,
                memo_ttl_secs: 120,
            },
        ),
        clock,
    )
}
fn request() -> CreateChallengeRequest {
    CreateChallengeRequest {
        algorithm: Algorithm::Pbkdf2Sha256,
        difficulty: Difficulty::Low,
        purpose: Purpose::Login,
        ttl_secs: 600,
        client_binding: CLIENT.into(),
        precision: Some(PrecisionPolicy {
            min_hold_ms: 3000,
            max_hold_ms: 3000,
            release_window_ms: 500,
        }),
    }
}
fn solve(challenge: &Challenge, receipt: Option<PrecisionReceipt>) -> VerifySolutionRequest {
    let salt = base64::engine::general_purpose::STANDARD
        .decode(&challenge.params.salt)
        .unwrap();
    let spec = KdfSpec {
        algorithm: challenge.params.alg,
        cost: challenge.params.cost,
    };
    for counter in 0..Difficulty::Low.max_attempts() {
        let key = key_hex(&derive_key(&spec, &salt, counter).unwrap());
        if key.starts_with(&challenge.params.prefix) {
            return VerifySolutionRequest {
                solution: Solution {
                    challenge: challenge.clone(),
                    counter,
                    key,
                    evidence: None,
                    precision_receipt: receipt,
                },
                purpose: Purpose::Login,
                client_binding: CLIENT.into(),
                evidence_mode: None,
            };
        }
    }
    panic!("real PoW did not find a solution within its attempt bound");
}

#[tokio::test]
async fn precision_requires_server_receipt_and_real_pow_then_consumes_challenge() {
    let (service, clock) = fixture();
    let challenge = service.create_challenge(&request(), 0.0).unwrap();
    assert_eq!(
        service
            .verify_solution(&solve(&challenge, None))
            .await
            .reason
            .as_deref(),
        Some("precision_receipt_required")
    );
    let ticket = service
        .start_precision(&challenge, Purpose::Login, CLIENT)
        .await
        .unwrap();
    assert_eq!(ticket.started_at_ms, NOW_MS);
    clock.set(NOW_MS + 3000);
    let receipt = service
        .release_precision(&challenge, &ticket, Purpose::Login, CLIENT)
        .await
        .unwrap();
    // A slower KDF may finish after the release window: the authenticated
    // release instant, not the final form submission instant, decides timing.
    clock.set(NOW_MS + 10_000);
    let solution = solve(&challenge, Some(receipt));
    let mut bad_pow = solution.clone();
    bad_pow.solution.key = "ff".repeat(32);
    assert!(!service.verify_solution(&bad_pow).await.valid);
    assert!(service.verify_solution(&solution).await.valid);
    assert_eq!(
        service.verify_solution(&solution).await.reason.as_deref(),
        Some("replayed")
    );
}

#[tokio::test]
async fn early_release_burns_attempt_and_cannot_be_retried() {
    let (service, clock) = fixture();
    let challenge = service.create_challenge(&request(), 0.0).unwrap();
    let ticket = service
        .start_precision(&challenge, Purpose::Login, CLIENT)
        .await
        .unwrap();
    clock.set(NOW_MS + 2999);
    assert_eq!(
        service
            .release_precision(&challenge, &ticket, Purpose::Login, CLIENT)
            .await
            .unwrap_err(),
        "precision_timing_mismatch"
    );
    clock.set(NOW_MS + 3000);
    assert_eq!(
        service
            .release_precision(&challenge, &ticket, Purpose::Login, CLIENT)
            .await
            .unwrap_err(),
        "replayed"
    );
}

#[tokio::test]
async fn late_release_is_rejected_and_exact_window_boundary_is_accepted() {
    for (elapsed_ms, accepted) in [(3500, true), (3501, false)] {
        let (service, clock) = fixture();
        let challenge = service.create_challenge(&request(), 0.0).unwrap();
        let ticket = service
            .start_precision(&challenge, Purpose::Login, CLIENT)
            .await
            .unwrap();
        clock.set(NOW_MS + elapsed_ms);
        assert_eq!(
            service
                .release_precision(&challenge, &ticket, Purpose::Login, CLIENT)
                .await
                .is_ok(),
            accepted
        );
    }
}

#[tokio::test]
async fn only_one_concurrent_start_and_release_can_win() {
    let (service, clock) = fixture();
    let challenge = service.create_challenge(&request(), 0.0).unwrap();
    let (a, b) = tokio::join!(
        service.start_precision(&challenge, Purpose::Login, CLIENT),
        service.start_precision(&challenge, Purpose::Login, CLIENT)
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let ticket = a.or(b).unwrap();
    clock.set(NOW_MS + 3000);
    let (a, b) = tokio::join!(
        service.release_precision(&challenge, &ticket, Purpose::Login, CLIENT),
        service.release_precision(&challenge, &ticket, Purpose::Login, CLIENT)
    );
    assert_ne!(a.is_ok(), b.is_ok());
}

#[tokio::test]
async fn ticket_receipt_and_signed_precision_cannot_be_tampered_or_transferred() {
    let (service, clock) = fixture();
    let challenge = service.create_challenge(&request(), 0.0).unwrap();
    let mut modified = challenge.clone();
    modified.params.precision.as_mut().unwrap().hold_ms = 1000;
    assert_eq!(
        service
            .start_precision(&modified, Purpose::Login, CLIENT)
            .await
            .unwrap_err(),
        "invalid_signature"
    );
    assert_eq!(
        service
            .start_precision(&challenge, Purpose::Register, CLIENT)
            .await
            .unwrap_err(),
        "purpose_mismatch"
    );
    assert_eq!(
        service
            .start_precision(&challenge, Purpose::Login, &"cd".repeat(32))
            .await
            .unwrap_err(),
        "client_binding_mismatch"
    );
    let ticket = service
        .start_precision(&challenge, Purpose::Login, CLIENT)
        .await
        .unwrap();
    let mut forged = ticket.clone();
    forged.started_at_ms -= 3000;
    clock.set(NOW_MS + 3000);
    assert_eq!(
        service
            .release_precision(&challenge, &forged, Purpose::Login, CLIENT)
            .await
            .unwrap_err(),
        "invalid_precision_ticket"
    );
    let receipt = service
        .release_precision(&challenge, &ticket, Purpose::Login, CLIENT)
        .await
        .unwrap();
    let mut forged = receipt.clone();
    forged.released_at_ms += 1;
    assert_eq!(
        service
            .verify_solution(&solve(&challenge, Some(forged)))
            .await
            .reason
            .as_deref(),
        Some("invalid_precision_receipt")
    );
    let other = service.create_challenge(&request(), 0.0).unwrap();
    assert_eq!(
        service
            .verify_solution(&solve(&other, Some(receipt)))
            .await
            .reason
            .as_deref(),
        Some("invalid_precision_receipt")
    );
}

#[tokio::test]
async fn precision_rejects_expiry_clock_rollback_and_nonprecision_capabilities() {
    let (service, clock) = fixture();
    let challenge = service.create_challenge(&request(), 0.0).unwrap();
    let ticket = service
        .start_precision(&challenge, Purpose::Login, CLIENT)
        .await
        .unwrap();
    clock.set(NOW_MS - 1);
    assert_eq!(
        service
            .release_precision(&challenge, &ticket, Purpose::Login, CLIENT)
            .await
            .unwrap_err(),
        "precision_timing_mismatch"
    );
    clock.set(NOW_MS + 600_000);
    assert_eq!(
        service
            .start_precision(&challenge, Purpose::Login, CLIENT)
            .await
            .unwrap_err(),
        "expired"
    );
    assert_eq!(
        service
            .release_precision(&challenge, &ticket, Purpose::Login, CLIENT)
            .await
            .unwrap_err(),
        "expired"
    );
    let mut plain = request();
    plain.precision = None;
    let challenge = service.create_challenge(&plain, 0.0).unwrap();
    assert_eq!(
        service
            .start_precision(&challenge, Purpose::Login, CLIENT)
            .await
            .unwrap_err(),
        "precision_not_required"
    );
}

#[test]
fn invalid_precision_policy_is_refused() {
    let (service, _) = fixture();
    for (min_hold_ms, max_hold_ms, release_window_ms) in [
        (999, 3000, 500),
        (3000, 30_001, 500),
        (3000, 2000, 500),
        (3000, 6000, 99),
        (3000, 6000, 20_001),
    ] {
        let mut req = request();
        req.precision = Some(PrecisionPolicy {
            min_hold_ms,
            max_hold_ms,
            release_window_ms,
        });
        assert!(service.create_challenge(&req, 0.0).is_err());
    }
}

#[tokio::test]
async fn legacy_pow_stays_compatible_without_precision_fields() {
    let (service, _) = fixture();
    let mut req = request();
    req.precision = None;
    let challenge = service.create_challenge(&req, 0.0).unwrap();
    let solution = solve(&challenge, None);
    assert!(
        !serde_json::to_string(&challenge)
            .unwrap()
            .contains("precision")
    );
    assert!(
        !serde_json::to_string(&solution.solution)
            .unwrap()
            .contains("precision")
    );
    assert!(service.verify_solution(&solution).await.valid);
}

#[tokio::test]
async fn challenge_expiring_during_real_kdf_cannot_be_consumed() {
    struct ExpiringKdf(Arc<FixtureClock>);
    impl KdfProvider for ExpiringKdf {
        fn derive(
            &self,
            spec: &KdfSpec,
            salt: &[u8],
            counter: u64,
        ) -> zerocaptcha::error::Result<[u8; 32]> {
            let derived = BuiltinKdfProvider.derive(spec, salt, counter)?;
            // Explicit scheduling fixture models work completing at expiry;
            // cryptography remains the real production KDF.
            self.0.set(NOW_MS + 600_000);
            Ok(derived)
        }
    }
    let clock = Arc::new(FixtureClock(AtomicU64::new(NOW_MS)));
    let service = ChallengeService::new(
        Some(b"precision-test-signing-secret-at-least-32-bytes".to_vec()),
        ChallengeServiceDependencies {
            clock: clock.clone(),
            store: Arc::new(InMemoryStore::new()),
            kdf: Arc::new(ExpiringKdf(clock.clone())),
        },
        ChallengeServiceOptions {
            evidence_mode: EvidenceMode::Off,
            adaptive: false,
            memo_max_entries: 100,
            memo_ttl_secs: 120,
        },
    );
    let challenge = service.create_challenge(&request(), 0.0).unwrap();
    let ticket = service
        .start_precision(&challenge, Purpose::Login, CLIENT)
        .await
        .unwrap();
    clock.set(NOW_MS + 3000);
    let receipt = service
        .release_precision(&challenge, &ticket, Purpose::Login, CLIENT)
        .await
        .unwrap();
    assert_eq!(
        service
            .verify_solution(&solve(&challenge, Some(receipt)))
            .await
            .reason
            .as_deref(),
        Some("expired")
    );
}

#[cfg(feature = "redis")]
#[tokio::test]
async fn real_unconfigured_redis_store_rejects_start_release_and_final_consumption() {
    use zerocaptcha::store::RedisStore;
    let (available, clock) = fixture();
    let unavailable = ChallengeService::new(
        Some(b"precision-test-signing-secret-at-least-32-bytes".to_vec()),
        ChallengeServiceDependencies {
            clock: clock.clone(),
            store: Arc::new(RedisStore::new(None)),
            kdf: Arc::new(BuiltinKdfProvider),
        },
        ChallengeServiceOptions {
            evidence_mode: EvidenceMode::Off,
            adaptive: false,
            memo_max_entries: 100,
            memo_ttl_secs: 120,
        },
    );
    let challenge = available.create_challenge(&request(), 0.0).unwrap();
    assert_eq!(
        unavailable
            .start_precision(&challenge, Purpose::Login, CLIENT)
            .await
            .unwrap_err(),
        "store_unavailable"
    );
    let ticket = available
        .start_precision(&challenge, Purpose::Login, CLIENT)
        .await
        .unwrap();
    clock.set(NOW_MS + 3000);
    assert_eq!(
        unavailable
            .release_precision(&challenge, &ticket, Purpose::Login, CLIENT)
            .await
            .unwrap_err(),
        "store_unavailable"
    );
    let receipt = available
        .release_precision(&challenge, &ticket, Purpose::Login, CLIENT)
        .await
        .unwrap();
    assert_eq!(
        unavailable
            .verify_solution(&solve(&challenge, Some(receipt)))
            .await
            .reason
            .as_deref(),
        Some("store_unavailable")
    );
}
