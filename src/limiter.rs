//! Per-client issuance/verification limits and adaptive-difficulty pressure.
//!
//! Callers provide an HMAC-SHA-256 client pseudonym, never a raw IP address.
//! Separate keyed token buckets prevent one client from consuming another
//! client's budget. State is bounded and stale buckets are removed lazily.

use governor::clock::DefaultClock;
use governor::middleware::NoOpMiddleware;
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Mutex;
use std::time::{Duration, Instant};

type KeyedLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock, NoOpMiddleware>;

#[derive(Clone, Copy)]
struct PressureWindow {
    started_at: Instant,
    issued: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitDecision {
    Allowed,
    Denied { retry_after_secs: u64 },
}

pub struct IssuanceLimiter {
    issue: KeyedLimiter,
    verify: KeyedLimiter,
    known_clients: Mutex<HashMap<String, Instant>>,
    pressure: Mutex<HashMap<String, PressureWindow>>,
    issue_quota: u32,
    window_secs: u64,
    max_keys: usize,
}

impl IssuanceLimiter {
    pub fn new(
        issue_per_window: u32,
        verify_per_window: u32,
        window_secs: u64,
        max_keys: usize,
    ) -> Self {
        Self {
            issue: RateLimiter::keyed(quota(issue_per_window, window_secs)),
            verify: RateLimiter::keyed(quota(verify_per_window, window_secs)),
            known_clients: Mutex::new(HashMap::new()),
            pressure: Mutex::new(HashMap::new()),
            issue_quota: issue_per_window.max(1),
            window_secs: window_secs.max(1),
            max_keys: max_keys.max(1),
        }
    }

    pub fn check_issue(&self, client_key: &str) -> LimitDecision {
        let decision = self.check(&self.issue, client_key);
        if decision == LimitDecision::Allowed {
            self.bump_issued(client_key);
        }
        decision
    }

    pub fn check_verify(&self, client_key: &str) -> LimitDecision {
        self.check(&self.verify, client_key)
    }

    pub fn issue_pressure(&self, client_key: &str) -> f64 {
        let mut pressure = self.pressure.lock().expect("pressure lock poisoned");
        let expired = pressure
            .get(client_key)
            .is_some_and(|value| value.started_at.elapsed() >= self.window_duration());
        if expired {
            pressure.remove(client_key);
        }
        let issued = pressure.get(client_key).map_or(0, |value| value.issued);
        (f64::from(issued) / f64::from(self.issue_quota)).min(1.0)
    }

    fn bump_issued(&self, client_key: &str) {
        let mut pressure = self.pressure.lock().expect("pressure lock poisoned");
        let now = Instant::now();
        if let Some(value) = pressure.get_mut(client_key) {
            if now.duration_since(value.started_at) >= self.window_duration() {
                *value = PressureWindow {
                    started_at: now,
                    issued: 1,
                };
            } else {
                value.issued = value.issued.saturating_add(1);
            }
            return;
        }

        // A full-map scan is reserved for saturation instead of running on
        // every request. This keeps the normal path O(1) while still bounding
        // memory under a rotating-identifier flood.
        if pressure.len() >= self.max_keys {
            let window = self.window_duration();
            pressure.retain(|_, value| now.duration_since(value.started_at) < window);
        }
        if pressure.len() < self.max_keys {
            pressure.insert(
                client_key.to_string(),
                PressureWindow {
                    started_at: now,
                    issued: 1,
                },
            );
        }
    }

    fn check(&self, limiter: &KeyedLimiter, client_key: &str) -> LimitDecision {
        use governor::clock::{Clock, DefaultClock as ClockT};

        if !self.admit_client(client_key) {
            return LimitDecision::Denied {
                retry_after_secs: self.window_secs,
            };
        }
        if limiter.len() >= self.max_keys {
            limiter.retain_recent();
        }

        match limiter.check_key(&client_key.to_string()) {
            Ok(_) => LimitDecision::Allowed,
            Err(not_until) => LimitDecision::Denied {
                retry_after_secs: not_until
                    .wait_time_from(ClockT::default().now())
                    .as_secs()
                    .max(1),
            },
        }
    }

    /// Preserve service for already-admitted clients when an identifier flood
    /// fills the cap. New keys fail closed until a stale entry expires; existing
    /// keys keep their own buckets and cannot be crowded out by the attacker.
    fn admit_client(&self, client_key: &str) -> bool {
        let mut clients = self.known_clients.lock().expect("client lock poisoned");
        let now = Instant::now();
        if let Some(last_seen) = clients.get_mut(client_key) {
            *last_seen = now;
            return true;
        }
        if clients.len() >= self.max_keys {
            let retention = Duration::from_secs(self.window_secs.saturating_mul(2));
            clients.retain(|_, last_seen| now.duration_since(*last_seen) < retention);
        }
        if clients.len() >= self.max_keys {
            return false;
        }
        clients.insert(client_key.to_string(), now);
        true
    }

    fn window_duration(&self) -> Duration {
        Duration::from_secs(self.window_secs)
    }
}

fn quota(per_window: u32, window_secs: u64) -> Quota {
    let count = per_window.max(1);
    let nanos = Duration::from_secs(window_secs.max(1)).as_nanos();
    let interval = Duration::from_nanos((nanos / u128::from(count)).max(1) as u64);
    Quota::with_period(interval)
        .expect("positive rate-limit interval")
        .allow_burst(NonZeroU32::new(count).expect("non-zero rate-limit quota"))
}

impl Default for IssuanceLimiter {
    fn default() -> Self {
        Self::new(20, 60, 60, 100_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_then_denies() {
        let limiter = IssuanceLimiter::new(5, 5, 60, 100);
        for _ in 0..5 {
            assert_eq!(limiter.check_issue("client-a"), LimitDecision::Allowed);
        }
        assert!(matches!(
            limiter.check_issue("client-a"),
            LimitDecision::Denied { .. }
        ));
        assert_eq!(limiter.check_verify("client-a"), LimitDecision::Allowed);
    }

    #[test]
    fn verify_bucket_has_its_own_quota() {
        let limiter = IssuanceLimiter::new(1, 3, 60, 100);
        for _ in 0..3 {
            assert_eq!(limiter.check_verify("client-a"), LimitDecision::Allowed);
        }
        assert!(matches!(
            limiter.check_verify("client-a"),
            LimitDecision::Denied { .. }
        ));
    }

    #[test]
    fn pressure_is_per_client() {
        let limiter = IssuanceLimiter::new(4, 4, 60, 100);
        limiter.check_issue("client-a");
        limiter.check_issue("client-a");
        assert!((limiter.issue_pressure("client-a") - 0.5).abs() < f64::EPSILON);
        assert_eq!(limiter.issue_pressure("client-b"), 0.0);
    }

    #[test]
    fn clients_have_independent_buckets() {
        let limiter = IssuanceLimiter::new(1, 1, 60, 100);
        assert_eq!(limiter.check_issue("client-a"), LimitDecision::Allowed);
        assert!(matches!(
            limiter.check_issue("client-a"),
            LimitDecision::Denied { .. }
        ));
        assert_eq!(limiter.check_issue("client-b"), LimitDecision::Allowed);
    }

    #[test]
    fn identifier_flood_cannot_evict_an_active_client() {
        let limiter = IssuanceLimiter::new(3, 3, 60, 1);
        assert_eq!(limiter.check_issue("active-client"), LimitDecision::Allowed);
        assert!(matches!(
            limiter.check_issue("attacker-rotation"),
            LimitDecision::Denied { .. }
        ));
        assert_eq!(limiter.check_issue("active-client"), LimitDecision::Allowed);
    }
}
