//! Single-use challenge store.
//!
//! A challenge must be spendable exactly once. Two implementations:
//! - [`InMemoryStore`] — default; single-instance deployments need no
//!   external state. Entries carry an expiry so consumed ids cannot outlive
//!   the challenges they protect.
//! - [`RedisStore`] (feature `redis`) — atomic `SET key NX EX ttl` claim,
//!   shared across replicas; REQUIRED for multi-instance deployments.
//!
//! Fail-closed: a store error at verification time rejects the solution
//! (`store_unavailable`) — a replayable verification path is worse than a
//! temporarily unusable captcha.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Port for the single-use claim. `Ok(true)` = this call claimed the
/// challenge (first use); `Ok(false)` = already consumed (replay);
/// `Err` = store unavailable → caller MUST fail closed.
#[async_trait::async_trait]
pub trait ChallengeStore: Send + Sync {
    async fn consume_once(
        &self,
        challenge_id: &str,
        ttl_secs: u64,
    ) -> std::result::Result<bool, String>;
}

/// In-memory store with TTL bookkeeping. Suitable for a single instance;
/// consumed ids are purged lazily (on insert) and by expiry.
pub struct InMemoryStore {
    /// challenge_id → expires_at (unix seconds).
    claims: Mutex<HashMap<String, u64>>,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            claims: Mutex::new(HashMap::new()),
        }
    }

    fn purge_expired(&self, now: u64) {
        let mut guard = self.claims.lock().expect("in-memory store lock");
        guard.retain(|_, expires_at| *expires_at > now);
    }
}

#[async_trait::async_trait]
impl ChallengeStore for InMemoryStore {
    async fn consume_once(
        &self,
        challenge_id: &str,
        ttl_secs: u64,
    ) -> std::result::Result<bool, String> {
        let now = now_unix();
        self.purge_expired(now);
        let mut guard = self.claims.lock().expect("in-memory store lock");
        if guard.contains_key(challenge_id) {
            return Ok(false);
        }
        guard.insert(challenge_id.to_string(), now + ttl_secs.max(1));
        Ok(true)
    }
}

/// Redis-backed implementation (feature `redis`): atomic claim-or-fail shared
/// across replicas, with a lazily-built auto-reconnecting connection manager.
#[cfg(feature = "redis")]
pub struct RedisStore {
    url: Option<String>,
    conn: tokio::sync::Mutex<Option<redis::aio::ConnectionManager>>,
}

#[cfg(feature = "redis")]
impl RedisStore {
    /// `url` = `ZEROCAPTCHA_REDIS_URL`; `None` makes every claim fail closed
    /// with a clear message instead of attempting a bogus default endpoint.
    pub fn new(url: Option<String>) -> Self {
        Self {
            url,
            conn: tokio::sync::Mutex::new(None),
        }
    }

    async fn connection(&self) -> std::result::Result<redis::aio::ConnectionManager, String> {
        let Some(url) = self.url.as_deref() else {
            return Err(
                "zerocaptcha redis not configured (set ZEROCAPTCHA_REDIS_URL for multi-instance)"
                    .to_string(),
            );
        };
        let mut guard = self.conn.lock().await;
        if let Some(cm) = guard.as_ref() {
            return Ok(cm.clone());
        }
        let client =
            redis::Client::open(url).map_err(|e| format!("zerocaptcha redis open: {e}"))?;
        let cm = client
            .get_connection_manager()
            .await
            .map_err(|e| format!("zerocaptcha redis connect: {e}"))?;
        // The connection URL can contain a password. Connection state is
        // useful operationally; the endpoint itself must never reach logs.
        tracing::info!("ZeroCaptcha single-use store connected to Redis.");
        *guard = Some(cm.clone());
        Ok(cm)
    }
}

#[cfg(feature = "redis")]
#[async_trait::async_trait]
impl ChallengeStore for RedisStore {
    async fn consume_once(
        &self,
        challenge_id: &str,
        ttl_secs: u64,
    ) -> std::result::Result<bool, String> {
        let mut conn = self.connection().await?;
        // Atomic claim: only the first SET with NX wins; EX ties the record's
        // lifetime to the challenge's remaining validity.
        let claimed: bool = redis::cmd("SET")
            .arg(format!("zerocaptcha:used:{challenge_id}"))
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ttl_secs.max(1))
            .query_async(&mut conn)
            .await
            .map_err(|e| format!("zerocaptcha redis claim: {e}"))?;
        Ok(claimed)
    }
}

/// Unix seconds (UTC) — the store's time base.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn first_claim_wins_second_is_replay() {
        let store = InMemoryStore::new();
        assert!(store.consume_once("challenge-1", 600).await.unwrap());
        assert!(
            !store.consume_once("challenge-1", 600).await.unwrap(),
            "replay"
        );
        assert!(
            store.consume_once("challenge-2", 600).await.unwrap(),
            "distinct ids"
        );
    }

    #[tokio::test]
    async fn expired_claims_are_reusable() {
        let store = InMemoryStore::new();
        assert!(store.consume_once("c", 1).await.unwrap());
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(
            store.consume_once("c", 600).await.unwrap(),
            "expired claim is gone"
        );
    }
}
