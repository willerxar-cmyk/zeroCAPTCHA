//! Bounded replay memo used to reject repeated solutions before KDF work.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(crate) struct SpentMemo {
    max_entries: usize,
    ttl: Duration,
    entries: Mutex<HashMap<String, Instant>>,
}

impl SpentMemo {
    pub(crate) fn new(max_entries: usize, ttl_secs: u64) -> Self {
        Self {
            max_entries: max_entries.max(1),
            ttl: Duration::from_secs(ttl_secs.max(1)),
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn is_spent(&self, id: &str) -> bool {
        let guard = self.entries.lock().expect("spent memo lock poisoned");
        guard.get(id).is_some_and(|at| at.elapsed() < self.ttl)
    }

    pub(crate) fn record(&self, id: &str) {
        let mut guard = self.entries.lock().expect("spent memo lock poisoned");
        if guard.len() >= self.max_entries {
            // Expired entries carry no security value; removing them keeps the
            // replay optimization bounded under identifier-flood attacks.
            guard.retain(|_, at| at.elapsed() < self.ttl);
            if guard.len() >= self.max_entries {
                return;
            }
        }
        guard.insert(id.to_string(), Instant::now());
    }
}
