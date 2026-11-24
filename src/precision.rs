//! Optional timed coordination layered on real PoW. These server-signed
//! timestamps attest protocol timing, never physical pressing or humanity.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrecisionPolicy {
    pub min_hold_ms: u64,
    pub max_hold_ms: u64,
    pub release_window_ms: u64,
}

impl PrecisionPolicy {
    pub fn validate(&self, ttl_secs: u64) -> bool {
        (1000..=30_000).contains(&self.min_hold_ms)
            && (self.min_hold_ms..=30_000).contains(&self.max_hold_ms)
            && (100..=20_000).contains(&self.release_window_ms)
            && self
                .max_hold_ms
                .checked_add(self.release_window_ms)
                .is_some_and(|window| window < ttl_secs.saturating_mul(1000))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrecisionParameters {
    pub hold_ms: u64,
    pub release_window_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrecisionTicket {
    pub challenge_id: String,
    pub challenge_sig: String,
    pub purpose: String,
    pub client_binding: String,
    pub started_at_ms: u64,
    pub sig: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrecisionReceipt {
    pub ticket: PrecisionTicket,
    pub released_at_ms: u64,
    pub sig: String,
}

/// Separate tagged requests share the authenticated verify subject so broker
/// reply grants can never become an unauthenticated timing-capability mint.
#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrecisionRequest {
    PrecisionStart {
        challenge: crate::challenge::Challenge,
        purpose: String,
        client_binding: String,
    },
    PrecisionRelease {
        challenge: crate::challenge::Challenge,
        purpose: String,
        client_binding: String,
        ticket: PrecisionTicket,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PrecisionResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precision_ticket: Option<PrecisionTicket>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precision_receipt: Option<PrecisionReceipt>,
}

impl PrecisionResponse {
    pub fn reject(reason: &str) -> Self {
        Self {
            valid: false,
            reason: Some(reason.into()),
            precision_ticket: None,
            precision_receipt: None,
        }
    }
}

/// Both transports apply the existing verify quota and the same service
/// validation; adding an operation never creates an unlimited mint path.
pub(crate) async fn execute_request(
    state: &crate::http::AppState,
    request: PrecisionRequest,
) -> PrecisionResponse {
    use std::str::FromStr;
    let (purpose, binding) = match &request {
        PrecisionRequest::PrecisionStart {
            purpose,
            client_binding,
            ..
        }
        | PrecisionRequest::PrecisionRelease {
            purpose,
            client_binding,
            ..
        } => (purpose, client_binding),
    };
    if !crate::challenge::is_valid_binding(binding) {
        return PrecisionResponse::reject("invalid_client_binding");
    }
    if let crate::limiter::LimitDecision::Denied { .. } = state.limiter.check_verify(binding) {
        return PrecisionResponse::reject("rate_limited");
    }
    let Ok(purpose) = crate::challenge::Purpose::from_str(purpose) else {
        return PrecisionResponse::reject("invalid_purpose");
    };
    match request {
        PrecisionRequest::PrecisionStart {
            challenge,
            client_binding,
            ..
        } => {
            match state
                .service
                .start_precision(&challenge, purpose, &client_binding)
                .await
            {
                Ok(ticket) => PrecisionResponse {
                    valid: true,
                    reason: None,
                    precision_ticket: Some(ticket),
                    precision_receipt: None,
                },
                Err(reason) => PrecisionResponse::reject(reason),
            }
        }
        PrecisionRequest::PrecisionRelease {
            challenge,
            ticket,
            client_binding,
            ..
        } => {
            match state
                .service
                .release_precision(&challenge, &ticket, purpose, &client_binding)
                .await
            {
                Ok(receipt) => PrecisionResponse {
                    valid: true,
                    reason: None,
                    precision_ticket: None,
                    precision_receipt: Some(receipt),
                },
                Err(reason) => PrecisionResponse::reject(reason),
            }
        }
    }
}
