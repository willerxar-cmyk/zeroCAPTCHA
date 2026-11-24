//! Server timing has its own one-use lifecycle: a failed release burns its
//! attempt, while successful release can precede completion of genuine PoW.
use super::*;
use crate::precision::{PrecisionReceipt, PrecisionTicket};
use serde::Serialize;

const TICKET_DOMAIN: &[u8] = b"zerocaptcha:public:precision-ticket:v1";
const RECEIPT_DOMAIN: &[u8] = b"zerocaptcha:public:precision-receipt:v1";

impl ChallengeService {
    pub async fn start_precision(
        &self,
        challenge: &Challenge,
        purpose: Purpose,
        client_binding: &str,
    ) -> std::result::Result<PrecisionTicket, &'static str> {
        self.validate_precision_challenge(challenge, purpose, client_binding)?;
        self.claim_precision("precision:start:", challenge).await?;
        let mut ticket = PrecisionTicket {
            challenge_id: challenge.params.id.clone(),
            challenge_sig: challenge.sig.clone(),
            purpose: purpose.as_str().into(),
            client_binding: client_binding.into(),
            started_at_ms: self.clock.now_unix_ms(),
            sig: String::new(),
        };
        ticket.sig = self.sign_precision(TICKET_DOMAIN, &ticket_payload(&ticket))?;
        Ok(ticket)
    }

    pub async fn release_precision(
        &self,
        challenge: &Challenge,
        ticket: &PrecisionTicket,
        purpose: Purpose,
        client_binding: &str,
    ) -> std::result::Result<PrecisionReceipt, &'static str> {
        self.validate_precision_challenge(challenge, purpose, client_binding)?;
        if !self.ticket_matches(challenge, ticket) {
            return Err("invalid_precision_ticket");
        }
        // Capture arrival before the store round trip: Redis latency must not
        // silently move an honest release outside its configured tolerance.
        let released_at_ms = self.clock.now_unix_ms();
        self.claim_precision("precision:release:", challenge)
            .await?;
        if !valid_duration(challenge, ticket.started_at_ms, released_at_ms) {
            return Err("precision_timing_mismatch");
        }
        let mut receipt = PrecisionReceipt {
            ticket: ticket.clone(),
            released_at_ms,
            sig: String::new(),
        };
        receipt.sig =
            self.sign_precision(RECEIPT_DOMAIN, &(&receipt.ticket, receipt.released_at_ms))?;
        Ok(receipt)
    }

    fn validate_precision_challenge(
        &self,
        challenge: &Challenge,
        purpose: Purpose,
        client_binding: &str,
    ) -> std::result::Result<(), &'static str> {
        let secret = self.secret.as_deref().ok_or(reasons::NOT_CONFIGURED)?;
        if self.clock.now_unix() >= challenge.params.expires_at {
            return Err(reasons::EXPIRED);
        }
        if !verify_params_signature(secret, challenge).unwrap_or(false) {
            return Err(reasons::INVALID_SIGNATURE);
        }
        if challenge.params.purpose != purpose {
            return Err(reasons::PURPOSE_MISMATCH);
        }
        if !bindings_match(&challenge.params.client_binding, client_binding) {
            return Err(reasons::CLIENT_BINDING_MISMATCH);
        }
        if challenge.params.precision.is_none() {
            return Err("precision_not_required");
        }
        if self.memo.is_spent(&challenge.params.id) {
            return Err(reasons::REPLAYED);
        }
        Ok(())
    }

    async fn claim_precision(
        &self,
        prefix: &str,
        challenge: &Challenge,
    ) -> std::result::Result<(), &'static str> {
        let remaining = (challenge.params.expires_at - self.clock.now_unix()).max(1) as u64;
        match self
            .store
            .consume_once(&format!("{prefix}{}", challenge.params.id), remaining)
            .await
        {
            Ok(true) => Ok(()),
            Ok(false) => Err(reasons::REPLAYED),
            Err(_) => Err(reasons::STORE_UNAVAILABLE),
        }
    }

    pub(super) fn verify_precision_receipt(
        &self,
        solution: &Solution,
    ) -> std::result::Result<(), &'static str> {
        match (
            &solution.challenge.params.precision,
            &solution.precision_receipt,
        ) {
            (None, None) => Ok(()),
            (Some(_), None) => Err("precision_receipt_required"),
            (None, Some(_)) => Err("invalid_precision_receipt"),
            (Some(_), Some(receipt)) => {
                let valid = self.ticket_matches(&solution.challenge, &receipt.ticket)
                    && self.precision_signature_matches(
                        RECEIPT_DOMAIN,
                        &(&receipt.ticket, receipt.released_at_ms),
                        &receipt.sig,
                    )
                    && receipt.released_at_ms <= self.clock.now_unix_ms()
                    && valid_duration(
                        &solution.challenge,
                        receipt.ticket.started_at_ms,
                        receipt.released_at_ms,
                    );
                if valid {
                    Ok(())
                } else {
                    Err("invalid_precision_receipt")
                }
            }
        }
    }

    fn ticket_matches(&self, challenge: &Challenge, ticket: &PrecisionTicket) -> bool {
        ticket.challenge_id == challenge.params.id
            && bindings_match(&ticket.challenge_sig, &challenge.sig)
            && ticket.purpose == challenge.params.purpose.as_str()
            && bindings_match(&ticket.client_binding, &challenge.params.client_binding)
            && self.precision_signature_matches(TICKET_DOMAIN, &ticket_payload(ticket), &ticket.sig)
    }

    fn precision_signature_matches<T: Serialize>(
        &self,
        domain: &[u8],
        payload: &T,
        signature: &str,
    ) -> bool {
        let Ok(expected) = self.sign_precision(domain, payload) else {
            return false;
        };
        bindings_match(&expected, signature)
    }

    fn sign_precision<T: Serialize>(
        &self,
        domain: &[u8],
        payload: &T,
    ) -> std::result::Result<String, &'static str> {
        let secret = self.secret.as_deref().ok_or(reasons::NOT_CONFIGURED)?;
        let canonical = serde_json::to_vec(payload).map_err(|_| reasons::INVALID_SIGNATURE)?;
        let mut mac = <SimpleHmac<Sha256> as Mac>::new_from_slice(secret)
            .map_err(|_| reasons::NOT_CONFIGURED)?;
        mac.update(domain);
        mac.update(&canonical);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }
}

fn ticket_payload(ticket: &PrecisionTicket) -> (&str, &str, &str, &str, u64) {
    (
        &ticket.challenge_id,
        &ticket.challenge_sig,
        &ticket.purpose,
        &ticket.client_binding,
        ticket.started_at_ms,
    )
}

fn valid_duration(challenge: &Challenge, started_at_ms: u64, released_at_ms: u64) -> bool {
    let Some(precision) = challenge.params.precision else {
        return false;
    };
    released_at_ms
        .checked_sub(started_at_ms)
        .is_some_and(|elapsed| {
            elapsed >= precision.hold_ms
                && precision
                    .hold_ms
                    .checked_add(precision.release_window_ms)
                    .is_some_and(|deadline| elapsed <= deadline)
        })
}
