//! Privacy-preserving human-evidence policy.
//!
//! These signals are only friction against unsophisticated automation. They
//! are never treated as identity because JavaScript clients can forge them.

use crate::challenge::Evidence;

/// Human-evidence scoring modes selected by deployment or application policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceMode {
    /// Ignore optional browser evidence.
    Off,
    /// Reject explicitly bot-like evidence while accepting absent evidence.
    Lenient,
    /// Require at least one coarse browser interaction/focus signal.
    Strict,
}

impl EvidenceMode {
    pub fn parse(raw: &str) -> Result<Self, &'static str> {
        match raw.to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "lenient" => Ok(Self::Lenient),
            "strict" => Ok(Self::Strict),
            _ => Err("evidence mode must be off, lenient, or strict"),
        }
    }

    pub(crate) fn accepts(self, evidence: &Option<Evidence>) -> bool {
        match self {
            Self::Off => true,
            Self::Lenient => evidence
                .as_ref()
                .is_none_or(|value| value.interactions > 0 || value.focus),
            Self::Strict => evidence
                .as_ref()
                .is_some_and(|value| value.interactions > 0 || value.focus),
        }
    }
}
