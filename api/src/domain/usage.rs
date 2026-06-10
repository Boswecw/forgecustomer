//! Quota decision logic. Pure and explainable: given current usage, reservations and a
//! limit, decide whether a requested amount fits.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaDecision {
    pub decision: Decision,
    pub reason: String,
    pub remaining_before: f64,
}

/// Decide whether `requested` units fit within `limit`, given already `used` and currently
/// `reserved` units. A `None` limit means unlimited. Negative requests are rejected.
pub fn decide(requested: f64, used: f64, reserved: f64, limit: Option<f64>) -> QuotaDecision {
    if requested < 0.0 {
        return QuotaDecision {
            decision: Decision::Deny,
            reason: "negative request".to_string(),
            remaining_before: 0.0,
        };
    }
    match limit {
        None => QuotaDecision {
            decision: Decision::Allow,
            reason: "unlimited meter".to_string(),
            remaining_before: f64::INFINITY,
        },
        Some(limit) => {
            let remaining = limit - used - reserved;
            if requested <= remaining {
                QuotaDecision {
                    decision: Decision::Allow,
                    reason: "within quota".to_string(),
                    remaining_before: remaining,
                }
            } else {
                QuotaDecision {
                    decision: Decision::Deny,
                    reason: format!(
                        "requested {} exceeds remaining {} (limit {}, used {}, reserved {})",
                        requested, remaining, limit, used, reserved
                    ),
                    remaining_before: remaining,
                }
            }
        }
    }
}

/// Rebuild a period total from a ledger of signed amounts (commits + compensations).
pub fn rebuild_total(amounts: &[f64]) -> f64 {
    amounts.iter().sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_within_quota() {
        let d = decide(100.0, 800.0, 50.0, Some(1000.0));
        assert_eq!(d.decision, Decision::Allow);
    }

    #[test]
    fn denies_over_quota_counting_reservations() {
        let d = decide(200.0, 800.0, 50.0, Some(1000.0));
        assert_eq!(d.decision, Decision::Deny);
    }

    #[test]
    fn exact_fit_allowed() {
        let d = decide(150.0, 800.0, 50.0, Some(1000.0));
        assert_eq!(d.decision, Decision::Allow);
    }

    #[test]
    fn unlimited_meter_always_allows() {
        assert_eq!(decide(1e9, 0.0, 0.0, None).decision, Decision::Allow);
    }

    #[test]
    fn negative_request_denied() {
        assert_eq!(decide(-1.0, 0.0, 0.0, Some(10.0)).decision, Decision::Deny);
    }

    #[test]
    fn totals_rebuild_with_compensations() {
        // commit 100, commit 50, compensation -30 => 120
        assert_eq!(rebuild_total(&[100.0, 50.0, -30.0]), 120.0);
    }
}
