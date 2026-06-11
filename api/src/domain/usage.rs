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

/// Validate a customer-requested usage amount: strictly positive, finite, bounded.
/// (Negative amounts are compensating events and exist only on the admin path.)
pub fn clean_usage_amount(value: f64) -> Result<f64, &'static str> {
    if !value.is_finite() {
        return Err("must be a finite number");
    }
    if value <= 0.0 {
        return Err("must be greater than zero");
    }
    if value > 1e12 {
        return Err("must be at most 1e12");
    }
    Ok(value)
}

/// The period key a meter accrues into right now: `YYYY-MM` for monthly cadence,
/// `YYYY-MM-DD` for daily, and the constant `all` for meters that never reset.
pub fn period_key_for(cadence: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    match cadence {
        "monthly" => now.format("%Y-%m").to_string(),
        "daily" => now.format("%Y-%m-%d").to_string(),
        _ => "all".to_string(),
    }
}

/// Quota-limit keys to look up for a meter, in precedence order: the cadence-qualified
/// key used by plan quotas (`cloud_tokens.monthly`), then the bare meter key.
pub fn quota_key_candidates(meter_key: &str, cadence: &str) -> [String; 2] {
    [format!("{meter_key}.{cadence}"), meter_key.to_string()]
}

/// Which configured thresholds (percent of limit) did this commit cross?
/// A threshold is crossed when usage moves from below it to at-or-above it. A
/// non-positive limit can never emit thresholds.
pub fn crossed_thresholds(
    used_before: f64,
    used_after: f64,
    limit: Option<f64>,
    percents: &[u8],
) -> Vec<u8> {
    let Some(limit) = limit.filter(|limit| *limit > 0.0) else {
        return Vec::new();
    };
    percents
        .iter()
        .copied()
        .filter(|pct| {
            let mark = limit * f64::from(*pct) / 100.0;
            used_before < mark && used_after >= mark
        })
        .collect()
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

    #[test]
    fn usage_amounts_are_positive_finite_and_bounded() {
        assert_eq!(clean_usage_amount(250.0), Ok(250.0));
        assert!(clean_usage_amount(0.0).is_err());
        assert!(clean_usage_amount(-1.0).is_err());
        assert!(clean_usage_amount(f64::NAN).is_err());
        assert!(clean_usage_amount(f64::INFINITY).is_err());
        assert!(clean_usage_amount(1e13).is_err());
    }

    #[test]
    fn period_keys_follow_cadence() {
        use chrono::TimeZone;
        let now = chrono::Utc.with_ymd_and_hms(2026, 6, 10, 12, 0, 0).unwrap();
        assert_eq!(period_key_for("monthly", now), "2026-06");
        assert_eq!(period_key_for("daily", now), "2026-06-10");
        assert_eq!(period_key_for("never", now), "all");
        assert_eq!(period_key_for("unknown", now), "all");
    }

    #[test]
    fn quota_key_candidates_prefer_cadence_qualified() {
        let [first, second] = quota_key_candidates("cloud_tokens", "monthly");
        assert_eq!(first, "cloud_tokens.monthly");
        assert_eq!(second, "cloud_tokens");
    }

    #[test]
    fn thresholds_fire_exactly_when_crossed() {
        let pcts = [80, 100];
        // Crossing 80% only.
        assert_eq!(
            crossed_thresholds(700.0, 850.0, Some(1000.0), &pcts),
            vec![80]
        );
        // Crossing both in one commit.
        assert_eq!(
            crossed_thresholds(700.0, 1000.0, Some(1000.0), &pcts),
            vec![80, 100]
        );
        // Already past: no re-fire.
        assert_eq!(
            crossed_thresholds(850.0, 900.0, Some(1000.0), &pcts),
            Vec::<u8>::new()
        );
        // Unlimited or zero limits never fire.
        assert_eq!(crossed_thresholds(0.0, 1e9, None, &pcts), Vec::<u8>::new());
        assert_eq!(
            crossed_thresholds(0.0, 10.0, Some(0.0), &pcts),
            Vec::<u8>::new()
        );
    }
}
