//! Subscription status normalization. Stripe status strings are mapped into the
//! ForgeCustomer canonical set. Unknown statuses fail closed to `incomplete`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Trialing,
    Active,
    PastDue,
    Unpaid,
    Canceled,
    Incomplete,
    Paused,
}

impl SubscriptionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SubscriptionStatus::Trialing => "trialing",
            SubscriptionStatus::Active => "active",
            SubscriptionStatus::PastDue => "past_due",
            SubscriptionStatus::Unpaid => "unpaid",
            SubscriptionStatus::Canceled => "canceled",
            SubscriptionStatus::Incomplete => "incomplete",
            SubscriptionStatus::Paused => "paused",
        }
    }

    /// Does this status entitle the customer to *cloud* features?
    /// Trialing and active grant cloud; everything else does not. Local product access is
    /// evaluated separately and is never gated by this.
    pub fn grants_cloud(self) -> bool {
        matches!(
            self,
            SubscriptionStatus::Trialing | SubscriptionStatus::Active
        )
    }
}

/// Normalize a raw Stripe subscription status into the canonical set.
/// Unknown/empty input fails closed to `Incomplete`.
pub fn normalize_stripe_status(raw: &str) -> SubscriptionStatus {
    match raw {
        "trialing" => SubscriptionStatus::Trialing,
        "active" => SubscriptionStatus::Active,
        "past_due" => SubscriptionStatus::PastDue,
        "unpaid" => SubscriptionStatus::Unpaid,
        "canceled" => SubscriptionStatus::Canceled,
        "incomplete" => SubscriptionStatus::Incomplete,
        // Stripe's terminal "incomplete_expired" collapses to canceled.
        "incomplete_expired" => SubscriptionStatus::Canceled,
        "paused" => SubscriptionStatus::Paused,
        _ => SubscriptionStatus::Incomplete,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_statuses() {
        assert_eq!(
            normalize_stripe_status("active"),
            SubscriptionStatus::Active
        );
        assert_eq!(
            normalize_stripe_status("trialing"),
            SubscriptionStatus::Trialing
        );
        assert_eq!(
            normalize_stripe_status("past_due"),
            SubscriptionStatus::PastDue
        );
        assert_eq!(
            normalize_stripe_status("paused"),
            SubscriptionStatus::Paused
        );
    }

    #[test]
    fn incomplete_expired_collapses_to_canceled() {
        assert_eq!(
            normalize_stripe_status("incomplete_expired"),
            SubscriptionStatus::Canceled
        );
    }

    #[test]
    fn unknown_fails_closed_to_incomplete() {
        assert_eq!(normalize_stripe_status(""), SubscriptionStatus::Incomplete);
        assert_eq!(
            normalize_stripe_status("wat"),
            SubscriptionStatus::Incomplete
        );
    }

    #[test]
    fn only_active_and_trialing_grant_cloud() {
        assert!(SubscriptionStatus::Active.grants_cloud());
        assert!(SubscriptionStatus::Trialing.grants_cloud());
        for s in [
            SubscriptionStatus::PastDue,
            SubscriptionStatus::Unpaid,
            SubscriptionStatus::Canceled,
            SubscriptionStatus::Incomplete,
            SubscriptionStatus::Paused,
        ] {
            assert!(!s.grants_cloud(), "{:?} must not grant cloud", s);
        }
    }
}
