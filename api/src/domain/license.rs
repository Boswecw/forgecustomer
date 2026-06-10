//! Pure licensing rules: device-limit enforcement, offline-lease validity, and the
//! license-status transition driven by subscription truth.

use chrono::{DateTime, Utc};

use crate::domain::subscription::SubscriptionStatus;

/// Can a new device be activated given the current active count and the limit?
/// Fails closed: a zero limit denies activation.
pub fn can_activate_device(active_devices: u32, device_limit: u32) -> bool {
    active_devices < device_limit
}

/// Canonical license statuses (mirrors the `licenses.status` check constraint).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseStatus {
    Active,
    Suspended,
    Revoked,
    Expired,
}

impl LicenseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            LicenseStatus::Active => "active",
            LicenseStatus::Suspended => "suspended",
            LicenseStatus::Revoked => "revoked",
            LicenseStatus::Expired => "expired",
        }
    }

    /// Parse a stored status. Unknown strings fail closed to `Revoked` so the sync logic
    /// never mutates a row it does not understand.
    pub fn parse(raw: &str) -> LicenseStatus {
        match raw {
            "active" => LicenseStatus::Active,
            "suspended" => LicenseStatus::Suspended,
            "expired" => LicenseStatus::Expired,
            _ => LicenseStatus::Revoked,
        }
    }
}

/// Status transition to apply to a subscription-linked license.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseSyncAction {
    Issue,
    Reactivate,
    Suspend,
    Expire,
}

/// Decide how a subscription-linked license must change when subscription truth changes.
///
/// Rules:
/// - A cloud-granting subscription (active/trialing) issues a missing license and
///   reactivates a suspended/expired one.
/// - `past_due` is a dunning grace window: the license stays usable.
/// - `unpaid`, `paused`, and `incomplete` suspend the license (new activations fail
///   closed; local product access is never gated here).
/// - `canceled` expires the license.
/// - A revoked license is never changed by subscription state — revocation is an
///   explicit denial that must not silently lift.
pub fn license_sync_action(
    existing: Option<LicenseStatus>,
    subscription: SubscriptionStatus,
) -> Option<LicenseSyncAction> {
    use SubscriptionStatus as Sub;

    match existing {
        None => subscription
            .grants_cloud()
            .then_some(LicenseSyncAction::Issue),
        Some(LicenseStatus::Revoked) => None,
        Some(LicenseStatus::Active) => match subscription {
            Sub::Active | Sub::Trialing | Sub::PastDue => None,
            Sub::Canceled => Some(LicenseSyncAction::Expire),
            Sub::Unpaid | Sub::Paused | Sub::Incomplete => Some(LicenseSyncAction::Suspend),
        },
        Some(LicenseStatus::Suspended) => match subscription {
            Sub::Active | Sub::Trialing => Some(LicenseSyncAction::Reactivate),
            Sub::Canceled => Some(LicenseSyncAction::Expire),
            Sub::PastDue | Sub::Unpaid | Sub::Paused | Sub::Incomplete => None,
        },
        Some(LicenseStatus::Expired) => match subscription {
            Sub::Active | Sub::Trialing => Some(LicenseSyncAction::Reactivate),
            _ => None,
        },
    }
}

/// Reasons a lease may be invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseInvalidReason {
    Expired,
    Revoked,
    OutsideGrace,
}

/// Validate an offline lease at evaluation time `now`. A lease is valid if it has not
/// expired, is not revoked, and `now` is within the offline grace window beyond expiry.
///
/// `grace_seconds` extends usability past `expires_at` so brief connectivity gaps do not
/// block cloud features, while revocation still denies immediately.
pub fn validate_lease(
    expires_at: DateTime<Utc>,
    revoked: bool,
    now: DateTime<Utc>,
    grace_seconds: i64,
) -> Result<(), LeaseInvalidReason> {
    if revoked {
        return Err(LeaseInvalidReason::Revoked);
    }
    if now <= expires_at {
        return Ok(());
    }
    let grace_end = expires_at + chrono::Duration::seconds(grace_seconds);
    if now <= grace_end {
        Ok(())
    } else {
        Err(LeaseInvalidReason::OutsideGrace)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn t(s: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(s, 0).single().unwrap()
    }

    #[test]
    fn enforces_device_limit() {
        assert!(can_activate_device(0, 1));
        assert!(can_activate_device(2, 3));
        assert!(!can_activate_device(3, 3));
        assert!(!can_activate_device(0, 0)); // fails closed
    }

    #[test]
    fn lease_valid_before_expiry() {
        assert!(validate_lease(t(1000), false, t(500), 3600).is_ok());
    }

    #[test]
    fn lease_within_grace_is_valid() {
        // expired at 1000, now 1500, grace 3600 => ok
        assert!(validate_lease(t(1000), false, t(1500), 3600).is_ok());
    }

    #[test]
    fn lease_outside_grace_invalid() {
        let r = validate_lease(t(1000), false, t(5000), 3600);
        assert_eq!(r, Err(LeaseInvalidReason::OutsideGrace));
    }

    #[test]
    fn revoked_lease_denied_even_before_expiry() {
        let r = validate_lease(t(1000), true, t(500), 3600);
        assert_eq!(r, Err(LeaseInvalidReason::Revoked));
    }

    #[test]
    fn cloud_granting_subscription_issues_missing_license() {
        assert_eq!(
            license_sync_action(None, SubscriptionStatus::Active),
            Some(LicenseSyncAction::Issue)
        );
        assert_eq!(
            license_sync_action(None, SubscriptionStatus::Trialing),
            Some(LicenseSyncAction::Issue)
        );
        // Non-granting statuses never issue.
        for status in [
            SubscriptionStatus::PastDue,
            SubscriptionStatus::Unpaid,
            SubscriptionStatus::Canceled,
            SubscriptionStatus::Incomplete,
            SubscriptionStatus::Paused,
        ] {
            assert_eq!(license_sync_action(None, status), None);
        }
    }

    #[test]
    fn active_license_follows_subscription_truth() {
        let active = Some(LicenseStatus::Active);
        assert_eq!(
            license_sync_action(active, SubscriptionStatus::Active),
            None
        );
        // Dunning grace: past_due keeps the license usable.
        assert_eq!(
            license_sync_action(active, SubscriptionStatus::PastDue),
            None
        );
        assert_eq!(
            license_sync_action(active, SubscriptionStatus::Unpaid),
            Some(LicenseSyncAction::Suspend)
        );
        assert_eq!(
            license_sync_action(active, SubscriptionStatus::Paused),
            Some(LicenseSyncAction::Suspend)
        );
        assert_eq!(
            license_sync_action(active, SubscriptionStatus::Canceled),
            Some(LicenseSyncAction::Expire)
        );
    }

    #[test]
    fn suspended_and_expired_licenses_reactivate_on_good_standing() {
        assert_eq!(
            license_sync_action(Some(LicenseStatus::Suspended), SubscriptionStatus::Active),
            Some(LicenseSyncAction::Reactivate)
        );
        assert_eq!(
            license_sync_action(Some(LicenseStatus::Expired), SubscriptionStatus::Trialing),
            Some(LicenseSyncAction::Reactivate)
        );
        assert_eq!(
            license_sync_action(Some(LicenseStatus::Suspended), SubscriptionStatus::Canceled),
            Some(LicenseSyncAction::Expire)
        );
        assert_eq!(
            license_sync_action(Some(LicenseStatus::Expired), SubscriptionStatus::Canceled),
            None
        );
    }

    #[test]
    fn revoked_license_never_changes_from_subscription_state() {
        for status in [
            SubscriptionStatus::Active,
            SubscriptionStatus::Trialing,
            SubscriptionStatus::PastDue,
            SubscriptionStatus::Unpaid,
            SubscriptionStatus::Canceled,
            SubscriptionStatus::Incomplete,
            SubscriptionStatus::Paused,
        ] {
            assert_eq!(
                license_sync_action(Some(LicenseStatus::Revoked), status),
                None
            );
        }
    }

    #[test]
    fn unknown_license_status_fails_closed_to_revoked() {
        assert_eq!(LicenseStatus::parse("wat"), LicenseStatus::Revoked);
        assert_eq!(LicenseStatus::parse("active"), LicenseStatus::Active);
        assert_eq!(LicenseStatus::parse("suspended"), LicenseStatus::Suspended);
        assert_eq!(LicenseStatus::parse("expired"), LicenseStatus::Expired);
    }
}
