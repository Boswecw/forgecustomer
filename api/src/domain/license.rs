//! Pure licensing rules: device-limit enforcement and offline-lease validity.

use chrono::{DateTime, Utc};

/// Can a new device be activated given the current active count and the limit?
/// Fails closed: a zero limit denies activation.
pub fn can_activate_device(active_devices: u32, device_limit: u32) -> bool {
    active_devices < device_limit
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
}
