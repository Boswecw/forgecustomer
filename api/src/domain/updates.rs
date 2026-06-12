//! Pure update-campaign eligibility helpers.
//!
//! The database decides ownership/state. This module keeps deterministic rollout and
//! version gates testable without I/O.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateValidationError {
    pub field: &'static str,
    pub message: &'static str,
}

fn err(field: &'static str, message: &'static str) -> UpdateValidationError {
    UpdateValidationError { field, message }
}

pub fn clean_update_platform(value: &str) -> Result<String, UpdateValidationError> {
    let value = value.trim();
    if matches!(value, "windows" | "linux" | "darwin") {
        Ok(value.to_string())
    } else {
        Err(err("target", "must be windows, linux, or darwin"))
    }
}

pub fn clean_update_architecture(value: &str) -> Result<String, UpdateValidationError> {
    let value = value.trim();
    if matches!(value, "x86_64" | "aarch64" | "i686" | "armv7") {
        Ok(value.to_string())
    } else {
        Err(err("arch", "must be x86_64, aarch64, i686, or armv7"))
    }
}

pub fn clean_update_package_format(value: Option<&str>) -> Result<String, UpdateValidationError> {
    let value = value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or("nsis");
    if value.len() > 40 {
        return Err(err("package_format", "must be at most 40 characters"));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err(err(
            "package_format",
            "must contain only letters, numbers, '.', '-', or '_'",
        ));
    }
    Ok(value.to_string())
}

pub fn clean_update_event_type(value: &str) -> Result<String, UpdateValidationError> {
    let value = value.trim();
    if matches!(
        value,
        "eligible"
            | "offered"
            | "download_started"
            | "downloaded"
            | "install_started"
            | "install_completed"
            | "relaunch_confirmed"
            | "post_update_health_passed"
            | "post_update_health_failed"
            | "rejected"
            | "failed"
            | "recovery_required"
    ) {
        Ok(value.to_string())
    } else {
        Err(err("event_type", "is not a supported update event type"))
    }
}

pub fn clean_update_failure_code(
    value: Option<&str>,
    field: &'static str,
) -> Result<Option<String>, UpdateValidationError> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if value.len() > 80 {
        return Err(err(field, "must be at most 80 characters"));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
    {
        return Err(err(
            field,
            "must contain only letters, numbers, '.', '-', '_', or ':'",
        ));
    }
    Ok(Some(value.to_string()))
}

pub fn rollout_bucket(
    secret: &str,
    campaign_id: Uuid,
    installation_id: Uuid,
) -> Result<u16, UpdateValidationError> {
    if secret.trim().is_empty() {
        return Err(err("update_rollout_secret", "is not configured"));
    }
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| err("update_rollout_secret", "is invalid"))?;
    mac.update(format!("{campaign_id}:{installation_id}").as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    Ok((u64::from_be_bytes(first) % 10_000) as u16)
}

pub fn rollout_allows(
    secret: &str,
    campaign_id: Uuid,
    installation_id: Uuid,
    rollout_percentage: i32,
) -> Result<bool, UpdateValidationError> {
    if secret.trim().is_empty() {
        return Err(err("update_rollout_secret", "is not configured"));
    }
    if rollout_percentage <= 0 {
        return Ok(false);
    }
    if rollout_percentage >= 100 {
        return Ok(true);
    }
    Ok(rollout_bucket(secret, campaign_id, installation_id)? < (rollout_percentage as u16 * 100))
}

pub fn version_greater(target: &str, current: &str) -> bool {
    match (version_parts(target), version_parts(current)) {
        (Some(target), Some(current)) => compare_parts(&target, &current).is_gt(),
        _ => false,
    }
}

pub fn version_at_least(value: &str, minimum: &str) -> bool {
    match (version_parts(value), version_parts(minimum)) {
        (Some(value), Some(minimum)) => !compare_parts(&value, &minimum).is_lt(),
        _ => false,
    }
}

fn version_parts(value: &str) -> Option<Vec<u64>> {
    let core = value
        .split(['-', '+'])
        .next()
        .map(str::trim)
        .filter(|v| !v.is_empty())?;
    let mut parts = Vec::new();
    for part in core.split('.') {
        parts.push(part.parse::<u64>().ok()?);
    }
    Some(parts)
}

fn compare_parts(left: &[u64], right: &[u64]) -> std::cmp::Ordering {
    let len = left.len().max(right.len()).max(3);
    for idx in 0..len {
        let l = left.get(idx).copied().unwrap_or(0);
        let r = right.get(idx).copied().unwrap_or(0);
        match l.cmp(&r) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    std::cmp::Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollout_bucket_matches_committed_vector() {
        let campaign_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let installation_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        assert_eq!(
            rollout_bucket("rollout-secret-test", campaign_id, installation_id).unwrap(),
            492
        );
        assert!(rollout_allows("rollout-secret-test", campaign_id, installation_id, 5).unwrap());
        assert!(!rollout_allows("rollout-secret-test", campaign_id, installation_id, 4).unwrap());
    }

    #[test]
    fn version_comparisons_fail_closed_on_unparseable_values() {
        assert!(version_greater("1.2.0", "1.1.9"));
        assert!(!version_greater("1.2.0", "1.2.0"));
        assert!(version_at_least("2.0", "2.0.0"));
        assert!(!version_at_least("1.9.9", "2.0.0"));
        assert!(!version_greater("release-candidate", "1.0.0"));
    }
}
