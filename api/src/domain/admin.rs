//! Pure validation for operator/admin mutations (consumed by Forge Command through the
//! `/v1/admin/*` surface). Every admin mutation requires a written reason; values are
//! bounded so a compromised operator token cannot write absurd commercial state.

use chrono::{Datelike, Utc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminValidationError {
    pub field: &'static str,
    pub message: &'static str,
}

fn err(field: &'static str, message: &'static str) -> AdminValidationError {
    AdminValidationError { field, message }
}

/// Every admin mutation carries a human-written reason that lands in the audit trail.
pub fn clean_reason(value: &str) -> Result<String, AdminValidationError> {
    let value = value.trim();
    if value.len() < 3 {
        return Err(err("reason", "must be at least 3 characters"));
    }
    if value.len() > 500 {
        return Err(err("reason", "must be at most 500 characters"));
    }
    if value.chars().any(char::is_control) {
        return Err(err("reason", "must not contain control characters"));
    }
    Ok(value.to_string())
}

pub fn clean_optional_display_name(
    value: Option<&str>,
) -> Result<Option<String>, AdminValidationError> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => {
            if value.len() > 120 {
                return Err(err("display_name", "must be at most 120 characters"));
            }
            if value.chars().any(char::is_control) {
                return Err(err("display_name", "must not contain control characters"));
            }
            Ok(Some(value.to_string()))
        }
        None => Ok(None),
    }
}

pub fn clean_update_ring(value: &str) -> Result<String, AdminValidationError> {
    let value = value.trim();
    if matches!(value, "canary" | "preview" | "standard" | "delayed") {
        Ok(value.to_string())
    } else {
        Err(err(
            "update_ring",
            "must be canary, preview, standard, or delayed",
        ))
    }
}

pub fn clean_release_channel_key(value: &str) -> Result<String, AdminValidationError> {
    let value = value.trim();
    if value.len() < 2 || value.len() > 40 {
        return Err(err("release_channel", "must be 2-40 characters"));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err(err(
            "release_channel",
            "must contain lowercase letters, digits, hyphen, or underscore",
        ));
    }
    Ok(value.to_string())
}

pub fn clean_campaign_slug(value: &str) -> Result<String, AdminValidationError> {
    let value = value.trim();
    let bytes = value.as_bytes();
    let valid_start = bytes
        .first()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let valid_body = bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-');
    if (3..=80).contains(&bytes.len()) && valid_start && valid_body {
        Ok(value.to_string())
    } else {
        Err(err(
            "campaign_slug",
            "must be 3-80 lowercase letters, digits, hyphen, or underscore",
        ))
    }
}

pub fn clean_rollout_percentage(value: i64) -> Result<i32, AdminValidationError> {
    if !(0..=100).contains(&value) {
        return Err(err("rollout_percentage", "must be between 0 and 100"));
    }
    i32::try_from(value).map_err(|_| err("rollout_percentage", "must be between 0 and 100"))
}

pub fn clean_release_version(value: &str) -> Result<String, AdminValidationError> {
    let value = value.trim();
    if value.len() > 64 {
        return Err(err("version", "must be at most 64 characters"));
    }
    let mut parts = value.split(['-', '+']);
    let core = parts.next().unwrap_or_default();
    let nums: Vec<&str> = core.split('.').collect();
    if nums.len() != 3 || nums.iter().any(|part| part.is_empty()) {
        return Err(err("version", "must be SemVer major.minor.patch"));
    }
    if nums.iter().any(|part| part.parse::<u64>().is_err()) {
        return Err(err("version", "must be SemVer major.minor.patch"));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
    {
        return Err(err(
            "version",
            "must contain only letters, numbers, '.', '-', '_', or '+'",
        ));
    }
    Ok(value.to_string())
}

pub fn clean_build_id(value: &str) -> Result<String, AdminValidationError> {
    let value = value.trim();
    if value.len() < 3 || value.len() > 120 {
        return Err(err("build_id", "must be 3-120 characters"));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
    {
        return Err(err(
            "build_id",
            "must contain only letters, numbers, '.', '-', '_', or ':'",
        ));
    }
    Ok(value.to_string())
}

pub fn clean_optional_markdown(
    value: Option<&str>,
    field: &'static str,
    max_len: usize,
) -> Result<Option<String>, AdminValidationError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.len() > max_len {
        return Err(err(field, "is too long"));
    }
    if value
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    {
        return Err(err(field, "must not contain control characters"));
    }
    Ok(Some(value.to_string()))
}

pub fn clean_artifact_role(value: &str) -> Result<String, AdminValidationError> {
    let value = value.trim();
    if matches!(value, "bootstrap" | "updater" | "recovery") {
        Ok(value.to_string())
    } else {
        Err(err(
            "artifact_role",
            "must be bootstrap, updater, or recovery",
        ))
    }
}

pub fn clean_artifact_platform(value: &str) -> Result<String, AdminValidationError> {
    let value = value.trim();
    if matches!(value, "windows" | "linux" | "darwin") {
        Ok(value.to_string())
    } else {
        Err(err("platform", "must be windows, linux, or darwin"))
    }
}

pub fn clean_artifact_architecture(value: &str) -> Result<String, AdminValidationError> {
    let value = value.trim();
    if matches!(value, "x86_64" | "aarch64" | "i686" | "armv7") {
        Ok(value.to_string())
    } else {
        Err(err(
            "architecture",
            "must be x86_64, aarch64, i686, or armv7",
        ))
    }
}

pub fn clean_package_format(value: &str) -> Result<String, AdminValidationError> {
    let value = value.trim();
    if value.len() > 40 {
        return Err(err("package_format", "must be at most 40 characters"));
    }
    if value.is_empty()
        || !value
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

pub fn clean_storage_key(value: &str) -> Result<String, AdminValidationError> {
    let value = value.trim();
    if value.len() < 3 || value.len() > 512 {
        return Err(err("storage_key", "must be 3-512 characters"));
    }
    if value.contains("..") || value.chars().any(char::is_control) {
        return Err(err("storage_key", "must be a bounded immutable object key"));
    }
    Ok(value.to_string())
}

pub fn clean_sha256(value: &str) -> Result<String, AdminValidationError> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(value)
    } else {
        Err(err("sha256", "must be a lowercase 64-character hex digest"))
    }
}

pub fn clean_signing_key_id(value: &str) -> Result<String, AdminValidationError> {
    let value = value.trim();
    if value.len() < 3 || value.len() > 120 {
        return Err(err("signing_key_id", "must be 3-120 characters"));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
    {
        return Err(err(
            "signing_key_id",
            "must contain only letters, numbers, '.', '-', '_', or ':'",
        ));
    }
    Ok(value.to_string())
}

pub fn clean_tauri_signature(value: Option<&str>) -> Result<Option<String>, AdminValidationError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.len() > 2048 {
        return Err(err("tauri_signature", "must be at most 2048 characters"));
    }
    if value.chars().any(char::is_control) {
        return Err(err(
            "tauri_signature",
            "must not contain control characters",
        ));
    }
    Ok(Some(value.to_string()))
}

pub fn clean_os_signature_status(value: &str) -> Result<String, AdminValidationError> {
    let value = value.trim();
    if matches!(value, "verified" | "not_applicable") {
        Ok(value.to_string())
    } else {
        Err(err(
            "os_signature_status",
            "must be verified or not_applicable for validated artifact registration",
        ))
    }
}

pub fn clean_size_bytes(value: i64) -> Result<i64, AdminValidationError> {
    if value <= 0 {
        return Err(err("size_bytes", "must be positive"));
    }
    Ok(value)
}

/// Device limit for operator-issued licenses. Defaults to a single device; bounded so a
/// typo cannot issue an effectively unlimited license.
pub fn clean_device_limit(value: Option<i64>) -> Result<i32, AdminValidationError> {
    let value = value.unwrap_or(1);
    if !(0..=10_000).contains(&value) {
        return Err(err("device_limit", "must be between 0 and 10000"));
    }
    i32::try_from(value).map_err(|_| err("device_limit", "must be between 0 and 10000"))
}

/// Usage adjustments are signed compensating amounts on the append-only ledger.
pub fn clean_adjustment_amount(value: f64) -> Result<f64, AdminValidationError> {
    if !value.is_finite() {
        return Err(err("amount", "must be a finite number"));
    }
    if value == 0.0 {
        return Err(err("amount", "must be non-zero"));
    }
    if value.abs() > 1e12 {
        return Err(err("amount", "must be at most 1e12 in magnitude"));
    }
    Ok(value)
}

/// Usage period key (`YYYY-MM`); defaults to the current UTC month.
pub fn clean_period_key(value: Option<&str>) -> Result<String, AdminValidationError> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(Utc::now().format("%Y-%m").to_string());
    };
    let bytes = value.as_bytes();
    let well_formed = bytes.len() == 7
        && bytes[4] == b'-'
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[5..].iter().all(u8::is_ascii_digit);
    if !well_formed {
        return Err(err("period_key", "must have the form YYYY-MM"));
    }
    let month: u32 = value[5..]
        .parse()
        .map_err(|_| err("period_key", "must have the form YYYY-MM"))?;
    let year: i32 = value[..4]
        .parse()
        .map_err(|_| err("period_key", "must have the form YYYY-MM"))?;
    if !(1..=12).contains(&month) {
        return Err(err("period_key", "month must be between 01 and 12"));
    }
    // Adjustments target recent history, not the far past/future.
    let current_year = Utc::now().year();
    if !((current_year - 5)..=(current_year + 1)).contains(&year) {
        return Err(err("period_key", "year is outside the adjustable window"));
    }
    Ok(value.to_string())
}

/// A typed override/grant value as stored in the bool/number/string value columns.
#[derive(Debug, Clone, PartialEq)]
pub enum OverrideValue {
    Bool(bool),
    Number(f64),
    Text(String),
}

impl OverrideValue {
    pub fn columns(&self) -> (Option<bool>, Option<f64>, Option<&str>) {
        match self {
            OverrideValue::Bool(value) => (Some(*value), None, None),
            OverrideValue::Number(value) => (None, Some(*value), None),
            OverrideValue::Text(value) => (None, None, Some(value.as_str())),
        }
    }
}

/// Parse an override value from request JSON: boolean, finite number, or short string.
pub fn clean_override_value(
    value: &serde_json::Value,
) -> Result<OverrideValue, AdminValidationError> {
    match value {
        serde_json::Value::Bool(value) => Ok(OverrideValue::Bool(*value)),
        serde_json::Value::Number(number) => {
            let number = number
                .as_f64()
                .filter(|number| number.is_finite())
                .ok_or_else(|| err("value", "must be a finite number"))?;
            Ok(OverrideValue::Number(number))
        }
        serde_json::Value::String(text) => {
            let text = text.trim();
            if text.is_empty() || text.len() > 200 {
                return Err(err("value", "must be 1-200 characters"));
            }
            Ok(OverrideValue::Text(text.to_string()))
        }
        _ => Err(err("value", "must be a boolean, number, or string")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reasons_are_required_and_bounded() {
        assert_eq!(clean_reason("  refund abuse  ").unwrap(), "refund abuse");
        assert!(clean_reason("ab").is_err());
        assert!(clean_reason(&"x".repeat(501)).is_err());
        assert!(clean_reason("bad\u{7}reason").is_err());
    }

    #[test]
    fn fleet_and_campaign_controls_are_bounded() {
        assert_eq!(
            clean_optional_display_name(Some("  Stable fleet ")).unwrap(),
            Some("Stable fleet".to_string())
        );
        assert!(clean_optional_display_name(Some(&"x".repeat(121))).is_err());
        assert_eq!(clean_update_ring("standard").unwrap(), "standard");
        assert!(clean_update_ring("prod").is_err());
        assert_eq!(clean_release_channel_key("stable").unwrap(), "stable");
        assert!(clean_release_channel_key("Stable").is_err());
        assert_eq!(
            clean_campaign_slug("authorforge-1-0-1").unwrap(),
            "authorforge-1-0-1"
        );
        assert!(clean_campaign_slug("-bad").is_err());
        assert_eq!(clean_rollout_percentage(10).unwrap(), 10);
        assert!(clean_rollout_percentage(101).is_err());
    }

    #[test]
    fn release_and_artifact_controls_are_bounded() {
        assert_eq!(clean_release_version("1.2.3").unwrap(), "1.2.3");
        assert!(clean_release_version("1.2").is_err());
        assert_eq!(clean_build_id("20260612.abcd").unwrap(), "20260612.abcd");
        assert!(clean_build_id("../bad").is_err());
        assert_eq!(clean_artifact_role("bootstrap").unwrap(), "bootstrap");
        assert!(clean_artifact_role("installer").is_err());
        assert_eq!(clean_artifact_platform("linux").unwrap(), "linux");
        assert_eq!(clean_artifact_architecture("x86_64").unwrap(), "x86_64");
        assert_eq!(clean_package_format("appimage").unwrap(), "appimage");
        assert!(clean_storage_key("../secret").is_err());
        assert_eq!(clean_size_bytes(42).unwrap(), 42);
        assert!(clean_size_bytes(0).is_err());
        assert_eq!(clean_sha256(&"A".repeat(64)).unwrap(), "a".repeat(64));
        assert!(clean_sha256("not-a-digest").is_err());
        assert_eq!(clean_signing_key_id("tauri-key-1").unwrap(), "tauri-key-1");
        assert_eq!(
            clean_tauri_signature(Some("sig")).unwrap(),
            Some("sig".to_string())
        );
        assert_eq!(clean_os_signature_status("verified").unwrap(), "verified");
        assert!(clean_os_signature_status("pending").is_err());
    }

    #[test]
    fn device_limit_defaults_and_bounds() {
        assert_eq!(clean_device_limit(None).unwrap(), 1);
        assert_eq!(clean_device_limit(Some(25)).unwrap(), 25);
        assert!(clean_device_limit(Some(-1)).is_err());
        assert!(clean_device_limit(Some(10_001)).is_err());
    }

    #[test]
    fn adjustment_amounts_are_finite_nonzero_and_bounded() {
        assert_eq!(clean_adjustment_amount(-250.0).unwrap(), -250.0);
        assert!(clean_adjustment_amount(0.0).is_err());
        assert!(clean_adjustment_amount(f64::NAN).is_err());
        assert!(clean_adjustment_amount(f64::INFINITY).is_err());
        assert!(clean_adjustment_amount(1e13).is_err());
    }

    #[test]
    fn period_keys_default_and_validate() {
        let current = Utc::now().format("%Y-%m").to_string();
        assert_eq!(clean_period_key(None).unwrap(), current);
        assert_eq!(clean_period_key(Some(&current)).unwrap(), current);
        assert!(clean_period_key(Some("2026-13")).is_err());
        assert!(clean_period_key(Some("2026-1")).is_err());
        assert!(clean_period_key(Some("1999-06")).is_err()); // outside window
        assert!(clean_period_key(Some("not-a-period")).is_err());
    }

    #[test]
    fn override_values_are_typed_and_bounded() {
        assert_eq!(
            clean_override_value(&json!(true)).unwrap(),
            OverrideValue::Bool(true)
        );
        assert_eq!(
            clean_override_value(&json!(10)).unwrap(),
            OverrideValue::Number(10.0)
        );
        assert_eq!(
            clean_override_value(&json!("beta")).unwrap(),
            OverrideValue::Text("beta".to_string())
        );
        assert!(clean_override_value(&json!(null)).is_err());
        assert!(clean_override_value(&json!([1])).is_err());
        assert!(clean_override_value(&json!("")).is_err());
    }
}
