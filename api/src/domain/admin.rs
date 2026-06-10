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
