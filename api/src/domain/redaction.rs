//! Redaction for outbox payloads and audit before/after states. Outbox events must never
//! carry PII, secrets, or creative content (see `docs/SECURITY.md`).

use serde_json::Value;

/// Keys that must never appear in a sanitized outbox payload.
pub const PROHIBITED_KEYS: &[&str] = &[
    "email",
    "full_name",
    "name",
    "display_name",
    "stripe_customer_id",
    "payment_method",
    "card",
    "raw_payload",
    "password",
    "session",
    "refresh_token",
    "access_token",
    "manuscript",
    "prompt",
    "content",
];

/// Recursively remove prohibited keys from a JSON value, returning a sanitized clone.
pub fn sanitize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if PROHIBITED_KEYS.contains(&k.as_str()) {
                    continue;
                }
                out.insert(k.clone(), sanitize(v));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(sanitize).collect()),
        other => other.clone(),
    }
}

/// True if the value contains any prohibited key at any depth. Used by tests/guards.
pub fn contains_prohibited(value: &Value) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(k, v)| PROHIBITED_KEYS.contains(&k.as_str()) || contains_prohibited(v)),
        Value::Array(items) => items.iter().any(contains_prohibited),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn strips_pii_and_secrets_recursively() {
        let input = json!({
            "customer_id": "cust_1",
            "email": "a@b.com",
            "nested": { "stripe_customer_id": "cus_x", "status": "active" },
            "list": [ { "prompt": "secret text", "keep": 1 } ]
        });
        let out = sanitize(&input);
        assert!(!contains_prohibited(&out));
        assert_eq!(out["customer_id"], json!("cust_1"));
        assert_eq!(out["nested"]["status"], json!("active"));
        assert_eq!(out["list"][0]["keep"], json!(1));
        assert!(out.get("email").is_none());
        assert!(out["nested"].get("stripe_customer_id").is_none());
    }

    #[test]
    fn detects_prohibited_keys() {
        assert!(contains_prohibited(&json!({ "email": "x" })));
        assert!(!contains_prohibited(&json!({ "customer_id": "x" })));
    }
}
