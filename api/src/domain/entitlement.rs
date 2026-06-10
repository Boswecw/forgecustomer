//! Deterministic entitlement evaluation.
//!
//! Precedence (lowest → highest), per `docs/ENTITLEMENTS.md`:
//!   product defaults → plan version → active subscription → license grants →
//!   promotional grants → admin overrides → suspension/revocation rules.
//!
//! Suspension/revocation always denies cloud capabilities regardless of upstream grants.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A typed feature value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FeatureValue {
    Bool(bool),
    Number(f64),
    Text(String),
}

/// Inputs to evaluation, gathered from repositories. Each layer is a map of feature key →
/// value. Later layers override earlier ones.
#[derive(Debug, Default, Clone)]
pub struct EntitlementInputs {
    pub product_defaults: BTreeMap<String, FeatureValue>,
    pub plan_version: BTreeMap<String, FeatureValue>,
    pub license_grants: BTreeMap<String, FeatureValue>,
    pub promotional_grants: BTreeMap<String, FeatureValue>,
    pub admin_overrides: BTreeMap<String, FeatureValue>,
    /// Quota limits (meter key → limit) sourced from the plan version + grants.
    pub quota_limits: BTreeMap<String, f64>,
    /// Whether the active subscription grants cloud features.
    pub subscription_grants_cloud: bool,
    /// Hard denials: customer suspended or license revoked.
    pub suspended: bool,
    pub revoked: bool,
}

/// The computed entitlement result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntitlementResult {
    pub features: BTreeMap<String, FeatureValue>,
    pub quotas: BTreeMap<String, f64>,
}

/// Feature keys whose truth depends on an active subscription (cloud capabilities).
/// These are forced off when the subscription does not grant cloud, or on suspension /
/// revocation. Local capabilities are never in this set.
fn is_cloud_feature(key: &str) -> bool {
    key.ends_with(".cloud.enabled")
        || key.ends_with(".deep_analysis.enabled")
        || key.ends_with(".premium.enabled")
}

/// Validate a customer-supplied feature/quota key for the check endpoint: dotted
/// lowercase identifiers only (e.g. `authorforge.cloud.enabled`, `cloud_tokens.monthly`).
pub fn clean_entitlement_key(value: &str) -> Result<String, &'static str> {
    let value = value.trim();
    if value.is_empty() {
        return Err("key is required");
    }
    if value.len() > 120 {
        return Err("key must be at most 120 characters");
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err("key must contain only letters, numbers, '.', '_', or '-'");
    }
    Ok(value.to_string())
}

/// Evaluate entitlements deterministically.
pub fn evaluate(inputs: &EntitlementInputs) -> EntitlementResult {
    let mut features: BTreeMap<String, FeatureValue> = BTreeMap::new();

    // Apply layers in precedence order; later layers overwrite earlier ones.
    for layer in [
        &inputs.product_defaults,
        &inputs.plan_version,
        &inputs.license_grants,
        &inputs.promotional_grants,
        &inputs.admin_overrides,
    ] {
        for (k, v) in layer {
            features.insert(k.clone(), v.clone());
        }
    }

    // Subscription gate: cloud features require an entitling subscription.
    if !inputs.subscription_grants_cloud {
        for (k, v) in features.iter_mut() {
            if is_cloud_feature(k) {
                *v = FeatureValue::Bool(false);
            }
        }
    }

    // Hard denials always win for cloud features (fail closed).
    if inputs.suspended || inputs.revoked {
        for (k, v) in features.iter_mut() {
            if is_cloud_feature(k) {
                *v = FeatureValue::Bool(false);
            }
        }
    }

    EntitlementResult {
        features,
        quotas: inputs.quota_limits.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(v: bool) -> FeatureValue {
        FeatureValue::Bool(v)
    }

    fn base() -> EntitlementInputs {
        let mut plan = BTreeMap::new();
        plan.insert("authorforge.cloud.enabled".into(), b(true));
        plan.insert("authorforge.devices.max".into(), FeatureValue::Number(3.0));
        EntitlementInputs {
            plan_version: plan,
            subscription_grants_cloud: true,
            ..Default::default()
        }
    }

    #[test]
    fn admin_override_wins_over_plan() {
        let mut inputs = base();
        inputs
            .admin_overrides
            .insert("authorforge.devices.max".into(), FeatureValue::Number(10.0));
        let r = evaluate(&inputs);
        assert_eq!(
            r.features.get("authorforge.devices.max"),
            Some(&FeatureValue::Number(10.0))
        );
    }

    #[test]
    fn inactive_subscription_disables_cloud_features() {
        let mut inputs = base();
        inputs.subscription_grants_cloud = false;
        let r = evaluate(&inputs);
        assert_eq!(r.features.get("authorforge.cloud.enabled"), Some(&b(false)));
        // Non-cloud feature unaffected.
        assert_eq!(
            r.features.get("authorforge.devices.max"),
            Some(&FeatureValue::Number(3.0))
        );
    }

    #[test]
    fn suspension_denies_cloud_even_with_override() {
        let mut inputs = base();
        inputs
            .admin_overrides
            .insert("authorforge.cloud.enabled".into(), b(true));
        inputs.suspended = true;
        let r = evaluate(&inputs);
        assert_eq!(r.features.get("authorforge.cloud.enabled"), Some(&b(false)));
    }

    #[test]
    fn revocation_denies_cloud() {
        let mut inputs = base();
        inputs.revoked = true;
        let r = evaluate(&inputs);
        assert_eq!(r.features.get("authorforge.cloud.enabled"), Some(&b(false)));
    }

    #[test]
    fn entitlement_key_validation() {
        assert_eq!(
            clean_entitlement_key(" authorforge.cloud.enabled "),
            Ok("authorforge.cloud.enabled".to_string())
        );
        assert_eq!(
            clean_entitlement_key("cloud_tokens.monthly"),
            Ok("cloud_tokens.monthly".to_string())
        );
        assert!(clean_entitlement_key("").is_err());
        assert!(clean_entitlement_key("bad key with spaces").is_err());
        assert!(clean_entitlement_key("inject';--").is_err());
    }

    #[test]
    fn deterministic_ordering() {
        // BTreeMap guarantees stable key ordering for canonical signing.
        let inputs = base();
        let r1 = evaluate(&inputs);
        let r2 = evaluate(&inputs);
        assert_eq!(
            serde_json::to_string(&r1.features).unwrap(),
            serde_json::to_string(&r2.features).unwrap()
        );
    }
}
