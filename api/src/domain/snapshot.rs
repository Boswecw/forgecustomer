//! The signed entitlement snapshot payload (`forge.entitlements.v1`).
//!
//! The signature covers the canonical JSON of every field EXCEPT `signature`. Canonical
//! form uses sorted keys (serde_json with BTreeMaps + ordered struct fields) so that
//! signing and verification agree byte-for-byte.

use crate::domain::entitlement::FeatureValue;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: &str = "forge.entitlements.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntitlementSnapshot {
    pub schema_version: String,
    pub customer_id: String,
    pub installation_id: Option<String>,
    pub product: String,
    pub issued_at: String,
    pub expires_at: String,
    pub features: BTreeMap<String, FeatureValue>,
    pub quotas: BTreeMap<String, f64>,
    pub key_id: String,
    /// Base64 Ed25519 signature. Empty until signed; excluded from the signed bytes.
    #[serde(default)]
    pub signature: String,
}

impl EntitlementSnapshot {
    /// Canonical bytes to sign / verify: the snapshot with `signature` cleared.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut unsigned = self.clone();
        unsigned.signature = String::new();
        serde_json::to_vec(&unsigned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> EntitlementSnapshot {
        let mut features = BTreeMap::new();
        features.insert("cloud.enabled".to_string(), FeatureValue::Bool(true));
        let mut quotas = BTreeMap::new();
        quotas.insert("cloud_tokens.monthly".to_string(), 1_000_000.0);
        EntitlementSnapshot {
            schema_version: SCHEMA_VERSION.to_string(),
            customer_id: "cust_1".to_string(),
            installation_id: Some("inst_1".to_string()),
            product: "authorforge".to_string(),
            issued_at: "2026-06-09T20:00:00Z".to_string(),
            expires_at: "2026-06-10T20:00:00Z".to_string(),
            features,
            quotas,
            key_id: "entitlement-key-1".to_string(),
            signature: String::new(),
        }
    }

    #[test]
    fn signing_bytes_ignore_signature_field() {
        let mut a = sample();
        let bytes_before = a.signing_bytes().unwrap();
        a.signature = "anything".to_string();
        let bytes_after = a.signing_bytes().unwrap();
        assert_eq!(bytes_before, bytes_after);
    }

    #[test]
    fn signing_bytes_are_stable() {
        let a = sample();
        assert_eq!(a.signing_bytes().unwrap(), a.signing_bytes().unwrap());
    }
}
