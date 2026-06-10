//! The signed offline lease payload (`forge.lease.v1`).
//!
//! A lease is a short-lived, signed permission that lets an activated installation keep
//! using cloud-adjacent capabilities across connectivity gaps. Like the entitlement
//! snapshot, the signature covers the canonical JSON of every field except `signature`.

use serde::{Deserialize, Serialize};

pub const LEASE_SCHEMA_VERSION: &str = "forge.lease.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OfflineLease {
    pub schema_version: String,
    pub lease_id: String,
    pub customer_id: String,
    pub license_id: String,
    pub installation_id: String,
    pub product: String,
    pub issued_at: String,
    pub expires_at: String,
    pub key_id: String,
    /// Base64 Ed25519 signature. Empty until signed; excluded from the signed bytes.
    #[serde(default)]
    pub signature: String,
}

impl OfflineLease {
    /// Canonical bytes to sign / verify: the lease with `signature` cleared.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut unsigned = self.clone();
        unsigned.signature = String::new();
        serde_json::to_vec(&unsigned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> OfflineLease {
        OfflineLease {
            schema_version: LEASE_SCHEMA_VERSION.to_string(),
            lease_id: "lease_1".to_string(),
            customer_id: "cust_1".to_string(),
            license_id: "lic_1".to_string(),
            installation_id: "inst_1".to_string(),
            product: "authorforge".to_string(),
            issued_at: "2026-06-10T20:00:00Z".to_string(),
            expires_at: "2026-06-24T20:00:00Z".to_string(),
            key_id: "entitlement-key-1".to_string(),
            signature: String::new(),
        }
    }

    #[test]
    fn signing_bytes_ignore_signature_field() {
        let mut lease = sample();
        let before = lease.signing_bytes().unwrap();
        lease.signature = "anything".to_string();
        assert_eq!(before, lease.signing_bytes().unwrap());
    }

    #[test]
    fn signing_bytes_are_stable() {
        let lease = sample();
        assert_eq!(
            lease.signing_bytes().unwrap(),
            lease.signing_bytes().unwrap()
        );
    }

    #[test]
    fn sign_and_verify_roundtrip_with_keyring() {
        use crate::services::signing::{Signer25519, VerifyingKeyRing};
        use base64::Engine;

        let seed = base64::engine::general_purpose::STANDARD.encode([5u8; 32]);
        let signer = Signer25519::from_base64_seed("entitlement-key-1", &seed).unwrap();
        let mut ring = VerifyingKeyRing::new();
        ring.add_signer(&signer);

        let mut lease = sample();
        lease.key_id = signer.key_id().to_string();
        let bytes = lease.signing_bytes().unwrap();
        lease.signature = signer.sign_bytes(&bytes);

        ring.verify(
            &lease.key_id,
            &lease.signing_bytes().unwrap(),
            &lease.signature,
        )
        .expect("valid lease signature verifies");

        // Tampering invalidates the signature.
        lease.expires_at = "2099-01-01T00:00:00Z".to_string();
        assert!(ring
            .verify(
                &lease.key_id,
                &lease.signing_bytes().unwrap(),
                &lease.signature
            )
            .is_err());
    }
}
