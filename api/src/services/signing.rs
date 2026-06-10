//! Ed25519 signing and verification for entitlement snapshots and offline leases.
//!
//! The private key is held only in server memory (loaded from a secret). Verification keys
//! are published by id; rotation works by keeping both old and new verifying keys in the
//! ring during the overlap window.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::domain::snapshot::EntitlementSnapshot;

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("invalid signing key: {0}")]
    InvalidKey(String),
    #[error("invalid signature encoding")]
    BadSignature,
    #[error("unknown key id: {0}")]
    UnknownKeyId(String),
    #[error("serialization error: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("signature verification failed")]
    VerificationFailed,
}

/// Holds the active private signing key plus its id.
pub struct Signer25519 {
    key_id: String,
    signing_key: SigningKey,
}

impl Signer25519 {
    /// Build from a base64-encoded 32-byte Ed25519 seed.
    pub fn from_base64_seed(
        key_id: impl Into<String>,
        b64_seed: &str,
    ) -> Result<Self, SigningError> {
        let raw = B64
            .decode(b64_seed.trim())
            .map_err(|e| SigningError::InvalidKey(e.to_string()))?;
        let seed: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| SigningError::InvalidKey("seed must be 32 bytes".into()))?;
        Ok(Self {
            key_id: key_id.into(),
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Base64 of the public verifying key, for publication.
    pub fn public_key_base64(&self) -> String {
        B64.encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Sign arbitrary bytes, returning a base64 signature.
    pub fn sign_bytes(&self, message: &[u8]) -> String {
        B64.encode(self.signing_key.sign(message).to_bytes())
    }

    /// Sign an entitlement snapshot in place, setting `key_id` and `signature`.
    pub fn sign_snapshot(&self, snapshot: &mut EntitlementSnapshot) -> Result<(), SigningError> {
        snapshot.key_id = self.key_id.clone();
        snapshot.signature = String::new();
        let bytes = snapshot.signing_bytes()?;
        snapshot.signature = self.sign_bytes(&bytes);
        Ok(())
    }
}

/// A ring of verifying keys by id, used to verify during key rotation.
#[derive(Default)]
pub struct VerifyingKeyRing {
    keys: HashMap<String, VerifyingKey>,
}

impl VerifyingKeyRing {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a verifying key (base64 of 32 raw bytes) under an id.
    pub fn add_base64(
        &mut self,
        key_id: impl Into<String>,
        b64_pub: &str,
    ) -> Result<(), SigningError> {
        let raw = B64
            .decode(b64_pub.trim())
            .map_err(|e| SigningError::InvalidKey(e.to_string()))?;
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| SigningError::InvalidKey("public key must be 32 bytes".into()))?;
        let vk = VerifyingKey::from_bytes(&bytes)
            .map_err(|e| SigningError::InvalidKey(e.to_string()))?;
        self.keys.insert(key_id.into(), vk);
        Ok(())
    }

    /// Register the active signer's public key into the ring.
    pub fn add_signer(&mut self, signer: &Signer25519) {
        self.keys.insert(
            signer.key_id().to_string(),
            signer.signing_key.verifying_key(),
        );
    }

    pub fn published(&self) -> Vec<(String, String)> {
        self.keys
            .iter()
            .map(|(id, vk)| (id.clone(), B64.encode(vk.to_bytes())))
            .collect()
    }

    /// Verify a base64 signature over `message` using the key identified by `key_id`.
    pub fn verify(&self, key_id: &str, message: &[u8], b64_sig: &str) -> Result<(), SigningError> {
        let vk = self
            .keys
            .get(key_id)
            .ok_or_else(|| SigningError::UnknownKeyId(key_id.to_string()))?;
        let raw = B64
            .decode(b64_sig.trim())
            .map_err(|_| SigningError::BadSignature)?;
        let sig_bytes: [u8; 64] = raw
            .as_slice()
            .try_into()
            .map_err(|_| SigningError::BadSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(message, &sig)
            .map_err(|_| SigningError::VerificationFailed)
    }

    /// Verify a fully-formed snapshot's signature against its declared `key_id`.
    pub fn verify_snapshot(&self, snapshot: &EntitlementSnapshot) -> Result<(), SigningError> {
        let bytes = snapshot.signing_bytes()?;
        self.verify(&snapshot.key_id, &bytes, &snapshot.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entitlement::FeatureValue;
    use crate::domain::snapshot::{EntitlementSnapshot, SCHEMA_VERSION};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use std::collections::BTreeMap;

    fn make_signer(key_id: &str, seed_byte: u8) -> Signer25519 {
        let seed = [seed_byte; 32];
        Signer25519::from_base64_seed(key_id, &B64.encode(seed)).unwrap()
    }

    fn snapshot() -> EntitlementSnapshot {
        let mut features = BTreeMap::new();
        features.insert("cloud.enabled".to_string(), FeatureValue::Bool(true));
        EntitlementSnapshot {
            schema_version: SCHEMA_VERSION.to_string(),
            customer_id: "cust_1".to_string(),
            installation_id: Some("inst_1".to_string()),
            product: "authorforge".to_string(),
            issued_at: "2026-06-09T20:00:00Z".to_string(),
            expires_at: "2026-06-10T20:00:00Z".to_string(),
            features,
            quotas: BTreeMap::new(),
            key_id: String::new(),
            signature: String::new(),
        }
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let signer = make_signer("entitlement-key-1", 7);
        let mut ring = VerifyingKeyRing::new();
        ring.add_signer(&signer);

        let mut snap = snapshot();
        signer.sign_snapshot(&mut snap).unwrap();
        assert_eq!(snap.key_id, "entitlement-key-1");
        assert!(!snap.signature.is_empty());
        ring.verify_snapshot(&snap)
            .expect("valid signature verifies");
    }

    #[test]
    fn forged_snapshot_fails_verification() {
        let signer = make_signer("entitlement-key-1", 7);
        let mut ring = VerifyingKeyRing::new();
        ring.add_signer(&signer);

        let mut snap = snapshot();
        signer.sign_snapshot(&mut snap).unwrap();
        // Tamper with a feature after signing.
        snap.features
            .insert("cloud.enabled".to_string(), FeatureValue::Bool(false));
        assert!(ring.verify_snapshot(&snap).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let signer = make_signer("entitlement-key-1", 7);
        let other = make_signer("entitlement-key-1", 9); // same id, different key
        let mut ring = VerifyingKeyRing::new();
        ring.add_signer(&other);

        let mut snap = snapshot();
        signer.sign_snapshot(&mut snap).unwrap();
        assert!(ring.verify_snapshot(&snap).is_err());
    }

    #[test]
    fn rotation_overlap_both_keys_verify() {
        let old = make_signer("entitlement-key-1", 1);
        let new = make_signer("entitlement-key-2", 2);
        let mut ring = VerifyingKeyRing::new();
        ring.add_signer(&old);
        ring.add_signer(&new);

        let mut s_old = snapshot();
        old.sign_snapshot(&mut s_old).unwrap();
        let mut s_new = snapshot();
        new.sign_snapshot(&mut s_new).unwrap();

        ring.verify_snapshot(&s_old)
            .expect("old key still verifies");
        ring.verify_snapshot(&s_new).expect("new key verifies");
    }

    #[test]
    fn unknown_key_id_rejected() {
        let signer = make_signer("entitlement-key-9", 3);
        let ring = VerifyingKeyRing::new(); // empty ring
        let mut snap = snapshot();
        signer.sign_snapshot(&mut snap).unwrap();
        match ring.verify_snapshot(&snap) {
            Err(SigningError::UnknownKeyId(_)) => {}
            other => panic!("expected UnknownKeyId, got {other:?}"),
        }
    }
}
