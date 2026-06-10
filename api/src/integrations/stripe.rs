//! Stripe integration. The security-critical webhook signature verification is implemented
//! and tested here; Checkout/session creation calls are the remaining MVP wiring.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum WebhookError {
    #[error("malformed Stripe-Signature header")]
    MalformedHeader,
    #[error("signature timestamp outside tolerance")]
    TimestampOutOfTolerance,
    #[error("no matching signature")]
    NoMatch,
    #[error("webhook secret not configured")]
    NotConfigured,
}

/// Verify a Stripe webhook signature.
///
/// The `Stripe-Signature` header looks like `t=<ts>,v1=<sig>,v1=<sig2>`. We compute
/// `HMAC_SHA256(secret, "<ts>.<payload>")` and compare against each provided `v1` value in
/// **constant time**. `tolerance_secs` bounds replay by timestamp skew.
pub fn verify_signature(
    payload: &[u8],
    sig_header: &str,
    secret: &str,
    now_unix: i64,
    tolerance_secs: i64,
) -> Result<(), WebhookError> {
    if secret.is_empty() {
        return Err(WebhookError::NotConfigured);
    }

    let mut timestamp: Option<i64> = None;
    let mut signatures: Vec<Vec<u8>> = Vec::new();

    for part in sig_header.split(',') {
        let (k, v) = part.split_once('=').ok_or(WebhookError::MalformedHeader)?;
        match k.trim() {
            "t" => {
                timestamp = Some(
                    v.trim()
                        .parse()
                        .map_err(|_| WebhookError::MalformedHeader)?,
                );
            }
            "v1" => {
                let bytes = hex::decode(v.trim()).map_err(|_| WebhookError::MalformedHeader)?;
                signatures.push(bytes);
            }
            _ => {} // ignore other schemes (e.g. v0)
        }
    }

    let ts = timestamp.ok_or(WebhookError::MalformedHeader)?;
    if (now_unix - ts).abs() > tolerance_secs {
        return Err(WebhookError::TimestampOutOfTolerance);
    }
    if signatures.is_empty() {
        return Err(WebhookError::MalformedHeader);
    }

    let signed_payload = {
        let mut v = Vec::with_capacity(payload.len() + 16);
        v.extend_from_slice(ts.to_string().as_bytes());
        v.push(b'.');
        v.extend_from_slice(payload);
        v
    };

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| WebhookError::NotConfigured)?;
    mac.update(&signed_payload);
    let expected = mac.finalize().into_bytes();

    // Constant-time compare against each candidate; OR the results to avoid early-out.
    let mut matched = 0u8;
    for sig in &signatures {
        if sig.len() == expected.len() {
            matched |= expected.as_slice().ct_eq(sig).unwrap_u8();
        }
    }
    if matched == 1 {
        Ok(())
    } else {
        Err(WebhookError::NoMatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    fn sign(payload: &[u8], secret: &str, ts: i64) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        let mut data = ts.to_string().into_bytes();
        data.push(b'.');
        data.extend_from_slice(payload);
        mac.update(&data);
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn accepts_valid_signature() {
        let payload = br#"{"id":"evt_1"}"#;
        let secret = "whsec_test";
        let ts = 1_700_000_000;
        let header = format!("t={ts},v1={}", sign(payload, secret, ts));
        assert!(verify_signature(payload, &header, secret, ts + 5, 300).is_ok());
    }

    #[test]
    fn rejects_tampered_payload() {
        let secret = "whsec_test";
        let ts = 1_700_000_000;
        let header = format!("t={ts},v1={}", sign(br#"{"id":"evt_1"}"#, secret, ts));
        let err = verify_signature(br#"{"id":"evt_2"}"#, &header, secret, ts, 300).unwrap_err();
        assert_eq!(err, WebhookError::NoMatch);
    }

    #[test]
    fn rejects_wrong_secret() {
        let payload = br#"{"id":"evt_1"}"#;
        let ts = 1_700_000_000;
        let header = format!("t={ts},v1={}", sign(payload, "whsec_a", ts));
        assert_eq!(
            verify_signature(payload, &header, "whsec_b", ts, 300).unwrap_err(),
            WebhookError::NoMatch
        );
    }

    #[test]
    fn rejects_replay_outside_tolerance() {
        let payload = br#"{"id":"evt_1"}"#;
        let secret = "whsec_test";
        let ts = 1_700_000_000;
        let header = format!("t={ts},v1={}", sign(payload, secret, ts));
        assert_eq!(
            verify_signature(payload, &header, secret, ts + 10_000, 300).unwrap_err(),
            WebhookError::TimestampOutOfTolerance
        );
    }

    #[test]
    fn rejects_malformed_header() {
        assert_eq!(
            verify_signature(b"{}", "garbage", "s", 0, 300).unwrap_err(),
            WebhookError::MalformedHeader
        );
    }

    #[test]
    fn unconfigured_secret_fails_closed() {
        assert_eq!(
            verify_signature(b"{}", "t=1,v1=ab", "", 1, 300).unwrap_err(),
            WebhookError::NotConfigured
        );
    }
}
