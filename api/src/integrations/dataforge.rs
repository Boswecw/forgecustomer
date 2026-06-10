//! DataForge client — publishes sanitized events. DataForge is a sink only; an outage here
//! must never break customer transactions (events are queued in `outbox_events` and
//! delivered asynchronously by the outbox worker).

use serde_json::Value;

use crate::domain::redaction;

#[derive(Debug, thiserror::Error)]
pub enum DataforgeError {
    #[error("payload contains prohibited fields (PII/secret/content)")]
    ProhibitedPayload,
    #[error("transport error: {0}")]
    Transport(String),
    #[error("not configured")]
    NotConfigured,
}

pub struct DataforgeClient {
    http: reqwest::Client,
    url: String,
    token: String,
}

impl DataforgeClient {
    pub fn new(http: reqwest::Client, url: String, token: String) -> Self {
        Self { http, url, token }
    }

    /// Publish a sanitized event. The payload is sanitized again here as a defense in depth;
    /// if prohibited fields somehow remain, delivery is refused (fail closed).
    pub async fn publish(
        &self,
        event_type: &str,
        delivery_key: &str,
        payload: &Value,
    ) -> Result<(), DataforgeError> {
        if self.url.is_empty() {
            return Err(DataforgeError::NotConfigured);
        }
        if redaction::contains_prohibited(payload) {
            return Err(DataforgeError::ProhibitedPayload);
        }
        let body = serde_json::json!({
            "event_type": event_type,
            "delivery_key": delivery_key,
            "payload": payload,
        });
        self.http
            .post(&self.url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| DataforgeError::Transport(e.to_string()))?
            .error_for_status()
            .map_err(|e| DataforgeError::Transport(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn refuses_prohibited_payload() {
        let client = DataforgeClient::new(
            reqwest::Client::new(),
            "https://example.invalid".into(),
            "t".into(),
        );
        let err = client
            .publish("customer_created", "k1", &json!({ "email": "a@b.com" }))
            .await
            .unwrap_err();
        matches!(err, DataforgeError::ProhibitedPayload)
            .then_some(())
            .expect("must refuse prohibited payload");
    }
}
