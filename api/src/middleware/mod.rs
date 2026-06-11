//! Tower middleware: correlation IDs, security headers, and per-client rate limiting.
//! JWT validation and customer/admin context are implemented as extractors in
//! `auth::extract`.

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use uuid::Uuid;

pub mod rate_limit;

/// Correlation id stored in request extensions and echoed on the response.
#[derive(Debug, Clone)]
pub struct CorrelationId(pub String);

const HEADER: &str = "x-correlation-id";

/// Client-supplied correlation ids are persisted into audit rows and logs, so only
/// short, log-safe values are honored; anything else is replaced with a generated id.
const MAX_CORRELATION_ID_LEN: usize = 128;

fn acceptable_correlation_id(value: &str) -> bool {
    (1..=MAX_CORRELATION_ID_LEN).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Assign or propagate a correlation id for every request.
pub async fn correlation_id(mut req: Request, next: Next) -> Response {
    let incoming = req
        .headers()
        .get(HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|s| acceptable_correlation_id(s))
        .map(|s| s.to_string());

    let id = incoming.unwrap_or_else(|| format!("corr_{}", Uuid::new_v4().simple()));
    req.extensions_mut().insert(CorrelationId(id.clone()));

    let mut res = next.run(req).await;
    if let Ok(value) = HeaderValue::from_str(&id) {
        res.headers_mut()
            .insert(HeaderName::from_static(HEADER), value);
    }
    res
}

/// Apply conservative security headers to every response.
pub async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    res
}

#[cfg(test)]
mod tests {
    use super::acceptable_correlation_id;

    #[test]
    fn accepts_short_log_safe_correlation_ids() {
        assert!(acceptable_correlation_id("corr_0af1"));
        assert!(acceptable_correlation_id("trace-7.segment_2"));
        assert!(acceptable_correlation_id(&"a".repeat(128)));
    }

    #[test]
    fn rejects_oversized_or_hostile_correlation_ids() {
        assert!(!acceptable_correlation_id(""));
        assert!(!acceptable_correlation_id(&"a".repeat(129)));
        assert!(!acceptable_correlation_id("corr id with spaces"));
        assert!(!acceptable_correlation_id("corr\"quote"));
        assert!(!acceptable_correlation_id("corr{json}"));
    }
}
