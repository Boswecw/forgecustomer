//! Tower middleware: correlation IDs and security headers. JWT validation and customer/
//! admin context are implemented as extractors in `auth::extract`.

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use uuid::Uuid;

/// Correlation id stored in request extensions and echoed on the response.
#[derive(Debug, Clone)]
pub struct CorrelationId(pub String);

const HEADER: &str = "x-correlation-id";

/// Assign or propagate a correlation id for every request.
pub async fn correlation_id(mut req: Request, next: Next) -> Response {
    let incoming = req
        .headers()
        .get(HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
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
