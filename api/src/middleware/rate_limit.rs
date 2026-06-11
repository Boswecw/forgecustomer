//! Per-client fixed-window rate limiting.
//!
//! Every request spends one unit of the client's per-minute budget
//! (`RATE_LIMIT_PER_MINUTE`; `0` disables). Exhausted budgets render `429 RATE_LIMITED`
//! through the shared error contract with a `retry-after` header. The limiter is
//! in-process (per instance), which matches the single-instance deployment; volumetric
//! attacks beyond that remain the platform edge's job.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::{AppError, ErrorCode};
use crate::middleware::CorrelationId;
use crate::state::AppState;

const WINDOW_SECS: u64 = 60;
/// Stale windows are swept at most once per window, and only once the table is at least
/// this large, so steady-state traffic never pays the sweep.
const SWEEP_MIN_ENTRIES: usize = 1024;
/// Hard cap on tracked clients. When the table is full, *new* clients are denied (fail
/// closed) rather than letting an address-rotating flood grow memory without bound.
const MAX_TRACKED_CLIENTS: usize = 100_000;

struct Window {
    started: u64,
    count: u32,
}

#[derive(Default)]
struct Inner {
    windows: HashMap<String, Window>,
    swept_window: u64,
}

/// Shared fixed-window counters, keyed by client.
#[derive(Default)]
pub struct RateLimiter {
    inner: Mutex<Inner>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RateDecision {
    Allow,
    Deny { retry_after_secs: u64 },
}

impl RateLimiter {
    /// Spend one unit of `key`'s budget for the window containing `now_unix`.
    pub fn check(&self, key: &str, limit: u32, now_unix: u64) -> RateDecision {
        let window = now_unix - (now_unix % WINDOW_SECS);
        let retry_after_secs = (window + WINDOW_SECS).saturating_sub(now_unix).max(1);

        let mut inner = match self.inner.lock() {
            Ok(guard) => guard,
            // A poisoned lock only means another thread panicked mid-update; the
            // counters are still structurally sound, so keep limiting.
            Err(poisoned) => poisoned.into_inner(),
        };

        if inner.swept_window != window && inner.windows.len() >= SWEEP_MIN_ENTRIES {
            inner.windows.retain(|_, w| w.started == window);
            inner.swept_window = window;
        }

        if inner.windows.len() >= MAX_TRACKED_CLIENTS && !inner.windows.contains_key(key) {
            return RateDecision::Deny { retry_after_secs };
        }

        let entry = inner.windows.entry(key.to_string()).or_insert(Window {
            started: window,
            count: 0,
        });
        if entry.started != window {
            entry.started = window;
            entry.count = 0;
        }
        if entry.count >= limit {
            RateDecision::Deny { retry_after_secs }
        } else {
            entry.count += 1;
            RateDecision::Allow
        }
    }
}

/// Resolve the client key. The rightmost `x-forwarded-for` entry is appended by the
/// trusted platform proxy and is the only hop a direct client cannot spoof; values that
/// do not parse as an IP fall through to the socket peer (local/dev) or a shared bucket,
/// which throttles rather than bypasses.
fn client_key(req: &Request) -> String {
    let forwarded_ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .map(str::trim)
        .and_then(|value| value.parse::<IpAddr>().ok());
    if let Some(ip) = forwarded_ip {
        return ip.to_string();
    }
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Enforce the per-client budget ahead of all handler work.
pub async fn enforce(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let limit = state.config.rate_limit_per_minute;
    if limit == 0 {
        return next.run(req).await;
    }

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let key = client_key(&req);

    match state.rate_limiter.check(&key, limit, now_unix) {
        RateDecision::Allow => next.run(req).await,
        RateDecision::Deny { retry_after_secs } => {
            let mut error = AppError::new(
                ErrorCode::RateLimited,
                "Too many requests from this client; retry after the indicated delay.",
            );
            if let Some(correlation) = req.extensions().get::<CorrelationId>() {
                error = error.with_correlation(correlation.0.clone());
            }
            let mut res = error.into_response();
            if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                res.headers_mut().insert(header::RETRY_AFTER, value);
            }
            res
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    #[test]
    fn allows_up_to_limit_then_denies() {
        let limiter = RateLimiter::default();
        assert_eq!(limiter.check("10.0.0.1", 2, NOW), RateDecision::Allow);
        assert_eq!(limiter.check("10.0.0.1", 2, NOW), RateDecision::Allow);
        assert!(matches!(
            limiter.check("10.0.0.1", 2, NOW),
            RateDecision::Deny { .. }
        ));
    }

    #[test]
    fn new_window_resets_the_budget() {
        let limiter = RateLimiter::default();
        assert_eq!(limiter.check("10.0.0.1", 1, NOW), RateDecision::Allow);
        assert!(matches!(
            limiter.check("10.0.0.1", 1, NOW + 1),
            RateDecision::Deny { .. }
        ));
        assert_eq!(
            limiter.check("10.0.0.1", 1, NOW + WINDOW_SECS),
            RateDecision::Allow
        );
    }

    #[test]
    fn distinct_clients_have_independent_budgets() {
        let limiter = RateLimiter::default();
        assert_eq!(limiter.check("10.0.0.1", 1, NOW), RateDecision::Allow);
        assert!(matches!(
            limiter.check("10.0.0.1", 1, NOW),
            RateDecision::Deny { .. }
        ));
        assert_eq!(limiter.check("10.0.0.2", 1, NOW), RateDecision::Allow);
    }

    #[test]
    fn retry_after_counts_down_to_the_window_boundary() {
        let limiter = RateLimiter::default();
        let start = NOW - (NOW % WINDOW_SECS);
        let late = start + WINDOW_SECS - 5;
        assert_eq!(limiter.check("10.0.0.1", 1, late), RateDecision::Allow);
        assert_eq!(
            limiter.check("10.0.0.1", 1, late),
            RateDecision::Deny {
                retry_after_secs: 5
            }
        );
    }

    #[test]
    fn full_table_fails_closed_for_new_clients() {
        let limiter = RateLimiter::default();
        for i in 0..MAX_TRACKED_CLIENTS {
            assert_eq!(limiter.check(&format!("k{i}"), 5, NOW), RateDecision::Allow);
        }
        // Known clients keep their budget; brand-new clients are denied.
        assert_eq!(limiter.check("k0", 5, NOW), RateDecision::Allow);
        assert!(matches!(
            limiter.check("fresh-client", 5, NOW),
            RateDecision::Deny { .. }
        ));
    }

    #[test]
    fn sweep_drops_stale_windows_so_new_clients_recover() {
        let limiter = RateLimiter::default();
        for i in 0..SWEEP_MIN_ENTRIES {
            limiter.check(&format!("k{i}"), 5, NOW);
        }
        // Next window: the sweep clears stale entries and admits new clients again.
        assert_eq!(
            limiter.check("fresh-client", 5, NOW + WINDOW_SECS),
            RateDecision::Allow
        );
        assert_eq!(
            limiter
                .inner
                .lock()
                .map(|inner| inner.windows.len())
                .unwrap_or(usize::MAX),
            1
        );
    }
}
