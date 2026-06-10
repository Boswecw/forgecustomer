//! Reservation expiry sweeper.
//!
//! Pending usage reservations hold quota until committed or released; this worker
//! reclaims overdue holds in the background. The reserve/commit paths also expire stale
//! reservations lazily for the customer they touch, so the sweeper is a safety net that
//! keeps `reserved` totals honest for idle customers.

use std::time::Duration;

use crate::repositories::usage::sweep_expired_reservations;
use crate::state::AppState;

const SWEEP_BATCH: i64 = 200;

/// Run the reservation expiry sweep loop.
pub async fn run(state: AppState, poll_interval: Duration) {
    loop {
        match sweep_expired_reservations(&state.pool, SWEEP_BATCH).await {
            Ok(0) => {}
            Ok(reclaimed) => {
                tracing::info!(reclaimed, "expired stale usage reservations");
            }
            Err(e) => {
                tracing::error!(error = %e, "usage reservation sweep failed");
            }
        }
        tokio::time::sleep(poll_interval).await;
    }
}
