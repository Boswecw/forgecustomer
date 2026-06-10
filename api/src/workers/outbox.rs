//! Transactional-outbox publisher.
//!
//! Commercial state changes write an `outbox_events` row in the same transaction. This
//! worker polls pending rows and delivers them to DataForge. Delivery is idempotent
//! (consumer dedupes on `delivery_key`); failures back off and eventually dead-letter.

use std::time::Duration;

use crate::integrations::dataforge::DataforgeClient;
use crate::state::AppState;

/// Compute the next backoff delay for a given attempt count (capped exponential).
pub fn backoff_for(attempts: i32) -> Duration {
    let exponent = attempts.max(0) as u32;
    let secs = 2u64.saturating_pow(exponent);
    Duration::from_secs(secs.min(3600))
}

/// Maximum delivery attempts before an event is dead-lettered.
pub const MAX_ATTEMPTS: i32 = 12;

/// Run the outbox publisher loop. Each tick claims a batch of due `pending` events and
/// attempts delivery. This is intentionally simple polling; it can be replaced with
/// `LISTEN/NOTIFY` later without changing the contract.
pub async fn run(state: AppState, client: DataforgeClient, poll_interval: Duration) {
    loop {
        if let Err(e) = tick(&state, &client).await {
            tracing::error!(error = %e, "outbox tick failed");
        }
        tokio::time::sleep(poll_interval).await;
    }
}

async fn tick(state: &AppState, client: &DataforgeClient) -> Result<(), sqlx::Error> {
    let due = sqlx::query_as::<_, OutboxRow>(
        "select id, event_type, delivery_key, payload, attempts \
         from public.outbox_events \
         where status = 'pending' and next_attempt_at <= now() \
         order by created_at limit 50",
    )
    .fetch_all(&state.pool)
    .await?;

    for row in due {
        match client
            .publish(&row.event_type, &row.delivery_key, &row.payload)
            .await
        {
            Ok(()) => {
                sqlx::query(
                    "update public.outbox_events \
                     set status = 'delivered', delivered_at = now() where id = $1",
                )
                .bind(row.id)
                .execute(&state.pool)
                .await?;
            }
            Err(e) => {
                let attempts = row.attempts + 1;
                let status = if attempts >= MAX_ATTEMPTS {
                    "dead_letter"
                } else {
                    "pending"
                };
                let next = backoff_for(attempts).as_secs() as i64;
                sqlx::query(
                    "update public.outbox_events set attempts = $2, status = $3, \
                     last_error = $4, next_attempt_at = now() + ($5 || ' seconds')::interval \
                     where id = $1",
                )
                .bind(row.id)
                .bind(attempts)
                .bind(status)
                .bind(e.to_string())
                .bind(next.to_string())
                .execute(&state.pool)
                .await?;
            }
        }
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct OutboxRow {
    id: uuid::Uuid,
    event_type: String,
    delivery_key: String,
    payload: serde_json::Value,
    attempts: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_exponential_and_capped() {
        assert_eq!(backoff_for(0), Duration::from_secs(1));
        assert_eq!(backoff_for(1), Duration::from_secs(2));
        assert_eq!(backoff_for(3), Duration::from_secs(8));
        assert_eq!(backoff_for(100), Duration::from_secs(3600)); // capped
    }
}
