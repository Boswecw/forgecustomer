//! Commerce and Stripe persistence.

use serde_json::Value;
use sqlx::PgPool;

use crate::integrations::stripe::{ParsedStripeEvent, StripeWebhookReceiptStatus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StripeWebhookRecordOutcome {
    Inserted,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StripeWebhookRecord {
    pub outcome: StripeWebhookRecordOutcome,
    pub status: String,
}

/// Store a verified Stripe event exactly once. The row is the idempotency receipt for
/// webhook delivery; supported events stay `received` for follow-up state application,
/// unsupported events are explicitly marked `ignored`.
pub async fn record_stripe_webhook_event(
    pool: &PgPool,
    event: &ParsedStripeEvent,
) -> Result<StripeWebhookRecord, sqlx::Error> {
    let status = event.receipt_status.as_str();
    let processed_at_sql = match event.receipt_status {
        StripeWebhookReceiptStatus::Received => "null",
        StripeWebhookReceiptStatus::Ignored => "now()",
    };
    let query = format!(
        r#"
        insert into public.stripe_webhook_events
            (stripe_event_id, event_type, status, processed_at, payload_summary)
        values
            ($1, $2, $3, {processed_at_sql}, $4)
        on conflict (stripe_event_id) do nothing
        returning status
        "#
    );

    let inserted_status = sqlx::query_scalar::<_, String>(&query)
        .bind(&event.id)
        .bind(&event.event_type)
        .bind(status)
        .bind(&event.payload_summary as &Value)
        .fetch_optional(pool)
        .await?;

    match inserted_status {
        Some(status) => Ok(StripeWebhookRecord {
            outcome: StripeWebhookRecordOutcome::Inserted,
            status,
        }),
        None => {
            let existing_status = sqlx::query_scalar::<_, String>(
                r#"
                select status
                from public.stripe_webhook_events
                where stripe_event_id = $1
                "#,
            )
            .bind(&event.id)
            .fetch_one(pool)
            .await?;
            Ok(StripeWebhookRecord {
                outcome: StripeWebhookRecordOutcome::Duplicate,
                status: existing_status,
            })
        }
    }
}
