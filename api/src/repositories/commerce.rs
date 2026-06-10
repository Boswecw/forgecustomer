//! Commerce and Stripe persistence.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::domain::redaction::sanitize;
use crate::domain::subscription::SubscriptionStatus;
use crate::integrations::stripe::{
    ParsedStripeEvent, StripeCheckoutCompleted, StripeInvoiceChange, StripeSubscriptionChange,
    StripeWebhookReceiptStatus,
};
use crate::repositories::licensing;

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

#[derive(Debug, thiserror::Error)]
pub enum StripeWebhookApplyError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error("Stripe checkout event did not include required checkout fields")]
    MissingCheckoutFields,
    #[error("Stripe subscription event did not include required subscription fields")]
    MissingSubscriptionFields,
    #[error("Stripe invoice event did not include required invoice fields")]
    MissingInvoiceFields,
    #[error("Stripe event could not be mapped to a ForgeCustomer customer")]
    MissingCustomer,
    #[error("Stripe event could not be mapped to an active ForgeCustomer plan version")]
    MissingPlanVersion,
    #[error("Stripe invoice event could not be mapped to an existing subscription")]
    MissingSubscription,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CheckoutPlan {
    pub plan_version_id: Uuid,
    pub plan_key: String,
    pub stripe_price_id: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CheckoutSessionRow {
    pub id: Uuid,
    pub stripe_checkout_session_id: String,
    pub status: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct StripeWebhookEventRow {
    id: Uuid,
    status: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct CheckoutSessionAppliedRow {
    id: Uuid,
    customer_id: Uuid,
    plan_version_id: Uuid,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct ExistingSubscriptionRow {
    id: Uuid,
    customer_id: Uuid,
    plan_version_id: Uuid,
    status: String,
    current_period_end: Option<DateTime<Utc>>,
    cancel_at_period_end: bool,
    stripe_event_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SubscriptionProjectionRow {
    id: Uuid,
    customer_id: Uuid,
    plan_version_id: Uuid,
    status: String,
    current_period_end: Option<DateTime<Utc>>,
    cancel_at_period_end: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct PlanDescriptor {
    product_key: String,
    plan_key: String,
}

struct SubscriptionProjectionInput<'a> {
    existing: Option<&'a ExistingSubscriptionRow>,
    customer_id: Uuid,
    billing_account_id: Uuid,
    plan_version_id: Uuid,
    stripe_subscription_id: &'a str,
    status: SubscriptionStatus,
    current_period_start: Option<DateTime<Utc>>,
    current_period_end: Option<DateTime<Utc>>,
    cancel_at_period_end: bool,
    stripe_event_at: Option<DateTime<Utc>>,
}

struct AuditRecord<'a> {
    event_type: &'a str,
    event: &'a ParsedStripeEvent,
    customer_id: Option<Uuid>,
    target_type: Option<&'a str>,
    target_id: Option<String>,
    before_state: Option<Value>,
    after_state: Option<Value>,
}

pub async fn find_active_checkout_plan(
    pool: &PgPool,
    product_key: &str,
    plan_key: &str,
) -> Result<Option<CheckoutPlan>, sqlx::Error> {
    sqlx::query_as::<_, CheckoutPlan>(
        r#"
        select pv.id as plan_version_id, pl.key as plan_key, pv.stripe_price_id
        from public.plan_versions pv
        join public.plans pl on pl.id = pv.plan_id
        join public.products p on p.id = pl.product_id
        where p.key = $1
          and p.status = 'active'
          and pl.key = $2
          and pl.status = 'active'
          and pv.status = 'active'
        "#,
    )
    .bind(product_key)
    .bind(plan_key)
    .fetch_optional(pool)
    .await
}

pub async fn record_checkout_session(
    pool: &PgPool,
    customer_id: Uuid,
    plan_version_id: Uuid,
    stripe_checkout_session_id: &str,
) -> Result<CheckoutSessionRow, sqlx::Error> {
    sqlx::query_as::<_, CheckoutSessionRow>(
        r#"
        insert into public.checkout_sessions
            (customer_id, plan_version_id, stripe_checkout_session_id, status)
        values
            ($1, $2, $3, 'created')
        on conflict (stripe_checkout_session_id) do update
            set stripe_checkout_session_id = excluded.stripe_checkout_session_id
        returning id, stripe_checkout_session_id, status
        "#,
    )
    .bind(customer_id)
    .bind(plan_version_id)
    .bind(stripe_checkout_session_id)
    .fetch_one(pool)
    .await
}

/// Store and apply a verified Stripe event exactly once. Unsupported events are retained
/// as ignored receipts. Supported events apply their state projection, audit row, and
/// sanitized outbox event in one transaction.
pub async fn process_stripe_webhook_event(
    pool: &PgPool,
    event: &ParsedStripeEvent,
) -> Result<StripeWebhookRecord, StripeWebhookApplyError> {
    let mut tx = pool.begin().await?;
    let inserted = insert_webhook_receipt(&mut tx, event).await?;

    let Some(inserted) = inserted else {
        let existing = fetch_webhook_receipt(&mut tx, &event.id).await?;
        if existing.status == "received"
            && matches!(event.receipt_status, StripeWebhookReceiptStatus::Received)
        {
            apply_supported_event(&mut tx, existing.id, event).await?;
            mark_webhook_processed(&mut tx, existing.id).await?;
            tx.commit().await?;
            return Ok(StripeWebhookRecord {
                outcome: StripeWebhookRecordOutcome::Duplicate,
                status: "processed".to_string(),
            });
        }
        tx.commit().await?;
        return Ok(StripeWebhookRecord {
            outcome: StripeWebhookRecordOutcome::Duplicate,
            status: existing.status,
        });
    };

    if matches!(event.receipt_status, StripeWebhookReceiptStatus::Ignored) {
        tx.commit().await?;
        return Ok(StripeWebhookRecord {
            outcome: StripeWebhookRecordOutcome::Inserted,
            status: inserted.status,
        });
    }

    apply_supported_event(&mut tx, inserted.id, event).await?;

    mark_webhook_processed(&mut tx, inserted.id).await?;
    tx.commit().await?;

    Ok(StripeWebhookRecord {
        outcome: StripeWebhookRecordOutcome::Inserted,
        status: "processed".to_string(),
    })
}

async fn apply_supported_event(
    tx: &mut Transaction<'_, Postgres>,
    webhook_event_id: Uuid,
    event: &ParsedStripeEvent,
) -> Result<(), StripeWebhookApplyError> {
    match event.event_type.as_str() {
        "checkout.session.completed" => {
            let checkout = event
                .checkout_completed()
                .ok_or(StripeWebhookApplyError::MissingCheckoutFields)?;
            apply_checkout_completed(tx, event, &checkout).await?;
        }
        "customer.subscription.created"
        | "customer.subscription.updated"
        | "customer.subscription.deleted" => {
            let change = event
                .subscription_change()
                .ok_or(StripeWebhookApplyError::MissingSubscriptionFields)?;
            apply_subscription_change(tx, webhook_event_id, event, &change).await?;
        }
        "invoice.paid" | "invoice.payment_failed" => {
            let invoice = event
                .invoice_change()
                .ok_or(StripeWebhookApplyError::MissingInvoiceFields)?;
            apply_invoice_change(tx, webhook_event_id, event, &invoice).await?;
        }
        _ => {}
    }
    Ok(())
}

/// Store a verified Stripe event exactly once. This receipt-only path is retained for
/// tests and tooling; the route uses [`process_stripe_webhook_event`] so supported events
/// also apply subscription projection.
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

async fn insert_webhook_receipt(
    tx: &mut Transaction<'_, Postgres>,
    event: &ParsedStripeEvent,
) -> Result<Option<StripeWebhookEventRow>, sqlx::Error> {
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
        returning id, status
        "#
    );

    sqlx::query_as::<_, StripeWebhookEventRow>(&query)
        .bind(&event.id)
        .bind(&event.event_type)
        .bind(status)
        .bind(&event.payload_summary as &Value)
        .fetch_optional(&mut **tx)
        .await
}

async fn fetch_webhook_receipt(
    tx: &mut Transaction<'_, Postgres>,
    event_id: &str,
) -> Result<StripeWebhookEventRow, sqlx::Error> {
    sqlx::query_as::<_, StripeWebhookEventRow>(
        r#"
        select id, status
        from public.stripe_webhook_events
        where stripe_event_id = $1
        "#,
    )
    .bind(event_id)
    .fetch_one(&mut **tx)
    .await
}

async fn mark_webhook_processed(
    tx: &mut Transaction<'_, Postgres>,
    webhook_event_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        update public.stripe_webhook_events
        set status = 'processed', processed_at = now()
        where id = $1
        "#,
    )
    .bind(webhook_event_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn apply_checkout_completed(
    tx: &mut Transaction<'_, Postgres>,
    event: &ParsedStripeEvent,
    checkout: &StripeCheckoutCompleted,
) -> Result<(), StripeWebhookApplyError> {
    let existing = sqlx::query_as::<_, CheckoutSessionAppliedRow>(
        r#"
        update public.checkout_sessions
        set status = 'completed'
        where stripe_checkout_session_id = $1
        returning id, customer_id, plan_version_id
        "#,
    )
    .bind(&checkout.stripe_checkout_session_id)
    .fetch_optional(&mut **tx)
    .await?;

    let row = match (existing, checkout.customer_id, checkout.plan_version_id) {
        (Some(row), _, _) => Some(row),
        (None, Some(customer_id), Some(plan_version_id)) => {
            let inserted = sqlx::query_as::<_, CheckoutSessionAppliedRow>(
                r#"
                insert into public.checkout_sessions
                    (customer_id, plan_version_id, stripe_checkout_session_id, status)
                values
                    ($1, $2, $3, 'completed')
                on conflict (stripe_checkout_session_id) do update
                    set status = 'completed'
                returning id, customer_id, plan_version_id
                "#,
            )
            .bind(customer_id)
            .bind(plan_version_id)
            .bind(&checkout.stripe_checkout_session_id)
            .fetch_one(&mut **tx)
            .await?;
            Some(inserted)
        }
        _ => None,
    };

    if let Some(row) = row {
        let billing_account_id = ensure_billing_account(tx, row.customer_id).await?;
        link_stripe_customer(
            tx,
            billing_account_id,
            checkout.stripe_customer_id.as_deref(),
        )
        .await?;

        write_audit(
            tx,
            AuditRecord {
                event_type: "checkout_completed",
                event,
                customer_id: Some(row.customer_id),
                target_type: Some("checkout_session"),
                target_id: Some(row.id.to_string()),
                before_state: None,
                after_state: Some(json!({
                "checkout_session_id": row.id,
                "plan_version_id": row.plan_version_id,
                "status": "completed",
                "has_stripe_customer": checkout.stripe_customer_id.is_some(),
                "has_stripe_subscription": checkout.stripe_subscription_id.is_some()
                })),
            },
        )
        .await?;
    }

    Ok(())
}

async fn apply_subscription_change(
    tx: &mut Transaction<'_, Postgres>,
    webhook_event_id: Uuid,
    event: &ParsedStripeEvent,
    change: &StripeSubscriptionChange,
) -> Result<(), StripeWebhookApplyError> {
    let existing = find_subscription_by_stripe_id(tx, &change.stripe_subscription_id).await?;
    if is_stale_event(
        event.created_at(),
        existing.as_ref().and_then(|row| row.stripe_event_at),
    ) {
        write_audit(
            tx,
            AuditRecord {
                event_type: "subscription_event_skipped",
                event,
                customer_id: existing.as_ref().map(|row| row.customer_id),
                target_type: Some("subscription"),
                target_id: existing.as_ref().map(|row| row.id.to_string()),
                before_state: existing.as_ref().map(existing_subscription_state),
                after_state: Some(
                    json!({ "reason": "out_of_order", "event_type": event.event_type }),
                ),
            },
        )
        .await?;
        return Ok(());
    }

    let customer_id = resolve_customer_id(
        tx,
        change.customer_id,
        change.stripe_customer_id.as_deref(),
        existing.as_ref(),
    )
    .await?
    .ok_or(StripeWebhookApplyError::MissingCustomer)?;
    let plan_version_id = resolve_plan_version_id(
        tx,
        change.plan_version_id,
        change.stripe_price_id.as_deref(),
        existing.as_ref(),
    )
    .await?
    .ok_or(StripeWebhookApplyError::MissingPlanVersion)?;

    let billing_account_id = ensure_billing_account(tx, customer_id).await?;
    link_stripe_customer(tx, billing_account_id, change.stripe_customer_id.as_deref()).await?;

    let before = existing.as_ref().map(existing_subscription_state);
    let row = upsert_subscription_projection(
        tx,
        SubscriptionProjectionInput {
            existing: existing.as_ref(),
            customer_id,
            billing_account_id,
            plan_version_id,
            stripe_subscription_id: &change.stripe_subscription_id,
            status: change.status,
            current_period_start: change.current_period_start,
            current_period_end: change.current_period_end,
            cancel_at_period_end: change.cancel_at_period_end,
            stripe_event_at: event.created_at(),
        },
    )
    .await?;

    let after = subscription_projection_state(&row);
    write_audit(
        tx,
        AuditRecord {
            event_type: "subscription_changed",
            event,
            customer_id: Some(row.customer_id),
            target_type: Some("subscription"),
            target_id: Some(row.id.to_string()),
            before_state: before,
            after_state: Some(after.clone()),
        },
    )
    .await?;
    write_subscription_outbox(tx, &webhook_event_id.to_string(), event.created_at(), &row).await?;
    sync_license_from_subscription_truth(tx, event, &row, change.status).await?;

    Ok(())
}

/// Keep the subscription-linked license consistent with the projected subscription, with
/// a stripe-actor audit record for any license mutation it causes.
async fn sync_license_from_subscription_truth(
    tx: &mut Transaction<'_, Postgres>,
    event: &ParsedStripeEvent,
    subscription: &SubscriptionProjectionRow,
    status: SubscriptionStatus,
) -> Result<(), StripeWebhookApplyError> {
    let Some(sync) = licensing::sync_license_for_subscription(
        tx,
        subscription.customer_id,
        subscription.id,
        subscription.plan_version_id,
        status,
    )
    .await?
    else {
        return Ok(());
    };

    write_audit(
        tx,
        AuditRecord {
            event_type: sync.audit_event_type(),
            event,
            customer_id: Some(subscription.customer_id),
            target_type: Some("license"),
            target_id: Some(sync.license_id.to_string()),
            before_state: sync.before_state(),
            after_state: Some(sync.after_state()),
        },
    )
    .await?;
    Ok(())
}

async fn apply_invoice_change(
    tx: &mut Transaction<'_, Postgres>,
    webhook_event_id: Uuid,
    event: &ParsedStripeEvent,
    invoice: &StripeInvoiceChange,
) -> Result<(), StripeWebhookApplyError> {
    let existing = find_subscription_by_stripe_id(tx, &invoice.stripe_subscription_id)
        .await?
        .ok_or(StripeWebhookApplyError::MissingSubscription)?;

    record_invoice_reference(tx, existing.id, invoice).await?;

    if is_stale_event(event.created_at(), existing.stripe_event_at) {
        write_audit(
            tx,
            AuditRecord {
                event_type: "invoice_event_skipped",
                event,
                customer_id: Some(existing.customer_id),
                target_type: Some("subscription"),
                target_id: Some(existing.id.to_string()),
                before_state: Some(existing_subscription_state(&existing)),
                after_state: Some(json!({
                "reason": "out_of_order",
                "invoice_status": invoice.invoice_status
                })),
            },
        )
        .await?;
        return Ok(());
    }

    if existing.status == SubscriptionStatus::Canceled.as_str()
        && invoice.status == SubscriptionStatus::Active
    {
        write_audit(
            tx,
            AuditRecord {
                event_type: "invoice_recorded",
                event,
                customer_id: Some(existing.customer_id),
                target_type: Some("subscription"),
                target_id: Some(existing.id.to_string()),
                before_state: Some(existing_subscription_state(&existing)),
                after_state: Some(json!({
                "invoice_status": invoice.invoice_status,
                "subscription_status_preserved": existing.status
                })),
            },
        )
        .await?;
        return Ok(());
    }

    let before = existing_subscription_state(&existing);
    let row = update_subscription_status_from_invoice(
        tx,
        existing.id,
        invoice.status,
        event.created_at(),
    )
    .await?;
    let after = subscription_projection_state(&row);

    if before != after {
        write_audit(
            tx,
            AuditRecord {
                event_type: "subscription_changed",
                event,
                customer_id: Some(row.customer_id),
                target_type: Some("subscription"),
                target_id: Some(row.id.to_string()),
                before_state: Some(before),
                after_state: Some(after),
            },
        )
        .await?;
        write_subscription_outbox(tx, &webhook_event_id.to_string(), event.created_at(), &row)
            .await?;
        sync_license_from_subscription_truth(tx, event, &row, invoice.status).await?;
    } else {
        write_audit(
            tx,
            AuditRecord {
                event_type: "invoice_recorded",
                event,
                customer_id: Some(row.customer_id),
                target_type: Some("subscription"),
                target_id: Some(row.id.to_string()),
                before_state: None,
                after_state: Some(json!({ "invoice_status": invoice.invoice_status })),
            },
        )
        .await?;
    }

    Ok(())
}

async fn find_subscription_by_stripe_id(
    tx: &mut Transaction<'_, Postgres>,
    stripe_subscription_id: &str,
) -> Result<Option<ExistingSubscriptionRow>, sqlx::Error> {
    sqlx::query_as::<_, ExistingSubscriptionRow>(
        r#"
        select id, customer_id, plan_version_id, status, current_period_end,
               cancel_at_period_end, stripe_event_at
        from public.subscriptions
        where stripe_subscription_id = $1
        "#,
    )
    .bind(stripe_subscription_id)
    .fetch_optional(&mut **tx)
    .await
}

async fn resolve_customer_id(
    tx: &mut Transaction<'_, Postgres>,
    metadata_customer_id: Option<Uuid>,
    stripe_customer_id: Option<&str>,
    existing: Option<&ExistingSubscriptionRow>,
) -> Result<Option<Uuid>, sqlx::Error> {
    if metadata_customer_id.is_some() {
        return Ok(metadata_customer_id);
    }
    if let Some(row) = existing {
        return Ok(Some(row.customer_id));
    }
    let Some(stripe_customer_id) = stripe_customer_id else {
        return Ok(None);
    };
    sqlx::query_scalar::<_, Uuid>(
        r#"
        select ba.customer_id
        from public.stripe_customers sc
        join public.billing_accounts ba on ba.id = sc.billing_account_id
        where sc.stripe_customer_id = $1
        "#,
    )
    .bind(stripe_customer_id)
    .fetch_optional(&mut **tx)
    .await
}

async fn resolve_plan_version_id(
    tx: &mut Transaction<'_, Postgres>,
    metadata_plan_version_id: Option<Uuid>,
    stripe_price_id: Option<&str>,
    existing: Option<&ExistingSubscriptionRow>,
) -> Result<Option<Uuid>, sqlx::Error> {
    if metadata_plan_version_id.is_some() {
        return Ok(metadata_plan_version_id);
    }
    if let Some(row) = existing {
        return Ok(Some(row.plan_version_id));
    }
    let Some(stripe_price_id) = stripe_price_id else {
        return Ok(None);
    };
    sqlx::query_scalar::<_, Uuid>(
        r#"
        select id
        from public.plan_versions
        where stripe_price_id = $1
          and status = 'active'
        "#,
    )
    .bind(stripe_price_id)
    .fetch_optional(&mut **tx)
    .await
}

async fn ensure_billing_account(
    tx: &mut Transaction<'_, Postgres>,
    customer_id: Uuid,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        r#"
        insert into public.billing_accounts (customer_id)
        values ($1)
        on conflict (customer_id) do update
            set updated_at = now()
        returning id
        "#,
    )
    .bind(customer_id)
    .fetch_one(&mut **tx)
    .await
}

async fn link_stripe_customer(
    tx: &mut Transaction<'_, Postgres>,
    billing_account_id: Uuid,
    stripe_customer_id: Option<&str>,
) -> Result<(), sqlx::Error> {
    let Some(stripe_customer_id) = stripe_customer_id.filter(|value| !value.trim().is_empty())
    else {
        return Ok(());
    };
    sqlx::query(
        r#"
        insert into public.stripe_customers (billing_account_id, stripe_customer_id)
        values ($1, $2)
        on conflict (stripe_customer_id) do nothing
        "#,
    )
    .bind(billing_account_id)
    .bind(stripe_customer_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn upsert_subscription_projection(
    tx: &mut Transaction<'_, Postgres>,
    input: SubscriptionProjectionInput<'_>,
) -> Result<SubscriptionProjectionRow, sqlx::Error> {
    match input.existing {
        Some(existing) => {
            sqlx::query_as::<_, SubscriptionProjectionRow>(
                r#"
                update public.subscriptions
                set billing_account_id = $2,
                    plan_version_id = $3,
                    status = $4,
                    current_period_start = $5,
                    current_period_end = $6,
                    cancel_at_period_end = $7,
                    stripe_event_at = $8
                where id = $1
                returning id, customer_id, plan_version_id, status, current_period_end,
                          cancel_at_period_end
                "#,
            )
            .bind(existing.id)
            .bind(input.billing_account_id)
            .bind(input.plan_version_id)
            .bind(input.status.as_str())
            .bind(input.current_period_start)
            .bind(input.current_period_end)
            .bind(input.cancel_at_period_end)
            .bind(input.stripe_event_at)
            .fetch_one(&mut **tx)
            .await
        }
        None => {
            sqlx::query_as::<_, SubscriptionProjectionRow>(
                r#"
                insert into public.subscriptions
                    (customer_id, billing_account_id, plan_version_id, stripe_subscription_id,
                     status, current_period_start, current_period_end, cancel_at_period_end,
                     stripe_event_at)
                values
                    ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                returning id, customer_id, plan_version_id, status, current_period_end,
                          cancel_at_period_end
                "#,
            )
            .bind(input.customer_id)
            .bind(input.billing_account_id)
            .bind(input.plan_version_id)
            .bind(input.stripe_subscription_id)
            .bind(input.status.as_str())
            .bind(input.current_period_start)
            .bind(input.current_period_end)
            .bind(input.cancel_at_period_end)
            .bind(input.stripe_event_at)
            .fetch_one(&mut **tx)
            .await
        }
    }
}

async fn update_subscription_status_from_invoice(
    tx: &mut Transaction<'_, Postgres>,
    subscription_id: Uuid,
    status: SubscriptionStatus,
    stripe_event_at: Option<DateTime<Utc>>,
) -> Result<SubscriptionProjectionRow, sqlx::Error> {
    sqlx::query_as::<_, SubscriptionProjectionRow>(
        r#"
        update public.subscriptions
        set status = $2,
            stripe_event_at = $3
        where id = $1
        returning id, customer_id, plan_version_id, status, current_period_end,
                  cancel_at_period_end
        "#,
    )
    .bind(subscription_id)
    .bind(status.as_str())
    .bind(stripe_event_at)
    .fetch_one(&mut **tx)
    .await
}

async fn record_invoice_reference(
    tx: &mut Transaction<'_, Postgres>,
    subscription_id: Uuid,
    invoice: &StripeInvoiceChange,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        insert into public.invoice_references
            (subscription_id, stripe_invoice_id, status, amount_due_cents, currency)
        values
            ($1, $2, $3, $4, $5)
        on conflict (stripe_invoice_id) do update
            set subscription_id = excluded.subscription_id,
                status = excluded.status,
                amount_due_cents = excluded.amount_due_cents,
                currency = excluded.currency
        "#,
    )
    .bind(subscription_id)
    .bind(&invoice.stripe_invoice_id)
    .bind(&invoice.invoice_status)
    .bind(invoice.amount_due_cents)
    .bind(invoice.currency.as_deref())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn plan_descriptor(
    tx: &mut Transaction<'_, Postgres>,
    plan_version_id: Uuid,
) -> Result<Option<PlanDescriptor>, sqlx::Error> {
    sqlx::query_as::<_, PlanDescriptor>(
        r#"
        select p.key as product_key, pl.key as plan_key
        from public.plan_versions pv
        join public.plans pl on pl.id = pv.plan_id
        join public.products p on p.id = pl.product_id
        where pv.id = $1
        "#,
    )
    .bind(plan_version_id)
    .fetch_optional(&mut **tx)
    .await
}

async fn write_subscription_outbox(
    tx: &mut Transaction<'_, Postgres>,
    delivery_discriminator: &str,
    occurred_at: Option<DateTime<Utc>>,
    subscription: &SubscriptionProjectionRow,
) -> Result<(), sqlx::Error> {
    let plan = plan_descriptor(tx, subscription.plan_version_id).await?;
    let payload = sanitize(&json!({
        "customer_id": subscription.customer_id,
        "subscription_id": subscription.id,
        "plan_version_id": subscription.plan_version_id,
        "product": plan.as_ref().map(|p| p.product_key.as_str()),
        "plan_key": plan.as_ref().map(|p| p.plan_key.as_str()),
        "status": subscription.status,
        "grants_cloud": matches!(subscription.status.as_str(), "trialing" | "active"),
        "cancel_at_period_end": subscription.cancel_at_period_end,
        "current_period_end": subscription.current_period_end,
        "occurred_at": occurred_at,
    }));
    let delivery_key = format!(
        "subscription_changed:{}:{delivery_discriminator}",
        subscription.id
    );

    sqlx::query(
        r#"
        insert into public.outbox_events (event_type, delivery_key, payload)
        values ('subscription_changed', $1, $2)
        on conflict (delivery_key) do nothing
        "#,
    )
    .bind(delivery_key)
    .bind(payload)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn write_audit(
    tx: &mut Transaction<'_, Postgres>,
    record: AuditRecord<'_>,
) -> Result<(), sqlx::Error> {
    let before_state = record.before_state.map(|value| sanitize(&value));
    let after_state = record.after_state.map(|value| sanitize(&value));
    sqlx::query(
        r#"
        insert into public.commercial_audit_events
            (event_type, actor_type, actor_id, customer_id, target_type, target_id, reason,
             before_state, after_state, correlation_id)
        values
            ($1, 'stripe', $2, $3, $4, $5, $6, $7, $8, $2)
        "#,
    )
    .bind(record.event_type)
    .bind(&record.event.id)
    .bind(record.customer_id)
    .bind(record.target_type)
    .bind(record.target_id)
    .bind(&record.event.event_type)
    .bind(before_state)
    .bind(after_state)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn is_stale_event(incoming: Option<DateTime<Utc>>, existing: Option<DateTime<Utc>>) -> bool {
    match (incoming, existing) {
        (Some(incoming), Some(existing)) => incoming < existing,
        _ => false,
    }
}

// --- Admin resync (operator-driven; Forge Command surface) ---------------------

/// Subscription identifiers needed to pull current truth from Stripe.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ResyncTarget {
    pub id: Uuid,
    pub stripe_subscription_id: String,
}

pub async fn find_subscription_for_resync(
    pool: &PgPool,
    subscription_id: Uuid,
) -> Result<Option<ResyncTarget>, sqlx::Error> {
    sqlx::query_as::<_, ResyncTarget>(
        "select id, stripe_subscription_id from public.subscriptions where id = $1",
    )
    .bind(subscription_id)
    .fetch_optional(pool)
    .await
}

#[derive(Debug, Clone)]
pub struct AdminResyncOutcome {
    pub subscription_id: Uuid,
    pub customer_id: Uuid,
    pub status: String,
    pub changed: bool,
    pub license_change: Option<&'static str>,
}

/// Apply freshly fetched Stripe subscription truth on an operator's behalf: reproject the
/// subscription, sync the linked license, and write operator-actor audit for both. The
/// projection's `stripe_event_at` is set to now so older out-of-order webhooks arriving
/// later are recognized as stale. The `subscription_changed` outbox event is only queued
/// when the projection actually changed.
pub async fn apply_admin_resync(
    pool: &PgPool,
    subscription_id: Uuid,
    change: &StripeSubscriptionChange,
    operator_id: &str,
    reason: &str,
    correlation_id: Option<&str>,
) -> Result<Option<AdminResyncOutcome>, StripeWebhookApplyError> {
    let mut tx = pool.begin().await?;

    let existing = sqlx::query_as::<_, ExistingSubscriptionRow>(
        r#"
        select id, customer_id, plan_version_id, status, current_period_end,
               cancel_at_period_end, stripe_event_at
        from public.subscriptions
        where id = $1
        for update
        "#,
    )
    .bind(subscription_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(existing) = existing else {
        return Ok(None);
    };

    let customer_id = resolve_customer_id(
        &mut tx,
        change.customer_id,
        change.stripe_customer_id.as_deref(),
        Some(&existing),
    )
    .await?
    .ok_or(StripeWebhookApplyError::MissingCustomer)?;
    let plan_version_id = resolve_plan_version_id(
        &mut tx,
        change.plan_version_id,
        change.stripe_price_id.as_deref(),
        Some(&existing),
    )
    .await?
    .ok_or(StripeWebhookApplyError::MissingPlanVersion)?;
    let billing_account_id = ensure_billing_account(&mut tx, customer_id).await?;
    link_stripe_customer(
        &mut tx,
        billing_account_id,
        change.stripe_customer_id.as_deref(),
    )
    .await?;

    let before = existing_subscription_state(&existing);
    let now = Utc::now();
    let row = upsert_subscription_projection(
        &mut tx,
        SubscriptionProjectionInput {
            existing: Some(&existing),
            customer_id,
            billing_account_id,
            plan_version_id,
            stripe_subscription_id: &change.stripe_subscription_id,
            status: change.status,
            current_period_start: change.current_period_start,
            current_period_end: change.current_period_end,
            cancel_at_period_end: change.cancel_at_period_end,
            stripe_event_at: Some(now),
        },
    )
    .await?;
    let after = subscription_projection_state(&row);
    let changed = before != after;

    crate::repositories::admin::write_operator_audit(
        &mut tx,
        crate::repositories::admin::OperatorAudit {
            event_type: "subscription_resynced",
            operator_id,
            customer_id: Some(row.customer_id),
            target_type: "subscription",
            target_id: row.id.to_string(),
            reason,
            before_state: Some(before),
            after_state: Some(after),
            correlation_id,
        },
    )
    .await?;
    if changed {
        write_subscription_outbox(
            &mut tx,
            &format!("resync:{}", Uuid::new_v4()),
            Some(now),
            &row,
        )
        .await?;
    }

    let sync = licensing::sync_license_for_subscription(
        &mut tx,
        row.customer_id,
        row.id,
        row.plan_version_id,
        change.status,
    )
    .await?;
    if let Some(sync) = &sync {
        crate::repositories::admin::write_operator_audit(
            &mut tx,
            crate::repositories::admin::OperatorAudit {
                event_type: sync.audit_event_type(),
                operator_id,
                customer_id: Some(row.customer_id),
                target_type: "license",
                target_id: sync.license_id.to_string(),
                reason,
                before_state: sync.before_state(),
                after_state: Some(sync.after_state()),
                correlation_id,
            },
        )
        .await?;
    }

    tx.commit().await?;
    Ok(Some(AdminResyncOutcome {
        subscription_id: row.id,
        customer_id: row.customer_id,
        status: row.status.clone(),
        changed,
        license_change: sync.map(|sync| sync.audit_event_type()),
    }))
}

fn existing_subscription_state(row: &ExistingSubscriptionRow) -> Value {
    json!({
        "subscription_id": row.id,
        "customer_id": row.customer_id,
        "plan_version_id": row.plan_version_id,
        "status": row.status,
        "current_period_end": row.current_period_end,
        "cancel_at_period_end": row.cancel_at_period_end,
    })
}

fn subscription_projection_state(row: &SubscriptionProjectionRow) -> Value {
    json!({
        "subscription_id": row.id,
        "customer_id": row.customer_id,
        "plan_version_id": row.plan_version_id,
        "status": row.status,
        "current_period_end": row.current_period_end,
        "cancel_at_period_end": row.cancel_at_period_end,
    })
}
