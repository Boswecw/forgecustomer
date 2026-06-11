//! Privacy persistence: the account-deletion workflow state machine and the
//! anonymization execution.
//!
//! Cooling-off is non-destructive (a customer cancel restores nothing because nothing
//! was touched). Execution is the point of no return: it anonymizes profile PII, deletes
//! contact emails, revokes devices and licenses (with explicit revocation records),
//! deactivates installations, writes a PII-free deletion receipt, queues the sanitized
//! `customer_anonymized` outbox event, and audits `deletion_completed` — all in one
//! transaction. Legally required accounting records (billing/invoice references, audit,
//! usage ledger) are retained per `docs/PRIVACY.md`.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::domain::deletion::{can_cancel, can_execute, can_reject, next_state};
use crate::repositories::admin::{write_operator_audit, OperatorAudit};
use crate::repositories::licensing::{write_customer_audit, write_outbox, CustomerAudit};

#[derive(Debug, thiserror::Error)]
pub enum DeletionError {
    #[error("deletion request not found")]
    NotFound,
    #[error("invalid state for this transition ({0})")]
    InvalidState(String),
    #[error("cooling-off period has not elapsed")]
    CoolingOffActive,
    #[error("customer still has a non-terminal subscription")]
    SubscriptionStillActive,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct DeletionRequestRow {
    pub id: Uuid,
    pub customer_id: Uuid,
    pub status: String,
    pub requested_at: DateTime<Utc>,
    pub cooling_off_until: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub receipt: Option<Value>,
    pub reason: Option<String>,
}

const REQUEST_COLUMNS: &str =
    "id, customer_id, status, requested_at, cooling_off_until, completed_at, receipt, reason";

#[derive(Debug, Clone)]
pub struct RequestedDeletion {
    pub request: DeletionRequestRow,
    pub created: bool,
}

/// Open (or return the existing open) deletion request for the customer. One
/// non-terminal request exists at a time; repeats are idempotent.
pub async fn request_deletion(
    pool: &PgPool,
    customer_id: Uuid,
    reason: Option<&str>,
    correlation_id: Option<&str>,
) -> Result<RequestedDeletion, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let existing = sqlx::query_as::<_, DeletionRequestRow>(&format!(
        r#"
        select {REQUEST_COLUMNS} from public.account_deletion_requests
        where customer_id = $1
          and status not in ('completed','rejected','canceled')
        order by requested_at desc
        limit 1
        for update
        "#
    ))
    .bind(customer_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(request) = existing {
        tx.commit().await?;
        return Ok(RequestedDeletion {
            request,
            created: false,
        });
    }

    let request = sqlx::query_as::<_, DeletionRequestRow>(&format!(
        r#"
        insert into public.account_deletion_requests (customer_id, reason)
        values ($1, $2)
        returning {REQUEST_COLUMNS}
        "#
    ))
    .bind(customer_id)
    .bind(reason)
    .fetch_one(&mut *tx)
    .await?;

    write_customer_audit(
        &mut tx,
        CustomerAudit {
            event_type: "deletion_requested",
            customer_id,
            target_type: "deletion_request",
            target_id: request.id.to_string(),
            reason: reason.unwrap_or("customer_request"),
            before_state: None,
            after_state: Some(json!({ "status": "requested" })),
            correlation_id,
        },
    )
    .await?;

    tx.commit().await?;
    Ok(RequestedDeletion {
        request,
        created: true,
    })
}

/// The customer's most recent deletion request, regardless of state.
pub async fn latest_request(
    pool: &PgPool,
    customer_id: Uuid,
) -> Result<Option<DeletionRequestRow>, sqlx::Error> {
    sqlx::query_as::<_, DeletionRequestRow>(&format!(
        r#"
        select {REQUEST_COLUMNS} from public.account_deletion_requests
        where customer_id = $1
        order by requested_at desc
        limit 1
        "#
    ))
    .bind(customer_id)
    .fetch_optional(pool)
    .await
}

async fn lock_request(
    tx: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
    customer_id: Option<Uuid>,
) -> Result<DeletionRequestRow, DeletionError> {
    let request = sqlx::query_as::<_, DeletionRequestRow>(&format!(
        r#"
        select {REQUEST_COLUMNS} from public.account_deletion_requests
        where id = $1 and ($2::uuid is null or customer_id = $2)
        for update
        "#
    ))
    .bind(request_id)
    .bind(customer_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(DeletionError::NotFound)?;
    Ok(request)
}

async fn set_request_status(
    tx: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
    status: &str,
    cooling_off_until: Option<DateTime<Utc>>,
) -> Result<DeletionRequestRow, sqlx::Error> {
    sqlx::query_as::<_, DeletionRequestRow>(&format!(
        r#"
        update public.account_deletion_requests
        set status = $2,
            cooling_off_until = coalesce($3, cooling_off_until)
        where id = $1
        returning {REQUEST_COLUMNS}
        "#
    ))
    .bind(request_id)
    .bind(status)
    .bind(cooling_off_until)
    .fetch_one(&mut **tx)
    .await
}

/// Customer-initiated cancel: clean while not yet processing.
pub async fn cancel_request(
    pool: &PgPool,
    customer_id: Uuid,
    correlation_id: Option<&str>,
) -> Result<DeletionRequestRow, DeletionError> {
    let mut tx = pool.begin().await?;

    let request = sqlx::query_as::<_, DeletionRequestRow>(&format!(
        r#"
        select {REQUEST_COLUMNS} from public.account_deletion_requests
        where customer_id = $1
          and status not in ('completed','rejected','canceled')
        order by requested_at desc
        limit 1
        for update
        "#
    ))
    .bind(customer_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(DeletionError::NotFound)?;
    if !can_cancel(&request.status) {
        return Err(DeletionError::InvalidState(request.status));
    }

    let updated = set_request_status(&mut tx, request.id, "canceled", None).await?;
    write_customer_audit(
        &mut tx,
        CustomerAudit {
            event_type: "deletion_request_canceled",
            customer_id,
            target_type: "deletion_request",
            target_id: request.id.to_string(),
            reason: "customer_cancel",
            before_state: Some(json!({ "status": request.status })),
            after_state: Some(json!({ "status": "canceled" })),
            correlation_id,
        },
    )
    .await?;

    tx.commit().await?;
    Ok(updated)
}

/// Operator listing, optionally filtered by status.
pub async fn list_requests(
    pool: &PgPool,
    status: Option<&str>,
    limit: i64,
) -> Result<Vec<DeletionRequestRow>, sqlx::Error> {
    sqlx::query_as::<_, DeletionRequestRow>(&format!(
        r#"
        select {REQUEST_COLUMNS} from public.account_deletion_requests
        where ($1::text is null or status = $1)
        order by requested_at desc
        limit $2
        "#
    ))
    .bind(status)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Operator-driven forward transition (requested → verified → cooling_off → processing).
/// Entering cooling_off stamps the configured window; entering processing requires the
/// window to have elapsed (fail closed).
pub async fn advance_request(
    pool: &PgPool,
    operator_id: &str,
    request_id: Uuid,
    cooling_off: chrono::Duration,
    reason: &str,
    correlation_id: Option<&str>,
) -> Result<DeletionRequestRow, DeletionError> {
    let mut tx = pool.begin().await?;

    let request = lock_request(&mut tx, request_id, None).await?;
    let Some(next) = next_state(&request.status) else {
        return Err(DeletionError::InvalidState(request.status));
    };

    let cooling_off_until = match next {
        "cooling_off" => Some(Utc::now() + cooling_off),
        "processing" => {
            let until = request.cooling_off_until.ok_or_else(|| {
                DeletionError::InvalidState("cooling_off window was never stamped".to_string())
            })?;
            if until > Utc::now() {
                return Err(DeletionError::CoolingOffActive);
            }
            None
        }
        _ => None,
    };

    let updated = set_request_status(&mut tx, request_id, next, cooling_off_until).await?;
    write_operator_audit(
        &mut tx,
        OperatorAudit {
            event_type: "deletion_request_advanced",
            operator_id,
            customer_id: Some(request.customer_id),
            target_type: "deletion_request",
            target_id: request_id.to_string(),
            reason,
            before_state: Some(json!({ "status": request.status })),
            after_state: Some(json!({
                "status": next,
                "cooling_off_until": updated.cooling_off_until,
            })),
            correlation_id,
        },
    )
    .await?;

    tx.commit().await?;
    Ok(updated)
}

/// Operator rejection of a not-yet-processing request.
pub async fn reject_request(
    pool: &PgPool,
    operator_id: &str,
    request_id: Uuid,
    reason: &str,
    correlation_id: Option<&str>,
) -> Result<DeletionRequestRow, DeletionError> {
    let mut tx = pool.begin().await?;

    let request = lock_request(&mut tx, request_id, None).await?;
    if !can_reject(&request.status) {
        return Err(DeletionError::InvalidState(request.status));
    }

    let updated = set_request_status(&mut tx, request_id, "rejected", None).await?;
    write_operator_audit(
        &mut tx,
        OperatorAudit {
            event_type: "deletion_request_rejected",
            operator_id,
            customer_id: Some(request.customer_id),
            target_type: "deletion_request",
            target_id: request_id.to_string(),
            reason,
            before_state: Some(json!({ "status": request.status })),
            after_state: Some(json!({ "status": "rejected" })),
            correlation_id,
        },
    )
    .await?;

    tx.commit().await?;
    Ok(updated)
}

/// Execute the deletion from `processing`: anonymize and freeze commercial state, write
/// the receipt, emit `customer_anonymized`, audit `deletion_completed`. Refuses while
/// any non-terminal subscription remains (cancel in Stripe first; resync projects it).
pub async fn execute_deletion(
    pool: &PgPool,
    operator_id: &str,
    request_id: Uuid,
    reason: &str,
    correlation_id: Option<&str>,
) -> Result<DeletionRequestRow, DeletionError> {
    let mut tx = pool.begin().await?;

    let request = lock_request(&mut tx, request_id, None).await?;
    if !can_execute(&request.status) {
        return Err(DeletionError::InvalidState(request.status));
    }
    let customer_id = request.customer_id;

    // Lock the profile row for the duration of the anonymization.
    let prior_status = sqlx::query_scalar::<_, String>(
        "select status from public.customer_profiles where id = $1 for update",
    )
    .bind(customer_id)
    .fetch_one(&mut *tx)
    .await?;

    // Subscriptions must already be terminal locally (canceled at Stripe + projected).
    let open_subscriptions = sqlx::query_scalar::<_, i64>(
        r#"
        select count(*) from public.subscriptions
        where customer_id = $1 and status not in ('canceled')
        "#,
    )
    .bind(customer_id)
    .fetch_one(&mut *tx)
    .await?;
    if open_subscriptions > 0 {
        return Err(DeletionError::SubscriptionStillActive);
    }

    // Direct PII: profile decoration + contact emails.
    sqlx::query(
        r#"
        update public.customer_profiles
        set status = 'anonymized', display_name = null, country_code = null, timezone = null
        where id = $1
        "#,
    )
    .bind(customer_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r#"
        insert into public.customer_status_history
            (customer_id, from_status, to_status, reason, actor_type, actor_id)
        values ($1, $2, 'anonymized', 'account_deletion', 'operator', $3)
        "#,
    )
    .bind(customer_id)
    .bind(&prior_status)
    .bind(operator_id)
    .execute(&mut *tx)
    .await?;
    let emails_deleted = sqlx::query("delete from public.customer_emails where customer_id = $1")
        .bind(customer_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

    // Device identity: revoke and strip labels (keys are pseudonymous; rows retained
    // for revocation integrity).
    let devices_revoked = sqlx::query(
        "update public.devices set status = 'revoked', label = null where customer_id = $1",
    )
    .bind(customer_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    // Licenses: explicit revocation (never silently reactivatable).
    let license_ids = sqlx::query_scalar::<_, Uuid>(
        r#"
        update public.licenses
        set status = 'revoked'
        where customer_id = $1 and status <> 'revoked'
        returning id
        "#,
    )
    .bind(customer_id)
    .fetch_all(&mut *tx)
    .await?;
    for license_id in &license_ids {
        sqlx::query(
            r#"
            insert into public.license_revocations (license_id, reason, actor_type, actor_id)
            values ($1, 'account_deletion', 'operator', $2)
            "#,
        )
        .bind(license_id)
        .bind(operator_id)
        .execute(&mut *tx)
        .await?;
    }

    // Installations: deactivate and release their activations.
    let installations_deactivated = sqlx::query(
        r#"
        update public.installations
        set status = 'deactivated'
        where customer_id = $1 and status = 'active'
        "#,
    )
    .bind(customer_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    sqlx::query(
        r#"
        update public.license_activations a
        set status = 'deactivated', deactivated_at = now()
        from public.licenses l
        where a.license_id = l.id and l.customer_id = $1 and a.status = 'active'
        "#,
    )
    .bind(customer_id)
    .execute(&mut *tx)
    .await?;

    // Entitlement overrides/grants die with the account.
    sqlx::query("update public.entitlement_overrides set active = false where customer_id = $1")
        .bind(customer_id)
        .execute(&mut *tx)
        .await?;

    // PII-free receipt: what changed, what is retained and why.
    let receipt = json!({
        "profile_anonymized": true,
        "emails_deleted": emails_deleted,
        "devices_revoked": devices_revoked,
        "licenses_revoked": license_ids.len(),
        "installations_deactivated": installations_deactivated,
        "retained": {
            "billing_and_invoice_references": "statutory accounting period",
            "commercial_audit_events": "append-only integrity",
            "usage_ledger": "billing correctness (aggregates, no PII)",
            "consent_records": "legal evidence of consent",
        },
        "external_steps": {
            "supabase_auth_user": "deleted/disabled via Supabase Auth by the operator",
            "stripe_customer": "subscriptions canceled at Stripe before execution",
        },
    });

    let updated = sqlx::query_as::<_, DeletionRequestRow>(&format!(
        r#"
        update public.account_deletion_requests
        set status = 'completed', completed_at = now(), receipt = $2
        where id = $1
        returning {REQUEST_COLUMNS}
        "#
    ))
    .bind(request_id)
    .bind(&receipt)
    .fetch_one(&mut *tx)
    .await?;

    write_outbox(
        &mut tx,
        "customer_anonymized",
        format!("customer_anonymized:{request_id}"),
        json!({
            "customer_id": customer_id,
            "occurred_at": Utc::now(),
        }),
    )
    .await?;
    write_operator_audit(
        &mut tx,
        OperatorAudit {
            event_type: "deletion_completed",
            operator_id,
            customer_id: Some(customer_id),
            target_type: "deletion_request",
            target_id: request_id.to_string(),
            reason,
            before_state: Some(json!({ "status": "processing", "customer_status": prior_status })),
            after_state: Some(receipt),
            correlation_id,
        },
    )
    .await?;

    tx.commit().await?;
    Ok(updated)
}
