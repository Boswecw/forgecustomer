//! Operator/admin persistence, consumed by Forge Command through `/v1/admin/*`.
//!
//! Every mutation runs in a transaction with an operator-actor commercial-audit row
//! carrying the operator id and the written reason; status changes and revocations also
//! queue their sanitized outbox events. Mutations are idempotent where retried operator
//! actions are plausible (suspend/restore, revoke, usage adjustment by idempotency key).

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::domain::admin::OverrideValue;
use crate::domain::redaction::sanitize;
use crate::repositories::licensing::write_outbox;

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("customer not found")]
    CustomerNotFound,
    #[error("product not found")]
    ProductNotFound,
    #[error("license not found")]
    LicenseNotFound,
    #[error("usage meter not found")]
    MeterNotFound,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Operator-actor audit record; every admin mutation writes one.
pub(crate) struct OperatorAudit<'a> {
    pub(crate) event_type: &'a str,
    pub(crate) operator_id: &'a str,
    pub(crate) customer_id: Option<Uuid>,
    pub(crate) target_type: &'a str,
    pub(crate) target_id: String,
    pub(crate) reason: &'a str,
    pub(crate) before_state: Option<Value>,
    pub(crate) after_state: Option<Value>,
    pub(crate) correlation_id: Option<&'a str>,
}

pub(crate) async fn write_operator_audit(
    tx: &mut Transaction<'_, Postgres>,
    record: OperatorAudit<'_>,
) -> Result<(), sqlx::Error> {
    let before_state = record.before_state.map(|value| sanitize(&value));
    let after_state = record.after_state.map(|value| sanitize(&value));
    sqlx::query(
        r#"
        insert into public.commercial_audit_events
            (event_type, actor_type, actor_id, customer_id, target_type, target_id, reason,
             before_state, after_state, correlation_id)
        values
            ($1, 'operator', $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(record.event_type)
    .bind(record.operator_id)
    .bind(record.customer_id)
    .bind(record.target_type)
    .bind(record.target_id)
    .bind(record.reason)
    .bind(before_state)
    .bind(after_state)
    .bind(record.correlation_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

// --- Customer listing & status ----------------------------------------------

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct AdminCustomerRow {
    pub id: Uuid,
    pub customer_type: String,
    pub display_name: Option<String>,
    pub status: String,
    pub country_code: Option<String>,
    pub primary_email: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct CustomerFilter<'a> {
    pub email: Option<&'a str>,
    pub status: Option<&'a str>,
    pub limit: i64,
    pub offset: i64,
}

pub async fn list_customers(
    pool: &PgPool,
    filter: CustomerFilter<'_>,
) -> Result<Vec<AdminCustomerRow>, sqlx::Error> {
    sqlx::query_as::<_, AdminCustomerRow>(
        r#"
        select c.id, c.customer_type, c.display_name, c.status, c.country_code,
               (select e.email from public.customer_emails e
                where e.customer_id = c.id and e.is_primary
                order by e.created_at limit 1) as primary_email,
               c.created_at
        from public.customer_profiles c
        where ($1::text is null
               or exists (select 1 from public.customer_emails e
                          where e.customer_id = c.id and e.email = $1))
          and ($2::text is null or c.status = $2)
        order by c.created_at desc
        limit $3 offset $4
        "#,
    )
    .bind(filter.email)
    .bind(filter.status)
    .bind(filter.limit)
    .bind(filter.offset)
    .fetch_all(pool)
    .await
}

#[derive(Debug, Clone)]
pub struct StatusChangeOutcome {
    pub customer_id: Uuid,
    pub from_status: String,
    pub status: String,
    pub changed: bool,
}

struct StatusChange<'a> {
    operator_id: &'a str,
    customer_id: Uuid,
    to_status: &'a str,
    /// Doubles as the audit and outbox event type (`customer_suspended`/`customer_restored`).
    event_type: &'a str,
    reason: &'a str,
    correlation_id: Option<&'a str>,
}

/// Set a customer's commercial status (suspend/restore). Idempotent: re-applying the
/// current status changes nothing and writes no duplicate history/audit/outbox rows.
async fn set_customer_status(
    pool: &PgPool,
    change: StatusChange<'_>,
) -> Result<StatusChangeOutcome, AdminError> {
    let StatusChange {
        operator_id,
        customer_id,
        to_status,
        event_type,
        reason,
        correlation_id,
    } = change;
    let mut tx = pool.begin().await?;

    let current = sqlx::query_scalar::<_, String>(
        "select status from public.customer_profiles where id = $1 for update",
    )
    .bind(customer_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AdminError::CustomerNotFound)?;

    if current == to_status {
        tx.commit().await?;
        return Ok(StatusChangeOutcome {
            customer_id,
            from_status: current.clone(),
            status: current,
            changed: false,
        });
    }

    sqlx::query("update public.customer_profiles set status = $2 where id = $1")
        .bind(customer_id)
        .bind(to_status)
        .execute(&mut *tx)
        .await?;
    let history_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        insert into public.customer_status_history
            (customer_id, from_status, to_status, reason, actor_type, actor_id)
        values
            ($1, $2, $3, $4, 'operator', $5)
        returning id
        "#,
    )
    .bind(customer_id)
    .bind(&current)
    .bind(to_status)
    .bind(reason)
    .bind(operator_id)
    .fetch_one(&mut *tx)
    .await?;

    write_operator_audit(
        &mut tx,
        OperatorAudit {
            event_type,
            operator_id,
            customer_id: Some(customer_id),
            target_type: "customer",
            target_id: customer_id.to_string(),
            reason,
            before_state: Some(json!({ "status": current })),
            after_state: Some(json!({ "status": to_status })),
            correlation_id,
        },
    )
    .await?;
    write_outbox(
        &mut tx,
        event_type,
        format!("{event_type}:{history_id}"),
        json!({
            "customer_id": customer_id,
            "status": to_status,
            "occurred_at": Utc::now(),
        }),
    )
    .await?;

    tx.commit().await?;
    Ok(StatusChangeOutcome {
        customer_id,
        from_status: current,
        status: to_status.to_string(),
        changed: true,
    })
}

pub async fn suspend_customer(
    pool: &PgPool,
    operator_id: &str,
    customer_id: Uuid,
    reason: &str,
    correlation_id: Option<&str>,
) -> Result<StatusChangeOutcome, AdminError> {
    set_customer_status(
        pool,
        StatusChange {
            operator_id,
            customer_id,
            to_status: "suspended",
            event_type: "customer_suspended",
            reason,
            correlation_id,
        },
    )
    .await
}

pub async fn restore_customer(
    pool: &PgPool,
    operator_id: &str,
    customer_id: Uuid,
    reason: &str,
    correlation_id: Option<&str>,
) -> Result<StatusChangeOutcome, AdminError> {
    set_customer_status(
        pool,
        StatusChange {
            operator_id,
            customer_id,
            to_status: "active",
            event_type: "customer_restored",
            reason,
            correlation_id,
        },
    )
    .await
}

// --- Licenses ----------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct IssuedLicenseRow {
    pub id: Uuid,
    pub customer_id: Uuid,
    pub product_key: String,
    pub status: String,
    pub device_limit: i32,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct IssueLicenseInput<'a> {
    pub operator_id: &'a str,
    pub customer_id: Uuid,
    pub product_key: &'a str,
    pub device_limit: i32,
    pub expires_at: Option<DateTime<Utc>>,
    pub reason: &'a str,
    pub correlation_id: Option<&'a str>,
}

/// Operator-issued license (support/migration paths; subscription-linked licenses are
/// managed exclusively by webhook sync).
pub async fn issue_license(
    pool: &PgPool,
    input: IssueLicenseInput<'_>,
) -> Result<IssuedLicenseRow, AdminError> {
    let IssueLicenseInput {
        operator_id,
        customer_id,
        product_key,
        device_limit,
        expires_at,
        reason,
        correlation_id,
    } = input;
    let mut tx = pool.begin().await?;

    let customer_exists = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from public.customer_profiles where id = $1)",
    )
    .bind(customer_id)
    .fetch_one(&mut *tx)
    .await?;
    if !customer_exists {
        return Err(AdminError::CustomerNotFound);
    }
    let product = sqlx::query_as::<_, (Uuid, String)>(
        "select id, key from public.products where key = $1 and status = 'active'",
    )
    .bind(product_key)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AdminError::ProductNotFound)?;

    let license = sqlx::query_as::<_, IssuedLicenseRow>(
        r#"
        insert into public.licenses (customer_id, product_id, status, device_limit, expires_at)
        values ($1, $2, 'active', $3, $4)
        returning id, customer_id, $5::text as product_key, status, device_limit,
                  issued_at, expires_at
        "#,
    )
    .bind(customer_id)
    .bind(product.0)
    .bind(device_limit)
    .bind(expires_at)
    .bind(&product.1)
    .fetch_one(&mut *tx)
    .await?;

    write_operator_audit(
        &mut tx,
        OperatorAudit {
            event_type: "license_issued",
            operator_id,
            customer_id: Some(customer_id),
            target_type: "license",
            target_id: license.id.to_string(),
            reason,
            before_state: None,
            after_state: Some(json!({
                "license_status": "active",
                "product": product.1,
                "device_limit": device_limit,
                "expires_at": expires_at,
            })),
            correlation_id,
        },
    )
    .await?;

    tx.commit().await?;
    Ok(license)
}

#[derive(Debug, Clone)]
pub struct RevocationOutcome {
    pub license_id: Uuid,
    pub customer_id: Uuid,
    pub status: String,
    pub changed: bool,
}

/// Revoke a license: explicit denial that blocks activation/leases and is never lifted
/// by subscription sync. Idempotent for an already-revoked license.
pub async fn revoke_license(
    pool: &PgPool,
    operator_id: &str,
    license_id: Uuid,
    reason: &str,
    correlation_id: Option<&str>,
) -> Result<RevocationOutcome, AdminError> {
    let mut tx = pool.begin().await?;

    let license = sqlx::query_as::<_, (Uuid, String)>(
        "select customer_id, status from public.licenses where id = $1 for update",
    )
    .bind(license_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AdminError::LicenseNotFound)?;
    if license.1 == "revoked" {
        tx.commit().await?;
        return Ok(RevocationOutcome {
            license_id,
            customer_id: license.0,
            status: license.1,
            changed: false,
        });
    }

    sqlx::query("update public.licenses set status = 'revoked' where id = $1")
        .bind(license_id)
        .execute(&mut *tx)
        .await?;
    let revocation_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        insert into public.license_revocations (license_id, reason, actor_type, actor_id)
        values ($1, $2, 'operator', $3)
        returning id
        "#,
    )
    .bind(license_id)
    .bind(reason)
    .bind(operator_id)
    .fetch_one(&mut *tx)
    .await?;

    write_operator_audit(
        &mut tx,
        OperatorAudit {
            event_type: "license_revoked",
            operator_id,
            customer_id: Some(license.0),
            target_type: "license",
            target_id: license_id.to_string(),
            reason,
            before_state: Some(json!({ "license_status": license.1 })),
            after_state: Some(json!({ "license_status": "revoked" })),
            correlation_id,
        },
    )
    .await?;
    write_outbox(
        &mut tx,
        "license_revoked",
        format!("license_revoked:{revocation_id}"),
        json!({
            "customer_id": license.0,
            "license_id": license_id,
            "occurred_at": Utc::now(),
        }),
    )
    .await?;

    tx.commit().await?;
    Ok(RevocationOutcome {
        license_id,
        customer_id: license.0,
        status: "revoked".to_string(),
        changed: true,
    })
}

// --- Entitlement overrides -----------------------------------------------------

#[derive(Debug, Clone)]
pub struct OverrideInput<'a> {
    pub customer_id: Uuid,
    pub product_key: &'a str,
    /// Exactly one of feature_key / quota_key (validated by the route).
    pub feature_key: Option<&'a str>,
    pub quota_key: Option<&'a str>,
    /// `None` clears the active override(s) for the key without setting a new one.
    pub value: Option<OverrideValue>,
    pub expires_at: Option<DateTime<Utc>>,
    pub reason: &'a str,
}

#[derive(Debug, Clone)]
pub struct OverrideOutcome {
    pub override_id: Option<Uuid>,
    pub cleared: u64,
}

/// Set (or clear) an admin entitlement override. Prior active overrides for the same key
/// are deactivated in the same transaction so evaluation sees exactly one winner.
pub async fn set_entitlement_override(
    pool: &PgPool,
    operator_id: &str,
    input: OverrideInput<'_>,
    correlation_id: Option<&str>,
) -> Result<OverrideOutcome, AdminError> {
    let mut tx = pool.begin().await?;

    let customer_exists = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from public.customer_profiles where id = $1)",
    )
    .bind(input.customer_id)
    .fetch_one(&mut *tx)
    .await?;
    if !customer_exists {
        return Err(AdminError::CustomerNotFound);
    }
    let product_id = sqlx::query_scalar::<_, Uuid>(
        "select id from public.products where key = $1 and status = 'active'",
    )
    .bind(input.product_key)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AdminError::ProductNotFound)?;

    let cleared = sqlx::query(
        r#"
        update public.entitlement_overrides
        set active = false
        where customer_id = $1
          and product_id = $2
          and active
          and (feature_key is not distinct from $3)
          and (quota_key is not distinct from $4)
        "#,
    )
    .bind(input.customer_id)
    .bind(product_id)
    .bind(input.feature_key)
    .bind(input.quota_key)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    let override_id = match &input.value {
        Some(value) => {
            let (bool_value, number_value, string_value) = value.columns();
            Some(
                sqlx::query_scalar::<_, Uuid>(
                    r#"
                    insert into public.entitlement_overrides
                        (customer_id, product_id, feature_key, quota_key, bool_value,
                         number_value, string_value, reason, actor_id, expires_at)
                    values
                        ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    returning id
                    "#,
                )
                .bind(input.customer_id)
                .bind(product_id)
                .bind(input.feature_key)
                .bind(input.quota_key)
                .bind(bool_value)
                .bind(number_value)
                .bind(string_value)
                .bind(input.reason)
                .bind(operator_id)
                .bind(input.expires_at)
                .fetch_one(&mut *tx)
                .await?,
            )
        }
        None => None,
    };

    let key = input.feature_key.or(input.quota_key).unwrap_or_default();
    write_operator_audit(
        &mut tx,
        OperatorAudit {
            event_type: if override_id.is_some() {
                "entitlement_override_set"
            } else {
                "entitlement_override_cleared"
            },
            operator_id,
            customer_id: Some(input.customer_id),
            target_type: "entitlement_override",
            target_id: override_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| key.to_string()),
            reason: input.reason,
            before_state: Some(json!({ "deactivated_overrides": cleared })),
            after_state: Some(json!({
                "key": key,
                "value": input.value.as_ref().map(|value| match value {
                    OverrideValue::Bool(value) => json!(value),
                    OverrideValue::Number(value) => json!(value),
                    OverrideValue::Text(value) => json!(value),
                }),
                "expires_at": input.expires_at,
            })),
            correlation_id,
        },
    )
    .await?;

    tx.commit().await?;
    Ok(OverrideOutcome {
        override_id,
        cleared,
    })
}

// --- Usage adjustment ----------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AdjustmentOutcome {
    pub usage_event_id: Uuid,
    pub customer_id: Uuid,
    pub meter_key: String,
    pub period_key: String,
    pub amount: f64,
    pub replayed: bool,
}

#[derive(Debug, Clone)]
pub struct UsageAdjustmentInput<'a> {
    pub operator_id: &'a str,
    pub customer_id: Uuid,
    pub meter_key: &'a str,
    pub amount: f64,
    pub period_key: &'a str,
    pub idempotency_key: &'a str,
    pub reason: &'a str,
    pub correlation_id: Option<&'a str>,
}

/// Append a compensating usage adjustment to the ledger and fold it into the period
/// total. Idempotent by (customer, idempotency key): a replay returns the original event
/// without re-applying the amount.
pub async fn adjust_usage(
    pool: &PgPool,
    input: UsageAdjustmentInput<'_>,
) -> Result<AdjustmentOutcome, AdminError> {
    let UsageAdjustmentInput {
        operator_id,
        customer_id,
        meter_key,
        amount,
        period_key,
        idempotency_key,
        reason,
        correlation_id,
    } = input;
    let mut tx = pool.begin().await?;

    let customer_exists = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from public.customer_profiles where id = $1)",
    )
    .bind(customer_id)
    .fetch_one(&mut *tx)
    .await?;
    if !customer_exists {
        return Err(AdminError::CustomerNotFound);
    }
    let meter_exists = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from public.usage_meters where key = $1)",
    )
    .bind(meter_key)
    .fetch_one(&mut *tx)
    .await?;
    if !meter_exists {
        return Err(AdminError::MeterNotFound);
    }

    let inserted = sqlx::query_scalar::<_, Uuid>(
        r#"
        insert into public.usage_events
            (customer_id, meter_key, amount, period_key, idempotency_key, kind)
        values
            ($1, $2, $3, $4, $5, 'adjustment')
        on conflict (customer_id, idempotency_key) do nothing
        returning id
        "#,
    )
    .bind(customer_id)
    .bind(meter_key)
    .bind(amount)
    .bind(period_key)
    .bind(idempotency_key)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(usage_event_id) = inserted else {
        // Replay of a previously applied adjustment: report the original, change nothing.
        let existing = sqlx::query_as::<_, (Uuid, String, String, f64)>(
            r#"
            select id, meter_key, period_key, amount::float8
            from public.usage_events
            where customer_id = $1 and idempotency_key = $2
            "#,
        )
        .bind(customer_id)
        .bind(idempotency_key)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(AdjustmentOutcome {
            usage_event_id: existing.0,
            customer_id,
            meter_key: existing.1,
            period_key: existing.2,
            amount: existing.3,
            replayed: true,
        });
    };

    sqlx::query(
        r#"
        insert into public.usage_period_totals (customer_id, meter_key, period_key, used)
        values ($1, $2, $3, $4)
        on conflict (customer_id, meter_key, period_key) do update
            set used = public.usage_period_totals.used + excluded.used
        "#,
    )
    .bind(customer_id)
    .bind(meter_key)
    .bind(period_key)
    .bind(amount)
    .execute(&mut *tx)
    .await?;

    write_operator_audit(
        &mut tx,
        OperatorAudit {
            event_type: "usage_adjusted",
            operator_id,
            customer_id: Some(customer_id),
            target_type: "usage_event",
            target_id: usage_event_id.to_string(),
            reason,
            before_state: None,
            after_state: Some(json!({
                "meter_key": meter_key,
                "period_key": period_key,
                "amount": amount,
                "kind": "adjustment",
            })),
            correlation_id,
        },
    )
    .await?;

    tx.commit().await?;
    Ok(AdjustmentOutcome {
        usage_event_id,
        customer_id,
        meter_key: meter_key.to_string(),
        period_key: period_key.to_string(),
        amount,
        replayed: false,
    })
}

// --- Audit read -----------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct AuditEventRow {
    pub id: Uuid,
    pub event_type: String,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub customer_id: Option<Uuid>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub reason: Option<String>,
    pub before_state: Option<Value>,
    pub after_state: Option<Value>,
    pub correlation_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct AuditFilter<'a> {
    pub customer_id: Option<Uuid>,
    pub event_type: Option<&'a str>,
    pub limit: i64,
}

pub async fn list_audit_events(
    pool: &PgPool,
    filter: AuditFilter<'_>,
) -> Result<Vec<AuditEventRow>, sqlx::Error> {
    sqlx::query_as::<_, AuditEventRow>(
        r#"
        select id, event_type, actor_type, actor_id, customer_id, target_type, target_id,
               reason, before_state, after_state, correlation_id, created_at
        from public.commercial_audit_events
        where ($1::uuid is null or customer_id = $1)
          and ($2::text is null or event_type = $2)
        order by created_at desc
        limit $3
        "#,
    )
    .bind(filter.customer_id)
    .bind(filter.event_type)
    .bind(filter.limit)
    .fetch_all(pool)
    .await
}
