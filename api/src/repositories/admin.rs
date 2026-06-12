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
    #[error("fleet not found")]
    FleetNotFound,
    #[error("release not found")]
    ReleaseNotFound,
    #[error("campaign not found")]
    CampaignNotFound,
    #[error("artifact not found")]
    ArtifactNotFound,
    #[error("fleet hold not found")]
    FleetHoldNotFound,
    #[error("invalid state: {0}")]
    InvalidState(&'static str),
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

// --- Fleets, releases, campaigns -----------------------------------------------

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct AdminFleetRow {
    pub id: Uuid,
    pub customer_id: Uuid,
    pub display_name: String,
    pub fleet_type: String,
    pub status: String,
    pub update_ring: String,
    pub release_channel_key: Option<String>,
    pub beta_enrolled: bool,
    pub installation_count: i64,
    pub active_hold_count: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn list_fleets(pool: &PgPool) -> Result<Vec<AdminFleetRow>, sqlx::Error> {
    sqlx::query_as::<_, AdminFleetRow>(
        r#"
        select f.id, f.customer_id, f.display_name, f.fleet_type, f.status, f.update_ring,
               rc.key as release_channel_key, f.beta_enrolled,
               (select count(*) from public.installations i where i.fleet_id = f.id) as installation_count,
               (select count(*) from public.update_campaign_holds h where h.fleet_id = f.id) as active_hold_count,
               f.created_at, f.updated_at
        from public.fleets f
        left join public.release_channels rc on rc.id = f.release_channel_id
        where f.status <> 'deleted'
        order by f.updated_at desc, f.created_at desc
        limit 200
        "#,
    )
    .fetch_all(pool)
    .await
}

pub async fn read_fleet(
    pool: &PgPool,
    fleet_id: Uuid,
) -> Result<Option<AdminFleetRow>, sqlx::Error> {
    sqlx::query_as::<_, AdminFleetRow>(
        r#"
        select f.id, f.customer_id, f.display_name, f.fleet_type, f.status, f.update_ring,
               rc.key as release_channel_key, f.beta_enrolled,
               (select count(*) from public.installations i where i.fleet_id = f.id) as installation_count,
               (select count(*) from public.update_campaign_holds h where h.fleet_id = f.id) as active_hold_count,
               f.created_at, f.updated_at
        from public.fleets f
        left join public.release_channels rc on rc.id = f.release_channel_id
        where f.id = $1 and f.status <> 'deleted'
        "#,
    )
    .bind(fleet_id)
    .fetch_optional(pool)
    .await
}

#[derive(Debug, Clone)]
pub struct UpdateFleetPolicyInput<'a> {
    pub operator_id: &'a str,
    pub fleet_id: Uuid,
    pub display_name: Option<&'a str>,
    pub update_ring: Option<&'a str>,
    pub release_channel_key: Option<&'a str>,
    pub beta_enrolled: Option<bool>,
    pub reason: &'a str,
    pub correlation_id: Option<&'a str>,
}

pub async fn update_fleet_policy(
    pool: &PgPool,
    input: UpdateFleetPolicyInput<'_>,
) -> Result<AdminFleetRow, AdminError> {
    let mut tx = pool.begin().await?;
    let before = sqlx::query_as::<_, AdminFleetRow>(
        r#"
        select f.id, f.customer_id, f.display_name, f.fleet_type, f.status, f.update_ring,
               rc.key as release_channel_key, f.beta_enrolled,
               (select count(*) from public.installations i where i.fleet_id = f.id) as installation_count,
               (select count(*) from public.update_campaign_holds h where h.fleet_id = f.id) as active_hold_count,
               f.created_at, f.updated_at
        from public.fleets f
        left join public.release_channels rc on rc.id = f.release_channel_id
        where f.id = $1 and f.status <> 'deleted'
        for update of f
        "#,
    )
    .bind(input.fleet_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AdminError::FleetNotFound)?;

    let release_channel_id = match input.release_channel_key {
        Some(key) => Some(
            sqlx::query_scalar::<_, Uuid>(
                r#"
                select rc.id
                from public.release_channels rc
                join public.products p on p.id = rc.product_id
                where p.key = 'authorforge' and rc.key = $1
                "#,
            )
            .bind(key)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AdminError::ProductNotFound)?,
        ),
        None => None,
    };

    let after = sqlx::query_as::<_, AdminFleetRow>(
        r#"
        update public.fleets f
        set display_name = coalesce($2, display_name),
            update_ring = coalesce($3, update_ring),
            release_channel_id = coalesce($4, release_channel_id),
            beta_enrolled = coalesce($5, beta_enrolled)
        where f.id = $1
        returning f.id, f.customer_id, f.display_name, f.fleet_type, f.status, f.update_ring,
                  (select rc.key from public.release_channels rc where rc.id = f.release_channel_id) as release_channel_key,
                  f.beta_enrolled,
                  (select count(*) from public.installations i where i.fleet_id = f.id) as installation_count,
                  (select count(*) from public.update_campaign_holds h where h.fleet_id = f.id) as active_hold_count,
                  f.created_at, f.updated_at
        "#,
    )
    .bind(input.fleet_id)
    .bind(input.display_name)
    .bind(input.update_ring)
    .bind(release_channel_id)
    .bind(input.beta_enrolled)
    .fetch_one(&mut *tx)
    .await?;

    write_operator_audit(
        &mut tx,
        OperatorAudit {
            event_type: "fleet_policy_updated",
            operator_id: input.operator_id,
            customer_id: Some(after.customer_id),
            target_type: "fleet",
            target_id: input.fleet_id.to_string(),
            reason: input.reason,
            before_state: Some(json!({
                "display_name": before.display_name,
                "update_ring": before.update_ring,
                "release_channel": before.release_channel_key,
                "beta_enrolled": before.beta_enrolled,
            })),
            after_state: Some(json!({
                "display_name": after.display_name,
                "update_ring": after.update_ring,
                "release_channel": after.release_channel_key,
                "beta_enrolled": after.beta_enrolled,
            })),
            correlation_id: input.correlation_id,
        },
    )
    .await?;

    tx.commit().await?;
    Ok(after)
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct AdminReleaseRow {
    pub id: Uuid,
    pub product_key: String,
    pub version: String,
    pub build_id: String,
    pub release_channel_key: String,
    pub status: String,
    pub changelog_markdown: Option<String>,
    pub minimum_supported_version: Option<String>,
    pub minimum_updater_version: Option<String>,
    pub artifact_count: i64,
    pub validated_artifact_count: i64,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub validated_at: Option<DateTime<Utc>>,
    pub published_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

fn release_select_sql(where_clause: &str) -> String {
    format!(
        r#"
        select r.id, p.key as product_key, r.version, r.build_id,
               rc.key as release_channel_key, r.status, r.changelog_markdown,
               r.minimum_supported_version, r.minimum_updater_version,
               (select count(*) from public.release_artifacts a where a.release_id = r.id) as artifact_count,
               (select count(*) from public.release_artifacts a where a.release_id = r.id and a.status = 'validated') as validated_artifact_count,
               r.created_by, r.created_at, r.validated_at, r.published_at, r.updated_at
        from public.product_releases r
        join public.products p on p.id = r.product_id
        join public.release_channels rc on rc.id = r.release_channel_id
        {where_clause}
        "#
    )
}

pub async fn list_releases(pool: &PgPool) -> Result<Vec<AdminReleaseRow>, sqlx::Error> {
    sqlx::query_as::<_, AdminReleaseRow>(&format!(
        "{} order by r.created_at desc limit 200",
        release_select_sql("")
    ))
    .fetch_all(pool)
    .await
}

pub async fn read_release(
    pool: &PgPool,
    release_id: Uuid,
) -> Result<Option<AdminReleaseRow>, sqlx::Error> {
    sqlx::query_as::<_, AdminReleaseRow>(&release_select_sql("where r.id = $1"))
        .bind(release_id)
        .fetch_optional(pool)
        .await
}

#[derive(Debug, Clone)]
pub struct CreateReleaseInput<'a> {
    pub operator_id: &'a str,
    pub product_key: &'a str,
    pub version: &'a str,
    pub build_id: &'a str,
    pub release_channel_key: &'a str,
    pub changelog_markdown: Option<&'a str>,
    pub minimum_supported_version: Option<&'a str>,
    pub minimum_updater_version: Option<&'a str>,
    pub reason: &'a str,
    pub correlation_id: Option<&'a str>,
}

pub async fn create_release(
    pool: &PgPool,
    input: CreateReleaseInput<'_>,
) -> Result<AdminReleaseRow, AdminError> {
    let mut tx = pool.begin().await?;
    let product_id = sqlx::query_scalar::<_, Uuid>(
        "select id from public.products where key = $1 and status = 'active'",
    )
    .bind(input.product_key)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AdminError::ProductNotFound)?;
    let release_channel_id = sqlx::query_scalar::<_, Uuid>(
        "select id from public.release_channels where product_id = $1 and key = $2",
    )
    .bind(product_id)
    .bind(input.release_channel_key)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AdminError::ProductNotFound)?;

    let inserted = sqlx::query_scalar::<_, Uuid>(
        r#"
        insert into public.product_releases
            (product_id, version, build_id, release_channel_id, status, changelog_markdown,
             minimum_supported_version, minimum_updater_version, created_by)
        values
            ($1, $2, $3, $4, 'draft', $5, $6, $7, $8)
        on conflict (product_id, version, build_id) do nothing
        returning id
        "#,
    )
    .bind(product_id)
    .bind(input.version)
    .bind(input.build_id)
    .bind(release_channel_id)
    .bind(input.changelog_markdown)
    .bind(input.minimum_supported_version)
    .bind(input.minimum_updater_version)
    .bind(input.operator_id)
    .fetch_optional(&mut *tx)
    .await?;

    let release_id = match inserted {
        Some(id) => {
            write_operator_audit(
                &mut tx,
                OperatorAudit {
                    event_type: "release_registered",
                    operator_id: input.operator_id,
                    customer_id: None,
                    target_type: "product_release",
                    target_id: id.to_string(),
                    reason: input.reason,
                    before_state: None,
                    after_state: Some(json!({
                        "product_key": input.product_key,
                        "version": input.version,
                        "build_id": input.build_id,
                        "release_channel": input.release_channel_key,
                        "status": "draft",
                    })),
                    correlation_id: input.correlation_id,
                },
            )
            .await?;
            id
        }
        None => {
            let existing = sqlx::query_as::<_, (Uuid, Uuid)>(
                r#"
                select id, release_channel_id
                from public.product_releases
                where product_id = $1 and version = $2 and build_id = $3
                "#,
            )
            .bind(product_id)
            .bind(input.version)
            .bind(input.build_id)
            .fetch_one(&mut *tx)
            .await?;
            if existing.1 != release_channel_id {
                return Err(AdminError::InvalidState(
                    "release already exists with a different channel",
                ));
            }
            existing.0
        }
    };

    tx.commit().await?;
    read_release(pool, release_id)
        .await?
        .ok_or(AdminError::ReleaseNotFound)
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct AdminArtifactRow {
    pub id: Uuid,
    pub release_id: Uuid,
    pub platform: String,
    pub architecture: String,
    pub package_format: String,
    pub artifact_role: String,
    pub storage_key: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub tauri_signature: Option<String>,
    pub signing_key_id: String,
    pub os_signature_status: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct RegisterArtifactInput<'a> {
    pub operator_id: &'a str,
    pub release_id: Uuid,
    pub platform: &'a str,
    pub architecture: &'a str,
    pub package_format: &'a str,
    pub artifact_role: &'a str,
    pub storage_key: &'a str,
    pub size_bytes: i64,
    pub sha256: &'a str,
    pub tauri_signature: Option<&'a str>,
    pub signing_key_id: &'a str,
    pub os_signature_status: &'a str,
    pub reason: &'a str,
    pub correlation_id: Option<&'a str>,
}

fn artifact_select_sql(where_clause: &str) -> String {
    format!(
        r#"
        select id, release_id, platform, architecture, package_format, artifact_role,
               storage_key, size_bytes, sha256, tauri_signature, signing_key_id,
               os_signature_status, status, created_at, updated_at
        from public.release_artifacts
        {where_clause}
        "#
    )
}

async fn read_artifact_tx(
    tx: &mut Transaction<'_, Postgres>,
    artifact_id: Uuid,
) -> Result<AdminArtifactRow, sqlx::Error> {
    sqlx::query_as::<_, AdminArtifactRow>(&artifact_select_sql("where id = $1"))
        .bind(artifact_id)
        .fetch_one(&mut **tx)
        .await
}

pub async fn register_artifact(
    pool: &PgPool,
    input: RegisterArtifactInput<'_>,
) -> Result<AdminArtifactRow, AdminError> {
    if input.artifact_role == "updater" && input.tauri_signature.is_none() {
        return Err(AdminError::InvalidState(
            "updater artifacts require a Tauri signature",
        ));
    }

    let mut tx = pool.begin().await?;
    let release_status = sqlx::query_scalar::<_, String>(
        "select status from public.product_releases where id = $1 for update",
    )
    .bind(input.release_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AdminError::ReleaseNotFound)?;
    if matches!(release_status.as_str(), "published" | "blocked" | "retired") {
        return Err(AdminError::InvalidState(
            "published, blocked, or retired releases are immutable",
        ));
    }

    let inserted = sqlx::query_scalar::<_, Uuid>(
        r#"
        insert into public.release_artifacts
            (release_id, platform, architecture, package_format, artifact_role, storage_key,
             size_bytes, sha256, tauri_signature, signing_key_id, os_signature_status, status)
        values
            ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'validated')
        on conflict (release_id, platform, architecture, package_format, artifact_role) do nothing
        returning id
        "#,
    )
    .bind(input.release_id)
    .bind(input.platform)
    .bind(input.architecture)
    .bind(input.package_format)
    .bind(input.artifact_role)
    .bind(input.storage_key)
    .bind(input.size_bytes)
    .bind(input.sha256)
    .bind(input.tauri_signature)
    .bind(input.signing_key_id)
    .bind(input.os_signature_status)
    .fetch_optional(&mut *tx)
    .await?;

    let artifact = match inserted {
        Some(id) => {
            if release_status == "draft" {
                sqlx::query(
                    "update public.product_releases set status = 'artifacts_pending' where id = $1",
                )
                .bind(input.release_id)
                .execute(&mut *tx)
                .await?;
            }
            let artifact = read_artifact_tx(&mut tx, id).await?;
            write_operator_audit(
                &mut tx,
                OperatorAudit {
                    event_type: "release_artifact_registered",
                    operator_id: input.operator_id,
                    customer_id: None,
                    target_type: "release_artifact",
                    target_id: id.to_string(),
                    reason: input.reason,
                    before_state: None,
                    after_state: Some(json!({
                        "release_id": input.release_id,
                        "platform": input.platform,
                        "architecture": input.architecture,
                        "package_format": input.package_format,
                        "artifact_role": input.artifact_role,
                        "storage_key": input.storage_key,
                        "size_bytes": input.size_bytes,
                        "sha256": input.sha256,
                        "signing_key_id": input.signing_key_id,
                        "os_signature_status": input.os_signature_status,
                        "status": "validated",
                    })),
                    correlation_id: input.correlation_id,
                },
            )
            .await?;
            artifact
        }
        None => {
            let existing = sqlx::query_as::<_, AdminArtifactRow>(&artifact_select_sql(
                r#"
                where release_id = $1 and platform = $2 and architecture = $3
                  and package_format = $4 and artifact_role = $5
                "#,
            ))
            .bind(input.release_id)
            .bind(input.platform)
            .bind(input.architecture)
            .bind(input.package_format)
            .bind(input.artifact_role)
            .fetch_one(&mut *tx)
            .await?;
            let same = existing.storage_key == input.storage_key
                && existing.size_bytes == input.size_bytes
                && existing.sha256 == input.sha256
                && existing.tauri_signature.as_deref() == input.tauri_signature
                && existing.signing_key_id == input.signing_key_id
                && existing.os_signature_status == input.os_signature_status;
            if !same {
                return Err(AdminError::InvalidState(
                    "artifact tuple already exists with different immutable metadata",
                ));
            }
            existing
        }
    };

    tx.commit().await?;
    Ok(artifact)
}

async fn lock_release_status(
    tx: &mut Transaction<'_, Postgres>,
    release_id: Uuid,
) -> Result<(Uuid, String, Uuid), AdminError> {
    sqlx::query_as::<_, (Uuid, String, Uuid)>(
        "select product_id, status, release_channel_id from public.product_releases where id = $1 for update",
    )
    .bind(release_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(AdminError::ReleaseNotFound)
}

pub async fn validate_release(
    pool: &PgPool,
    operator_id: &str,
    release_id: Uuid,
    reason: &str,
    correlation_id: Option<&str>,
) -> Result<AdminReleaseRow, AdminError> {
    let mut tx = pool.begin().await?;
    let (_product_id, status, _channel_id) = lock_release_status(&mut tx, release_id).await?;
    if matches!(status.as_str(), "blocked" | "retired") {
        return Err(AdminError::InvalidState(
            "blocked or retired releases cannot be validated",
        ));
    }
    if !matches!(status.as_str(), "validated" | "published") {
        let validated_artifacts = sqlx::query_scalar::<_, i64>(
            "select count(*) from public.release_artifacts where release_id = $1 and status = 'validated'",
        )
        .bind(release_id)
        .fetch_one(&mut *tx)
        .await?;
        if validated_artifacts == 0 {
            return Err(AdminError::InvalidState(
                "at least one validated artifact is required",
            ));
        }
        sqlx::query(
            "update public.product_releases set status = 'validated', validated_at = coalesce(validated_at, now()) where id = $1",
        )
        .bind(release_id)
        .execute(&mut *tx)
        .await?;
        write_operator_audit(
            &mut tx,
            OperatorAudit {
                event_type: "release_validated",
                operator_id,
                customer_id: None,
                target_type: "product_release",
                target_id: release_id.to_string(),
                reason,
                before_state: Some(json!({ "status": status })),
                after_state: Some(json!({ "status": "validated" })),
                correlation_id,
            },
        )
        .await?;
    }
    tx.commit().await?;
    read_release(pool, release_id)
        .await?
        .ok_or(AdminError::ReleaseNotFound)
}

pub async fn publish_release(
    pool: &PgPool,
    operator_id: &str,
    release_id: Uuid,
    reason: &str,
    correlation_id: Option<&str>,
) -> Result<AdminReleaseRow, AdminError> {
    let mut tx = pool.begin().await?;
    let (_product_id, status, _channel_id) = lock_release_status(&mut tx, release_id).await?;
    match status.as_str() {
        "published" => {}
        "validated" => {
            sqlx::query(
                "update public.product_releases set status = 'published', published_at = coalesce(published_at, now()) where id = $1",
            )
            .bind(release_id)
            .execute(&mut *tx)
            .await?;
            write_operator_audit(
                &mut tx,
                OperatorAudit {
                    event_type: "release_published",
                    operator_id,
                    customer_id: None,
                    target_type: "product_release",
                    target_id: release_id.to_string(),
                    reason,
                    before_state: Some(json!({ "status": status })),
                    after_state: Some(json!({ "status": "published" })),
                    correlation_id,
                },
            )
            .await?;
        }
        _ => {
            return Err(AdminError::InvalidState(
                "only validated releases can be published",
            ))
        }
    }
    tx.commit().await?;
    read_release(pool, release_id)
        .await?
        .ok_or(AdminError::ReleaseNotFound)
}

pub async fn block_release(
    pool: &PgPool,
    operator_id: &str,
    release_id: Uuid,
    reason: &str,
    correlation_id: Option<&str>,
) -> Result<AdminReleaseRow, AdminError> {
    let mut tx = pool.begin().await?;
    let (_product_id, status, _channel_id) = lock_release_status(&mut tx, release_id).await?;
    if status != "blocked" {
        if status == "retired" {
            return Err(AdminError::InvalidState(
                "retired releases cannot be blocked",
            ));
        }
        sqlx::query("update public.product_releases set status = 'blocked' where id = $1")
            .bind(release_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "update public.update_campaigns set status = 'paused' where target_release_id = $1 and status = 'active'",
        )
        .bind(release_id)
        .execute(&mut *tx)
        .await?;
        write_operator_audit(
            &mut tx,
            OperatorAudit {
                event_type: "release_blocked",
                operator_id,
                customer_id: None,
                target_type: "product_release",
                target_id: release_id.to_string(),
                reason,
                before_state: Some(json!({ "status": status })),
                after_state: Some(json!({ "status": "blocked" })),
                correlation_id,
            },
        )
        .await?;
    }
    tx.commit().await?;
    read_release(pool, release_id)
        .await?
        .ok_or(AdminError::ReleaseNotFound)
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct AdminCampaignRow {
    pub id: Uuid,
    pub product_key: String,
    pub target_release_id: Uuid,
    pub campaign_slug: String,
    pub status: String,
    pub release_channel_key: String,
    pub target_update_ring: String,
    pub rollout_percentage: i32,
    pub emergency: bool,
    pub starts_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub hold_count: i64,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn campaign_select_sql(where_clause: &str) -> String {
    format!(
        r#"
        select c.id, p.key as product_key, c.target_release_id, c.campaign_slug, c.status,
               rc.key as release_channel_key, c.target_update_ring, c.rollout_percentage,
               c.emergency, c.starts_at, c.completed_at,
               (select count(*) from public.update_campaign_holds h where h.campaign_id = c.id) as hold_count,
               c.created_by, c.created_at, c.updated_at
        from public.update_campaigns c
        join public.products p on p.id = c.product_id
        join public.release_channels rc on rc.id = c.release_channel_id
        {where_clause}
        "#
    )
}

pub async fn read_campaign(
    pool: &PgPool,
    campaign_id: Uuid,
) -> Result<Option<AdminCampaignRow>, sqlx::Error> {
    sqlx::query_as::<_, AdminCampaignRow>(&campaign_select_sql("where c.id = $1"))
        .bind(campaign_id)
        .fetch_optional(pool)
        .await
}

#[derive(Debug, Clone)]
pub struct CreateCampaignInput<'a> {
    pub operator_id: &'a str,
    pub product_key: &'a str,
    pub target_release_id: Uuid,
    pub campaign_slug: &'a str,
    pub release_channel_key: &'a str,
    pub target_update_ring: &'a str,
    pub starts_at: Option<DateTime<Utc>>,
    pub emergency: bool,
    pub reason: &'a str,
    pub correlation_id: Option<&'a str>,
}

pub async fn create_campaign(
    pool: &PgPool,
    input: CreateCampaignInput<'_>,
) -> Result<AdminCampaignRow, AdminError> {
    let mut tx = pool.begin().await?;
    let product_id = sqlx::query_scalar::<_, Uuid>(
        "select id from public.products where key = $1 and status = 'active'",
    )
    .bind(input.product_key)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AdminError::ProductNotFound)?;
    let release_channel_id = sqlx::query_scalar::<_, Uuid>(
        "select id from public.release_channels where product_id = $1 and key = $2",
    )
    .bind(product_id)
    .bind(input.release_channel_key)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AdminError::ProductNotFound)?;
    let release = sqlx::query_as::<_, (Uuid, String)>(
        "select product_id, status from public.product_releases where id = $1",
    )
    .bind(input.target_release_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AdminError::ReleaseNotFound)?;
    if release.0 != product_id {
        return Err(AdminError::InvalidState(
            "campaign release must belong to the product",
        ));
    }
    if release.1 == "blocked" || release.1 == "retired" {
        return Err(AdminError::InvalidState(
            "blocked or retired releases cannot be targeted",
        ));
    }

    let inserted = sqlx::query_scalar::<_, Uuid>(
        r#"
        insert into public.update_campaigns
            (product_id, target_release_id, campaign_slug, status, release_channel_id,
             target_update_ring, rollout_percentage, emergency, starts_at, created_by)
        values
            ($1, $2, $3, 'draft', $4, $5, 0, $6, $7, $8)
        on conflict (product_id, campaign_slug) do nothing
        returning id
        "#,
    )
    .bind(product_id)
    .bind(input.target_release_id)
    .bind(input.campaign_slug)
    .bind(release_channel_id)
    .bind(input.target_update_ring)
    .bind(input.emergency)
    .bind(input.starts_at)
    .bind(input.operator_id)
    .fetch_optional(&mut *tx)
    .await?;

    let campaign_id = match inserted {
        Some(id) => {
            write_operator_audit(
                &mut tx,
                OperatorAudit {
                    event_type: "update_campaign_created",
                    operator_id: input.operator_id,
                    customer_id: None,
                    target_type: "update_campaign",
                    target_id: id.to_string(),
                    reason: input.reason,
                    before_state: None,
                    after_state: Some(json!({
                        "campaign_slug": input.campaign_slug,
                        "target_release_id": input.target_release_id,
                        "status": "draft",
                        "rollout_percentage": 0,
                    })),
                    correlation_id: input.correlation_id,
                },
            )
            .await?;
            id
        }
        None => sqlx::query_scalar::<_, Uuid>(
            "select id from public.update_campaigns where product_id = $1 and campaign_slug = $2",
        )
        .bind(product_id)
        .bind(input.campaign_slug)
        .fetch_one(&mut *tx)
        .await?,
    };

    tx.commit().await?;
    read_campaign(pool, campaign_id)
        .await?
        .ok_or(AdminError::CampaignNotFound)
}

async fn campaign_status_mutation(
    pool: &PgPool,
    operator_id: &str,
    campaign_id: Uuid,
    to_status: &'static str,
    event_type: &'static str,
    reason: &str,
    correlation_id: Option<&str>,
) -> Result<AdminCampaignRow, AdminError> {
    let mut tx = pool.begin().await?;
    let current = sqlx::query_as::<_, (String, Uuid)>(
        "select status, target_release_id from public.update_campaigns where id = $1 for update",
    )
    .bind(campaign_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AdminError::CampaignNotFound)?;
    if current.0 != to_status {
        if to_status == "active" {
            let release_ok = sqlx::query_scalar::<_, bool>(
                "select exists(select 1 from public.product_releases where id = $1 and status = 'published')",
            )
            .bind(current.1)
            .fetch_one(&mut *tx)
            .await?;
            if !release_ok {
                return Err(AdminError::InvalidState(
                    "only campaigns targeting published releases can resume",
                ));
            }
        }
        if current.0 == "revoked" {
            return Err(AdminError::InvalidState(
                "revoked campaigns cannot transition",
            ));
        }
        sqlx::query("update public.update_campaigns set status = $2 where id = $1")
            .bind(campaign_id)
            .bind(to_status)
            .execute(&mut *tx)
            .await?;
        write_operator_audit(
            &mut tx,
            OperatorAudit {
                event_type,
                operator_id,
                customer_id: None,
                target_type: "update_campaign",
                target_id: campaign_id.to_string(),
                reason,
                before_state: Some(json!({ "status": current.0 })),
                after_state: Some(json!({ "status": to_status })),
                correlation_id,
            },
        )
        .await?;
    }
    tx.commit().await?;
    read_campaign(pool, campaign_id)
        .await?
        .ok_or(AdminError::CampaignNotFound)
}

pub async fn pause_campaign(
    pool: &PgPool,
    operator_id: &str,
    campaign_id: Uuid,
    reason: &str,
    correlation_id: Option<&str>,
) -> Result<AdminCampaignRow, AdminError> {
    campaign_status_mutation(
        pool,
        operator_id,
        campaign_id,
        "paused",
        "update_campaign_paused",
        reason,
        correlation_id,
    )
    .await
}

pub async fn resume_campaign(
    pool: &PgPool,
    operator_id: &str,
    campaign_id: Uuid,
    reason: &str,
    correlation_id: Option<&str>,
) -> Result<AdminCampaignRow, AdminError> {
    campaign_status_mutation(
        pool,
        operator_id,
        campaign_id,
        "active",
        "update_campaign_resumed",
        reason,
        correlation_id,
    )
    .await
}

pub async fn revoke_campaign(
    pool: &PgPool,
    operator_id: &str,
    campaign_id: Uuid,
    reason: &str,
    correlation_id: Option<&str>,
) -> Result<AdminCampaignRow, AdminError> {
    campaign_status_mutation(
        pool,
        operator_id,
        campaign_id,
        "revoked",
        "update_campaign_revoked",
        reason,
        correlation_id,
    )
    .await
}

pub async fn set_campaign_rollout(
    pool: &PgPool,
    operator_id: &str,
    campaign_id: Uuid,
    rollout_percentage: i32,
    reason: &str,
    correlation_id: Option<&str>,
) -> Result<AdminCampaignRow, AdminError> {
    let mut tx = pool.begin().await?;
    let current = sqlx::query_as::<_, (String, i32)>(
        "select status, rollout_percentage from public.update_campaigns where id = $1 for update",
    )
    .bind(campaign_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AdminError::CampaignNotFound)?;
    if current.0 == "revoked" {
        return Err(AdminError::InvalidState(
            "revoked campaigns cannot change rollout",
        ));
    }
    if current.1 != rollout_percentage {
        sqlx::query("update public.update_campaigns set rollout_percentage = $2 where id = $1")
            .bind(campaign_id)
            .bind(rollout_percentage)
            .execute(&mut *tx)
            .await?;
        write_operator_audit(
            &mut tx,
            OperatorAudit {
                event_type: "update_campaign_rollout_changed",
                operator_id,
                customer_id: None,
                target_type: "update_campaign",
                target_id: campaign_id.to_string(),
                reason,
                before_state: Some(json!({ "rollout_percentage": current.1 })),
                after_state: Some(json!({ "rollout_percentage": rollout_percentage })),
                correlation_id,
            },
        )
        .await?;
    }
    tx.commit().await?;
    read_campaign(pool, campaign_id)
        .await?
        .ok_or(AdminError::CampaignNotFound)
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct FleetHoldRow {
    pub id: Uuid,
    pub campaign_id: Uuid,
    pub fleet_id: Uuid,
    pub reason: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

pub async fn add_fleet_hold(
    pool: &PgPool,
    operator_id: &str,
    campaign_id: Uuid,
    fleet_id: Uuid,
    reason: &str,
    correlation_id: Option<&str>,
) -> Result<FleetHoldRow, AdminError> {
    let mut tx = pool.begin().await?;
    let campaign_exists = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from public.update_campaigns where id = $1)",
    )
    .bind(campaign_id)
    .fetch_one(&mut *tx)
    .await?;
    if !campaign_exists {
        return Err(AdminError::CampaignNotFound);
    }
    let customer_id = sqlx::query_scalar::<_, Uuid>(
        "select customer_id from public.fleets where id = $1 and status <> 'deleted'",
    )
    .bind(fleet_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AdminError::FleetNotFound)?;

    let hold = sqlx::query_as::<_, FleetHoldRow>(
        r#"
        insert into public.update_campaign_holds (campaign_id, fleet_id, reason, created_by)
        values ($1, $2, $3, $4)
        on conflict (campaign_id, fleet_id) do update
          set reason = excluded.reason,
              created_by = excluded.created_by
        returning id, campaign_id, fleet_id, reason, created_by, created_at
        "#,
    )
    .bind(campaign_id)
    .bind(fleet_id)
    .bind(reason)
    .bind(operator_id)
    .fetch_one(&mut *tx)
    .await?;
    write_operator_audit(
        &mut tx,
        OperatorAudit {
            event_type: "fleet_hold_added",
            operator_id,
            customer_id: Some(customer_id),
            target_type: "update_campaign_hold",
            target_id: hold.id.to_string(),
            reason,
            before_state: None,
            after_state: Some(json!({ "campaign_id": campaign_id, "fleet_id": fleet_id })),
            correlation_id,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(hold)
}

pub async fn remove_fleet_hold(
    pool: &PgPool,
    operator_id: &str,
    campaign_id: Uuid,
    fleet_id: Uuid,
    reason: &str,
    correlation_id: Option<&str>,
) -> Result<FleetHoldRow, AdminError> {
    let mut tx = pool.begin().await?;
    let hold = sqlx::query_as::<_, FleetHoldRow>(
        r#"
        delete from public.update_campaign_holds
        where campaign_id = $1 and fleet_id = $2
        returning id, campaign_id, fleet_id, reason, created_by, created_at
        "#,
    )
    .bind(campaign_id)
    .bind(fleet_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AdminError::FleetHoldNotFound)?;
    let customer_id =
        sqlx::query_scalar::<_, Uuid>("select customer_id from public.fleets where id = $1")
            .bind(fleet_id)
            .fetch_optional(&mut *tx)
            .await?;
    write_operator_audit(
        &mut tx,
        OperatorAudit {
            event_type: "fleet_hold_removed",
            operator_id,
            customer_id,
            target_type: "update_campaign_hold",
            target_id: hold.id.to_string(),
            reason,
            before_state: Some(json!({ "campaign_id": campaign_id, "fleet_id": fleet_id })),
            after_state: None,
            correlation_id,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(hold)
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct UpdateFailureRow {
    pub event_id: Uuid,
    pub installation_id: Option<Uuid>,
    pub fleet_id: Option<Uuid>,
    pub campaign_id: Option<Uuid>,
    pub release_id: Option<Uuid>,
    pub event_type: String,
    pub failure_code: Option<String>,
    pub failure_class: Option<String>,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub occurred_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
}

pub async fn list_update_failures(pool: &PgPool) -> Result<Vec<UpdateFailureRow>, sqlx::Error> {
    sqlx::query_as::<_, UpdateFailureRow>(
        r#"
        select e.id as event_id, e.installation_id, i.fleet_id, e.campaign_id, e.release_id,
               e.event_type, e.failure_code, e.failure_class, e.from_version, e.to_version,
               e.occurred_at, e.received_at
        from public.installation_update_events e
        left join public.installations i on i.id = e.installation_id
        where e.event_type in ('post_update_health_failed','failed','recovery_required')
        order by e.received_at desc
        limit 200
        "#,
    )
    .fetch_all(pool)
    .await
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct ArtifactQuarantineRow {
    pub artifact_id: Uuid,
    pub release_id: Uuid,
    pub status: String,
    pub paused_campaigns: i64,
}

pub async fn quarantine_artifact(
    pool: &PgPool,
    operator_id: &str,
    artifact_id: Uuid,
    reason: &str,
    correlation_id: Option<&str>,
) -> Result<ArtifactQuarantineRow, AdminError> {
    let mut tx = pool.begin().await?;
    let current = sqlx::query_as::<_, (Uuid, String)>(
        "select release_id, status from public.release_artifacts where id = $1 for update",
    )
    .bind(artifact_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AdminError::ArtifactNotFound)?;
    if current.1 != "quarantined" {
        sqlx::query("update public.release_artifacts set status = 'quarantined' where id = $1")
            .bind(artifact_id)
            .execute(&mut *tx)
            .await?;
    }
    let paused_campaigns = sqlx::query(
        "update public.update_campaigns set status = 'paused' where target_release_id = $1 and status = 'active'",
    )
    .bind(current.0)
    .execute(&mut *tx)
    .await?
    .rows_affected() as i64;
    write_operator_audit(
        &mut tx,
        OperatorAudit {
            event_type: "release_artifact_quarantined",
            operator_id,
            customer_id: None,
            target_type: "release_artifact",
            target_id: artifact_id.to_string(),
            reason,
            before_state: Some(json!({ "status": current.1 })),
            after_state: Some(json!({
                "status": "quarantined",
                "paused_campaigns": paused_campaigns,
            })),
            correlation_id,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(ArtifactQuarantineRow {
        artifact_id,
        release_id: current.0,
        status: "quarantined".to_string(),
        paused_campaigns,
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
