//! Entitlement persistence: assembling evaluation inputs from catalog, subscription,
//! license, grant, and override rows; recording issued snapshots; and issuing signed
//! offline leases.
//!
//! Assembly maps the precedence layers in `docs/ENTITLEMENTS.md` onto data sources:
//! the product's `<product>_included` plan is the baseline ("product defaults"), the
//! customer's current subscription contributes its plan version, then license grants,
//! promotional grants, and admin overrides apply in order. Cloud gating and
//! suspension/revocation denials are applied by the pure evaluator.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::entitlement::{EntitlementInputs, FeatureValue};
use crate::domain::lease::{OfflineLease, LEASE_SCHEMA_VERSION};
use crate::domain::snapshot::EntitlementSnapshot;
use crate::domain::subscription::{normalize_stripe_status, SubscriptionStatus};
use crate::repositories::licensing::{write_customer_audit, CustomerAudit};
use crate::services::signing::Signer25519;

#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("installation not found")]
    InstallationNotFound,
    #[error("installation is deactivated")]
    InstallationDeactivated,
    #[error("no active license activation for this installation")]
    NoActiveActivation,
    #[error("license is not active ({0})")]
    LicenseNotActive(String),
    #[error("lease issuance blocked by an explicit revocation")]
    RevocationBlocked,
    #[error("signing failed: {0}")]
    Signing(#[from] crate::services::signing::SigningError),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Everything needed to evaluate and issue a snapshot for (customer, product).
#[derive(Debug, Clone)]
pub struct LoadedEntitlements {
    pub product_id: Uuid,
    pub product_key: String,
    pub inputs: EntitlementInputs,
    pub subscription_status: Option<SubscriptionStatus>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct FeatureValueRow {
    key: String,
    bool_value: Option<bool>,
    number_value: Option<f64>,
    string_value: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct QuotaRow {
    meter_key: String,
    limit_value: f64,
    reset_cadence: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct GrantRow {
    feature_key: Option<String>,
    quota_key: Option<String>,
    bool_value: Option<bool>,
    number_value: Option<f64>,
    string_value: Option<String>,
}

fn feature_value(
    bool_value: Option<bool>,
    number_value: Option<f64>,
    string_value: Option<String>,
) -> Option<FeatureValue> {
    if let Some(value) = bool_value {
        return Some(FeatureValue::Bool(value));
    }
    if let Some(value) = number_value {
        return Some(FeatureValue::Number(value));
    }
    string_value.map(FeatureValue::Text)
}

fn merge_grants(
    rows: Vec<GrantRow>,
    features: &mut BTreeMap<String, FeatureValue>,
    quotas: &mut BTreeMap<String, f64>,
) {
    for row in rows {
        if let Some(key) = row.feature_key {
            if let Some(value) =
                feature_value(row.bool_value, row.number_value, row.string_value.clone())
            {
                features.insert(key, value);
            }
        } else if let Some(key) = row.quota_key {
            if let Some(value) = row.number_value {
                quotas.insert(key, value);
            }
        }
    }
}

async fn plan_feature_layer(
    pool: &PgPool,
    plan_version_id: Uuid,
) -> Result<BTreeMap<String, FeatureValue>, sqlx::Error> {
    let rows = sqlx::query_as::<_, FeatureValueRow>(
        r#"
        select f.key, pf.bool_value, pf.number_value::float8 as number_value, pf.string_value
        from public.plan_features pf
        join public.features f on f.id = pf.feature_id
        where pf.plan_version_id = $1
        "#,
    )
    .bind(plan_version_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            feature_value(row.bool_value, row.number_value, row.string_value)
                .map(|value| (row.key, value))
        })
        .collect())
}

async fn plan_quota_layer(
    pool: &PgPool,
    plan_version_id: Uuid,
) -> Result<Vec<QuotaRow>, sqlx::Error> {
    sqlx::query_as::<_, QuotaRow>(
        r#"
        select meter_key, limit_value::float8 as limit_value, reset_cadence
        from public.plan_quotas
        where plan_version_id = $1
        "#,
    )
    .bind(plan_version_id)
    .fetch_all(pool)
    .await
}

/// The active plan version of the product's `<product>_included` plan: the baseline every
/// customer holds without a subscription.
async fn included_plan_version(
    pool: &PgPool,
    product_id: Uuid,
    product_key: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        r#"
        select pv.id
        from public.plan_versions pv
        join public.plans pl on pl.id = pv.plan_id
        where pl.product_id = $1
          and pl.key = $2
          and pl.status = 'active'
          and pv.status = 'active'
        "#,
    )
    .bind(product_id)
    .bind(format!("{product_key}_included"))
    .fetch_optional(pool)
    .await
}

/// The customer's current subscription for the product: prefer a cloud-granting one,
/// otherwise the most recent non-canceled one (its plan still describes non-cloud terms
/// during dunning). Canceled subscriptions contribute nothing.
async fn current_subscription(
    pool: &PgPool,
    customer_id: Uuid,
    product_id: Uuid,
) -> Result<Option<(Uuid, String)>, sqlx::Error> {
    sqlx::query_as::<_, (Uuid, String)>(
        r#"
        select s.plan_version_id, s.status
        from public.subscriptions s
        join public.plan_versions pv on pv.id = s.plan_version_id
        join public.plans pl on pl.id = pv.plan_id
        where s.customer_id = $1
          and pl.product_id = $2
          and s.status <> 'canceled'
        order by (s.status in ('active','trialing')) desc,
                 s.stripe_event_at desc nulls last,
                 s.created_at desc
        limit 1
        "#,
    )
    .bind(customer_id)
    .bind(product_id)
    .fetch_optional(pool)
    .await
}

/// Load every evaluation layer for (customer, product). Returns `None` for an unknown or
/// inactive product. Suspension is enforced at the route boundary (`require_active`), so
/// `inputs.suspended` is always false here.
pub async fn load_entitlement_inputs(
    pool: &PgPool,
    customer_id: Uuid,
    product_key: &str,
) -> Result<Option<LoadedEntitlements>, sqlx::Error> {
    let Some(product_id) = sqlx::query_scalar::<_, Uuid>(
        "select id from public.products where key = $1 and status = 'active'",
    )
    .bind(product_key)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };

    let mut inputs = EntitlementInputs::default();
    let mut quotas: BTreeMap<String, f64> = BTreeMap::new();
    let mut cadences: BTreeMap<String, String> = BTreeMap::new();

    // Baseline: the included plan ("product defaults" layer).
    if let Some(plan_version_id) = included_plan_version(pool, product_id, product_key).await? {
        inputs.product_defaults = plan_feature_layer(pool, plan_version_id).await?;
        for quota in plan_quota_layer(pool, plan_version_id).await? {
            cadences.insert(quota.meter_key.clone(), quota.reset_cadence);
            quotas.insert(quota.meter_key, quota.limit_value);
        }
    }

    // Subscription plan layer + cloud gate.
    let subscription = current_subscription(pool, customer_id, product_id).await?;
    let subscription_status = subscription
        .as_ref()
        .map(|(_, status)| normalize_stripe_status(status));
    if let Some((plan_version_id, _)) = subscription {
        inputs.plan_version = plan_feature_layer(pool, plan_version_id).await?;
        for quota in plan_quota_layer(pool, plan_version_id).await? {
            cadences.insert(quota.meter_key.clone(), quota.reset_cadence);
            quotas.insert(quota.meter_key, quota.limit_value);
        }
    }
    inputs.subscription_grants_cloud = subscription_status
        .map(SubscriptionStatus::grants_cloud)
        .unwrap_or(false);

    // License grants from active, unexpired licenses; revocation denial from the
    // customer's most recent license for the product.
    let license_grant_rows = sqlx::query_as::<_, FeatureValueRow>(
        r#"
        select g.feature_key as key, g.bool_value, g.number_value::float8 as number_value,
               g.string_value
        from public.license_grants g
        join public.licenses l on l.id = g.license_id
        where l.customer_id = $1
          and l.product_id = $2
          and l.status = 'active'
          and (l.expires_at is null or l.expires_at > now())
        order by g.created_at
        "#,
    )
    .bind(customer_id)
    .bind(product_id)
    .fetch_all(pool)
    .await?;
    inputs.license_grants = license_grant_rows
        .into_iter()
        .filter_map(|row| {
            feature_value(row.bool_value, row.number_value, row.string_value)
                .map(|value| (row.key, value))
        })
        .collect();

    inputs.revoked = sqlx::query_scalar::<_, Option<String>>(
        r#"
        select status from public.licenses
        where customer_id = $1 and product_id = $2
        order by issued_at desc
        limit 1
        "#,
    )
    .bind(customer_id)
    .bind(product_id)
    .fetch_optional(pool)
    .await?
    .flatten()
    .as_deref()
        == Some("revoked");

    // Promotional grants then admin overrides (highest precedence below denials).
    let grant_rows = sqlx::query_as::<_, GrantRow>(
        r#"
        select feature_key, quota_key, bool_value, number_value::float8 as number_value,
               string_value
        from public.entitlement_grants
        where customer_id = $1
          and product_id = $2
          and (expires_at is null or expires_at > now())
        order by created_at
        "#,
    )
    .bind(customer_id)
    .bind(product_id)
    .fetch_all(pool)
    .await?;
    merge_grants(grant_rows, &mut inputs.promotional_grants, &mut quotas);

    let override_rows = sqlx::query_as::<_, GrantRow>(
        r#"
        select feature_key, quota_key, bool_value, number_value::float8 as number_value,
               string_value
        from public.entitlement_overrides
        where customer_id = $1
          and product_id = $2
          and active
          and (expires_at is null or expires_at > now())
        order by created_at
        "#,
    )
    .bind(customer_id)
    .bind(product_id)
    .fetch_all(pool)
    .await?;
    merge_grants(override_rows, &mut inputs.admin_overrides, &mut quotas);

    inputs.quota_limits = quotas;

    // Current committed usage for monthly meters, surfaced as `<meter>.used` alongside
    // the limits (the meter key strips the cadence suffix, e.g. `cloud_tokens.monthly`
    // counts usage on the `cloud_tokens` meter).
    let period_key = Utc::now().format("%Y-%m").to_string();
    let mut used_entries: BTreeMap<String, f64> = BTreeMap::new();
    for (meter_key, cadence) in &cadences {
        if cadence != "monthly" {
            continue;
        }
        let base = meter_key
            .strip_suffix(".monthly")
            .unwrap_or(meter_key.as_str());
        let used = sqlx::query_scalar::<_, Option<f64>>(
            r#"
            select used::float8 from public.usage_period_totals
            where customer_id = $1 and meter_key = $2 and period_key = $3
            "#,
        )
        .bind(customer_id)
        .bind(base)
        .bind(&period_key)
        .fetch_optional(pool)
        .await?
        .flatten()
        .unwrap_or(0.0);
        used_entries.insert(format!("{base}.used"), used);
    }
    inputs.quota_limits.extend(used_entries);

    Ok(Some(LoadedEntitlements {
        product_id,
        product_key: product_key.to_string(),
        inputs,
        subscription_status,
    }))
}

/// Quota state for a single meter (check endpoint).
#[derive(Debug, Clone, Copy, Default)]
pub struct MeterUsage {
    pub used: f64,
    pub reserved: f64,
}

/// Read current committed/reserved totals for one quota key in the current monthly period.
pub async fn meter_usage(
    pool: &PgPool,
    customer_id: Uuid,
    quota_key: &str,
) -> Result<MeterUsage, sqlx::Error> {
    let base = quota_key.strip_suffix(".monthly").unwrap_or(quota_key);
    let period_key = Utc::now().format("%Y-%m").to_string();
    let row = sqlx::query_as::<_, (f64, f64)>(
        r#"
        select used::float8, reserved::float8 from public.usage_period_totals
        where customer_id = $1 and meter_key = $2 and period_key = $3
        "#,
    )
    .bind(customer_id)
    .bind(base)
    .bind(period_key)
    .fetch_optional(pool)
    .await?;
    Ok(row
        .map(|(used, reserved)| MeterUsage { used, reserved })
        .unwrap_or_default())
}

/// Record an issued snapshot for audit/replay verification. `payload` is the canonical
/// signed snapshot JSON, serialized by the caller so serialization failures surface
/// before anything is stored or returned.
pub async fn store_snapshot(
    pool: &PgPool,
    customer_id: Uuid,
    installation_id: Option<Uuid>,
    product_id: Uuid,
    snapshot: &EntitlementSnapshot,
    payload: &serde_json::Value,
    expires_at: DateTime<Utc>,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        r#"
        insert into public.entitlement_snapshots
            (customer_id, installation_id, product_id, schema_version, payload, key_id,
             signature, expires_at)
        values
            ($1, $2, $3, $4, $5, $6, $7, $8)
        returning id
        "#,
    )
    .bind(customer_id)
    .bind(installation_id)
    .bind(product_id)
    .bind(&snapshot.schema_version)
    .bind(payload)
    .bind(&snapshot.key_id)
    .bind(&snapshot.signature)
    .bind(expires_at)
    .fetch_one(pool)
    .await
}

/// Resolve an installation owned by the customer, returning its product binding.
pub async fn find_owned_installation(
    pool: &PgPool,
    customer_id: Uuid,
    installation_id: Uuid,
) -> Result<Option<(Uuid, String)>, sqlx::Error> {
    sqlx::query_as::<_, (Uuid, String)>(
        r#"
        select i.id, p.key
        from public.installations i
        join public.products p on p.id = i.product_id
        where i.id = $1 and i.customer_id = $2
        "#,
    )
    .bind(installation_id)
    .bind(customer_id)
    .fetch_optional(pool)
    .await
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct LeaseContextRow {
    installation_status: String,
    device_id: Option<Uuid>,
    device_status: Option<String>,
    product_key: String,
    // Null when the installation has no active activation (left joins).
    license_id: Option<Uuid>,
    license_status: Option<String>,
    license_expires_at: Option<DateTime<Utc>>,
}

/// The signed lease plus its stored row id.
#[derive(Debug, Clone)]
pub struct IssuedLease {
    pub lease: OfflineLease,
}

/// Issue a signed offline lease for an activated installation. Fails closed: requires an
/// active installation with an active activation on an active, unexpired license, no
/// explicit revocation in scope, and a non-revoked device. Writes the lease row and a
/// `lease_issued` audit event in one transaction.
pub async fn issue_offline_lease(
    pool: &PgPool,
    signer: &Signer25519,
    customer_id: Uuid,
    installation_id: Uuid,
    lease_ttl: chrono::Duration,
    correlation_id: Option<&str>,
) -> Result<IssuedLease, LeaseError> {
    let mut tx = pool.begin().await?;

    let context = sqlx::query_as::<_, LeaseContextRow>(
        r#"
        select i.status as installation_status,
               i.device_id,
               d.status as device_status,
               p.key as product_key,
               l.id as license_id,
               l.status as license_status,
               l.expires_at as license_expires_at
        from public.installations i
        join public.products p on p.id = i.product_id
        left join public.devices d on d.id = i.device_id
        left join public.license_activations a
               on a.installation_id = i.id and a.status = 'active'
        left join public.licenses l on l.id = a.license_id
        where i.id = $1 and i.customer_id = $2
        order by a.activated_at desc nulls last
        limit 1
        "#,
    )
    .bind(installation_id)
    .bind(customer_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(LeaseError::InstallationNotFound)?;

    if context.installation_status == "deactivated" {
        return Err(LeaseError::InstallationDeactivated);
    }
    if context.device_status.as_deref() == Some("revoked") {
        return Err(LeaseError::RevocationBlocked);
    }
    // The left joins yield a row even without an activation; null license columns mean
    // the installation was never activated (or its activations were released).
    let (Some(license_id), Some(license_status)) = (context.license_id, context.license_status)
    else {
        return Err(LeaseError::NoActiveActivation);
    };
    if license_status == "revoked" {
        return Err(LeaseError::RevocationBlocked);
    }
    if license_status != "active" {
        return Err(LeaseError::LicenseNotActive(license_status));
    }
    if matches!(context.license_expires_at, Some(at) if at <= Utc::now()) {
        return Err(LeaseError::LicenseNotActive("expired".to_string()));
    }

    let revocation_blocked = sqlx::query_scalar::<_, bool>(
        r#"
        select exists (
            select 1 from public.license_revocations r
            where (r.license_id = $1 and r.installation_id is null and r.device_id is null)
               or r.installation_id = $2
               or ($3::uuid is not null and r.device_id = $3)
        )
        "#,
    )
    .bind(license_id)
    .bind(installation_id)
    .bind(context.device_id)
    .fetch_one(&mut *tx)
    .await?;
    if revocation_blocked {
        return Err(LeaseError::RevocationBlocked);
    }

    let lease_id = Uuid::new_v4();
    let issued_at = Utc::now();
    let expires_at = issued_at + lease_ttl;
    let mut lease = OfflineLease {
        schema_version: LEASE_SCHEMA_VERSION.to_string(),
        lease_id: lease_id.to_string(),
        customer_id: customer_id.to_string(),
        license_id: license_id.to_string(),
        installation_id: installation_id.to_string(),
        product: context.product_key,
        issued_at: issued_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        expires_at: expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        key_id: signer.key_id().to_string(),
        signature: String::new(),
    };
    let bytes = lease
        .signing_bytes()
        .map_err(|e| LeaseError::Signing(crate::services::signing::SigningError::Serialize(e)))?;
    lease.signature = signer.sign_bytes(&bytes);

    sqlx::query(
        r#"
        insert into public.license_leases
            (id, license_id, installation_id, issued_at, expires_at, key_id, signature)
        values
            ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(lease_id)
    .bind(license_id)
    .bind(installation_id)
    .bind(issued_at)
    .bind(expires_at)
    .bind(&lease.key_id)
    .bind(&lease.signature)
    .execute(&mut *tx)
    .await?;

    write_customer_audit(
        &mut tx,
        CustomerAudit {
            event_type: "lease_issued",
            customer_id,
            target_type: "license_lease",
            target_id: lease_id.to_string(),
            reason: "offline_lease_request",
            before_state: None,
            after_state: Some(json!({
                "license_id": license_id,
                "installation_id": installation_id,
                "expires_at": lease.expires_at,
            })),
            correlation_id,
        },
    )
    .await?;

    tx.commit().await?;
    Ok(IssuedLease { lease })
}
