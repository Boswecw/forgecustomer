//! Immutable global commercial-policy versions owned by ForgeCustomer.
//!
//! This is deliberately not an entitlement-override repository: overrides are exceptions for one
//! customer, while a policy version is the auditable global contract for an AuthorForge plan.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::repositories::admin::{write_operator_audit, OperatorAudit};
use crate::repositories::licensing::write_outbox;

const AUTHORFORGE_PRODUCT_KEY: &str = "authorforge";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLimits {
    pub cloud_tokens_per_month: i64,
    pub deep_analysis_runs_per_month: i64,
    pub premium_model_requests_per_month: i64,
    pub device_limit: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    pub included: PolicyLimits,
    pub pro: PolicyLimits,
}

impl PolicyDocument {
    pub fn validate(&self) -> Result<(), PolicyError> {
        for (plan, limits) in [("included", &self.included), ("pro", &self.pro)] {
            for (field, value) in [
                ("cloud_tokens_per_month", limits.cloud_tokens_per_month),
                (
                    "deep_analysis_runs_per_month",
                    limits.deep_analysis_runs_per_month,
                ),
                (
                    "premium_model_requests_per_month",
                    limits.premium_model_requests_per_month,
                ),
                ("device_limit", limits.device_limit),
            ] {
                if value < 0 {
                    return Err(PolicyError::Invalid(format!(
                        "{plan}.{field} must be non-negative"
                    )));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct CommercialPolicyVersion {
    pub product_key: String,
    pub plan_version: String,
    pub effective_at: DateTime<Utc>,
    pub policy: Value,
    pub reason: String,
    pub published_by: String,
    pub correlation_id: Option<String>,
    pub published_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct PublishInput<'a> {
    pub operator_id: &'a str,
    pub base_plan_version: &'a str,
    pub effective_at: DateTime<Utc>,
    pub policy: PolicyDocument,
    pub reason: &'a str,
    pub idempotency_key: &'a str,
    pub correlation_id: Option<&'a str>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("AuthorForge product not found")]
    ProductNotFound,
    #[error("no active commercial policy version exists")]
    NoActivePolicy,
    #[error("base policy version does not match the active policy")]
    VersionConflict,
    #[error("effective_at must not be more than five minutes in the past")]
    EffectiveAtInPast,
    #[error("invalid commercial policy: {0}")]
    Invalid(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

#[derive(sqlx::FromRow)]
struct StoredPolicyVersion {
    product_key: String,
    version: i64,
    effective_at: DateTime<Utc>,
    policy: Value,
    reason: String,
    created_by: String,
    correlation_id: Option<String>,
    created_at: DateTime<Utc>,
}

impl From<StoredPolicyVersion> for CommercialPolicyVersion {
    fn from(row: StoredPolicyVersion) -> Self {
        Self {
            product_key: row.product_key,
            plan_version: row.version.to_string(),
            effective_at: row.effective_at,
            policy: row.policy,
            reason: row.reason,
            published_by: row.created_by,
            correlation_id: row.correlation_id,
            published_at: row.created_at,
        }
    }
}

async fn active_policy(
    tx: &mut Transaction<'_, Postgres>,
    product_id: Uuid,
) -> Result<Option<StoredPolicyVersion>, sqlx::Error> {
    sqlx::query_as::<_, StoredPolicyVersion>(
        r#"
        select p.key as product_key, cp.version, cp.effective_at, cp.policy, cp.reason,
               cp.created_by, cp.correlation_id, cp.created_at
        from public.commercial_policy_versions cp
        join public.products p on p.id = cp.product_id
        where cp.product_id = $1 and cp.effective_at <= now()
        order by cp.effective_at desc, cp.version desc
        limit 1
        "#,
    )
    .bind(product_id)
    .fetch_optional(&mut **tx)
    .await
}

pub async fn read_active(pool: &PgPool) -> Result<Option<CommercialPolicyVersion>, sqlx::Error> {
    let row = sqlx::query_as::<_, StoredPolicyVersion>(
        r#"
        select p.key as product_key, cp.version, cp.effective_at, cp.policy, cp.reason,
               cp.created_by, cp.correlation_id, cp.created_at
        from public.commercial_policy_versions cp
        join public.products p on p.id = cp.product_id
        where p.key = $1 and cp.effective_at <= now()
        order by cp.effective_at desc, cp.version desc
        limit 1
        "#,
    )
    .bind(AUTHORFORGE_PRODUCT_KEY)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

/// The effective document used by entitlement and licensing evaluation. The database is the
/// authority; a malformed historic record is treated as a database decode failure rather than
/// silently falling back to stale plan-version values.
pub async fn active_document(pool: &PgPool) -> Result<Option<PolicyDocument>, sqlx::Error> {
    let policy = sqlx::query_scalar::<_, Value>(
        r#"
        select cp.policy
        from public.commercial_policy_versions cp
        join public.products p on p.id = cp.product_id
        where p.key = $1 and cp.effective_at <= now()
        order by cp.effective_at desc, cp.version desc
        limit 1
        "#,
    )
    .bind(AUTHORFORGE_PRODUCT_KEY)
    .fetch_optional(pool)
    .await?;
    policy
        .map(serde_json::from_value::<PolicyDocument>)
        .transpose()
        .map_err(|error| sqlx::Error::Decode(Box::new(error)))
}

pub async fn publish(
    pool: &PgPool,
    input: PublishInput<'_>,
) -> Result<CommercialPolicyVersion, PolicyError> {
    input.policy.validate()?;
    if input.effective_at < Utc::now() - Duration::minutes(5) {
        return Err(PolicyError::EffectiveAtInPast);
    }

    let mut tx = pool.begin().await?;
    // Locking the product serializes version allocation and prevents two operators from both
    // successfully publishing against the same active version.
    let product_id = sqlx::query_scalar::<_, Uuid>(
        "select id from public.products where key = $1 and status = 'active' for update",
    )
    .bind(AUTHORFORGE_PRODUCT_KEY)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(PolicyError::ProductNotFound)?;

    let existing = sqlx::query_as::<_, StoredPolicyVersion>(
        r#"
        select p.key as product_key, cp.version, cp.effective_at, cp.policy, cp.reason,
               cp.created_by, cp.correlation_id, cp.created_at
        from public.commercial_policy_versions cp
        join public.products p on p.id = cp.product_id
        where cp.product_id = $1 and cp.idempotency_key = $2
        "#,
    )
    .bind(product_id)
    .bind(input.idempotency_key)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = existing {
        tx.commit().await?;
        return Ok(row.into());
    }

    let active = active_policy(&mut tx, product_id)
        .await?
        .ok_or(PolicyError::NoActivePolicy)?;
    if input.base_plan_version.trim() != active.version.to_string() {
        return Err(PolicyError::VersionConflict);
    }

    let next_version = sqlx::query_scalar::<_, i64>(
        "select coalesce(max(version), 0) + 1 from public.commercial_policy_versions where product_id = $1",
    )
    .bind(product_id)
    .fetch_one(&mut *tx)
    .await?;
    let policy = serde_json::to_value(&input.policy)
        .map_err(|error| PolicyError::Invalid(error.to_string()))?;

    let inserted = sqlx::query_as::<_, StoredPolicyVersion>(
        r#"
        insert into public.commercial_policy_versions
          (product_id, version, effective_at, policy, reason, created_by, idempotency_key, correlation_id)
        values ($1, $2, $3, $4, $5, $6, $7, $8)
        returning $9::text as product_key, version, effective_at, policy, reason, created_by,
                  correlation_id, created_at
        "#,
    )
    .bind(product_id)
    .bind(next_version)
    .bind(input.effective_at)
    .bind(&policy)
    .bind(input.reason)
    .bind(input.operator_id)
    .bind(input.idempotency_key)
    .bind(input.correlation_id)
    .bind(AUTHORFORGE_PRODUCT_KEY)
    .fetch_one(&mut *tx)
    .await?;

    write_operator_audit(
        &mut tx,
        OperatorAudit {
            event_type: "commercial_policy_version_published",
            operator_id: input.operator_id,
            customer_id: None,
            target_type: "commercial_policy",
            target_id: format!("{AUTHORFORGE_PRODUCT_KEY}:{}", inserted.version),
            reason: input.reason,
            before_state: Some(json!({ "plan_version": active.version, "policy": active.policy })),
            after_state: Some(json!({ "plan_version": inserted.version, "effective_at": inserted.effective_at, "policy": inserted.policy })),
            correlation_id: input.correlation_id,
        },
    )
    .await?;
    write_outbox(
        &mut tx,
        "commercial_policy_version_published",
        format!(
            "commercial-policy:{AUTHORFORGE_PRODUCT_KEY}:{}",
            inserted.version
        ),
        json!({
            "product_key": AUTHORFORGE_PRODUCT_KEY,
            "plan_version": inserted.version,
            "effective_at": inserted.effective_at,
        }),
    )
    .await?;

    tx.commit().await?;
    Ok(inserted.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_document_rejects_negative_limits() {
        let policy = PolicyDocument {
            included: PolicyLimits {
                cloud_tokens_per_month: 0,
                deep_analysis_runs_per_month: 0,
                premium_model_requests_per_month: 0,
                device_limit: 1,
            },
            pro: PolicyLimits {
                cloud_tokens_per_month: 1,
                deep_analysis_runs_per_month: 1,
                premium_model_requests_per_month: 1,
                device_limit: -1,
            },
        };
        assert!(
            matches!(policy.validate(), Err(PolicyError::Invalid(message)) if message == "pro.device_limit must be non-negative")
        );
    }
}
