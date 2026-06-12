//! Customer profile lookups and API-owned profile provisioning.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Minimal customer projection used for context resolution.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CustomerRow {
    pub id: Uuid,
    pub status: String,
}

/// Full customer profile projection returned by account provisioning.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CustomerProfileRow {
    pub id: Uuid,
    pub auth_user_id: Uuid,
    pub customer_type: String,
    pub display_name: Option<String>,
    pub status: String,
    pub country_code: Option<String>,
    pub timezone: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Result of idempotent profile provisioning.
#[derive(Debug, Clone)]
pub struct ProvisionedCustomer {
    pub profile: CustomerProfileRow,
    pub default_fleet_id: Uuid,
    pub created: bool,
}

/// Resolve a customer profile from the Supabase auth user id. Returns `None` if no profile
/// exists yet (e.g. profile-creation flow has not run).
pub async fn find_by_auth_user_id(
    pool: &PgPool,
    auth_user_id: Uuid,
) -> Result<Option<CustomerRow>, sqlx::Error> {
    sqlx::query_as::<_, CustomerRow>(
        "select id, status from public.customer_profiles where auth_user_id = $1",
    )
    .bind(auth_user_id)
    .fetch_optional(pool)
    .await
}

/// Create or return the ForgeCustomer business profile for a Supabase-authenticated user.
///
/// The profile is inserted once per `auth_user_id`, with a status-history receipt written
/// in the same transaction for newly-created profiles. Repeated calls return the existing
/// row without creating duplicate history.
pub async fn provision_for_auth_user(
    pool: &PgPool,
    auth_user_id: Uuid,
    email: Option<&str>,
    display_name: Option<&str>,
    country_code: Option<&str>,
    timezone: Option<&str>,
) -> Result<ProvisionedCustomer, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let inserted = sqlx::query_as::<_, CustomerProfileRow>(
        r#"
        insert into public.customer_profiles
            (auth_user_id, customer_type, display_name, status, country_code, timezone)
        values
            ($1, 'individual', $2, 'active', $3, $4)
        on conflict (auth_user_id) do nothing
        returning id, auth_user_id, customer_type, display_name, status,
                  country_code, timezone, created_at, updated_at
        "#,
    )
    .bind(auth_user_id)
    .bind(display_name)
    .bind(country_code)
    .bind(timezone)
    .fetch_optional(&mut *tx)
    .await?;

    let (profile, created) = match inserted {
        Some(profile) => {
            sqlx::query(
                r#"
                insert into public.customer_status_history
                    (customer_id, from_status, to_status, reason, actor_type, actor_id)
                values
                    ($1, null, $2, 'account_provisioned', 'customer', $3)
                "#,
            )
            .bind(profile.id)
            .bind(&profile.status)
            .bind(auth_user_id.to_string())
            .execute(&mut *tx)
            .await?;
            crate::repositories::licensing::write_outbox(
                &mut tx,
                "customer_created",
                format!("customer_created:{}", profile.id),
                serde_json::json!({
                    "customer_id": profile.id,
                    "customer_type": profile.customer_type,
                    "occurred_at": profile.created_at,
                }),
            )
            .await?;
            (profile, true)
        }
        None => {
            let profile = sqlx::query_as::<_, CustomerProfileRow>(
                r#"
                select id, auth_user_id, customer_type, display_name, status,
                       country_code, timezone, created_at, updated_at
                from public.customer_profiles
                where auth_user_id = $1
                "#,
            )
            .bind(auth_user_id)
            .fetch_one(&mut *tx)
            .await?;
            (profile, false)
        }
    };

    let default_fleet_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        with inserted as (
          insert into public.fleets (customer_id, display_name, fleet_type, status, update_ring, release_channel_id)
          values (
            $1,
            coalesce(nullif(trim($2), ''), 'Default fleet'),
            'default',
            'active',
            'standard',
            (
              select rc.id
              from public.release_channels rc
              join public.products p on p.id = rc.product_id
              where p.key = 'authorforge' and rc.key = 'stable'
              limit 1
            )
          )
          on conflict do nothing
          returning id
        )
        select id from inserted
        union all
        select id from public.fleets
        where customer_id = $1 and fleet_type = 'default' and status <> 'deleted'
        limit 1
        "#,
    )
    .bind(profile.id)
    .bind(profile.display_name.as_deref())
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        insert into public.fleet_applications (fleet_id, product_id, status, update_ring, release_channel_id)
        select $1, p.id, 'active', 'standard',
               (select rc.id from public.release_channels rc
                where rc.product_id = p.id and rc.key = 'stable' limit 1)
        from public.products p
        where p.key = 'authorforge'
        on conflict (fleet_id, product_id) do nothing
        "#,
    )
    .bind(default_fleet_id)
    .execute(&mut *tx)
    .await?;

    if let Some(email) = email {
        sqlx::query(
            r#"
            insert into public.customer_emails (customer_id, email, is_primary)
            values ($1, $2, true)
            on conflict do nothing
            "#,
        )
        .bind(profile.id)
        .bind(email)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(ProvisionedCustomer {
        profile,
        default_fleet_id,
        created,
    })
}
