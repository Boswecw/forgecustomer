//! Update-campaign lookup and minimal update-event receipts.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum UpdateEventError {
    #[error("installation not found")]
    InstallationNotFound,
    #[error("update ticket is invalid, expired, or does not belong to the installation")]
    InvalidUpdateTicket,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UpdateCandidateRow {
    pub campaign_id: Uuid,
    pub release_id: Uuid,
    pub version: String,
    pub build_id: String,
    pub changelog_markdown: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
    pub minimum_supported_version: Option<String>,
    pub minimum_updater_version: Option<String>,
    pub storage_key: String,
    pub tauri_signature: Option<String>,
    pub rollout_percentage: i32,
}

const CANDIDATE_ROWS_SQL: &str = r#"
        select c.id as campaign_id,
               r.id as release_id,
               r.version,
               r.build_id,
               r.changelog_markdown,
               r.published_at,
               r.minimum_supported_version,
               r.minimum_updater_version,
               a.storage_key,
               a.tauri_signature,
               c.rollout_percentage
        from public.installations i
        join public.fleets f
          on f.id = i.fleet_id
         and f.customer_id = i.customer_id
        join public.products p
          on p.key = $3
         and p.status = 'active'
        join public.fleet_applications fa
          on fa.fleet_id = f.id
         and fa.product_id = p.id
        join public.update_campaigns c
          on c.product_id = p.id
         and c.release_channel_id = fa.release_channel_id
         and c.target_update_ring = fa.update_ring
        join public.product_releases r
          on r.id = c.target_release_id
         and r.product_id = p.id
         and r.release_channel_id = c.release_channel_id
        join public.release_artifacts a
          on a.release_id = r.id
        where i.id = $2
          and i.customer_id = $1
          and i.status = 'active'
          and f.status = 'active'
          and fa.status = 'active'
          and c.status = 'active'
          and (c.starts_at is null or c.starts_at <= now())
          and r.status = 'published'
          and a.status = 'validated'
          and a.artifact_role = 'updater'
          and a.platform = $4
          and a.architecture = $5
          and a.package_format = $6
          and not exists (
            select 1
            from public.update_campaign_holds h
            where h.campaign_id = c.id and h.fleet_id = f.id
          )
        order by c.emergency desc, c.created_at desc
        limit 20
        "#;

pub struct UpdateLookupInput<'a> {
    pub customer_id: Uuid,
    pub installation_id: Uuid,
    pub product_key: &'a str,
    pub platform: &'a str,
    pub architecture: &'a str,
    pub package_format: &'a str,
}

pub async fn candidate_rows(
    pool: &PgPool,
    input: UpdateLookupInput<'_>,
) -> Result<Vec<UpdateCandidateRow>, sqlx::Error> {
    sqlx::query_as::<_, UpdateCandidateRow>(CANDIDATE_ROWS_SQL)
        .bind(input.customer_id)
        .bind(input.installation_id)
        .bind(input.product_key)
        .bind(input.platform)
        .bind(input.architecture)
        .bind(input.package_format)
        .fetch_all(pool)
        .await
}

/// Returns the stable opaque ticket for this eligible installation/campaign/release
/// combination, extending its short receipt window from the current lookup. The UUID
/// deliberately has no client-meaningful campaign or release information.
pub async fn issue_update_ticket(
    pool: &PgPool,
    installation_id: Uuid,
    campaign_id: Uuid,
    release_id: Uuid,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        r#"
        insert into public.update_outcome_tickets
            (installation_id, campaign_id, release_id, expires_at, issued_at)
        values
            ($1, $2, $3, now() + interval '1 hour', now())
        on conflict (installation_id, campaign_id, release_id) do update
        set expires_at = excluded.expires_at,
            issued_at = excluded.issued_at
        returning token
        "#,
    )
    .bind(installation_id)
    .bind(campaign_id)
    .bind(release_id)
    .fetch_one(pool)
    .await
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct PublicReleaseRow {
    pub product_key: String,
    pub version: String,
    pub build_id: String,
    pub release_channel_key: String,
    pub release_notes: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
}

pub async fn latest_published_release(
    pool: &PgPool,
    product_key: &str,
    channel_key: &str,
) -> Result<Option<PublicReleaseRow>, sqlx::Error> {
    sqlx::query_as::<_, PublicReleaseRow>(
        r#"
        select p.key as product_key, r.version, r.build_id, rc.key as release_channel_key,
               r.changelog_markdown as release_notes, r.published_at
        from public.product_releases r
        join public.products p on p.id = r.product_id
        join public.release_channels rc on rc.id = r.release_channel_id
        where p.key = $1
          and p.status = 'active'
          and rc.key = $2
          and r.status = 'published'
        order by r.published_at desc nulls last, r.created_at desc
        limit 1
        "#,
    )
    .bind(product_key)
    .bind(channel_key)
    .fetch_optional(pool)
    .await
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BootstrapDownloadRow {
    pub product_key: String,
    pub version: String,
    pub build_id: String,
    pub release_channel_key: String,
    pub platform: String,
    pub architecture: String,
    pub package_format: String,
    pub storage_key: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub release_notes: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
}

pub struct BootstrapDownloadInput<'a> {
    pub product_key: &'a str,
    pub channel_key: &'a str,
    pub platform: &'a str,
    pub architecture: &'a str,
    pub package_format: Option<&'a str>,
}

pub async fn bootstrap_download(
    pool: &PgPool,
    input: BootstrapDownloadInput<'_>,
) -> Result<Option<BootstrapDownloadRow>, sqlx::Error> {
    sqlx::query_as::<_, BootstrapDownloadRow>(
        r#"
        select p.key as product_key, r.version, r.build_id, rc.key as release_channel_key,
               a.platform, a.architecture, a.package_format, a.storage_key, a.sha256,
               a.size_bytes, r.changelog_markdown as release_notes, r.published_at
        from public.product_releases r
        join public.products p on p.id = r.product_id
        join public.release_channels rc on rc.id = r.release_channel_id
        join public.release_artifacts a on a.release_id = r.id
        where p.key = $1
          and p.status = 'active'
          and rc.key = $2
          and r.status = 'published'
          and a.status = 'validated'
          and a.artifact_role = 'bootstrap'
          and a.platform = $3
          and a.architecture = $4
          and ($5::text is null or a.package_format = $5)
        order by r.published_at desc nulls last, r.created_at desc, a.package_format asc
        limit 1
        "#,
    )
    .bind(input.product_key)
    .bind(input.channel_key)
    .bind(input.platform)
    .bind(input.architecture)
    .bind(input.package_format)
    .fetch_optional(pool)
    .await
}

pub struct UpdateEventInput<'a> {
    pub event_id: Uuid,
    pub customer_id: Uuid,
    pub installation_id: Uuid,
    pub update_ticket: Uuid,
    pub event_type: &'a str,
    pub failure_code: Option<&'a str>,
    pub failure_class: Option<&'a str>,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct UpdateEventReceipt {
    pub event_id: Uuid,
    pub event_type: String,
    pub received: bool,
}

pub async fn record_update_event(
    pool: &PgPool,
    input: UpdateEventInput<'_>,
) -> Result<UpdateEventReceipt, UpdateEventError> {
    let mut tx = pool.begin().await?;

    let installation_exists = sqlx::query_scalar::<_, bool>(
        r#"
        select exists(
          select 1 from public.installations
          where id = $1 and customer_id = $2
        )
        "#,
    )
    .bind(input.installation_id)
    .bind(input.customer_id)
    .fetch_one(&mut *tx)
    .await?;
    if !installation_exists {
        return Err(UpdateEventError::InstallationNotFound);
    }

    let ticket_binding = sqlx::query_as::<_, (Uuid, Uuid)>(
        r#"
        select campaign_id, release_id
        from public.update_outcome_tickets
        where token = $1
          and installation_id = $2
          and expires_at > now()
        "#,
    )
    .bind(input.update_ticket)
    .bind(input.installation_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(UpdateEventError::InvalidUpdateTicket)?;

    let inserted = sqlx::query_scalar::<_, Uuid>(
        r#"
        insert into public.installation_update_events
            (id, installation_id, campaign_id, release_id, update_ticket, event_type,
             failure_code, failure_class, occurred_at)
        values
            ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        on conflict (id) do nothing
        returning id
        "#,
    )
    .bind(input.event_id)
    .bind(input.installation_id)
    .bind(ticket_binding.0)
    .bind(ticket_binding.1)
    .bind(input.update_ticket)
    .bind(input.event_type)
    .bind(input.failure_code)
    .bind(input.failure_class)
    .bind(input.occurred_at)
    .fetch_optional(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(UpdateEventReceipt {
        event_id: input.event_id,
        event_type: input.event_type.to_string(),
        received: inserted.is_some(),
    })
}

#[cfg(test)]
mod tests {
    use super::CANDIDATE_ROWS_SQL;

    #[test]
    fn candidate_query_requires_updater_artifacts() {
        assert!(CANDIDATE_ROWS_SQL.contains("a.artifact_role = 'updater'"));
    }
}
