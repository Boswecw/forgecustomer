//! Customer profile lookups.

use sqlx::PgPool;
use uuid::Uuid;

/// Minimal customer projection used for context resolution.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CustomerRow {
    pub id: Uuid,
    pub status: String,
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
