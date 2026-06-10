//! Public product/plan catalog queries (safe to expose; non-PII).

use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ProductRow {
    pub id: Uuid,
    pub key: String,
    pub name: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct PlanRow {
    pub id: Uuid,
    pub product_id: Uuid,
    pub key: String,
    pub name: String,
    pub status: String,
}

pub async fn list_products(pool: &PgPool) -> Result<Vec<ProductRow>, sqlx::Error> {
    sqlx::query_as::<_, ProductRow>(
        "select id, key, name, status from public.products where status = 'active' order by key",
    )
    .fetch_all(pool)
    .await
}

pub async fn list_plans(pool: &PgPool) -> Result<Vec<PlanRow>, sqlx::Error> {
    sqlx::query_as::<_, PlanRow>(
        "select id, product_id, key, name, status from public.plans \
         where status = 'active' order by key",
    )
    .fetch_all(pool)
    .await
}
