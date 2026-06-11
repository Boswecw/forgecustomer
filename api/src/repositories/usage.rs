//! Usage persistence: the reserve → commit → release lifecycle against the append-only
//! `usage_events` ledger, with `usage_period_totals` as the derived optimization and
//! `quota_decisions` as the explainable decision history.
//!
//! Idempotency: reservations dedupe on `(customer_id, idempotency_key)` in
//! `usage_reservations`; commits dedupe on the same pair in `usage_events`. Replays
//! return the original row without re-applying. Quota math runs under a lock on the
//! `(customer, meter, period)` totals row so concurrent requests serialize, and stale
//! pending reservations are lazily expired inside that lock (a background sweeper also
//! reclaims them; see `workers::usage`).

use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::domain::usage::{crossed_thresholds, decide, Decision};
use crate::repositories::licensing::write_outbox;

#[derive(Debug, thiserror::Error)]
pub enum UsageError {
    #[error("usage meter not found")]
    MeterNotFound,
    #[error("reservation not found")]
    ReservationNotFound,
    #[error("reservation is not committable ({0})")]
    ReservationNotCommittable(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MeterRow {
    pub key: String,
    pub unit: String,
    pub reset_cadence: String,
}

pub async fn find_meter(pool: &PgPool, meter_key: &str) -> Result<Option<MeterRow>, sqlx::Error> {
    sqlx::query_as::<_, MeterRow>(
        "select key, unit, reset_cadence from public.usage_meters where key = $1",
    )
    .bind(meter_key)
    .fetch_optional(pool)
    .await
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ReservationRow {
    pub id: Uuid,
    pub meter_key: String,
    pub amount: f64,
    pub status: String,
    pub period_key: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct DeniedDecision {
    pub reason: String,
    pub limit: Option<f64>,
    pub used: f64,
    pub reserved: f64,
    pub remaining_before: f64,
}

#[derive(Debug, Clone)]
pub enum ReserveOutcome {
    Reserved(ReservationRow),
    Replayed(ReservationRow),
    Denied(DeniedDecision),
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct UsageEventRow {
    pub id: Uuid,
    pub meter_key: String,
    pub amount: f64,
    pub period_key: String,
    pub reservation_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub enum CommitOutcome {
    Committed {
        event: UsageEventRow,
        used_after: f64,
        thresholds_crossed: Vec<u8>,
    },
    Replayed(UsageEventRow),
    Denied(DeniedDecision),
}

#[derive(Debug, Clone)]
pub enum ReleaseOutcome {
    Released { amount: f64 },
    AlreadyTerminal { status: String },
}

/// Lock (creating if absent) the totals row for `(customer, meter, period)` and return
/// the current `(used, reserved)`.
async fn lock_totals(
    tx: &mut Transaction<'_, Postgres>,
    customer_id: Uuid,
    meter_key: &str,
    period_key: &str,
) -> Result<(f64, f64), sqlx::Error> {
    sqlx::query(
        r#"
        insert into public.usage_period_totals (customer_id, meter_key, period_key)
        values ($1, $2, $3)
        on conflict (customer_id, meter_key, period_key) do nothing
        "#,
    )
    .bind(customer_id)
    .bind(meter_key)
    .bind(period_key)
    .execute(&mut **tx)
    .await?;
    sqlx::query_as::<_, (f64, f64)>(
        r#"
        select used::float8, reserved::float8 from public.usage_period_totals
        where customer_id = $1 and meter_key = $2 and period_key = $3
        for update
        "#,
    )
    .bind(customer_id)
    .bind(meter_key)
    .bind(period_key)
    .fetch_one(&mut **tx)
    .await
}

/// Expire stale pending reservations for the locked `(customer, meter, period)` and
/// release their hold. Returns the reclaimed amount.
async fn expire_stale_reservations(
    tx: &mut Transaction<'_, Postgres>,
    customer_id: Uuid,
    meter_key: &str,
    period_key: &str,
) -> Result<f64, sqlx::Error> {
    let reclaimed = sqlx::query_scalar::<_, Option<f64>>(
        r#"
        with expired as (
            update public.usage_reservations
            set status = 'expired'
            where customer_id = $1
              and meter_key = $2
              and period_key = $3
              and status = 'pending'
              and expires_at <= now()
            returning amount
        )
        select sum(amount)::float8 from expired
        "#,
    )
    .bind(customer_id)
    .bind(meter_key)
    .bind(period_key)
    .fetch_one(&mut **tx)
    .await?
    .unwrap_or(0.0);

    if reclaimed > 0.0 {
        sqlx::query(
            r#"
            update public.usage_period_totals
            set reserved = greatest(0, reserved - $4)
            where customer_id = $1 and meter_key = $2 and period_key = $3
            "#,
        )
        .bind(customer_id)
        .bind(meter_key)
        .bind(period_key)
        .bind(reclaimed)
        .execute(&mut **tx)
        .await?;
    }
    Ok(reclaimed)
}

struct DecisionRecord<'a> {
    customer_id: Uuid,
    meter_key: &'a str,
    requested: f64,
    limit: Option<f64>,
    used: f64,
    reserved: f64,
    decision: Decision,
    reason: &'a str,
    correlation_id: Option<&'a str>,
}

async fn record_decision(
    tx: &mut Transaction<'_, Postgres>,
    record: DecisionRecord<'_>,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        r#"
        insert into public.quota_decisions
            (customer_id, meter_key, requested, limit_value, used_before, reserved_before,
             decision, reason, correlation_id)
        values
            ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        returning id
        "#,
    )
    .bind(record.customer_id)
    .bind(record.meter_key)
    .bind(record.requested)
    .bind(record.limit)
    .bind(record.used)
    .bind(record.reserved)
    .bind(match record.decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
    })
    .bind(record.reason)
    .bind(record.correlation_id)
    .fetch_one(&mut **tx)
    .await
}

/// Read current totals without locking (advisory check path).
pub async fn read_totals(
    pool: &PgPool,
    customer_id: Uuid,
    meter_key: &str,
    period_key: &str,
) -> Result<(f64, f64), sqlx::Error> {
    Ok(sqlx::query_as::<_, (f64, f64)>(
        r#"
        select used::float8, reserved::float8 from public.usage_period_totals
        where customer_id = $1 and meter_key = $2 and period_key = $3
        "#,
    )
    .bind(customer_id)
    .bind(meter_key)
    .bind(period_key)
    .fetch_optional(pool)
    .await?
    .unwrap_or((0.0, 0.0)))
}

/// Read a reservation owned by the customer (no lock; the commit path re-locks).
pub async fn find_reservation(
    pool: &PgPool,
    customer_id: Uuid,
    reservation_id: Uuid,
) -> Result<Option<ReservationRow>, sqlx::Error> {
    sqlx::query_as::<_, ReservationRow>(
        r#"
        select id, meter_key, amount::float8 as amount, status, period_key, expires_at
        from public.usage_reservations
        where id = $1 and customer_id = $2
        "#,
    )
    .bind(reservation_id)
    .bind(customer_id)
    .fetch_optional(pool)
    .await
}

#[derive(Debug, Clone)]
pub struct ReserveInput<'a> {
    pub customer_id: Uuid,
    pub meter_key: &'a str,
    pub amount: f64,
    pub limit: Option<f64>,
    pub period_key: &'a str,
    pub ttl: chrono::Duration,
    pub idempotency_key: &'a str,
    pub correlation_id: Option<&'a str>,
}

/// Hold `amount` units against the quota. Idempotent by `(customer, idempotency key)`;
/// a denied request records an explainable decision and holds nothing (retries with the
/// same key re-evaluate, so a later retry may succeed once quota frees up).
pub async fn reserve(pool: &PgPool, input: ReserveInput<'_>) -> Result<ReserveOutcome, UsageError> {
    let mut tx = pool.begin().await?;

    let existing = sqlx::query_as::<_, ReservationRow>(
        r#"
        select id, meter_key, amount::float8 as amount, status, period_key, expires_at
        from public.usage_reservations
        where customer_id = $1 and idempotency_key = $2
        "#,
    )
    .bind(input.customer_id)
    .bind(input.idempotency_key)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(existing) = existing {
        tx.commit().await?;
        return Ok(ReserveOutcome::Replayed(existing));
    }

    let _ = lock_totals(
        &mut tx,
        input.customer_id,
        input.meter_key,
        input.period_key,
    )
    .await?;
    expire_stale_reservations(
        &mut tx,
        input.customer_id,
        input.meter_key,
        input.period_key,
    )
    .await?;
    // Re-read after expiry reclaimed any stale holds.
    let (used, reserved) = sqlx::query_as::<_, (f64, f64)>(
        r#"
        select used::float8, reserved::float8 from public.usage_period_totals
        where customer_id = $1 and meter_key = $2 and period_key = $3
        "#,
    )
    .bind(input.customer_id)
    .bind(input.meter_key)
    .bind(input.period_key)
    .fetch_one(&mut *tx)
    .await?;

    let decision = decide(input.amount, used, reserved, input.limit);
    record_decision(
        &mut tx,
        DecisionRecord {
            customer_id: input.customer_id,
            meter_key: input.meter_key,
            requested: input.amount,
            limit: input.limit,
            used,
            reserved,
            decision: decision.decision,
            reason: &decision.reason,
            correlation_id: input.correlation_id,
        },
    )
    .await?;

    if decision.decision == Decision::Deny {
        tx.commit().await?;
        return Ok(ReserveOutcome::Denied(DeniedDecision {
            reason: decision.reason,
            limit: input.limit,
            used,
            reserved,
            remaining_before: decision.remaining_before,
        }));
    }

    let reservation = sqlx::query_as::<_, ReservationRow>(
        r#"
        insert into public.usage_reservations
            (customer_id, meter_key, amount, idempotency_key, status, period_key, expires_at)
        values
            ($1, $2, $3, $4, 'pending', $5, $6)
        on conflict (customer_id, idempotency_key) do nothing
        returning id, meter_key, amount::float8 as amount, status, period_key, expires_at
        "#,
    )
    .bind(input.customer_id)
    .bind(input.meter_key)
    .bind(input.amount)
    .bind(input.idempotency_key)
    .bind(input.period_key)
    .bind(Utc::now() + input.ttl)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(reservation) = reservation else {
        // Lost an idempotency race after our initial check: surface the winner.
        let existing = sqlx::query_as::<_, ReservationRow>(
            r#"
            select id, meter_key, amount::float8 as amount, status, period_key, expires_at
            from public.usage_reservations
            where customer_id = $1 and idempotency_key = $2
            "#,
        )
        .bind(input.customer_id)
        .bind(input.idempotency_key)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(ReserveOutcome::Replayed(existing));
    };

    sqlx::query(
        r#"
        update public.usage_period_totals
        set reserved = reserved + $4
        where customer_id = $1 and meter_key = $2 and period_key = $3
        "#,
    )
    .bind(input.customer_id)
    .bind(input.meter_key)
    .bind(input.period_key)
    .bind(input.amount)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(ReserveOutcome::Reserved(reservation))
}

#[derive(Debug, Clone)]
pub enum CommitMode {
    /// Convert a pending reservation into a ledger event.
    Reservation(Uuid),
    /// Direct charge without a reservation; quota-gated at commit time.
    Direct { meter_key: String, amount: f64 },
}

#[derive(Debug, Clone)]
pub struct CommitInput<'a> {
    pub customer_id: Uuid,
    pub mode: CommitMode,
    /// Quota limit for the meter (None = unlimited), used for direct gating and
    /// threshold detection.
    pub limit: Option<f64>,
    pub period_key: &'a str,
    pub threshold_percents: &'a [u8],
    pub idempotency_key: &'a str,
    pub correlation_id: Option<&'a str>,
}

/// Append a usage commit to the ledger. Idempotent by `(customer, idempotency key)`.
/// Reservation commits convert the hold; direct commits are quota-gated and record a
/// decision. Threshold crossings queue sanitized `quota_threshold_reached` events, once
/// per (customer, meter, period, threshold).
pub async fn commit(pool: &PgPool, input: CommitInput<'_>) -> Result<CommitOutcome, UsageError> {
    let mut tx = pool.begin().await?;

    let existing = sqlx::query_as::<_, UsageEventRow>(
        r#"
        select id, meter_key, amount::float8 as amount, period_key, reservation_id
        from public.usage_events
        where customer_id = $1 and idempotency_key = $2
        "#,
    )
    .bind(input.customer_id)
    .bind(input.idempotency_key)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(existing) = existing {
        tx.commit().await?;
        return Ok(CommitOutcome::Replayed(existing));
    }

    let (meter_key, amount, period_key, reservation_id) = match input.mode {
        CommitMode::Reservation(reservation_id) => {
            let reservation = sqlx::query_as::<_, (String, f64, String, String, DateTime<Utc>)>(
                r#"
                select meter_key, amount::float8, status, period_key, expires_at
                from public.usage_reservations
                where id = $1 and customer_id = $2
                for update
                "#,
            )
            .bind(reservation_id)
            .bind(input.customer_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(UsageError::ReservationNotFound)?;
            let (meter_key, amount, status, period_key, expires_at) = reservation;
            if status != "pending" {
                return Err(UsageError::ReservationNotCommittable(status));
            }
            if expires_at <= Utc::now() {
                // Mark it expired and release its hold before failing closed.
                sqlx::query(
                    "update public.usage_reservations set status = 'expired' where id = $1",
                )
                .bind(reservation_id)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    r#"
                    update public.usage_period_totals
                    set reserved = greatest(0, reserved - $4)
                    where customer_id = $1 and meter_key = $2 and period_key = $3
                    "#,
                )
                .bind(input.customer_id)
                .bind(&meter_key)
                .bind(&period_key)
                .bind(amount)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                return Err(UsageError::ReservationNotCommittable("expired".to_string()));
            }
            (meter_key, amount, period_key, Some(reservation_id))
        }
        CommitMode::Direct { meter_key, amount } => {
            let _ = lock_totals(&mut tx, input.customer_id, &meter_key, input.period_key).await?;
            expire_stale_reservations(&mut tx, input.customer_id, &meter_key, input.period_key)
                .await?;
            let (used, reserved) = sqlx::query_as::<_, (f64, f64)>(
                r#"
                select used::float8, reserved::float8 from public.usage_period_totals
                where customer_id = $1 and meter_key = $2 and period_key = $3
                "#,
            )
            .bind(input.customer_id)
            .bind(&meter_key)
            .bind(input.period_key)
            .fetch_one(&mut *tx)
            .await?;

            let decision = decide(amount, used, reserved, input.limit);
            record_decision(
                &mut tx,
                DecisionRecord {
                    customer_id: input.customer_id,
                    meter_key: &meter_key,
                    requested: amount,
                    limit: input.limit,
                    used,
                    reserved,
                    decision: decision.decision,
                    reason: &decision.reason,
                    correlation_id: input.correlation_id,
                },
            )
            .await?;
            if decision.decision == Decision::Deny {
                write_outbox(
                    &mut tx,
                    "usage_commit_failed",
                    format!(
                        "usage_commit_failed:{}:{}",
                        input.customer_id, input.idempotency_key
                    ),
                    json!({
                        "customer_id": input.customer_id,
                        "meter_key": meter_key,
                        "period_key": input.period_key,
                        "requested": amount,
                        "limit": input.limit,
                        "occurred_at": Utc::now(),
                    }),
                )
                .await?;
                tx.commit().await?;
                return Ok(CommitOutcome::Denied(DeniedDecision {
                    reason: decision.reason,
                    limit: input.limit,
                    used,
                    reserved,
                    remaining_before: decision.remaining_before,
                }));
            }
            (meter_key, amount, input.period_key.to_string(), None)
        }
    };

    let event = sqlx::query_as::<_, UsageEventRow>(
        r#"
        insert into public.usage_events
            (customer_id, meter_key, amount, period_key, idempotency_key, reservation_id, kind)
        values
            ($1, $2, $3, $4, $5, $6, 'commit')
        on conflict (customer_id, idempotency_key) do nothing
        returning id, meter_key, amount::float8 as amount, period_key, reservation_id
        "#,
    )
    .bind(input.customer_id)
    .bind(&meter_key)
    .bind(amount)
    .bind(&period_key)
    .bind(input.idempotency_key)
    .bind(reservation_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(event) = event else {
        let existing = sqlx::query_as::<_, UsageEventRow>(
            r#"
            select id, meter_key, amount::float8 as amount, period_key, reservation_id
            from public.usage_events
            where customer_id = $1 and idempotency_key = $2
            "#,
        )
        .bind(input.customer_id)
        .bind(input.idempotency_key)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(CommitOutcome::Replayed(existing));
    };

    if let Some(reservation_id) = reservation_id {
        sqlx::query("update public.usage_reservations set status = 'committed' where id = $1")
            .bind(reservation_id)
            .execute(&mut *tx)
            .await?;
    }

    // Fold into totals: committed usage grows `used`; a converted reservation frees its
    // hold. The returning row gives us before/after for threshold detection.
    let reserved_delta = if reservation_id.is_some() {
        amount
    } else {
        0.0
    };
    let (used_after,) = sqlx::query_as::<_, (f64,)>(
        r#"
        update public.usage_period_totals
        set used = used + $4,
            reserved = greatest(0, reserved - $5)
        where customer_id = $1 and meter_key = $2 and period_key = $3
        returning used::float8
        "#,
    )
    .bind(input.customer_id)
    .bind(&meter_key)
    .bind(&period_key)
    .bind(amount)
    .bind(reserved_delta)
    .fetch_one(&mut *tx)
    .await?;
    let used_before = used_after - amount;

    let thresholds = crossed_thresholds(
        used_before,
        used_after,
        input.limit,
        input.threshold_percents,
    );
    for pct in &thresholds {
        write_outbox(
            &mut tx,
            "quota_threshold_reached",
            format!(
                "quota_threshold_reached:{}:{}:{}:{}",
                input.customer_id, meter_key, period_key, pct
            ),
            json!({
                "customer_id": input.customer_id,
                "meter_key": meter_key,
                "period_key": period_key,
                "threshold_percent": pct,
                "used": used_after,
                "limit": input.limit,
                "occurred_at": Utc::now(),
            }),
        )
        .await?;
    }

    tx.commit().await?;
    Ok(CommitOutcome::Committed {
        event,
        used_after,
        thresholds_crossed: thresholds,
    })
}

/// Release an unused reservation, freeing its hold. Idempotent: terminal reservations
/// (committed/released/expired) report their status without changing anything.
pub async fn release(
    pool: &PgPool,
    customer_id: Uuid,
    reservation_id: Uuid,
) -> Result<Option<ReleaseOutcome>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let reservation = sqlx::query_as::<_, (String, f64, String, String)>(
        r#"
        select status, amount::float8, meter_key, period_key
        from public.usage_reservations
        where id = $1 and customer_id = $2
        for update
        "#,
    )
    .bind(reservation_id)
    .bind(customer_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((status, amount, meter_key, period_key)) = reservation else {
        return Ok(None);
    };
    if status != "pending" {
        tx.commit().await?;
        return Ok(Some(ReleaseOutcome::AlreadyTerminal { status }));
    }

    sqlx::query("update public.usage_reservations set status = 'released' where id = $1")
        .bind(reservation_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        r#"
        update public.usage_period_totals
        set reserved = greatest(0, reserved - $4)
        where customer_id = $1 and meter_key = $2 and period_key = $3
        "#,
    )
    .bind(customer_id)
    .bind(&meter_key)
    .bind(&period_key)
    .bind(amount)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(Some(ReleaseOutcome::Released { amount }))
}

/// Current-period totals for every cataloged meter (zero rows when unused).
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct CurrentUsageRow {
    pub meter_key: String,
    pub unit: String,
    pub reset_cadence: String,
    pub period_key: String,
    pub used: f64,
    pub reserved: f64,
}

pub async fn current_usage(
    pool: &PgPool,
    customer_id: Uuid,
) -> Result<Vec<CurrentUsageRow>, sqlx::Error> {
    sqlx::query_as::<_, CurrentUsageRow>(
        r#"
        select m.key as meter_key, m.unit, m.reset_cadence,
               case m.reset_cadence
                   when 'monthly' then to_char(now() at time zone 'utc', 'YYYY-MM')
                   when 'daily' then to_char(now() at time zone 'utc', 'YYYY-MM-DD')
                   else 'all'
               end as period_key,
               coalesce(t.used, 0)::float8 as used,
               coalesce(t.reserved, 0)::float8 as reserved
        from public.usage_meters m
        left join public.usage_period_totals t
               on t.customer_id = $1
              and t.meter_key = m.key
              and t.period_key = case m.reset_cadence
                                     when 'monthly' then to_char(now() at time zone 'utc', 'YYYY-MM')
                                     when 'daily' then to_char(now() at time zone 'utc', 'YYYY-MM-DD')
                                     else 'all'
                                 end
        order by m.key
        "#,
    )
    .bind(customer_id)
    .fetch_all(pool)
    .await
}

/// Background sweep: expire overdue pending reservations (any customer) and release
/// their holds. Returns the number of reservations reclaimed.
pub async fn sweep_expired_reservations(pool: &PgPool, batch: i64) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let expired = sqlx::query_as::<_, (Uuid, Uuid, String, String, f64)>(
        r#"
        update public.usage_reservations
        set status = 'expired'
        where id in (
            select id from public.usage_reservations
            where status = 'pending' and expires_at <= now()
            order by expires_at
            for update skip locked
            limit $1
        )
        returning id, customer_id, meter_key, period_key, amount::float8
        "#,
    )
    .bind(batch)
    .fetch_all(&mut *tx)
    .await?;

    for (_, customer_id, meter_key, period_key, amount) in &expired {
        sqlx::query(
            r#"
            update public.usage_period_totals
            set reserved = greatest(0, reserved - $4)
            where customer_id = $1 and meter_key = $2 and period_key = $3
            "#,
        )
        .bind(customer_id)
        .bind(meter_key)
        .bind(period_key)
        .bind(amount)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(expired.len() as u64)
}
