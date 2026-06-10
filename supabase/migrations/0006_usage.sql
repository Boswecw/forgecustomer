-- 0006_usage.sql
-- Phase 8 — Usage & quotas. usage_events is the authoritative append-only ledger;
-- usage_period_totals is a rebuildable optimization; quota_decisions is explainable
-- history.

-- ---------------------------------------------------------------------------
-- usage_meters — meter catalog (explicit units, reset cadence)
-- ---------------------------------------------------------------------------
create table if not exists public.usage_meters (
  id            uuid primary key default gen_random_uuid(),
  key           text not null unique,           -- 'cloud_tokens', 'deep_analysis_runs'
  unit          text not null,                  -- 'tokens','runs','requests','bytes'
  reset_cadence text not null default 'monthly'
                  check (reset_cadence in ('monthly','daily','never')),
  created_at    timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- usage_reservations — in-flight holds against a quota (expire if not committed)
-- ---------------------------------------------------------------------------
create table if not exists public.usage_reservations (
  id            uuid primary key default gen_random_uuid(),
  customer_id   uuid not null references public.customer_profiles(id) on delete cascade,
  meter_key     text not null references public.usage_meters(key),
  amount        numeric not null check (amount >= 0),
  idempotency_key text not null,
  status        text not null default 'pending'
                  check (status in ('pending','committed','released','expired')),
  period_key    text not null,                  -- e.g. '2026-06' for monthly
  expires_at    timestamptz not null,
  created_at    timestamptz not null default now(),
  unique (customer_id, idempotency_key)
);

create index if not exists idx_reservations_expiry
  on public.usage_reservations(status, expires_at);

-- ---------------------------------------------------------------------------
-- usage_events — AUTHORITATIVE append-only ledger (never edited; corrections compensate)
-- ---------------------------------------------------------------------------
create table if not exists public.usage_events (
  id              uuid primary key default gen_random_uuid(),
  customer_id     uuid not null references public.customer_profiles(id) on delete cascade,
  meter_key       text not null references public.usage_meters(key),
  amount          numeric not null,             -- may be negative for compensating events
  period_key      text not null,
  idempotency_key text not null,
  reservation_id  uuid references public.usage_reservations(id) on delete set null,
  kind            text not null default 'commit'
                    check (kind in ('commit','adjustment','compensation')),
  created_at      timestamptz not null default now(),
  unique (customer_id, idempotency_key)
);

create index if not exists idx_usage_events_period
  on public.usage_events(customer_id, meter_key, period_key);

-- ---------------------------------------------------------------------------
-- usage_period_totals — derived optimization (rebuildable from usage_events)
-- ---------------------------------------------------------------------------
create table if not exists public.usage_period_totals (
  id           uuid primary key default gen_random_uuid(),
  customer_id  uuid not null references public.customer_profiles(id) on delete cascade,
  meter_key    text not null references public.usage_meters(key),
  period_key   text not null,
  used         numeric not null default 0,
  reserved     numeric not null default 0,
  updated_at   timestamptz not null default now(),
  unique (customer_id, meter_key, period_key)
);

drop trigger if exists trg_usage_period_totals_updated_at on public.usage_period_totals;
create trigger trg_usage_period_totals_updated_at
  before update on public.usage_period_totals
  for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- quota_decisions — explainable decision history (allow/deny + reason)
-- ---------------------------------------------------------------------------
create table if not exists public.quota_decisions (
  id            uuid primary key default gen_random_uuid(),
  customer_id   uuid not null references public.customer_profiles(id) on delete cascade,
  meter_key     text not null,
  requested     numeric not null,
  limit_value   numeric,
  used_before   numeric,
  reserved_before numeric,
  decision      text not null check (decision in ('allow','deny')),
  reason        text,
  correlation_id text,
  created_at    timestamptz not null default now()
);

create index if not exists idx_quota_decisions_customer
  on public.quota_decisions(customer_id, created_at);
