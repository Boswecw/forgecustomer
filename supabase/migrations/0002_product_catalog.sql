-- 0002_product_catalog.sql
-- Phase 3 — Product catalog. Plans are versioned; feature access and quotas are
-- data-driven so product code never hard-codes plan names as behavior.

-- ---------------------------------------------------------------------------
-- products & product_versions
-- ---------------------------------------------------------------------------
create table if not exists public.products (
  id          uuid primary key default gen_random_uuid(),
  key         text not null unique,             -- e.g. 'authorforge'
  name        text not null,
  status      text not null default 'active'
                check (status in ('active','retired')),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table if not exists public.product_versions (
  id          uuid primary key default gen_random_uuid(),
  product_id  uuid not null references public.products(id) on delete cascade,
  version     text not null,
  created_at  timestamptz not null default now(),
  unique (product_id, version)
);

-- ---------------------------------------------------------------------------
-- features — catalog of feature flags (boolean/numeric/string valued via plan_features)
-- ---------------------------------------------------------------------------
create table if not exists public.features (
  id          uuid primary key default gen_random_uuid(),
  key         text not null unique,             -- e.g. 'authorforge.cloud.enabled'
  value_type  text not null default 'boolean'
                check (value_type in ('boolean','number','string')),
  description text,
  created_at  timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- plans & plan_versions — subscriptions point at a plan VERSION (immutable terms)
-- ---------------------------------------------------------------------------
create table if not exists public.plans (
  id          uuid primary key default gen_random_uuid(),
  product_id  uuid not null references public.products(id) on delete cascade,
  key         text not null,                    -- e.g. 'authorforge_pro'
  name        text not null,
  status      text not null default 'active'
                check (status in ('active','retired')),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  unique (product_id, key)
);

create table if not exists public.plan_versions (
  id          uuid primary key default gen_random_uuid(),
  plan_id     uuid not null references public.plans(id) on delete cascade,
  version     integer not null,
  status      text not null default 'active'
                check (status in ('active','retired')),
  -- Stripe price linkage for paid plans (nullable for included/free plans).
  stripe_price_id text,
  created_at  timestamptz not null default now(),
  unique (plan_id, version)
);

-- Exactly one active version per plan (historical versions retained as 'retired').
create unique index if not exists uq_plan_versions_active
  on public.plan_versions(plan_id) where status = 'active';

-- ---------------------------------------------------------------------------
-- plan_features — feature values bound to a specific plan version
-- ---------------------------------------------------------------------------
create table if not exists public.plan_features (
  id              uuid primary key default gen_random_uuid(),
  plan_version_id uuid not null references public.plan_versions(id) on delete cascade,
  feature_id      uuid not null references public.features(id),
  bool_value      boolean,
  number_value    numeric,
  string_value    text,
  created_at      timestamptz not null default now(),
  unique (plan_version_id, feature_id)
);

-- ---------------------------------------------------------------------------
-- plan_quotas — quota limits bound to a plan version
-- ---------------------------------------------------------------------------
create table if not exists public.plan_quotas (
  id              uuid primary key default gen_random_uuid(),
  plan_version_id uuid not null references public.plan_versions(id) on delete cascade,
  meter_key       text not null,                -- e.g. 'cloud_tokens.monthly'
  limit_value     numeric not null,
  reset_cadence   text not null default 'monthly'
                    check (reset_cadence in ('monthly','daily','never')),
  created_at      timestamptz not null default now(),
  unique (plan_version_id, meter_key)
);

-- ---------------------------------------------------------------------------
-- release_channels — update channels referenced by features (e.g. stable/beta)
-- ---------------------------------------------------------------------------
create table if not exists public.release_channels (
  id          uuid primary key default gen_random_uuid(),
  product_id  uuid not null references public.products(id) on delete cascade,
  key         text not null,                    -- 'stable','beta','nightly'
  name        text not null,
  created_at  timestamptz not null default now(),
  unique (product_id, key)
);

drop trigger if exists trg_products_updated_at on public.products;
create trigger trg_products_updated_at
  before update on public.products
  for each row execute function public.set_updated_at();

drop trigger if exists trg_plans_updated_at on public.plans;
create trigger trg_plans_updated_at
  before update on public.plans
  for each row execute function public.set_updated_at();
