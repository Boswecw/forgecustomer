-- 0005_entitlements.sql
-- Phase 7 — Entitlements. Grants + overrides feed deterministic evaluation; snapshots are
-- signed (Ed25519) and versioned.

-- ---------------------------------------------------------------------------
-- entitlement_grants — promotional / non-plan grants (additive)
-- ---------------------------------------------------------------------------
create table if not exists public.entitlement_grants (
  id          uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.customer_profiles(id) on delete cascade,
  product_id  uuid not null references public.products(id),
  feature_key text,
  quota_key   text,
  bool_value  boolean,
  number_value numeric,
  string_value text,
  source      text not null default 'promotional'
                check (source in ('promotional','migration','support')),
  expires_at  timestamptz,
  created_at  timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- entitlement_overrides — admin overrides (highest precedence below suspension/revocation)
-- ---------------------------------------------------------------------------
create table if not exists public.entitlement_overrides (
  id          uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.customer_profiles(id) on delete cascade,
  product_id  uuid not null references public.products(id),
  feature_key text,
  quota_key   text,
  bool_value  boolean,
  number_value numeric,
  string_value text,
  reason      text not null,
  actor_id    text not null,                    -- operator who set the override
  active      boolean not null default true,
  expires_at  timestamptz,
  created_at  timestamptz not null default now()
);

create index if not exists idx_overrides_customer
  on public.entitlement_overrides(customer_id) where active;

-- ---------------------------------------------------------------------------
-- entitlement_snapshots — issued signed snapshots (for audit / replay verification)
-- ---------------------------------------------------------------------------
create table if not exists public.entitlement_snapshots (
  id              uuid primary key default gen_random_uuid(),
  customer_id     uuid not null references public.customer_profiles(id) on delete cascade,
  installation_id uuid references public.installations(id) on delete set null,
  product_id      uuid not null references public.products(id),
  schema_version  text not null default 'forge.entitlements.v1',
  payload         jsonb not null,               -- canonical signed payload
  key_id          text not null,
  signature       text not null,                -- base64 Ed25519 signature
  issued_at       timestamptz not null default now(),
  expires_at      timestamptz not null
);

create index if not exists idx_snapshots_customer
  on public.entitlement_snapshots(customer_id, issued_at);
