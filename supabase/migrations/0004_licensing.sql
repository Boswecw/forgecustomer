-- 0004_licensing.sql
-- Phase 6 — Licensing. License / Installation / Device / Activation / Lease / Revocation
-- are DISTINCT concepts and are never collapsed into one table.

-- ---------------------------------------------------------------------------
-- licenses — a product-use grant
-- ---------------------------------------------------------------------------
create table if not exists public.licenses (
  id              uuid primary key default gen_random_uuid(),
  customer_id     uuid not null references public.customer_profiles(id) on delete cascade,
  product_id      uuid not null references public.products(id),
  subscription_id uuid references public.subscriptions(id) on delete set null,
  status          text not null default 'active'
                    check (status in ('active','suspended','revoked','expired')),
  device_limit    integer not null default 1 check (device_limit >= 0),
  issued_at       timestamptz not null default now(),
  expires_at      timestamptz,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

create index if not exists idx_licenses_customer on public.licenses(customer_id);

drop trigger if exists trg_licenses_updated_at on public.licenses;
create trigger trg_licenses_updated_at
  before update on public.licenses
  for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- license_grants — what a license grants (feature/quota grants beyond plan defaults)
-- ---------------------------------------------------------------------------
create table if not exists public.license_grants (
  id          uuid primary key default gen_random_uuid(),
  license_id  uuid not null references public.licenses(id) on delete cascade,
  feature_key text not null,
  bool_value  boolean,
  number_value numeric,
  string_value text,
  created_at  timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- devices — machine identity by registered PUBLIC key (private key stays client-side)
-- ---------------------------------------------------------------------------
create table if not exists public.devices (
  id            uuid primary key default gen_random_uuid(),
  customer_id   uuid not null references public.customer_profiles(id) on delete cascade,
  public_key    text not null,                  -- base64 Ed25519 public key
  public_key_fpr text not null,                 -- fingerprint for lookup
  label         text,
  status        text not null default 'active'
                  check (status in ('active','revoked')),
  created_at    timestamptz not null default now(),
  unique (customer_id, public_key_fpr)
);

-- ---------------------------------------------------------------------------
-- installations — an installed application instance
-- ---------------------------------------------------------------------------
create table if not exists public.installations (
  id               uuid primary key default gen_random_uuid(),
  customer_id      uuid not null references public.customer_profiles(id) on delete cascade,
  device_id        uuid references public.devices(id) on delete set null,
  -- client-supplied stable key makes registration idempotent
  install_key      text not null,
  product_id       uuid not null references public.products(id),
  app_version      text,
  status           text not null default 'active'
                     check (status in ('active','deactivated')),
  last_heartbeat_at timestamptz,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  unique (customer_id, install_key)
);

drop trigger if exists trg_installations_updated_at on public.installations;
create trigger trg_installations_updated_at
  before update on public.installations
  for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- license_activations — link between a license and an installation
-- ---------------------------------------------------------------------------
create table if not exists public.license_activations (
  id              uuid primary key default gen_random_uuid(),
  license_id      uuid not null references public.licenses(id) on delete cascade,
  installation_id uuid not null references public.installations(id) on delete cascade,
  device_id       uuid references public.devices(id) on delete set null,
  status          text not null default 'active'
                    check (status in ('active','deactivated')),
  activated_at    timestamptz not null default now(),
  deactivated_at  timestamptz
);

-- A given installation can have at most one ACTIVE activation per license.
create unique index if not exists uq_active_activation
  on public.license_activations(license_id, installation_id) where status = 'active';

-- ---------------------------------------------------------------------------
-- license_leases — signed temporary offline permission
-- ---------------------------------------------------------------------------
create table if not exists public.license_leases (
  id              uuid primary key default gen_random_uuid(),
  license_id      uuid not null references public.licenses(id) on delete cascade,
  installation_id uuid not null references public.installations(id) on delete cascade,
  issued_at       timestamptz not null default now(),
  expires_at      timestamptz not null,
  key_id          text not null,                -- signing key id used
  signature       text not null,                -- Ed25519 signature (base64)
  revoked         boolean not null default false,
  created_at      timestamptz not null default now()
);

create index if not exists idx_license_leases_installation
  on public.license_leases(installation_id, expires_at);

-- ---------------------------------------------------------------------------
-- license_revocations — explicit denial record (blocks silent reactivation)
-- ---------------------------------------------------------------------------
create table if not exists public.license_revocations (
  id              uuid primary key default gen_random_uuid(),
  license_id      uuid references public.licenses(id) on delete cascade,
  device_id       uuid references public.devices(id) on delete cascade,
  installation_id uuid references public.installations(id) on delete cascade,
  reason          text not null,
  actor_type      text not null default 'operator'
                    check (actor_type in ('system','operator')),
  actor_id        text,
  created_at      timestamptz not null default now()
);

create index if not exists idx_revocations_device on public.license_revocations(device_id);
create index if not exists idx_revocations_license on public.license_revocations(license_id);
