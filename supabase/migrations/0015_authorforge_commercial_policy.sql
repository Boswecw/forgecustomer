-- 0015_authorforge_commercial_policy.sql
-- Immutable, effective-dated global AuthorForge commercial-policy versions. This is the
-- commercial authority consumed by Forge Command's operator cockpit; it is intentionally
-- separate from per-customer entitlement overrides.

create table if not exists public.commercial_policy_versions (
  id              uuid primary key default gen_random_uuid(),
  product_id      uuid not null references public.products(id) on delete cascade,
  version         bigint not null check (version > 0),
  effective_at    timestamptz not null,
  policy          jsonb not null,
  reason          text not null,
  created_by      text not null,
  idempotency_key text not null,
  correlation_id  text,
  created_at      timestamptz not null default now(),
  unique (product_id, version),
  unique (product_id, idempotency_key)
);

create index if not exists idx_commercial_policy_versions_active
  on public.commercial_policy_versions(product_id, effective_at desc, version desc);

-- Existing deployments have the AuthorForge catalog already. Give them the same explicit
-- bootstrap policy as a fresh seed so the cockpit becomes usable immediately after migration.
-- Fresh databases receive the same row from seed.sql after the catalog is inserted.
insert into public.commercial_policy_versions
  (product_id, version, effective_at, policy, reason, created_by, idempotency_key)
select p.id,
       1,
       '2026-01-01T00:00:00Z'::timestamptz,
       jsonb_build_object(
         'included', jsonb_build_object(
           'cloud_tokens_per_month', 0,
           'deep_analysis_runs_per_month', 0,
           'premium_model_requests_per_month', 0,
           'device_limit', 1
         ),
         'pro', jsonb_build_object(
           'cloud_tokens_per_month', 1000000,
           'deep_analysis_runs_per_month', 500,
           'premium_model_requests_per_month', 2000,
           'device_limit', 3
         )
       ),
       'Bootstrap policy mirrored from the existing AuthorForge catalog.',
       'system:migration-0015',
       'migration:0015:authorforge-commercial-policy-v1'
from public.products p
where p.key = 'authorforge'
on conflict (product_id, version) do nothing;

-- Policies are immutable commercial terms. Publishing always inserts a new version; no actor
-- (including the service role) may silently rewrite or remove historic terms.
create or replace function public.reject_commercial_policy_version_mutation()
returns trigger
language plpgsql
as $$
begin
  raise exception 'commercial policy versions are immutable';
end;
$$;

drop trigger if exists trg_commercial_policy_versions_immutable on public.commercial_policy_versions;
create trigger trg_commercial_policy_versions_immutable
  before update or delete on public.commercial_policy_versions
  for each row execute function public.reject_commercial_policy_version_mutation();

alter table public.commercial_policy_versions enable row level security;
alter table public.commercial_policy_versions force row level security;
