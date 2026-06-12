-- 0011_fleet_release_update_domain.sql
-- AuthorForge fleet + release + update-campaign foundation.
--
-- This is additive. Existing customer, license, entitlement, installation, audit,
-- deletion, and outbox behavior remains authoritative; this migration introduces the
-- owned tables needed by Forge Command's operator cockpit and AuthorForge update checks.

-- ---------------------------------------------------------------------------
-- fleets — customer-owned managed populations
-- ---------------------------------------------------------------------------
create table if not exists public.fleets (
  id                 uuid primary key default gen_random_uuid(),
  customer_id        uuid not null references public.customer_profiles(id) on delete cascade,
  display_name       text not null,
  fleet_type         text not null default 'default'
                       check (fleet_type in ('default','operator_created')),
  status             text not null default 'active'
                       check (status in ('active','held','retired','deleted')),
  update_ring        text not null default 'standard'
                       check (update_ring in ('canary','preview','standard','delayed')),
  release_channel_id uuid references public.release_channels(id) on delete set null,
  beta_enrolled      boolean not null default false,
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now()
);

create unique index if not exists uq_fleets_default_per_customer
  on public.fleets(customer_id) where fleet_type = 'default' and status <> 'deleted';
create index if not exists idx_fleets_customer on public.fleets(customer_id);

drop trigger if exists trg_fleets_updated_at on public.fleets;
create trigger trg_fleets_updated_at
  before update on public.fleets
  for each row execute function public.set_updated_at();

-- Fleet/product policy. MVP has one default fleet; this table keeps the product/ring
-- boundary explicit so update eligibility never trusts client-supplied fleet claims.
create table if not exists public.fleet_applications (
  id                 uuid primary key default gen_random_uuid(),
  fleet_id           uuid not null references public.fleets(id) on delete cascade,
  product_id         uuid not null references public.products(id),
  status             text not null default 'active'
                       check (status in ('active','held','retired')),
  update_ring        text not null default 'standard'
                       check (update_ring in ('canary','preview','standard','delayed')),
  release_channel_id uuid references public.release_channels(id) on delete set null,
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now(),
  unique (fleet_id, product_id)
);

drop trigger if exists trg_fleet_applications_updated_at on public.fleet_applications;
create trigger trg_fleet_applications_updated_at
  before update on public.fleet_applications
  for each row execute function public.set_updated_at();

alter table public.installations
  add column if not exists fleet_id uuid references public.fleets(id) on delete set null,
  add column if not exists build_id text,
  add column if not exists platform text,
  add column if not exists architecture text,
  add column if not exists package_format text,
  add column if not exists updater_version text;

create index if not exists idx_installations_fleet on public.installations(fleet_id);

-- ---------------------------------------------------------------------------
-- product releases and artifacts — signed release catalog
-- ---------------------------------------------------------------------------
create table if not exists public.product_releases (
  id                         uuid primary key default gen_random_uuid(),
  product_id                 uuid not null references public.products(id),
  version                    text not null,
  build_id                   text not null,
  release_channel_id         uuid not null references public.release_channels(id),
  status                     text not null default 'draft'
                               check (status in (
                                 'draft','artifacts_pending','validated','published',
                                 'blocked','retired'
                               )),
  changelog_markdown         text,
  minimum_supported_version  text,
  minimum_updater_version    text,
  created_by                 text not null,
  created_at                 timestamptz not null default now(),
  validated_at               timestamptz,
  published_at               timestamptz,
  updated_at                 timestamptz not null default now(),
  unique (product_id, version, build_id)
);

create index if not exists idx_product_releases_product_status
  on public.product_releases(product_id, status, created_at desc);

drop trigger if exists trg_product_releases_updated_at on public.product_releases;
create trigger trg_product_releases_updated_at
  before update on public.product_releases
  for each row execute function public.set_updated_at();

create table if not exists public.release_artifacts (
  id                    uuid primary key default gen_random_uuid(),
  release_id            uuid not null references public.product_releases(id) on delete cascade,
  platform              text not null check (platform in ('windows','linux','darwin')),
  architecture          text not null check (architecture in ('x86_64','aarch64','i686','armv7')),
  package_format        text not null,
  artifact_role         text not null
                          check (artifact_role in ('bootstrap','updater','recovery')),
  storage_key           text not null,
  size_bytes            bigint not null check (size_bytes > 0),
  sha256                text not null check (sha256 ~ '^[a-f0-9]{64}$'),
  tauri_signature       text,
  signing_key_id        text not null,
  os_signature_status   text not null default 'pending'
                          check (os_signature_status in (
                            'pending','verified','not_applicable','failed'
                          )),
  status                text not null default 'pending'
                          check (status in ('pending','validated','quarantined','retired')),
  created_at            timestamptz not null default now(),
  updated_at            timestamptz not null default now(),
  unique (release_id, platform, architecture, package_format, artifact_role)
);

create index if not exists idx_release_artifacts_release_status
  on public.release_artifacts(release_id, status);

drop trigger if exists trg_release_artifacts_updated_at on public.release_artifacts;
create trigger trg_release_artifacts_updated_at
  before update on public.release_artifacts
  for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- update campaigns, holds, and minimal outcome events
-- ---------------------------------------------------------------------------
create table if not exists public.update_campaigns (
  id                   uuid primary key default gen_random_uuid(),
  product_id           uuid not null references public.products(id),
  target_release_id    uuid not null references public.product_releases(id),
  campaign_slug        text not null
                         check (campaign_slug ~ '^[a-z0-9][a-z0-9_-]{2,79}$'),
  status               text not null default 'draft'
                         check (status in ('draft','active','paused','completed','revoked')),
  release_channel_id   uuid not null references public.release_channels(id),
  target_update_ring   text not null default 'standard'
                         check (target_update_ring in ('canary','preview','standard','delayed')),
  rollout_percentage   integer not null default 0 check (rollout_percentage between 0 and 100),
  emergency            boolean not null default false,
  starts_at            timestamptz,
  completed_at         timestamptz,
  created_by           text not null,
  created_at           timestamptz not null default now(),
  updated_at           timestamptz not null default now(),
  unique (product_id, campaign_slug)
);

create index if not exists idx_update_campaigns_release_status
  on public.update_campaigns(target_release_id, status);

drop trigger if exists trg_update_campaigns_updated_at on public.update_campaigns;
create trigger trg_update_campaigns_updated_at
  before update on public.update_campaigns
  for each row execute function public.set_updated_at();

create table if not exists public.update_campaign_holds (
  id           uuid primary key default gen_random_uuid(),
  campaign_id  uuid not null references public.update_campaigns(id) on delete cascade,
  fleet_id     uuid not null references public.fleets(id) on delete cascade,
  reason       text not null check (length(trim(reason)) >= 3),
  created_by   text not null,
  created_at   timestamptz not null default now(),
  unique (campaign_id, fleet_id)
);

create table if not exists public.installation_update_events (
  id              uuid primary key,
  installation_id uuid references public.installations(id) on delete set null,
  campaign_id     uuid references public.update_campaigns(id) on delete set null,
  release_id      uuid references public.product_releases(id) on delete set null,
  event_type      text not null check (event_type in (
                    'eligible','offered','download_started','downloaded','install_started',
                    'install_completed','relaunch_confirmed','post_update_health_passed',
                    'post_update_health_failed','rejected','failed','recovery_required'
                  )),
  from_version    text,
  from_build_id   text,
  to_version      text,
  to_build_id     text,
  failure_code    text,
  failure_class   text,
  occurred_at     timestamptz not null,
  received_at     timestamptz not null default now()
);

create index if not exists idx_installation_update_events_failure
  on public.installation_update_events(event_type, received_at desc)
  where event_type in ('post_update_health_failed','failed','recovery_required');

-- ---------------------------------------------------------------------------
-- Backfill default fleets for existing customers and installations.
-- ---------------------------------------------------------------------------
insert into public.fleets (customer_id, display_name, fleet_type, status, update_ring, release_channel_id)
select c.id,
       coalesce(nullif(trim(c.display_name), ''), 'Default fleet'),
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
from public.customer_profiles c
on conflict do nothing;

insert into public.fleet_applications (fleet_id, product_id, status, update_ring, release_channel_id)
select f.id, p.id, 'active', f.update_ring,
       coalesce(
         f.release_channel_id,
         (select rc.id from public.release_channels rc
          where rc.product_id = p.id and rc.key = 'stable' limit 1)
       )
from public.fleets f
cross join public.products p
where p.key = 'authorforge'
on conflict (fleet_id, product_id) do nothing;

update public.installations i
set fleet_id = f.id
from public.fleets f
where i.customer_id = f.customer_id
  and f.fleet_type = 'default'
  and f.status <> 'deleted'
  and i.fleet_id is null;

-- ---------------------------------------------------------------------------
-- RLS: customers can read their own fleets/application policy and update events.
-- Release metadata is public only for published releases; all mutations remain service-only.
-- ---------------------------------------------------------------------------
do $$
declare
  t text;
  all_tables text[] := array[
    'fleets','fleet_applications','product_releases','release_artifacts',
    'update_campaigns','update_campaign_holds','installation_update_events'
  ];
begin
  foreach t in array all_tables loop
    execute format('alter table public.%I enable row level security;', t);
    execute format('alter table public.%I force row level security;', t);
  end loop;
end $$;

drop policy if exists p_fleets_read_own on public.fleets;
create policy p_fleets_read_own on public.fleets
  for select using (customer_id = public.current_customer_id());

drop policy if exists p_fleet_applications_read_own on public.fleet_applications;
create policy p_fleet_applications_read_own on public.fleet_applications
  for select using (
    exists (
      select 1 from public.fleets f
      where f.id = fleet_applications.fleet_id
        and f.customer_id = public.current_customer_id()
    )
  );

drop policy if exists p_installation_update_events_read_own on public.installation_update_events;
create policy p_installation_update_events_read_own on public.installation_update_events
  for select using (
    exists (
      select 1 from public.installations i
      where i.id = installation_update_events.installation_id
        and i.customer_id = public.current_customer_id()
    )
  );

drop policy if exists p_product_releases_published_read on public.product_releases;
create policy p_product_releases_published_read on public.product_releases
  for select using (status = 'published');

drop policy if exists p_release_artifacts_published_read on public.release_artifacts;
create policy p_release_artifacts_published_read on public.release_artifacts
  for select using (
    status = 'validated'
    and exists (
      select 1 from public.product_releases r
      where r.id = release_artifacts.release_id and r.status = 'published'
    )
  );
