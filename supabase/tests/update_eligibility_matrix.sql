-- update_eligibility_matrix.sql
-- DB-backed proof for the AuthorForge update eligibility gates.
--
-- Run after supabase/migrations/*.sql and supabase/seed.sql. The transaction rolls
-- back so CI keeps the migration database clean for later assertions.

begin;

create or replace function pg_temp.assert_eq(label text, actual integer, expected integer)
returns void
language plpgsql
as $$
begin
  if actual <> expected then
    raise exception '% expected %, got %', label, expected, actual;
  end if;
end;
$$;

create or replace function pg_temp.eligible_update_count(
  p_customer_id uuid,
  p_installation_id uuid,
  p_product_key text default 'authorforge',
  p_platform text default 'linux',
  p_architecture text default 'x86_64',
  p_package_format text default 'appimage'
)
returns integer
language sql
stable
as $$
  select count(*)::integer
  from public.installations i
  join public.fleets f
    on f.id = i.fleet_id
   and f.customer_id = i.customer_id
  join public.products p
    on p.key = p_product_key
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
  where i.id = p_installation_id
    and i.customer_id = p_customer_id
    and i.status = 'active'
    and f.status = 'active'
    and fa.status = 'active'
    and c.status = 'active'
    and (c.starts_at is null or c.starts_at <= now())
    and r.status = 'published'
    and a.status = 'validated'
    and a.artifact_role = 'updater'
    and a.platform = p_platform
    and a.architecture = p_architecture
    and a.package_format = p_package_format
    and not exists (
      select 1
      from public.update_campaign_holds h
      where h.campaign_id = c.id and h.fleet_id = f.id
    );
$$;

do $$
declare
  v_product_id uuid;
  v_channel_id uuid;
  v_customer_id uuid := '00000000-0000-4000-8000-000000000101';
  v_other_customer_id uuid := '00000000-0000-4000-8000-000000000102';
  v_fleet_id uuid := '00000000-0000-4000-8000-000000000201';
  v_installation_id uuid := '00000000-0000-4000-8000-000000000301';
  v_release_id uuid := '00000000-0000-4000-8000-000000000401';
  v_artifact_id uuid := '00000000-0000-4000-8000-000000000501';
  v_campaign_id uuid := '00000000-0000-4000-8000-000000000601';
  v_event_id uuid := '00000000-0000-4000-8000-000000000701';
begin
  select id into strict v_product_id from public.products where key = 'authorforge';
  select id into strict v_channel_id
  from public.release_channels
  where product_id = v_product_id and key = 'stable';

  insert into public.customer_profiles (id, auth_user_id, status, display_name)
  values
    (v_customer_id, '00000000-0000-4000-8000-000000000111', 'active', 'Eligibility Customer'),
    (v_other_customer_id, '00000000-0000-4000-8000-000000000112', 'active', 'Other Customer');

  insert into public.fleets
      (id, customer_id, display_name, fleet_type, status, update_ring, release_channel_id)
  values
      (v_fleet_id, v_customer_id, 'Default fleet', 'default', 'active', 'standard', v_channel_id);

  insert into public.fleet_applications
      (fleet_id, product_id, status, update_ring, release_channel_id)
  values
      (v_fleet_id, v_product_id, 'active', 'standard', v_channel_id);

  insert into public.installations
      (id, customer_id, install_key, product_id, app_version, status, fleet_id,
       platform, architecture, package_format, updater_version)
  values
      (v_installation_id, v_customer_id, 'eligibility-install', v_product_id,
       '1.0.0', 'active', v_fleet_id, 'linux', 'x86_64', 'appimage', '1.0.0');

  insert into public.product_releases
      (id, product_id, version, build_id, release_channel_id, status,
       changelog_markdown, created_by, validated_at, published_at)
  values
      (v_release_id, v_product_id, '1.1.0', '20260612.matrix', v_channel_id,
       'published', 'Eligibility proof release', 'ci-update-matrix', now(), now());

  insert into public.release_artifacts
      (id, release_id, platform, architecture, package_format, artifact_role,
       storage_key, size_bytes, sha256, tauri_signature, signing_key_id,
       os_signature_status, status)
  values
      (v_artifact_id, v_release_id, 'linux', 'x86_64', 'appimage', 'updater',
       'authorforge/1.1.0/linux-x86_64.appimage', 100,
       repeat('a', 64), 'tauri-signature', 'tauri-key-1', 'verified', 'validated');

  insert into public.update_campaigns
      (id, product_id, target_release_id, campaign_slug, status, release_channel_id,
       target_update_ring, rollout_percentage, starts_at, created_by)
  values
      (v_campaign_id, v_product_id, v_release_id, 'eligibility-matrix', 'active',
       v_channel_id, 'standard', 100, now() - interval '1 hour', 'ci-update-matrix');

  perform pg_temp.assert_eq(
    'baseline eligible updater candidate',
    pg_temp.eligible_update_count(v_customer_id, v_installation_id),
    1
  );

  perform pg_temp.assert_eq(
    'cross-customer installation lookup is denied',
    pg_temp.eligible_update_count(v_other_customer_id, v_installation_id),
    0
  );

  update public.fleets set status = 'held' where id = v_fleet_id;
  perform pg_temp.assert_eq(
    'held fleet is ineligible',
    pg_temp.eligible_update_count(v_customer_id, v_installation_id),
    0
  );
  update public.fleets set status = 'active' where id = v_fleet_id;

  insert into public.update_campaign_holds
      (campaign_id, fleet_id, reason, created_by)
  values
      (v_campaign_id, v_fleet_id, 'CI matrix hold', 'ci-update-matrix');
  perform pg_temp.assert_eq(
    'campaign hold blocks fleet eligibility',
    pg_temp.eligible_update_count(v_customer_id, v_installation_id),
    0
  );
  delete from public.update_campaign_holds
  where campaign_id = v_campaign_id and fleet_id = v_fleet_id;

  update public.update_campaigns set status = 'paused' where id = v_campaign_id;
  perform pg_temp.assert_eq(
    'paused campaign is ineligible',
    pg_temp.eligible_update_count(v_customer_id, v_installation_id),
    0
  );
  update public.update_campaigns set status = 'revoked' where id = v_campaign_id;
  perform pg_temp.assert_eq(
    'revoked campaign is ineligible',
    pg_temp.eligible_update_count(v_customer_id, v_installation_id),
    0
  );
  update public.update_campaigns set status = 'active' where id = v_campaign_id;

  update public.product_releases set status = 'validated' where id = v_release_id;
  perform pg_temp.assert_eq(
    'unpublished release is ineligible',
    pg_temp.eligible_update_count(v_customer_id, v_installation_id),
    0
  );
  update public.product_releases set status = 'published' where id = v_release_id;

  update public.release_artifacts set status = 'quarantined' where id = v_artifact_id;
  perform pg_temp.assert_eq(
    'quarantined artifact is ineligible',
    pg_temp.eligible_update_count(v_customer_id, v_installation_id),
    0
  );
  update public.release_artifacts set status = 'validated' where id = v_artifact_id;

  update public.release_artifacts set artifact_role = 'bootstrap' where id = v_artifact_id;
  perform pg_temp.assert_eq(
    'bootstrap artifact is not a Tauri updater candidate',
    pg_temp.eligible_update_count(v_customer_id, v_installation_id),
    0
  );
  update public.release_artifacts set artifact_role = 'updater' where id = v_artifact_id;

  insert into public.installation_update_events
      (id, installation_id, campaign_id, release_id, event_type,
       from_version, to_version, occurred_at)
  values
      (v_event_id, v_installation_id, v_campaign_id, v_release_id,
       'downloaded', '1.0.0', '1.1.0', now())
  on conflict (id) do nothing;

  insert into public.installation_update_events
      (id, installation_id, campaign_id, release_id, event_type,
       from_version, to_version, occurred_at)
  values
      (v_event_id, v_installation_id, v_campaign_id, v_release_id,
       'failed', '1.0.0', '1.1.0', now())
  on conflict (id) do nothing;

  perform pg_temp.assert_eq(
    'duplicate update-event receipt remains single-row',
    (
      select count(*)::integer
      from public.installation_update_events
      where id = v_event_id and event_type = 'downloaded'
    ),
    1
  );
end $$;

rollback;
