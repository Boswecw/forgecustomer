-- update_campaign_http_smoke.sql
-- Fixture rows for the HTTP/live-PostgreSQL AuthorForge update endpoint smoke.
--
-- This file commits deterministic rows. The smoke runner mutates those rows between
-- curl assertions to prove version-minimum, updater-minimum, same-build, and rollout
-- gates through the real API.

begin;

do $$
declare
  v_product_id uuid;
  v_channel_id uuid;
  v_customer_id uuid := '00000000-0000-4000-8000-000000000901';
  v_auth_user_id uuid := '00000000-0000-4000-8000-000000000911';
  v_fleet_id uuid := '00000000-0000-4000-8000-000000000902';
  v_installation_id uuid := '00000000-0000-4000-8000-000000000903';
  v_release_id uuid := '00000000-0000-4000-8000-000000000904';
  v_artifact_id uuid := '00000000-0000-4000-8000-000000000905';
  v_campaign_id uuid := '00000000-0000-4000-8000-000000000906';
begin
  select id into strict v_product_id from public.products where key = 'authorforge';
  select id into strict v_channel_id
  from public.release_channels
  where product_id = v_product_id and key = 'stable';

  delete from public.customer_profiles where id = v_customer_id;

  insert into public.customer_profiles (id, auth_user_id, status, display_name)
  values (v_customer_id, v_auth_user_id, 'active', 'HTTP update smoke customer');

  insert into public.fleets
      (id, customer_id, display_name, fleet_type, status, update_ring, release_channel_id)
  values
      (v_fleet_id, v_customer_id, 'HTTP update smoke fleet', 'default', 'active',
       'standard', v_channel_id);

  insert into public.fleet_applications
      (fleet_id, product_id, status, update_ring, release_channel_id)
  values
      (v_fleet_id, v_product_id, 'active', 'standard', v_channel_id);

  insert into public.installations
      (id, customer_id, install_key, product_id, app_version, build_id, status, fleet_id,
       platform, architecture, package_format, updater_version)
  values
      (v_installation_id, v_customer_id, 'http-update-smoke-install', v_product_id,
       '1.0.0', '20260612.previous', 'active', v_fleet_id, 'linux', 'x86_64',
       'appimage', '1.0.0');

  insert into public.product_releases
      (id, product_id, version, build_id, release_channel_id, status,
       changelog_markdown, minimum_supported_version, minimum_updater_version,
       created_by, validated_at, published_at)
  values
      (v_release_id, v_product_id, '1.2.0', '20260612.http-smoke', v_channel_id,
       'published', 'HTTP update smoke release notes', '1.0.0', '1.0.0',
       'ci-update-http-smoke', now(), now());

  insert into public.release_artifacts
      (id, release_id, platform, architecture, package_format, artifact_role,
       storage_key, size_bytes, sha256, tauri_signature, signing_key_id,
       os_signature_status, status)
  values
      (v_artifact_id, v_release_id, 'linux', 'x86_64', 'appimage', 'updater',
       'authorforge/http-smoke/authorforge-updater-linux-x86_64.appimage', 128,
       repeat('c', 64), 'ci-tauri-http-smoke-signature', 'ci-http-smoke-tauri-key',
       'verified', 'validated');

  insert into public.update_campaigns
      (id, product_id, target_release_id, campaign_slug, status, release_channel_id,
       target_update_ring, rollout_percentage, starts_at, created_by)
  values
      (v_campaign_id, v_product_id, v_release_id, 'http-update-smoke', 'active',
       v_channel_id, 'standard', 100, now() - interval '1 hour', 'ci-update-http-smoke');
end $$;

commit;
