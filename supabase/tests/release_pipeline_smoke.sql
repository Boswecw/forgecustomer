-- release_pipeline_smoke.sql
-- DB-backed release package publication proof.
--
-- This file is driven by scripts/release_pipeline_smoke.sh after migrations and
-- seed data are applied. It commits deterministic smoke rows so the API can
-- resolve them through the public bootstrap lookup during the same run.

\if :{?bootstrap_storage_key}
\else
\echo 'bootstrap_storage_key psql variable is required'
\quit 1
\endif
\if :{?bootstrap_size_bytes}
\else
\echo 'bootstrap_size_bytes psql variable is required'
\quit 1
\endif
\if :{?bootstrap_sha256}
\else
\echo 'bootstrap_sha256 psql variable is required'
\quit 1
\endif
\if :{?updater_storage_key}
\else
\echo 'updater_storage_key psql variable is required'
\quit 1
\endif
\if :{?updater_size_bytes}
\else
\echo 'updater_size_bytes psql variable is required'
\quit 1
\endif
\if :{?updater_sha256}
\else
\echo 'updater_sha256 psql variable is required'
\quit 1
\endif

begin;

create or replace function pg_temp.assert_eq_text(label text, actual text, expected text)
returns void
language plpgsql
as $$
begin
  if actual is distinct from expected then
    raise exception '% expected %, got %', label, expected, actual;
  end if;
end;
$$;

create or replace function pg_temp.assert_eq_integer(label text, actual integer, expected integer)
returns void
language plpgsql
as $$
begin
  if actual <> expected then
    raise exception '% expected %, got %', label, expected, actual;
  end if;
end;
$$;

create or replace function pg_temp.assert_eq_bigint(label text, actual bigint, expected bigint)
returns void
language plpgsql
as $$
begin
  if actual <> expected then
    raise exception '% expected %, got %', label, expected, actual;
  end if;
end;
$$;

create or replace function pg_temp.public_bootstrap_count()
returns integer
language sql
stable
as $$
  select count(*)::integer
  from public.product_releases r
  join public.products p on p.id = r.product_id
  join public.release_channels rc on rc.id = r.release_channel_id
  join public.release_artifacts a on a.release_id = r.id
  where p.key = 'authorforge'
    and p.status = 'active'
    and rc.key = 'stable'
    and r.status = 'published'
    and a.status = 'validated'
    and a.artifact_role = 'bootstrap'
    and a.platform = 'linux'
    and a.architecture = 'x86_64'
    and a.package_format = 'appimage';
$$;

create temp table release_smoke_input (
  bootstrap_storage_key text not null,
  bootstrap_size_bytes bigint not null,
  bootstrap_sha256 text not null,
  updater_storage_key text not null,
  updater_size_bytes bigint not null,
  updater_sha256 text not null
) on commit drop;

insert into release_smoke_input
    (bootstrap_storage_key, bootstrap_size_bytes, bootstrap_sha256,
     updater_storage_key, updater_size_bytes, updater_sha256)
values
    (:'bootstrap_storage_key', :bootstrap_size_bytes, :'bootstrap_sha256',
     :'updater_storage_key', :updater_size_bytes, :'updater_sha256');

do $$
declare
  v_product_id uuid;
  v_channel_id uuid;
  v_release_id uuid := '00000000-0000-4000-8000-000000000811';
  v_bootstrap_artifact_id uuid := '00000000-0000-4000-8000-000000000812';
  v_updater_artifact_id uuid := '00000000-0000-4000-8000-000000000813';
  v_bootstrap_storage_key text;
  v_bootstrap_size_bytes bigint;
  v_bootstrap_sha256 text;
  v_updater_storage_key text;
  v_updater_size_bytes bigint;
  v_updater_sha256 text;
  v_storage_key text;
  v_sha256 text;
  v_size_bytes bigint;
begin
  select bootstrap_storage_key, bootstrap_size_bytes, bootstrap_sha256,
         updater_storage_key, updater_size_bytes, updater_sha256
  into strict v_bootstrap_storage_key, v_bootstrap_size_bytes, v_bootstrap_sha256,
              v_updater_storage_key, v_updater_size_bytes, v_updater_sha256
  from release_smoke_input;

  select id into strict v_product_id from public.products where key = 'authorforge';
  select id into strict v_channel_id
  from public.release_channels
  where product_id = v_product_id and key = 'stable';

  delete from public.product_releases where id = v_release_id;

  insert into public.product_releases
      (id, product_id, version, build_id, release_channel_id, status,
       changelog_markdown, created_by)
  values
      (v_release_id, v_product_id, '9.9.901', '20260612.release-smoke',
       v_channel_id, 'draft', 'Release pipeline smoke fixture',
       'ci-release-pipeline-smoke');

  perform pg_temp.assert_eq_integer(
    'draft release is hidden from public bootstrap lookup',
    pg_temp.public_bootstrap_count(),
    0
  );

  insert into public.release_artifacts
      (id, release_id, platform, architecture, package_format, artifact_role,
       storage_key, size_bytes, sha256, tauri_signature, signing_key_id,
       os_signature_status, status)
  values
      (v_bootstrap_artifact_id, v_release_id, 'linux', 'x86_64', 'appimage',
       'bootstrap', v_bootstrap_storage_key, v_bootstrap_size_bytes,
       v_bootstrap_sha256, null, 'ci-smoke-os-key', 'verified', 'validated'),
      (v_updater_artifact_id, v_release_id, 'linux', 'x86_64', 'appimage',
       'updater', v_updater_storage_key, v_updater_size_bytes,
       v_updater_sha256, 'ci-tauri-smoke-signature', 'ci-smoke-tauri-key',
       'verified', 'validated');

  update public.product_releases
  set status = 'artifacts_pending'
  where id = v_release_id;

  perform pg_temp.assert_eq_integer(
    'artifact-pending release is hidden from public bootstrap lookup',
    pg_temp.public_bootstrap_count(),
    0
  );

  update public.product_releases
  set status = 'validated',
      validated_at = now()
  where id = v_release_id;

  perform pg_temp.assert_eq_integer(
    'validated but unpublished release is hidden from public bootstrap lookup',
    pg_temp.public_bootstrap_count(),
    0
  );

  update public.product_releases
  set status = 'published',
      published_at = now()
  where id = v_release_id;

  perform pg_temp.assert_eq_integer(
    'published release exposes exactly one bootstrap artifact',
    pg_temp.public_bootstrap_count(),
    1
  );

  perform pg_temp.assert_eq_integer(
    'updater artifact was registered alongside bootstrap artifact',
    (
      select count(*)::integer
      from public.release_artifacts
      where release_id = v_release_id and artifact_role = 'updater'
    ),
    1
  );

  select a.storage_key, a.sha256, a.size_bytes
  into strict v_storage_key, v_sha256, v_size_bytes
  from public.product_releases r
  join public.release_artifacts a on a.release_id = r.id
  where r.id = v_release_id
    and r.status = 'published'
    and a.status = 'validated'
    and a.artifact_role = 'bootstrap'
    and a.platform = 'linux'
    and a.architecture = 'x86_64'
    and a.package_format = 'appimage';

  perform pg_temp.assert_eq_text(
    'bootstrap storage key matches uploaded object',
    v_storage_key,
    v_bootstrap_storage_key
  );
  perform pg_temp.assert_eq_text(
    'bootstrap checksum matches uploaded object',
    v_sha256,
    v_bootstrap_sha256
  );
  perform pg_temp.assert_eq_bigint(
    'bootstrap size matches uploaded object',
    v_size_bytes,
    v_bootstrap_size_bytes
  );
end $$;

commit;
