-- rls_customer_write_denial.sql
-- Proves customer JWT roles cannot mutate commercial authority even when granted broad
-- table privileges. RLS policies, not missing SQL grants, must deny the writes.

create or replace function auth.uid()
returns uuid
language sql
stable
as $$
  select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid;
$$;

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'forgecustomer_rls_customer') then
    create role forgecustomer_rls_customer;
  end if;
end $$;

grant usage on schema public to forgecustomer_rls_customer;
grant usage on schema auth to forgecustomer_rls_customer;
grant select, insert, update, delete on all tables in schema public to forgecustomer_rls_customer;

do $$
declare
  v_product_id uuid;
  v_customer_id uuid := '00000000-0000-4000-8000-000000000a01';
  v_other_customer_id uuid := '00000000-0000-4000-8000-000000000a02';
  v_auth_user_id uuid := '00000000-0000-4000-8000-000000000a11';
  v_other_auth_user_id uuid := '00000000-0000-4000-8000-000000000a12';
  v_license_id uuid := '00000000-0000-4000-8000-000000000a21';
begin
  select id into strict v_product_id from public.products where key = 'authorforge';

  delete from public.customer_profiles where id in (v_customer_id, v_other_customer_id);

  insert into public.customer_profiles (id, auth_user_id, status, display_name)
  values
    (v_customer_id, v_auth_user_id, 'active', 'RLS Customer'),
    (v_other_customer_id, v_other_auth_user_id, 'active', 'Other RLS Customer');

  insert into public.licenses (id, customer_id, product_id, status, device_limit)
  values (v_license_id, v_customer_id, v_product_id, 'active', 1);

  insert into public.usage_period_totals
      (customer_id, meter_key, period_key, used, reserved)
  values
      (v_customer_id, 'cloud_tokens', '2026-06', 5, 0),
      (v_other_customer_id, 'cloud_tokens', '2026-06', 50, 0);
end $$;

set role forgecustomer_rls_customer;
select set_config('request.jwt.claim.sub', '00000000-0000-4000-8000-000000000a11', false);

do $$
declare
  v_count integer;
  v_rows integer;
  v_used numeric;
begin
  select count(*)::integer into v_count from public.customer_profiles;
  if v_count <> 1 then
    raise exception 'RLS customer profile read expected 1 visible row, got %', v_count;
  end if;

  select count(*)::integer into v_count
  from public.usage_period_totals
  where customer_id = '00000000-0000-4000-8000-000000000a02';
  if v_count <> 0 then
    raise exception 'RLS exposed another customer usage total';
  end if;

  begin
    insert into public.licenses (customer_id, product_id, status, device_limit)
    select '00000000-0000-4000-8000-000000000a01', id, 'active', 99
    from public.products where key = 'authorforge';
    raise exception 'customer role unexpectedly inserted a license';
  exception
    when insufficient_privilege or check_violation or with_check_option_violation then
      null;
  end;

  begin
    insert into public.license_grants
        (license_id, feature_key, bool_value)
    values
        ('00000000-0000-4000-8000-000000000a21',
         'authorforge.cloud.enabled', true);
    raise exception 'customer role unexpectedly inserted a license grant';
  exception
    when insufficient_privilege or check_violation or with_check_option_violation then
      null;
  end;

  begin
    insert into public.entitlement_grants
        (customer_id, product_id, feature_key, bool_value, source)
    select '00000000-0000-4000-8000-000000000a01', id,
           'authorforge.deep_analysis.enabled', true, 'support'
    from public.products where key = 'authorforge';
    raise exception 'customer role unexpectedly inserted an entitlement grant';
  exception
    when insufficient_privilege or check_violation or with_check_option_violation then
      null;
  end;

  begin
    insert into public.entitlement_overrides
        (customer_id, product_id, feature_key, bool_value, reason, actor_id)
    select '00000000-0000-4000-8000-000000000a01', id,
           'authorforge.cloud.enabled', true, 'customer escalation', 'customer'
    from public.products where key = 'authorforge';
    raise exception 'customer role unexpectedly inserted an entitlement override';
  exception
    when insufficient_privilege or check_violation or with_check_option_violation then
      null;
  end;

  begin
    insert into public.usage_events
        (customer_id, meter_key, amount, period_key, idempotency_key)
    values
        ('00000000-0000-4000-8000-000000000a01',
         'cloud_tokens', -1000, '2026-06', 'customer-forged-usage');
    raise exception 'customer role unexpectedly inserted a usage event';
  exception
    when insufficient_privilege or check_violation or with_check_option_violation then
      null;
  end;

  update public.usage_period_totals
  set used = 999
  where customer_id = '00000000-0000-4000-8000-000000000a01'
    and meter_key = 'cloud_tokens'
    and period_key = '2026-06';
  get diagnostics v_rows = row_count;
  if v_rows <> 0 then
    raise exception 'customer role unexpectedly updated % usage total rows', v_rows;
  end if;

  select used into strict v_used
  from public.usage_period_totals
  where customer_id = '00000000-0000-4000-8000-000000000a01'
    and meter_key = 'cloud_tokens'
    and period_key = '2026-06';
  if v_used <> 5 then
    raise exception 'customer-visible usage total changed to %', v_used;
  end if;
end $$;

reset role;
