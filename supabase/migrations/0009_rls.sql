-- 0009_rls.sql
-- Phase 18 — Row Level Security. Enable RLS on all customer-facing tables BEFORE customer
-- access. Customers read only their own rows; privileged tables deny normal JWTs entirely.
-- The service role (used ONLY by ForgeCustomer server processes) bypasses RLS.

-- Resolve the calling customer's business id from the Supabase auth uid.
create or replace function public.current_customer_id()
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select id from public.customer_profiles where auth_user_id = auth.uid();
$$;

-- ---------------------------------------------------------------------------
-- Helper: enable RLS on a table (no-op if already enabled).
-- ---------------------------------------------------------------------------
do $$
declare
  t text;
  read_own text[] := array[
    'customer_profiles','customer_status_history','customer_emails',
    'billing_accounts','subscriptions','licenses','installations','devices',
    'entitlement_snapshots','usage_period_totals','usage_reservations',
    'consent_records','account_deletion_requests'
  ];
  privileged text[] := array[
    'stripe_customers','subscription_items','billing_periods','checkout_sessions',
    'invoice_references','stripe_webhook_events','license_grants','license_activations',
    'license_leases','license_revocations','entitlement_grants','entitlement_overrides',
    'usage_meters','usage_events','quota_decisions','commercial_audit_events',
    'outbox_events','policy_versions','products','product_versions','plans',
    'plan_versions','features','plan_features','plan_quotas','release_channels'
  ];
begin
  -- Enable RLS everywhere.
  foreach t in array (read_own || privileged) loop
    execute format('alter table public.%I enable row level security;', t);
    execute format('alter table public.%I force row level security;', t);
  end loop;
end $$;

-- ---------------------------------------------------------------------------
-- Customer-owned READ policies (SELECT only). No customer INSERT/UPDATE/DELETE policies
-- exist on these tables, so customers cannot write commercial truth.
-- ---------------------------------------------------------------------------

-- customer_profiles: read own (matched by auth_user_id directly).
drop policy if exists p_profiles_read_own on public.customer_profiles;
create policy p_profiles_read_own on public.customer_profiles
  for select using (auth_user_id = auth.uid());

-- Generic "owned by current customer via customer_id" SELECT policies.
do $$
declare
  t text;
  owned text[] := array[
    'customer_status_history','customer_emails','billing_accounts','subscriptions',
    'licenses','installations','devices','entitlement_snapshots','usage_period_totals',
    'usage_reservations','consent_records','account_deletion_requests'
  ];
begin
  foreach t in array owned loop
    execute format('drop policy if exists p_%1$s_read_own on public.%1$s;', t);
    execute format(
      'create policy p_%1$s_read_own on public.%1$s for select
         using (customer_id = public.current_customer_id());', t);
  end loop;
end $$;

-- ---------------------------------------------------------------------------
-- Public catalog: products and plans are world-readable (safe, non-PII).
-- ---------------------------------------------------------------------------
do $$
declare
  t text;
  catalog text[] := array[
    'products','product_versions','plans','plan_versions','features',
    'plan_features','plan_quotas','release_channels'
  ];
begin
  foreach t in array catalog loop
    execute format('drop policy if exists p_%1$s_public_read on public.%1$s;', t);
    execute format(
      'create policy p_%1$s_public_read on public.%1$s for select using (true);', t);
  end loop;
end $$;

-- All remaining privileged tables have RLS enabled with NO policy => deny by default for
-- normal JWTs. Only the service role (RLS-bypassing) may access them.
