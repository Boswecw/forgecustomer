-- 0008_privacy.sql
-- Phase 12 — Privacy: policy versions, consent records, account deletion requests.

-- ---------------------------------------------------------------------------
-- policy_versions — versions of terms/privacy/etc.
-- ---------------------------------------------------------------------------
create table if not exists public.policy_versions (
  id           uuid primary key default gen_random_uuid(),
  policy_key   text not null,                   -- 'terms','privacy','dpa'
  version      text not null,
  effective_at timestamptz not null default now(),
  url          text,
  created_at   timestamptz not null default now(),
  unique (policy_key, version)
);

-- ---------------------------------------------------------------------------
-- consent_records — which policy version a customer accepted
-- ---------------------------------------------------------------------------
create table if not exists public.consent_records (
  id                uuid primary key default gen_random_uuid(),
  customer_id       uuid not null references public.customer_profiles(id) on delete cascade,
  policy_version_id uuid not null references public.policy_versions(id),
  accepted_at       timestamptz not null default now(),
  source            text,                        -- 'signup','settings', etc.
  created_at        timestamptz not null default now(),
  unique (customer_id, policy_version_id)
);

-- ---------------------------------------------------------------------------
-- account_deletion_requests — deletion workflow state machine
-- ---------------------------------------------------------------------------
create table if not exists public.account_deletion_requests (
  id              uuid primary key default gen_random_uuid(),
  customer_id     uuid not null references public.customer_profiles(id) on delete cascade,
  status          text not null default 'requested'
                    check (status in ('requested','verified','cooling_off',
                                      'processing','completed','rejected','canceled')),
  requested_at    timestamptz not null default now(),
  cooling_off_until timestamptz,
  completed_at    timestamptz,
  -- deletion receipt (what was anonymized/retained), no PII payload
  receipt         jsonb,
  reason          text,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

create index if not exists idx_deletion_requests_status
  on public.account_deletion_requests(status);

drop trigger if exists trg_deletion_requests_updated_at on public.account_deletion_requests;
create trigger trg_deletion_requests_updated_at
  before update on public.account_deletion_requests
  for each row execute function public.set_updated_at();
