-- 0001_customer_identity.sql
-- Phase 2 — Customer identity model.
-- ForgeCustomer keeps its OWN business customer id; auth.users.id is referenced but is
-- never the sole business identifier.

create extension if not exists pgcrypto;   -- gen_random_uuid()

-- Shared updated_at trigger function (idempotent).
create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

-- ---------------------------------------------------------------------------
-- customer_profiles — one business customer per Supabase auth user.
-- ---------------------------------------------------------------------------
create table if not exists public.customer_profiles (
  id            uuid primary key default gen_random_uuid(),
  auth_user_id  uuid not null unique,
  customer_type text not null default 'individual'
                  check (customer_type in ('individual', 'organization')),
  display_name  text,
  status        text not null default 'pending'
                  check (status in ('pending','active','suspended','closed','anonymized')),
  country_code  text check (country_code is null or country_code ~ '^[A-Z]{2}$'),
  timezone      text,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

create index if not exists idx_customer_profiles_status on public.customer_profiles(status);

drop trigger if exists trg_customer_profiles_updated_at on public.customer_profiles;
create trigger trg_customer_profiles_updated_at
  before update on public.customer_profiles
  for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- customer_status_history — append-only record of status transitions.
-- ---------------------------------------------------------------------------
create table if not exists public.customer_status_history (
  id           uuid primary key default gen_random_uuid(),
  customer_id  uuid not null references public.customer_profiles(id) on delete cascade,
  from_status  text,
  to_status    text not null,
  reason       text,
  actor_type   text not null default 'system'
                 check (actor_type in ('system','customer','operator')),
  actor_id     text,
  created_at   timestamptz not null default now()
);

create index if not exists idx_customer_status_history_customer
  on public.customer_status_history(customer_id, created_at);

-- ---------------------------------------------------------------------------
-- customer_emails — normalized contact emails (Supabase Auth remains login authority).
-- ---------------------------------------------------------------------------
create table if not exists public.customer_emails (
  id           uuid primary key default gen_random_uuid(),
  customer_id  uuid not null references public.customer_profiles(id) on delete cascade,
  email        text not null,
  is_primary   boolean not null default false,
  verified_at  timestamptz,
  created_at   timestamptz not null default now()
);

-- At most one primary email per customer.
create unique index if not exists uq_customer_emails_primary
  on public.customer_emails(customer_id) where is_primary;
create unique index if not exists uq_customer_emails_value
  on public.customer_emails(customer_id, lower(email));
