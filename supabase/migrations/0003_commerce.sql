-- 0003_commerce.sql
-- Phase 5 — Commerce & Stripe. ForgeCustomer stores a NORMALIZED projection of Stripe
-- state. Only verified webhook processing changes subscription truth. Raw card data is
-- never stored.

-- ---------------------------------------------------------------------------
-- billing_accounts — a customer's commercial account
-- ---------------------------------------------------------------------------
create table if not exists public.billing_accounts (
  id           uuid primary key default gen_random_uuid(),
  customer_id  uuid not null references public.customer_profiles(id) on delete cascade,
  currency     text not null default 'usd',
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now(),
  unique (customer_id)
);

-- ---------------------------------------------------------------------------
-- stripe_customers — linkage to Stripe customer ids (server-side only)
-- ---------------------------------------------------------------------------
create table if not exists public.stripe_customers (
  id                  uuid primary key default gen_random_uuid(),
  billing_account_id  uuid not null references public.billing_accounts(id) on delete cascade,
  stripe_customer_id  text not null unique,
  created_at          timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- subscriptions — normalized subscription state
-- ---------------------------------------------------------------------------
create table if not exists public.subscriptions (
  id                     uuid primary key default gen_random_uuid(),
  customer_id            uuid not null references public.customer_profiles(id) on delete cascade,
  billing_account_id     uuid not null references public.billing_accounts(id) on delete cascade,
  plan_version_id        uuid not null references public.plan_versions(id),
  stripe_subscription_id text unique,
  status                 text not null
                           check (status in ('trialing','active','past_due','unpaid',
                                             'canceled','incomplete','paused')),
  current_period_start   timestamptz,
  current_period_end     timestamptz,
  cancel_at_period_end   boolean not null default false,
  -- last Stripe event timestamp applied, for out-of-order protection
  stripe_event_at        timestamptz,
  created_at             timestamptz not null default now(),
  updated_at             timestamptz not null default now()
);

create index if not exists idx_subscriptions_customer on public.subscriptions(customer_id);

drop trigger if exists trg_subscriptions_updated_at on public.subscriptions;
create trigger trg_subscriptions_updated_at
  before update on public.subscriptions
  for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- subscription_items — line items within a subscription
-- ---------------------------------------------------------------------------
create table if not exists public.subscription_items (
  id                   uuid primary key default gen_random_uuid(),
  subscription_id      uuid not null references public.subscriptions(id) on delete cascade,
  stripe_item_id       text,
  stripe_price_id      text,
  quantity             integer not null default 1,
  created_at           timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- billing_periods — historical period bounds (for proration / audit)
-- ---------------------------------------------------------------------------
create table if not exists public.billing_periods (
  id              uuid primary key default gen_random_uuid(),
  subscription_id uuid not null references public.subscriptions(id) on delete cascade,
  period_start    timestamptz not null,
  period_end      timestamptz not null,
  status          text not null default 'open'
                    check (status in ('open','closed')),
  created_at      timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- checkout_sessions — references to Stripe Checkout sessions (redirect does NOT activate)
-- ---------------------------------------------------------------------------
create table if not exists public.checkout_sessions (
  id                        uuid primary key default gen_random_uuid(),
  customer_id               uuid not null references public.customer_profiles(id) on delete cascade,
  plan_version_id           uuid not null references public.plan_versions(id),
  stripe_checkout_session_id text unique,
  status                    text not null default 'created'
                              check (status in ('created','completed','expired')),
  created_at                timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- invoice_references — references to Stripe invoices (no raw payment data)
-- ---------------------------------------------------------------------------
create table if not exists public.invoice_references (
  id                 uuid primary key default gen_random_uuid(),
  subscription_id    uuid references public.subscriptions(id) on delete set null,
  stripe_invoice_id  text not null unique,
  status             text not null
                       check (status in ('paid','open','void','uncollectible','draft')),
  amount_due_cents   bigint,
  currency           text,
  created_at         timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- stripe_webhook_events — dedupe + minimal, secured payload retention
-- ---------------------------------------------------------------------------
create table if not exists public.stripe_webhook_events (
  id                uuid primary key default gen_random_uuid(),
  stripe_event_id   text not null unique,        -- idempotency key
  event_type        text not null,
  received_at       timestamptz not null default now(),
  processed_at      timestamptz,
  status            text not null default 'received'
                      check (status in ('received','processed','ignored','failed')),
  -- minimal retained payload, secured; purged on a schedule
  payload_summary   jsonb
);
