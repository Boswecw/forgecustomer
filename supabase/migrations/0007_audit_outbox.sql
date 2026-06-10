-- 0007_audit_outbox.sql
-- Phase 9 — Commercial audit (append-only) and Phase 11 — DataForge outbox.

-- ---------------------------------------------------------------------------
-- commercial_audit_events — append-only audit of every privileged mutation
-- ---------------------------------------------------------------------------
create table if not exists public.commercial_audit_events (
  id             uuid primary key default gen_random_uuid(),
  event_type     text not null,                 -- e.g. 'customer_suspended'
  actor_type     text not null
                   check (actor_type in ('system','operator','stripe','customer')),
  actor_id       text,
  customer_id    uuid references public.customer_profiles(id) on delete set null,
  target_type    text,
  target_id      text,
  reason         text,
  before_state   jsonb,
  after_state    jsonb,
  correlation_id text,
  created_at     timestamptz not null default now()
);

create index if not exists idx_audit_customer
  on public.commercial_audit_events(customer_id, created_at);
create index if not exists idx_audit_type
  on public.commercial_audit_events(event_type, created_at);

-- ---------------------------------------------------------------------------
-- outbox_events — sanitized events for DataForge (transactional outbox pattern)
-- ---------------------------------------------------------------------------
create table if not exists public.outbox_events (
  id             uuid primary key default gen_random_uuid(),
  event_type     text not null,                 -- e.g. 'subscription_changed'
  -- idempotent delivery key (consumer dedupes on this)
  delivery_key   text not null unique,
  payload        jsonb not null,                -- SANITIZED: no PII / secrets / content
  status         text not null default 'pending'
                   check (status in ('pending','delivered','dead_letter')),
  attempts       integer not null default 0,
  last_error     text,
  next_attempt_at timestamptz not null default now(),
  delivered_at   timestamptz,
  created_at     timestamptz not null default now()
);

create index if not exists idx_outbox_pending
  on public.outbox_events(status, next_attempt_at);
