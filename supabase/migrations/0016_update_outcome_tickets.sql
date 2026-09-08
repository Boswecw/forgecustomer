-- Opaque, short-lived correlation handles for native AuthorForge updater receipts.
-- The client never receives campaign/release identifiers and cannot select them.
create table if not exists public.update_outcome_tickets (
  token uuid primary key default gen_random_uuid(),
  installation_id uuid not null references public.installations(id) on delete cascade,
  campaign_id uuid not null references public.update_campaigns(id) on delete cascade,
  release_id uuid not null references public.product_releases(id) on delete cascade,
  expires_at timestamptz not null,
  issued_at timestamptz not null default now(),
  check (expires_at > issued_at),
  unique (installation_id, campaign_id, release_id)
);

create index if not exists idx_update_outcome_tickets_installation_expiry
  on public.update_outcome_tickets (installation_id, expires_at desc);

alter table public.installation_update_events
  add column if not exists update_ticket uuid
    references public.update_outcome_tickets(token) on delete set null;

create index if not exists idx_installation_update_events_ticket
  on public.installation_update_events (update_ticket, received_at desc)
  where update_ticket is not null;

alter table public.update_outcome_tickets enable row level security;
alter table public.update_outcome_tickets force row level security;

drop policy if exists p_update_outcome_tickets_read_own on public.update_outcome_tickets;
create policy p_update_outcome_tickets_read_own on public.update_outcome_tickets
  for select using (
    exists (
      select 1 from public.installations i
      where i.id = update_outcome_tickets.installation_id
        and i.customer_id = public.current_customer_id()
    )
  );
