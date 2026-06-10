-- 0010_seed_constraints.sql
-- Integrity guards that must exist before seed/customer access:
--  * append-only enforcement for ledgers and audit
--  * referential helper indexes

-- ---------------------------------------------------------------------------
-- Append-only enforcement. usage_events and commercial_audit_events must never be
-- UPDATEd or DELETEd (corrections are compensating inserts). Reject at the DB level so
-- even the service role cannot silently mutate history.
-- ---------------------------------------------------------------------------
create or replace function public.reject_mutation()
returns trigger
language plpgsql
as $$
begin
  raise exception 'append-only table %: % is not permitted', tg_table_name, tg_op;
end;
$$;

drop trigger if exists trg_usage_events_append_only on public.usage_events;
create trigger trg_usage_events_append_only
  before update or delete on public.usage_events
  for each row execute function public.reject_mutation();

drop trigger if exists trg_audit_append_only on public.commercial_audit_events;
create trigger trg_audit_append_only
  before update or delete on public.commercial_audit_events
  for each row execute function public.reject_mutation();

-- ---------------------------------------------------------------------------
-- Convenience indexes used by the API hot paths.
-- ---------------------------------------------------------------------------
create index if not exists idx_subscriptions_status on public.subscriptions(status);
create index if not exists idx_installations_customer on public.installations(customer_id);
create index if not exists idx_devices_customer on public.devices(customer_id);
create index if not exists idx_outbox_delivery_key on public.outbox_events(delivery_key);
