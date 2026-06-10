//! Background workers. The outbox publisher drains `outbox_events` and delivers sanitized
//! events to DataForge with retry/backoff, dead-lettering, and idempotent delivery keys.

pub mod outbox;
