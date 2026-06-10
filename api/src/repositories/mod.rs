//! Database access. Uses the SQLx runtime query API (no compile-time macros) so the crate
//! builds without a live database. All privileged mutations are expected to run inside a
//! transaction together with their audit + outbox writes (see services/workers).

pub mod admin;
pub mod catalog;
pub mod commerce;
pub mod customers;
pub mod entitlements;
pub mod licensing;
