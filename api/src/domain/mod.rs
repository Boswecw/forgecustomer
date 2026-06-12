//! Domain types and pure business logic. Everything here is deterministic and unit
//! tested; no I/O lives in this module.

pub mod admin;
pub mod checkout;
pub mod customer;
pub mod deletion;
pub mod entitlement;
pub mod installation;
pub mod lease;
pub mod license;
pub mod redaction;
pub mod snapshot;
pub mod subscription;
pub mod updates;
pub mod usage;
