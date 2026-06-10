//! Domain types and pure business logic. Everything here is deterministic and unit
//! tested; no I/O lives in this module.

pub mod checkout;
pub mod customer;
pub mod entitlement;
pub mod license;
pub mod redaction;
pub mod snapshot;
pub mod subscription;
pub mod usage;
