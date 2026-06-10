//! Business services. Pure-ish logic that may compose domain logic with signing/crypto.
//! Database access lives in `repositories`; this layer orchestrates.

pub mod signing;
