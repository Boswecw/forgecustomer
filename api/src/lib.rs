//! ForgeCustomer API library crate.
//!
//! The binary (`src/main.rs`) is a thin entry point over this library so that integration
//! and security tests under `tests/` can exercise the same code, and so the public surface
//! is treated as API (not dead code) by the compiler.

pub mod auth;
pub mod config;
pub mod domain;
pub mod error;
pub mod integrations;
pub mod middleware;
pub mod repositories;
pub mod routes;
pub mod services;
pub mod state;
pub mod workers;
