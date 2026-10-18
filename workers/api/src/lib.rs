//! NNTune v2 accounts/auth/session/vault core.
//!
//! Native + wasm32 compatible. No Worker runtime imports here: the HTTP +
//! Hyperdrive wiring lives in the Worker entry (follow-up once staging
//! secrets are provisioned). This crate holds the security-critical logic
//! with unit + integration tests.

pub mod auth;
pub mod b64;
pub mod session;
pub mod vault;
