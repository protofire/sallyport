//! eth_attest_module — Logos core module for RFP-021 (U1/U3).
//!
//! `verify` (host dry run of lc-core + inclusion) and `produce` (material builder) are plain Rust,
//! tested with `cargo test --no-default-features`; the Logos glue (`glue.rs`, generated scaffold,
//! beacon_api_module client, EL HTTP) is behind the default `logos_module` feature.

pub mod produce;
pub mod verify;

#[cfg(test)]
mod tests;

#[cfg(feature = "logos_module")]
mod glue;
