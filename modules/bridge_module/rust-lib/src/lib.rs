//! bridge_module — Logos core module for the RFP-022 prototype (U1, private-only).
//!
//! `core` is plain Rust over `bridge-core`, tested with `cargo test --no-default-features`; the
//! Logos glue is behind the default `logos_module` feature.

pub mod core;

#[cfg(feature = "logos_module")]
mod glue;
