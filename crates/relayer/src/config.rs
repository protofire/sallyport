use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub beacon_endpoints: Vec<String>,
    #[serde(default = "default_defer")]
    pub max_defer_secs: u64,
    pub state_file: PathBuf,
    /// Seeds the deferral jitter; required and distinct per operator (a shared default would give
    /// every operator the same deferral and so the same collisions).
    pub operator_key: String,
    #[serde(default = "default_poll")]
    pub poll_secs: u64,
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,
    /// Target LEZ instance (required by `run-relayer`); wallet comes from `LEE_WALLET_HOME_DIR`.
    pub lez: Option<LezConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LezConfig {
    /// Fee payer / signer account (base58, imported in the wallet).
    pub payer: String,
    pub attest_program: String,
    /// 32-byte hex of an existing instance: the id `program-e2e init` printed, i.e.
    /// `attest_program::instance_id(cfg, checkpoint root)` (Init rejects any other id).
    pub instance_id: String,
    /// Ceiling on any tx's `max_fee` (LEZ native units); default `lez_client::DEFAULT_MAX_FEE_CAP`.
    pub max_fee_cap: Option<u64>,
}
fn default_defer() -> u64 {
    600
}
fn default_poll() -> u64 {
    12
}
fn default_chain_id() -> u64 {
    11155111
}

impl Config {
    pub fn load(p: &Path) -> Result<Self> {
        toml::from_str(
            &std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?,
        )
        .context("parse config")
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn operator_key_is_required() {
        let base = "beacon_endpoints = [\"http://b\"]\nstate_file = \"s.json\"\n";
        assert!(toml::from_str::<Config>(base).is_err());
        let c: Config = toml::from_str(&format!("{base}operator_key = \"op-1\"\n")).unwrap();
        assert_eq!(c.operator_key, "op-1");
    }
}
