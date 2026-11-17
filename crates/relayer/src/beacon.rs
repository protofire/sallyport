use crate::material::UpdateMaterial;
use anyhow::{anyhow, Context, Result};
use beacon_api_module::{BeaconApi, HealthBook, LcRequest, Plan};
use serde_json::{json, Value};
use std::time::Duration;

pub const SLOTS_PER_PERIOD: u64 = 32 * 256;

pub fn period_of(slot: u64) -> u64 {
    slot / SLOTS_PER_PERIOD
}

/// LC material via logos-evm-beacon-api-module (failover across providers, fail-closed).
pub struct Beacon {
    plan: Plan,
    health: HealthBook,
}

impl Beacon {
    /// Empty `endpoints` uses the module's built-in defaults for the chain.
    pub fn new(chain_id: u64, endpoints: &[String]) -> Result<Self> {
        let mut api = BeaconApi::new();
        if endpoints.is_empty() {
            api.init_defaults();
        } else {
            let providers: Vec<Value> =
                endpoints.iter().map(|e| json!({ "endpoint": e })).collect();
            api.set_chain_config(chain_id, &json!({ "providers": providers }))
                .map_err(|e| anyhow!(e))?;
        }
        let plan = api
            .plan(chain_id)
            .map_err(|e| anyhow!(e.to_json().to_string()))?;
        Ok(Self {
            plan,
            health: HealthBook::default(),
        })
    }

    fn lc(&self, req: LcRequest) -> Result<Value> {
        let f = self
            .plan
            .fetch(&self.health, &req, None, Duration::from_secs(60))
            .map_err(|e| anyhow!(e.to_json().to_string()))?;
        serde_json::from_str(&f.body).context("beacon body not JSON")
    }

    pub fn finality_update(&self) -> Result<Value> {
        self.lc(LcRequest::Finality)
    }

    pub fn finalized_slot(fin: &Value) -> Result<u64> {
        fin["data"]["finalized_header"]["beacon"]["slot"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow!("finality_update has no finalized slot"))
    }

    pub fn updates(&self, start_period: u64, count: u64) -> Result<Vec<Value>> {
        match self.lc(LcRequest::Updates {
            start_period,
            count,
        })? {
            Value::Array(a) => Ok(a),
            other => Err(anyhow!(
                "updates not an array: {}",
                other.to_string().chars().take(120).collect::<String>()
            )),
        }
    }

    pub fn bootstrap(&self, block_root: &str) -> Result<Value> {
        self.lc(LcRequest::Bootstrap {
            block_root: block_root.into(),
        })
    }

    /// `bootstrap_root = "finalized"`: the finality update's finalized header root (fresh checkpoint).
    pub fn fetch_update(
        &self,
        period: u64,
        bootstrap_root: Option<&str>,
    ) -> Result<UpdateMaterial> {
        let updates = self.updates(period, 1)?;
        if updates.is_empty() {
            return Err(anyhow!("no update for period {period}"));
        }
        let finality_update = self.finality_update()?;
        let root = match bootstrap_root {
            Some("finalized") => Some(finalized_root(&finality_update)?),
            r => r.map(String::from),
        };
        Ok(UpdateMaterial {
            bootstrap: root.as_deref().map(|r| self.bootstrap(r)).transpose()?,
            bootstrap_root: root,
            updates,
            finality_update,
        })
    }
}

/// hash_tree_root of the finalized beacon header in a finality update, as 0x-hex.
pub fn finalized_root(fin: &Value) -> Result<String> {
    let u = lc_core::json::update_from_value(fin).map_err(|e| anyhow!("finality update: {e:?}"))?;
    let (h, _) = u
        .finalized_header
        .ok_or_else(|| anyhow!("no finalized header"))?;
    Ok(format!(
        "0x{}",
        lc_core::hash_tree_root_header(&h.beacon)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}
