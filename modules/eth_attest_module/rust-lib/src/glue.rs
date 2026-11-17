//! Logos module glue for `eth_attest_module` (rust-first authoring).
//!
//! The builder derives the `.lidl` from the `EthAttestModule` trait below and generates the scaffold
//! (`install`, `modules()` with the typed `beacon_api_module`, `eth_rpc_module` and
//! `verified_proxy_module` clients). EL routing per call: `inclusion::host::el_route`. Structured values cross as JSON
//! strings: `{ "ok": true, ... }` / `{ "ok": false, "errorCode", "error" }`. `errorCode` is the U5
//! number (docs/CONSUMER-GUIDE.md) for verification failures, or a string for usage/transport errors.

use std::collections::HashMap;
use std::time::Duration;

use serde_json::{json, Value};

use crate::produce::{produce, Request, Sources};

pub trait EthAttestModule: Send + 'static {
    /// RFP U1 produceAttestation. Builds verifier material for one fact in the latest finalized EL
    /// block (`block_hash` empty = that block; any other hash is refused with 1101) and dry-runs it.
    /// Locator: `slot` non-empty = storage slot of `address`; `tx_index`/`log_index` >= 0 = receipt
    /// log (log index within the receipt); else the account itself. `predicate_json`:
    /// `{ "field": "balance|nonce|storage_root|code_hash|slot|log.address|log.topicN|log.dataN|log.status",
    ///    "op": "eq|ne|lt|le|gt|ge", "value": "0x.." }`.
    /// `{ ok, material, dryRun }`; `material` is what `verify_attestation_dry_run` / the LEZ program take.
    fn produce_attestation(&mut self, chain_id: i64, block_hash: String, address: String, slot: String,
                           tx_index: i64, log_index: i64, predicate_json: String) -> String;
    /// RFP U1 verifyAttestationDryRun. Runs lc-core (host BLS) + inclusion over `material` exactly as
    /// the program would: `{ ok, errorCode, stage?, error?, statementId?, blockNumber?, ... }`.
    fn verify_attestation_dry_run(&mut self, material: String) -> String;
    /// RFP U1 submitUpdate. Advances instance `instance_id` by one light-client update: lc-core
    /// pre-check, then one atomic Update for K <= lez_client::ONE_TX_MAX_NON_SIGNERS (any update
    /// kind), else UpdateBegin + UpdateVerify (residue witness), signed with the operator key
    /// (`operatorKeyFile` in set_chain_config) and sent to `lezRpc` (shared `lez_client::LezClient`).
    /// `material` = a Beacon-API update JSON (envelope or `data`); empty or `{}` = fetch the latest
    /// finality update through beacon_api_module. `{ ok, txs, finalizedSlot, executionBlockHash,
    /// period, nextKnown, headers }`; errors `lez_config` / `bad_request` / `lez_submit`.
    fn submit_update(&mut self, instance_id: String, material: String) -> String;
    /// RFP U1 readInstance. Reads the instance account from the LEZ sequencer (`getAccountView`,
    /// shared `lez_client::read_instance`):
    /// `{ ok, period, finalizedSlot, executionBlockHash, nextKnown, headers, headerRoot }`.
    fn read_instance(&mut self, instance_id: String) -> String;
    /// Per-chain settings: `{ "checkpointRoot": "0x..", "elRpc": "https://..",
    /// "lezRpc": "http://host:3040", "attestProgram": "<base58>", "operatorKeyFile": "/path" }`
    /// (omitted keys kept). The key file (32-byte hex, mode 0600) is read at each submit, never echoed.
    fn set_chain_config(&mut self, chain_id: i64, config_json: String) -> String;

    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

const SEPOLIA: u64 = 11_155_111;
/// Same default as crates/relayer (DECISIONS.md D-MOD-2: eth_rpc_module sends no User-Agent, which 0xrpc.io requires).
const SEPOLIA_EL: &str = "https://sepolia.gateway.tenderly.co";
const LC_TIMEOUT: Duration = Duration::from_secs(120);
const EL_TIMEOUT: Duration = Duration::from_secs(60);
/// The proxy's own budget is queueTimeoutMs + callTimeoutMs (30 s + 30 s by default).
const VP_TIMEOUT: Duration = Duration::from_secs(65);

#[derive(Default, Clone)]
struct ChainSettings {
    checkpoint_root: String,
    el_rpc: String,
    lez_rpc: String,
    attest_program: String,
    operator_key_file: String,
}

// shortcut: settings are in-memory only (lost on module restart); persist under
// ctx.instance_persistence_path when the daemon flow needs it.
#[derive(Default)]
struct EthAttest {
    chains: HashMap<u64, ChainSettings>,
}

fn err(code: &str, e: impl std::fmt::Display) -> String {
    json!({ "ok": false, "errorCode": code, "error": e.to_string() }).to_string()
}

fn hex(b: &[u8]) -> String {
    format!("0x{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>())
}

struct Live<'a> {
    chain_id: i64,
    el_rpc: &'a str,
}

impl Sources for Live<'_> {
    fn lc(&self, endpoint: &str, params: Value) -> Result<Value, String> {
        let beacon = modules().beacon_api_module;
        // Seeds the built-in providers where absent; idempotent, safe for any consumer to call.
        beacon.init_defaults().map_err(|e| format!("beacon_api_module.init_defaults: {e}"))?;
        let raw = beacon
            .lc_request_with_timeout(self.chain_id, endpoint, &params.to_string(), "", 0, LC_TIMEOUT)
            .map_err(|e| format!("beacon_api_module.lc_request({endpoint}): {e}"))?;
        let r: Value = serde_json::from_str(&raw).map_err(|e| format!("beacon_api_module reply not JSON: {e}"))?;
        if r["ok"] != json!(true) {
            return Err(format!("beacon_api_module.lc_request({endpoint}) failed: {r}"));
        }
        let body = r["body"].as_str().ok_or("beacon_api_module reply has no body")?;
        serde_json::from_str(body).map_err(|e| format!("{endpoint} body not JSON: {e}"))
    }

    fn el(&self, method: &str, params: Value) -> Result<Value, String> {
        if inclusion::host::el_route(method) == inclusion::host::ElRoute::Verified {
            let r = modules()
                .verified_proxy_module
                .rpc_with_timeout(method, params.as_array().map(Vec::as_slice).unwrap_or_default(), VP_TIMEOUT)
                .map_err(|e| format!("verified_proxy_module.rpc({method}): {e}"))?;
            // `rpc` is declared `-> result`: a {success, value, error} envelope. No raw fallback.
            return match r.get("value") {
                Some(v) if r.get("success") == Some(&json!(true)) => Ok(v.clone()),
                _ => Err(format!("verified_proxy_module.rpc({method}) failed: {}", r.get("error").unwrap_or(&Value::Null))),
            };
        }
        let raw = modules()
            .eth_rpc_module
            .raw_rpc_with_timeout(self.chain_id, method, &params.to_string(), EL_TIMEOUT)
            .map_err(|e| format!("eth_rpc_module.raw_rpc({method}): {e}"))?;
        let r: Value = serde_json::from_str(&raw).map_err(|e| format!("eth_rpc_module reply not JSON: {e}"))?;
        match r.get("result") {
            Some(v) if r["ok"] == json!(true) => Ok(v.clone()),
            _ => Err(format!("eth_rpc_module.raw_rpc({method}) failed: {r}")),
        }
    }
}

impl Live<'_> {
    /// The verified leg serves one network and is configured by its owner (trusted block root,
    /// execution URLs; shared by every app on the device), so this only checks it is ours.
    fn check_verified(&self) -> Result<(), String> {
        let want = match self.chain_id {
            1 => "mainnet",
            11_155_111 => "sepolia",
            _ => return Ok(()), // produce refuses the chain itself (1002)
        };
        let cfg = modules().verified_proxy_module.get_config().map_err(|e| format!("verified_proxy_module.getConfig: {e}"))?;
        // `{tstr: any}` comes back as a map: index with get, never [] (panics on a missing key).
        match cfg.get("network").and_then(|v| v.as_str()) {
            Some(n) if n == want => Ok(()),
            Some(n) => Err(format!("verified_proxy_module serves {n}, not {want}")),
            None => Err("verified_proxy_module is not configured: configure({network, trustedBlockRoot, executionApiUrls}) and start() it".into()),
        }
    }

    /// Points eth_rpc_module's chain record at our EL endpoint. An operator-set `elRpc` overrides
    /// the record; otherwise it is only seeded where absent, so a shared record is not retuned.
    fn prepare(&self, explicit: bool) -> Result<(), String> {
        let rpc = modules().eth_rpc_module;
        let cfg = json!({ "endpoint": self.el_rpc }).to_string();
        let r = if explicit { rpc.set_chain_config(self.chain_id, &cfg).map(|b| b.to_string()) } else { rpc.ensure_chain_config(self.chain_id, &cfg) };
        r.map(|_| ()).map_err(|e| format!("eth_rpc_module config: {e}"))
    }
}

impl EthAttestModule for EthAttest {
    fn produce_attestation(&mut self, chain_id: i64, block_hash: String, address: String, slot: String,
                           tx_index: i64, log_index: i64, predicate_json: String) -> String {
        let Ok(id) = u64::try_from(chain_id) else {
            return json!({ "ok": false, "errorCode": "bad_request", "error": "chain id must be positive" }).to_string();
        };
        let predicate = match serde_json::from_str(&predicate_json) {
            Ok(p) => p,
            Err(e) => return json!({ "ok": false, "errorCode": 1001, "error": format!("predicate_json: {e}") }).to_string(),
        };
        let s = self.chains.get(&id).cloned().unwrap_or_default();
        let explicit = !s.el_rpc.is_empty();
        let el_rpc = if !explicit && id == SEPOLIA { SEPOLIA_EL.to_string() } else { s.el_rpc };
        let req = Request { chain_id: id, block_hash, address, slot, tx_index, log_index, predicate, checkpoint_root: s.checkpoint_root };
        let live = Live { chain_id, el_rpc: &el_rpc };
        if !el_rpc.is_empty() {
            if let Err(e) = live.prepare(explicit) {
                return json!({ "ok": false, "errorCode": "el_config", "error": e }).to_string();
            }
        }
        if let Err(e) = live.check_verified() {
            return json!({ "ok": false, "errorCode": "el_config", "error": e }).to_string();
        }
        produce(&live, &req).to_string()
    }

    fn verify_attestation_dry_run(&mut self, material: String) -> String {
        crate::verify::dry_run_json(&material).to_string()
    }

    fn submit_update(&mut self, instance_id: String, material: String) -> String {
        let (s, id) = match lez_target(&self.chains, &instance_id) {
            Ok(t) => t,
            Err(e) => return e,
        };
        if s.operator_key_file.is_empty() {
            return err("lez_config", "set_chain_config(11155111, {operatorKeyFile}) first");
        }
        let raw = match material.trim() {
            "" | "{}" => match (Live { chain_id: SEPOLIA as i64, el_rpc: "" }).lc("getLightClientFinalityUpdate", json!({})) {
                Ok(v) => v,
                Err(e) => return err("lez_submit", e),
            },
            m => match serde_json::from_str(m) {
                Ok(v) => v,
                Err(e) => return err("bad_request", format!("material: {e}")),
            },
        };
        let r = lez_client::LezClient::from_key_file(&s.lez_rpc, std::path::Path::new(&s.operator_key_file), &s.attest_program, id)
            .and_then(|c| Ok((c.submit_update_json(&raw)?, c.instance()?)));
        match r {
            Ok((txs, st)) => {
                let mut v = instance_json(&instance_id, &st);
                v["txs"] = json!(txs);
                v.to_string()
            }
            Err(e) => err("lez_submit", format!("{e:#}")),
        }
    }

    fn read_instance(&mut self, instance_id: String) -> String {
        let (s, id) = match lez_target(&self.chains, &instance_id) {
            Ok(t) => t,
            Err(e) => return e,
        };
        match lez_client::account_id(&s.attest_program).and_then(|a| lez_client::read_instance(&s.lez_rpc, a, &id)) {
            Ok(st) => instance_json(&instance_id, &st).to_string(),
            Err(e) => err("lez_read", format!("{e:#}")),
        }
    }

    fn set_chain_config(&mut self, chain_id: i64, config_json: String) -> String {
        let Ok(id) = u64::try_from(chain_id) else {
            return json!({ "ok": false, "errorCode": "bad_request", "error": "chain id must be positive" }).to_string();
        };
        let patch: Value = match serde_json::from_str(&config_json) {
            Ok(v) => v,
            Err(e) => return json!({ "ok": false, "errorCode": "bad_request", "error": e.to_string() }).to_string(),
        };
        let s = self.chains.entry(id).or_default();
        if let Some(r) = patch["checkpointRoot"].as_str() {
            if crate::verify::hx(&json!(r)).map(|b| b.len()) != Ok(32) {
                return json!({ "ok": false, "errorCode": "bad_request", "error": "checkpointRoot must be 32-byte hex" }).to_string();
            }
            s.checkpoint_root = r.to_string();
        }
        if let Some(u) = patch["elRpc"].as_str() {
            s.el_rpc = u.to_string();
        }
        for (k, f) in [("lezRpc", &mut s.lez_rpc), ("attestProgram", &mut s.attest_program),
                       ("operatorKeyFile", &mut s.operator_key_file)] {
            if let Some(v) = patch[k].as_str() {
                *f = v.to_string();
            }
        }
        json!({ "ok": true, "chainId": id, "checkpointRoot": s.checkpoint_root, "elRpc": s.el_rpc,
                "lezRpc": s.lez_rpc, "attestProgram": s.attest_program, "operatorKeyFile": s.operator_key_file }).to_string()
    }
}

/// Sepolia LEZ settings + parsed instance id (the program serves Sepolia only for now).
fn lez_target(chains: &HashMap<u64, ChainSettings>, instance_id: &str) -> Result<(ChainSettings, [u8; 32]), String> {
    let s = chains.get(&SEPOLIA).cloned().unwrap_or_default();
    if s.lez_rpc.is_empty() || s.attest_program.is_empty() {
        return Err(err("lez_config", "set_chain_config(11155111, {lezRpc, attestProgram}) first"));
    }
    let id = crate::verify::hx(&json!(instance_id)).ok().and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| err("bad_request", "instance_id must be 32-byte hex"))?;
    Ok((s, id))
}

fn instance_json(instance_id: &str, st: &lez_client::InstanceState) -> Value {
    let f = &st.store.finalized_header;
    json!({
        "ok": true,
        "instanceId": instance_id,
        "chainId": st.cfg.chain.chain_id,
        "period": st.store.period(),
        "finalizedSlot": f.beacon.slot,
        "executionBlockHash": hex(&f.execution_block_hash),
        "nextKnown": st.store.next_sync_committee.is_some(),
        "headers": st.headers.leaves,
        "headerRoot": hex(&st.headers.root()),
    })
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<EthAttest>();
}
