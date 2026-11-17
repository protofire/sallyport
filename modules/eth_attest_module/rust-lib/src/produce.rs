//! Build attestation material (the same shape `verify::dry_run` and the LEZ program consume) from
//! live sources: beacon light-client data (in the module: via `beacon_api_module`) and EL JSON-RPC.
//! Sources are a trait so the logic is tested offline against fixtures/sepolia.

use crate::verify::{hx, predicate};
use lc_core::ChainConfig;
use serde_json::{json, Value};

pub trait Sources {
    /// One light-client request by beacon_api_module endpoint name; returns the parsed response body.
    fn lc(&self, endpoint: &str, params: Value) -> Result<Value, String>;
    /// One EL JSON-RPC call; returns `result`.
    fn el(&self, method: &str, params: Value) -> Result<Value, String>;
}

pub struct Request {
    pub chain_id: u64,
    /// Empty = the latest finalized EL block. Otherwise must equal it (see `produce`).
    pub block_hash: String,
    pub address: String,
    /// Empty = no storage slot.
    pub slot: String,
    /// Both >= 0 selects a receipt log (`log_index` = index inside that receipt's logs).
    pub tx_index: i64,
    pub log_index: i64,
    pub predicate: Value,
    /// Trusted beacon block root the light client bootstraps from (weak-subjectivity checkpoint).
    pub checkpoint_root: String,
}

const SLOTS_PER_PERIOD: u64 = 32 * 256;

fn err(code: impl Into<Value>, why: impl Into<String>) -> Value {
    json!({ "ok": false, "errorCode": code.into(), "error": why.into() })
}
fn data(v: &Value) -> &Value {
    v.get("data").unwrap_or(v)
}
fn slot_of(header: &Value) -> Option<u64> {
    header["beacon"]["slot"].as_str()?.parse().ok()
}
fn exec_hash(header: &Value) -> Option<&str> {
    // Gloas carries the hash directly; Electra/Fulu inside the payload header.
    header["execution_block_hash"].as_str().or_else(|| header["execution"]["block_hash"].as_str())
}

pub fn chain_config(chain_id: u64) -> Option<ChainConfig> {
    match chain_id {
        1 => Some(ChainConfig::mainnet()),
        11_155_111 => Some(ChainConfig::sepolia()),
        _ => None,
    }
}

/// `{ ok: true, material, dryRun }` or `{ ok: false, errorCode, error }`. `errorCode` is a U5 number
/// when the inputs fail verification, or `"fetch_failed"` / `"bad_request"` for transport/usage errors.
pub fn produce(src: &impl Sources, r: &Request) -> Value {
    // inclusion::host helpers panic on malformed RPC data; never let that cross the C ABI.
    let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| build(src, r)))
        .unwrap_or_else(|_| Err(err("fetch_failed", "malformed EL/beacon response (host helper panicked)")));
    match built {
        Ok(material) => {
            let verdict = crate::verify::dry_run_json(&material.to_string());
            json!({ "ok": verdict["ok"], "material": material, "dryRun": verdict })
        }
        Err(e) => e,
    }
}

fn build(src: &impl Sources, r: &Request) -> Result<Value, Value> {
    let fetch = |e: String| err("fetch_failed", e);
    let Some(cfg) = chain_config(r.chain_id) else {
        return Err(err(1002, format!("unsupported chain {}", r.chain_id)));
    };
    if r.checkpoint_root.is_empty() {
        return Err(err("bad_request", "no checkpointRoot configured for this chain: call set_chain_config first"));
    }
    predicate(&r.predicate).map_err(|(c, w)| err(c, w))?; // validate early; material carries the JSON

    // --- consensus side: bootstrap at the checkpoint, then forward to the latest finality.
    let boot = src.lc("getLightClientBootstrap", json!({ "block_root": r.checkpoint_root })).map_err(fetch)?;
    let boot = data(&boot).clone();
    let fin = src.lc("getLightClientFinalityUpdate", json!({})).map_err(fetch)?;
    let fin = data(&fin).clone();
    let bad = |w: &str| err("fetch_failed", format!("malformed beacon response: {w}"));
    let mut tracked = slot_of(&boot["header"]).ok_or_else(|| bad("bootstrap header slot"))?;
    let now: u64 = fin["signature_slot"].as_str().and_then(|s| s.parse().ok()).ok_or_else(|| bad("signature_slot"))?;
    let mut header = boot["header"].clone();
    let mut updates = vec![];
    let (p0, p1) = (tracked / SLOTS_PER_PERIOD, now / SLOTS_PER_PERIOD);
    if p1 > p0 {
        let us = src
            .lc("getLightClientUpdatesByRange", json!({ "start_period": p0, "count": p1 - p0 }))
            .map_err(fetch)?;
        // Mirror lc-core's acceptance (prepare_update/apply_update): an update is kept if it advances
        // finality, or if it supplies the still-unknown next committee within the store's period.
        let mut next_known = false; // a bootstrap carries only the current committee
        let period = |slot: u64| slot / SLOTS_PER_PERIOD;
        for u in us.as_array().ok_or_else(|| bad("updates not an array"))? {
            let u = data(u);
            let (Some(fin_slot), Some(att_slot)) = (slot_of(&u["finalized_header"]), slot_of(&u["attested_header"])) else {
                continue;
            };
            let has_next = !u["next_sync_committee"].is_null();
            let advances = fin_slot > tracked;
            let learns = !next_known
                && has_next
                && period(fin_slot) == period(att_slot)
                && period(att_slot) == period(tracked);
            if !(advances || learns) {
                continue;
            }
            let rotate = next_known && period(fin_slot) == period(tracked) + 1;
            if rotate || !next_known {
                next_known = has_next;
            }
            if advances {
                tracked = fin_slot;
                header = u["finalized_header"].clone();
            }
            updates.push(u.clone());
        }
    }
    // A finality update carries no next committee, so lc-core accepts it only if it advances
    // finality (else 1106): include it only if newer.
    if slot_of(&fin["finalized_header"]).is_some_and(|s| s > tracked) {
        header = fin["finalized_header"].clone();
        updates.push(fin.clone());
    }
    let finalized_hash = exec_hash(&header).ok_or_else(|| bad("finalized execution block hash"))?.to_string();
    // shortcut: lc-core tracks only the latest finalized header (no historical-root accumulator),
    // so only that block can be attested; upgrade when the LEZ program keeps a header history.
    if !r.block_hash.is_empty() && !r.block_hash.eq_ignore_ascii_case(&finalized_hash) {
        return Err(err(
            1101,
            format!("block {} is not the latest finalized EL block ({finalized_hash}); only that block is attestable", r.block_hash),
        ));
    }

    // --- execution side, bound to that block.
    let block = src.el("eth_getBlockByHash", json!([finalized_hash, false])).map_err(fetch)?;
    if block.is_null() {
        return Err(err("fetch_failed", format!("EL has no block {finalized_hash}")));
    }
    let rlp = inclusion::host::header_rlp_from_rpc(&block);
    let (locator, proof) = if r.tx_index >= 0 && r.log_index >= 0 {
        // By number: verified_proxy_module's eth_getBlockReceipts takes a BlockTag, not a hash. The
        // receipts are bound to this header by the receipts-root check in the dry run / guest.
        let receipts = src.el("eth_getBlockReceipts", json!([block["number"]])).map_err(fetch)?;
        let bytes: Vec<Vec<u8>> = receipts
            .as_array()
            .ok_or_else(|| err("fetch_failed", "eth_getBlockReceipts: not an array"))?
            .iter()
            .map(inclusion::host::receipt_bytes_from_rpc)
            .collect();
        let tx = u32::try_from(r.tx_index).map_err(|_| err("bad_request", "tx_index > u32"))?;
        if tx as usize >= bytes.len() {
            return Err(err("bad_request", format!("tx_index {tx} >= {} receipts in block", bytes.len())));
        }
        let (_, nodes) = inclusion::host::receipt_proof(&bytes, tx);
        (
            json!({ "type": "log", "tx_index": tx, "log_index": r.log_index }),
            json!({ "receipt_proof": nodes.iter().map(|n| format!("0x{}", hex::encode(n))).collect::<Vec<_>>() }),
        )
    } else {
        let addr = hx(&json!(r.address)).ok().filter(|a| a.len() == 20).ok_or_else(|| err("bad_request", "address must be 20-byte hex"))?;
        let slot = if r.slot.is_empty() {
            None
        } else {
            let h = r.slot.trim_start_matches("0x");
            let s = hex::decode(if h.len() % 2 == 1 { format!("0{h}") } else { h.to_string() }).ok().filter(|s| s.len() <= 32).ok_or_else(|| err("bad_request", "slot must be <= 32-byte hex"))?;
            let mut p = [0u8; 32];
            p[32 - s.len()..].copy_from_slice(&s);
            Some(format!("0x{}", hex::encode(p)))
        };
        let gp = src
            .el("eth_getProof", json!([r.address, slot.iter().collect::<Vec<_>>(), { "blockHash": finalized_hash }]))
            .map_err(fetch)?;
        let storage: Vec<Value> = gp["storageProof"]
            .as_array()
            .map(|a| a.iter().map(|e| json!({ "key": slot.clone().unwrap_or_default(), "proof": e["proof"] })).collect())
            .unwrap_or_default();
        let addr = format!("0x{}", hex::encode(addr));
        let loc = match &slot {
            Some(s) => json!({ "type": "storage", "address": addr, "slot": s }),
            None => json!({ "type": "account", "address": addr }),
        };
        (loc, json!({ "account_proof": gp["accountProof"], "storage_proof": storage }))
    };

    Ok(json!({
        "config": {
            "chain_id": cfg.chain_id,
            "genesis_validators_root": format!("0x{}", hex::encode(cfg.genesis_validators_root)),
            "fork_versions": cfg.fork_versions.iter()
                .map(|(e, v)| json!({ "epoch": e, "version": format!("0x{}", hex::encode(v)) }))
                .collect::<Vec<_>>(),
            "gloas_fork_epoch": cfg.gloas_fork_epoch,
            "min_participation": cfg.min_participation,
            "ws_period_epochs": cfg.ws_period_epochs,
            "checkpoint_root": r.checkpoint_root,
            "current_slot": now,
        },
        "bootstrap": boot,
        "updates": updates,
        "attest": {
            "header": header,
            "el_header_rlp": format!("0x{}", hex::encode(rlp)),
            "locator": locator,
            "proof": proof,
            "predicate": r.predicate,
        },
    }))
}
