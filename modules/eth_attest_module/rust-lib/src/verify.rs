//! Host-side dry run of the full verification pipeline: config -> bootstrap -> updates -> attest,
//! using lc-core (host BLS via blst) and inclusion. Same typed error codes as the on-chain program
//! (docs/CONSUMER-GUIDE.md). Material = the `input` object of a fixtures/adversarial vector.
//!
//! Ported from crates/vector-runner/tests/vectors.rs, with every panic turned into 1001 Malformed:
//! material is caller-supplied, so nothing here may unwrap on it.

use inclusion as inc;
use lc_core::host_bls::BlstVerifier;
use lc_core::json::{bootstrap_from_value, update_from_value};
use lc_core::{apply_update, bootstrap, hash_tree_root_header, verify_update, ChainConfig, ErrorCode, Store};
use serde_json::{json, Value};

/// (error code, human reason)
pub type Fail = (u16, String);
type R<T> = Result<T, Fail>;

fn m(why: impl Into<String>) -> Fail {
    (ErrorCode::Malformed as u16, why.into())
}
fn c(e: ErrorCode) -> Fail {
    (e as u16, format!("{e:?}"))
}
fn ic(e: inc::ErrorCode) -> Fail {
    (e as u16, format!("{e:?}"))
}

pub(crate) fn hx(v: &Value) -> R<Vec<u8>> {
    let s = v.as_str().ok_or_else(|| m(format!("expected hex string, got {v}")))?;
    hex::decode(s.trim_start_matches("0x")).map_err(|e| m(format!("bad hex {s}: {e}")))
}
fn arr<const N: usize>(v: &Value) -> R<[u8; N]> {
    hx(v)?.try_into().map_err(|_| m(format!("expected {N} bytes: {v}")))
}
fn num(v: &Value) -> R<u64> {
    v.as_u64().ok_or_else(|| m(format!("expected unsigned int, got {v}")))
}
fn pad32(b: &[u8]) -> R<[u8; 32]> {
    if b.len() > 32 {
        return Err(m("value longer than 32 bytes"));
    }
    let mut o = [0u8; 32];
    o[32 - b.len()..].copy_from_slice(b);
    Ok(o)
}

// ---- minimal RLP, only to read leaf values out of proof node lists (the proofs themselves are
// verified by inclusion; this just extracts the claimed value to verify against).
fn rlp_item(b: &[u8]) -> Option<(bool, &[u8], &[u8])> {
    let t = *b.first()?;
    let (list, hdr, len) = match t {
        0..=0x7f => return Some((false, &b[..1], &b[1..])),
        0x80..=0xb7 => (false, 1, (t - 0x80) as usize),
        0xb8..=0xbf | 0xf8..=0xff => {
            let n = (t - if t >= 0xf8 { 0xf7 } else { 0xb7 }) as usize;
            if n > 8 {
                return None;
            }
            let l = b.get(1..1 + n)?.iter().fold(0usize, |a, x| (a << 8) | *x as usize);
            (t >= 0xf8, 1 + n, l)
        }
        _ => (true, 1, (t - 0xc0) as usize),
    };
    let end = hdr.checked_add(len)?;
    Some((list, b.get(hdr..end)?, b.get(end..)?))
}
fn rlp_list(b: &[u8]) -> Option<Vec<(bool, &[u8])>> {
    let (l, mut p, rest) = rlp_item(b)?;
    if !l || !rest.is_empty() {
        return None;
    }
    let mut out = vec![];
    while !p.is_empty() {
        let (l, x, r) = rlp_item(p)?;
        out.push((l, x));
        p = r;
    }
    Some(out)
}
/// Value payload of the last proof node, if it is a 2-item (leaf/extension) node.
fn leaf_value(proof: &[Vec<u8>]) -> Option<Vec<u8>> {
    let it = rlp_list(proof.last()?)?;
    (it.len() == 2 && !it[1].0).then(|| it[1].1.to_vec())
}
/// Value of storage `slot` under `storage_root`, proven by `proof`.
pub(crate) fn storage_value(storage_root: &[u8; 32], slot: &[u8; 32], proof: &[Vec<u8>]) -> R<[u8; 32]> {
    // The last node's value is the slot's only if that leaf holds the slot's key; an exclusion
    // proof may end in another key's leaf (or an extension), and then the slot reads as zero.
    // verify_storage decides which: it checks the key path.
    let val = leaf_value(proof)
        .and_then(|v| rlp_item(&v).map(|(_, p, _)| p.to_vec()))
        .filter(|b| b.len() <= 32)
        .map(|b| pad32(&b))
        .transpose()
        .ok()
        .flatten()
        .filter(|v| inc::verify_storage(storage_root, slot, v, proof).is_ok())
        .unwrap_or([0; 32]);
    inc::verify_storage(storage_root, slot, &val, proof).map_err(ic)?;
    Ok(val)
}
fn proof_list(v: Option<&Value>) -> R<Vec<Vec<u8>>> {
    match v {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(a)) => a.iter().map(hx).collect(),
        Some(o) => Err(m(format!("proof must be an array, got {o}"))),
    }
}

/// Base config by chain id (supplies `electra_fork_epoch`, which vectors don't carry), overridden by
/// the material's config. Returns (cfg, checkpoint_root, current_slot).
fn config(v: &Value) -> R<(ChainConfig, [u8; 32], u64)> {
    let chain_id = num(&v["chain_id"])?;
    let mut cfg = if chain_id == 1 { ChainConfig::mainnet() } else { ChainConfig::sepolia() };
    cfg.chain_id = chain_id;
    cfg.genesis_validators_root = arr(&v["genesis_validators_root"])?;
    cfg.fork_versions = v["fork_versions"]
        .as_array()
        .ok_or_else(|| m("config.fork_versions must be an array"))?
        .iter()
        .map(|f| Ok((num(&f["epoch"])?, arr::<4>(&f["version"])?)))
        .collect::<R<_>>()?;
    cfg.gloas_fork_epoch = num(&v["gloas_fork_epoch"])?;
    cfg.min_participation = u16::try_from(num(&v["min_participation"])?).map_err(|_| m("min_participation > u16"))?;
    cfg.ws_period_epochs = num(&v["ws_period_epochs"])?;
    Ok((cfg, arr(&v["checkpoint_root"])?, num(&v["current_slot"])?))
}

/// Run the pipeline. Ok = the verified statement summary; Err = (code, reason) at the failing stage.
pub fn dry_run(material: &Value) -> Result<Value, (Fail, &'static str)> {
    // A whole vector file is accepted too (its `input` is the material).
    let inp = material.get("input").filter(|i| i.is_object()).unwrap_or(material);
    let st = |stage| move |f: Fail| (f, stage);
    let (cfg, ckpt, now) = config(&inp["config"]).map_err(st("config"))?;
    if inp["bootstrap"].is_null() {
        return Err((m("bootstrap missing (SSZ-only bootstrap is not supported: lc-core is JSON-only)"), "bootstrap"));
    }
    let boot = bootstrap_from_value(&inp["bootstrap"]).map_err(c).map_err(st("bootstrap"))?;
    let mut store = bootstrap(&cfg, &ckpt, &boot, now).map_err(c).map_err(st("bootstrap"))?;
    let updates = match &inp["updates"] {
        Value::Null => vec![],
        Value::Array(a) => a.clone(),
        _ => return Err((m("updates must be an array"), "update")),
    };
    for u in &updates {
        update_from_value(u)
            .and_then(|up| verify_update(&cfg, &store, &up, now, &BlstVerifier))
            .and_then(|ver| apply_update(&mut store, &ver))
            .map_err(c)
            .map_err(st("update"))?;
    }
    let fin = json!({
        "slot": store.finalized_header.beacon.slot,
        "executionBlockHash": format!("0x{}", hex::encode(store.finalized_header.execution_block_hash)),
        "updatesApplied": updates.len(),
    });
    if inp["attest"].is_null() {
        return Ok(json!({ "finalized": fin }));
    }
    let s = attest(&cfg, &store, &inp["attest"]).map_err(st("attest"))?;
    Ok(json!({
        "finalized": fin,
        "statementId": format!("0x{}", hex::encode(s.id)),
        "blockNumber": s.fact.block_number,
        "executionBlockHash": format!("0x{}", hex::encode(s.fact.execution_block_hash)),
        "chainId": s.fact.chain_id,
        "locator": format!("{:?}", s.fact.locator),
    }))
}

fn field_sel(f: &str) -> R<inc::FieldSel> {
    use inc::FieldSel as F;
    Ok(match f {
        "nonce" => F::Nonce,
        "balance" => F::Balance,
        "storage_root" => F::StorageRoot,
        "code_hash" => F::CodeHash,
        "slot" => F::Slot,
        "log.address" => F::LogAddress,
        "log.status" => F::LogStatus,
        "log.data" => F::LogDataWord(0),
        t => {
            let bad = || m(format!("unknown predicate field {t}"));
            if let Some(n) = t.strip_prefix("log.topic") {
                F::LogTopic(n.parse().map_err(|_| bad())?)
            } else if let Some(n) = t.strip_prefix("log.data") {
                F::LogDataWord(n.parse().map_err(|_| bad())?)
            } else {
                return Err(bad());
            }
        }
    })
}

pub(crate) fn predicate(pr: &Value) -> R<inc::Pred> {
    let field = field_sel(pr["field"].as_str().ok_or_else(|| m("predicate.field missing"))?)?;
    let value = hx(&pr["value"])?;
    Ok(match pr["op"].as_str().ok_or_else(|| m("predicate.op missing"))? {
        "eq" => inc::Pred::Eq { field, value },
        "ne" => inc::Pred::Ne { field, value },
        "lt" => inc::Pred::Lt { field, value },
        "le" => inc::Pred::Le { field, value },
        "gt" => inc::Pred::Gt { field, value },
        "ge" => inc::Pred::Ge { field, value },
        o => return Err(m(format!("unknown predicate op {o}"))),
    })
}

fn attest(cfg: &ChainConfig, store: &Store, a: &Value) -> R<inc::Statement> {
    // header parsing reuses the bootstrap parser via a dummy envelope
    let env = json!({"header": a["header"], "current_sync_committee": {"pubkeys": [], "aggregate_pubkey": format!("0x{}", "00".repeat(48))}, "current_sync_committee_branch": []});
    let hdr = bootstrap_from_value(&env).map_err(c)?.header;
    if hash_tree_root_header(&hdr.beacon) != hash_tree_root_header(&store.finalized_header.beacon) {
        return Err(c(ErrorCode::HeaderNotFinalised));
    }
    let fin = hdr.to_finalized(cfg).map_err(c)?;
    if fin.execution_block_hash != store.finalized_header.execution_block_hash {
        return Err(c(ErrorCode::ExecutionHeaderMismatch));
    }
    let eh = inc::verify_exec_header(&hx(&a["el_header_rlp"])?, fin.execution_block_hash).map_err(ic)?;
    let bad = || ic(inc::ErrorCode::InclusionInvalid);

    let p = &a["proof"];
    let loc = &a["locator"];
    let account_of = |addr: &[u8; 20]| -> R<inc::Account> {
        let proof = proof_list(p.get("account_proof"))?;
        let val = leaf_value(&proof).ok_or_else(bad)?;
        let it = rlp_list(&val).ok_or_else(bad)?;
        if it.len() != 4 || it[0].1.len() > 8 || it[1].1.len() > 32 {
            return Err(bad());
        }
        let acc = inc::Account {
            nonce: it[0].1.iter().fold(0u64, |a, b| (a << 8) | *b as u64),
            balance: pad32(it[1].1)?,
            storage_root: it[2].1.try_into().map_err(|_| bad())?,
            code_hash: it[3].1.try_into().map_err(|_| bad())?,
        };
        inc::verify_account(&eh.state_root, addr, &acc, &proof).map_err(ic)?;
        Ok(acc)
    };
    let (locator, value) = match loc["type"].as_str().unwrap_or("") {
        "account" => {
            let addr = arr::<20>(&loc["address"])?;
            (inc::Locator::Account { address: addr }, inc::FactValue::Account(account_of(&addr)?))
        }
        "storage" => {
            let addr = arr::<20>(&loc["address"])?;
            let slot = arr::<32>(&loc["slot"])?;
            let acc = account_of(&addr)?;
            let mut sp = None;
            for e in p["storage_proof"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
                if pad32(&hx(&e["key"])?)? == slot {
                    sp = Some(e);
                    break;
                }
            }
            let sp = sp.ok_or_else(bad)?;
            let proof = proof_list(sp.get("proof"))?;
            let val = storage_value(&acc.storage_root, &slot, &proof)?;
            (inc::Locator::Storage { address: addr, slot }, inc::FactValue::Slot(val))
        }
        "log" => {
            let idx = |k: &str| u32::try_from(num(&loc[k])?).map_err(|_| m(format!("{k} > u32")));
            let (t, l) = (idx("tx_index")?, idx("log_index")?);
            let proof = proof_list(p.get("receipt_proof"))?;
            let receipt = leaf_value(&proof).ok_or_else(bad)?;
            let lv = inc::verify_receipt_log(&eh.receipts_root, t, l, &receipt, &proof).map_err(ic)?;
            (inc::Locator::Log { tx_index: t, log_index: l }, inc::FactValue::Log(lv))
        }
        o => return Err(m(format!("unknown locator type {o:?}"))),
    };
    let fact = inc::Fact {
        chain_id: cfg.chain_id,
        genesis_validators_root: cfg.genesis_validators_root,
        execution_block_hash: fin.execution_block_hash,
        block_number: eh.number,
        locator,
        value,
    };
    let st = inc::attest(fact, vec![predicate(&a["predicate"])?]).map_err(ic)?;
    if let Some(ef) = a["expected_fact"].as_object() {
        check_expected(&st, ef)?;
    }
    Ok(st)
}

/// Optional caller claim about the resulting fact: any difference is 1002 (chain) or 1204.
fn check_expected(st: &inc::Statement, ef: &serde_json::Map<String, Value>) -> R<()> {
    let f = &st.fact;
    if ef.get("chain_id").and_then(Value::as_u64) != Some(f.chain_id)
        || arr::<32>(&ef["genesis_validators_root"])? != f.genesis_validators_root
    {
        return Err(c(ErrorCode::ChainMismatch));
    }
    let ev = &ef["value"];
    let val_ok = match (&f.value, ev["type"].as_str().unwrap_or("")) {
        (inc::FactValue::Account(x), "account") => {
            ev["nonce"].as_u64() == Some(x.nonce)
                && arr::<32>(&ev["balance"])? == x.balance
                && arr::<32>(&ev["storage_root"])? == x.storage_root
                && arr::<32>(&ev["code_hash"])? == x.code_hash
        }
        (inc::FactValue::Slot(x), "slot") => arr::<32>(&ev["value"])? == *x,
        (inc::FactValue::Log(x), "log") => {
            let topics = ev["topics"].as_array().ok_or_else(|| m("expected_fact topics"))?;
            arr::<20>(&ev["address"])? == x.address
                && hx(&ev["data"])? == x.data
                && ev["status"].as_u64() == Some(x.status as u64)
                && topics.iter().map(arr::<32>).collect::<R<Vec<_>>>()? == x.topics
        }
        _ => false,
    };
    if arr::<32>(&ef["execution_block_hash"])? != f.execution_block_hash
        || ef.get("block_number").and_then(Value::as_u64) != Some(f.block_number)
        || !val_ok
        || arr::<32>(&ef["statement_id"])? != st.id
    {
        return Err(c(ErrorCode::StatementMismatch));
    }
    Ok(())
}

/// The module's response shape: `{ ok, errorCode, ... }` (errorCode 0 on success).
pub fn dry_run_json(material: &str) -> Value {
    let v: Value = match serde_json::from_str(material) {
        Ok(v) => v,
        Err(e) => return json!({ "ok": false, "errorCode": 1001, "stage": "parse", "error": format!("material is not JSON: {e}") }),
    };
    // Defence in depth: a panic inside lc-core/inclusion on hostile input must not cross the C ABI.
    match std::panic::catch_unwind(|| dry_run(&v)) {
        Ok(Ok(mut s)) => {
            s["ok"] = json!(true);
            s["errorCode"] = json!(0);
            s
        }
        Ok(Err(((code, why), stage))) => json!({ "ok": false, "errorCode": code, "stage": stage, "error": why }),
        Err(_) => json!({ "ok": false, "errorCode": 1001, "stage": "panic", "error": "verifier panicked on this material" }),
    }
}
