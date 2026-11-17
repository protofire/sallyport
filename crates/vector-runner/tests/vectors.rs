//! Runs every bootstrap|update|attest vector in fixtures/adversarial against lc-core + inclusion,
//! collects ALL results (no fail-fast), writes RESULTS.md, then asserts.

use inclusion as inc;
use lc_core::host_bls::BlstVerifier;
use lc_core::json::{bootstrap_from_value, update_from_value};
use lc_core::{
    apply_update, bootstrap, hash_tree_root_header, verify_update, ChainConfig, ErrorCode, Store,
};
use serde_json::{json, Value};
use std::fmt::Write as _;

type Res = Result<(), u16>;

fn c(e: ErrorCode) -> u16 {
    e as u16
}
fn ic(e: inc::ErrorCode) -> u16 {
    e as u16
}
fn hx(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    hex::decode(s.trim_start_matches("0x")).expect("valid hex")
}
fn arr<const N: usize>(v: &Value) -> [u8; N] {
    hx(v).try_into().expect("fixed len")
}
fn pad32(b: &[u8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[32 - b.len()..].copy_from_slice(b);
    o
}

// ---- minimal RLP, only to read leaf values out of proof node lists (harness-side decoding)
fn rlp_item(b: &[u8]) -> Option<(bool, &[u8], &[u8])> {
    let t = *b.first()?;
    let (list, hdr, len) = match t {
        0..=0x7f => return Some((false, &b[..1], &b[1..])),
        0x80..=0xb7 => (false, 1, (t - 0x80) as usize),
        0xb8..=0xbf | 0xf8..=0xff => {
            let n = (t - if t >= 0xf8 { 0xf7 } else { 0xb7 }) as usize;
            let l = b
                .get(1..1 + n)?
                .iter()
                .fold(0usize, |a, x| (a << 8) | *x as usize);
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

fn proof_list(v: Option<&Value>) -> Vec<Vec<u8>> {
    v.and_then(|x| x.as_array())
        .map(|a| a.iter().map(hx).collect())
        .unwrap_or_default()
}

fn config(v: &Value) -> (ChainConfig, [u8; 32], u64) {
    let mut cfg = ChainConfig::sepolia(); // electra_fork_epoch is not in the vector config
    cfg.chain_id = v["chain_id"].as_u64().unwrap();
    cfg.genesis_validators_root = arr(&v["genesis_validators_root"]);
    cfg.fork_versions = v["fork_versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (f["epoch"].as_u64().unwrap(), arr::<4>(&f["version"])))
        .collect();
    cfg.gloas_fork_epoch = v["gloas_fork_epoch"].as_u64().unwrap();
    cfg.min_participation = v["min_participation"].as_u64().unwrap() as u16;
    cfg.ws_period_epochs = v["ws_period_epochs"].as_u64().unwrap();
    (
        cfg,
        arr(&v["checkpoint_root"]),
        v["current_slot"].as_u64().unwrap(),
    )
}

/// Returns Ok(note) when it ran, Err(reason) when the input shape can't be expressed.
fn run(v: &Value) -> Result<(Res, Vec<String>), String> {
    let inp = &v["input"];
    let mut notes = vec![];
    if inp["bootstrap"].is_null() {
        return Err(
            "bootstrap given only as SSZ; lc-core has no SSZ decoder (JSON-only API)".into(),
        );
    }
    if inp.get("update_ssz").is_some() && inp["updates"].as_array().unwrap().is_empty() {
        return Err("update given only as SSZ; lc-core has no SSZ decoder".into());
    }
    let (cfg, ckpt, now) = config(&inp["config"]);
    let boot = match bootstrap_from_value(&inp["bootstrap"]) {
        Ok(b) => b,
        Err(e) => return Ok((Err(c(e)), notes)),
    };
    let mut store = match bootstrap(&cfg, &ckpt, &boot, now) {
        Ok(s) => s,
        Err(e) => return Ok((Err(c(e)), notes)),
    };
    for (k, u) in inp["updates"].as_array().unwrap().iter().enumerate() {
        if u["sync_aggregate"].get("non_signers_hint").is_some() {
            notes.push("non_signers_hint ignored (lc-core derives non-signers from bits)".into());
        }
        let r = update_from_value(u)
            .and_then(|up| verify_update(&cfg, &store, &up, now, &BlstVerifier))
            .and_then(|ver| apply_update(&mut store, &ver));
        if let Err(e) = r {
            notes.push(format!("failed at update #{k}"));
            return Ok((Err(c(e)), notes));
        }
    }
    if inp["attest"].is_null() {
        return Ok((Ok(()), notes));
    }
    let r = attest(&cfg, &store, &inp["attest"]);
    if r.is_err() {
        notes.push("failed at attest".into());
    }
    Ok((r, notes))
}

fn attest(cfg: &ChainConfig, store: &Store, a: &Value) -> Res {
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
    let eh =
        inc::verify_exec_header(&hx(&a["el_header_rlp"]), fin.execution_block_hash).map_err(ic)?;
    let bad = || ic(inc::ErrorCode::InclusionInvalid);

    let p = &a["proof"];
    let loc = &a["locator"];
    let account_of = |addr: &[u8; 20]| -> Result<inc::Account, u16> {
        let proof = proof_list(p.get("account_proof"));
        let val = leaf_value(&proof).ok_or_else(bad)?;
        let it = rlp_list(&val).ok_or_else(bad)?;
        if it.len() != 4 {
            return Err(bad());
        }
        let acc = inc::Account {
            nonce: it[0].1.iter().fold(0u64, |a, b| (a << 8) | *b as u64),
            balance: if it[1].1.len() <= 32 {
                pad32(it[1].1)
            } else {
                return Err(bad());
            },
            storage_root: it[2].1.try_into().map_err(|_| bad())?,
            code_hash: it[3].1.try_into().map_err(|_| bad())?,
        };
        inc::verify_account(&eh.state_root, addr, &acc, &proof).map_err(ic)?;
        Ok(acc)
    };
    let (locator, value) = match loc["type"].as_str().unwrap() {
        "account" => {
            let addr = arr::<20>(&loc["address"]);
            (
                inc::Locator::Account { address: addr },
                inc::FactValue::Account(account_of(&addr)?),
            )
        }
        "storage" => {
            let addr = arr::<20>(&loc["address"]);
            let slot = arr::<32>(&loc["slot"]);
            let acc = account_of(&addr)?;
            let sp = p["storage_proof"]
                .as_array()
                .and_then(|s| s.iter().find(|e| hx(&e["key"]) == slot));
            let proof = proof_list(sp.map(|e| &e["proof"]));
            if sp.is_none() {
                return Err(bad());
            }
            // empty / exclusion proofs read as zero
            let val = leaf_value(&proof)
                .and_then(|v| rlp_item(&v).map(|(_, p, _)| p.to_vec()))
                .filter(|b| b.len() <= 32)
                .map(|b| pad32(&b))
                .unwrap_or([0; 32]);
            inc::verify_storage(&acc.storage_root, &slot, &val, &proof).map_err(ic)?;
            (
                inc::Locator::Storage {
                    address: addr,
                    slot,
                },
                inc::FactValue::Slot(val),
            )
        }
        "log" => {
            let (t, l) = (
                loc["tx_index"].as_u64().unwrap() as u32,
                loc["log_index"].as_u64().unwrap() as u32,
            );
            let proof = proof_list(p.get("receipt_proof"));
            let receipt = leaf_value(&proof).ok_or_else(bad)?;
            let lv =
                inc::verify_receipt_log(&eh.receipts_root, t, l, &receipt, &proof).map_err(ic)?;
            (
                inc::Locator::Log {
                    tx_index: t,
                    log_index: l,
                },
                inc::FactValue::Log(lv),
            )
        }
        o => panic!("unknown locator {o}"),
    };
    let fact = inc::Fact {
        chain_id: cfg.chain_id,
        genesis_validators_root: cfg.genesis_validators_root,
        execution_block_hash: fin.execution_block_hash,
        block_number: eh.number,
        locator,
        value,
    };
    let pr = &a["predicate"];
    let field = match pr["field"].as_str().unwrap() {
        "nonce" => inc::FieldSel::Nonce,
        "balance" => inc::FieldSel::Balance,
        "storage_root" => inc::FieldSel::StorageRoot,
        "code_hash" => inc::FieldSel::CodeHash,
        "slot" => inc::FieldSel::Slot,
        "log.address" => inc::FieldSel::LogAddress,
        "log.status" => inc::FieldSel::LogStatus,
        "log.data" => inc::FieldSel::LogDataWord(0),
        t => inc::FieldSel::LogTopic(t.strip_prefix("log.topic").unwrap().parse().unwrap()),
    };
    let value = hx(&pr["value"]);
    let pred = match pr["op"].as_str().unwrap() {
        "eq" => inc::Pred::Eq { field, value },
        "ne" => inc::Pred::Ne { field, value },
        "lt" => inc::Pred::Lt { field, value },
        "le" => inc::Pred::Le { field, value },
        "gt" => inc::Pred::Gt { field, value },
        _ => inc::Pred::Ge { field, value },
    };
    let st = inc::attest(fact, vec![pred]).map_err(ic)?;
    if let Some(ef) = a["expected_fact"].as_object() {
        let f = &st.fact;
        if ef["chain_id"].as_u64() != Some(f.chain_id)
            || arr::<32>(&ef["genesis_validators_root"]) != f.genesis_validators_root
        {
            return Err(c(ErrorCode::ChainMismatch));
        }
        let ev = &ef["value"];
        let val_ok = match (&f.value, ev["type"].as_str().unwrap()) {
            (inc::FactValue::Account(x), "account") => {
                ev["nonce"].as_u64() == Some(x.nonce)
                    && arr::<32>(&ev["balance"]) == x.balance
                    && arr::<32>(&ev["storage_root"]) == x.storage_root
                    && arr::<32>(&ev["code_hash"]) == x.code_hash
            }
            (inc::FactValue::Slot(x), "slot") => arr::<32>(&ev["value"]) == *x,
            (inc::FactValue::Log(x), "log") => {
                arr::<20>(&ev["address"]) == x.address
                    && hx(&ev["data"]) == x.data
                    && ev["status"].as_u64() == Some(x.status as u64)
                    && ev["topics"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(arr::<32>)
                        .collect::<Vec<_>>()
                        == x.topics
            }
            _ => false,
        };
        if arr::<32>(&ef["execution_block_hash"]) != f.execution_block_hash
            || ef["block_number"].as_u64() != Some(f.block_number)
            || !val_ok
            || arr::<32>(&ef["statement_id"]) != st.id
        {
            return Err(c(ErrorCode::StatementMismatch));
        }
    }
    Ok(())
}

#[test]
fn adversarial_vectors() {
    let dir = format!("{}/../../fixtures/adversarial", env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.extension().is_some_and(|e| e == "json")
                && !matches!(
                    p.file_name().unwrap().to_str().unwrap(),
                    "schema.json" | "index.json"
                )
        })
        .collect();
    files.sort();

    let (mut pass, mut mism, mut unsup) = (0, 0, 0);
    let mut md = String::from("# Adversarial vector results\n\nGenerated by `cargo test -p vector-runner`.\n\n| id | layer | expected | accept_also | got | status | note |\n|---|---|---|---|---|---|---|\n");
    for f in &files {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap();
        let id = v["id"].as_str().unwrap();
        let exp = v["expected_error"].as_u64().unwrap() as u16;
        let also: Vec<u16> = v
            .get("accept_also")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().map(|x| x.as_u64().unwrap() as u16).collect())
            .unwrap_or_default();
        let run = std::panic::catch_unwind(|| run(&v));
        let (got, status, note) = match run {
            Ok(Ok((r, notes))) => {
                let got = r.err().unwrap_or(0);
                let ok = got == exp || also.contains(&got);
                if ok {
                    pass += 1
                } else {
                    mism += 1
                }
                (
                    got.to_string(),
                    if ok { "PASS" } else { "MISMATCH" },
                    notes.join("; "),
                )
            }
            Ok(Err(why)) => {
                unsup += 1;
                ("-".into(), "UNSUPPORTED", why)
            }
            Err(_) => {
                mism += 1;
                (
                    "PANIC".into(),
                    "MISMATCH",
                    "harness or library panicked".into(),
                )
            }
        };
        let also_s = if also.is_empty() {
            "-".into()
        } else {
            also.iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        let _ = writeln!(
            md,
            "| {id} | {} | {exp} | {also_s} | {got} | {status} | {note} |",
            v["layer"].as_str().unwrap()
        );
    }
    let total = files.len();
    let _ = write!(
        md,
        "\nTotal {total}: PASS {pass}, MISMATCH {mism}, UNSUPPORTED {unsup}\n"
    );
    print!("{md}");
    std::fs::write(format!("{}/RESULTS.md", env!("CARGO_MANIFEST_DIR")), &md).unwrap();
    // Exact totals: 89 vectors = 74 adversarial cases + 15 positive controls (`ok_*`), all matching.
    let controls = files
        .iter()
        .filter(|f| f.file_name().unwrap().to_str().unwrap().starts_with("ok_"))
        .count();
    assert_eq!(total, 89, "expected exactly 89 vectors, got {total}");
    assert_eq!(
        controls, 15,
        "expected 15 positive controls (ok_*), got {controls}"
    );
    assert_eq!(total - controls, 74, "expected 74 adversarial cases");
    assert_eq!(unsup, 0, "{unsup} vectors unsupported by the host harness");
    assert_eq!(mism, 0, "{mism} vectors mismatched (see RESULTS.md)");
    assert_eq!(pass, 89, "expected 89/89 PASS, got {pass}");
}
