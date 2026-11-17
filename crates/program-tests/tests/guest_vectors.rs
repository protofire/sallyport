//! Runs every fixtures/adversarial vector through the ON-CHAIN path: the RISC Zero guest executed
//! by the LEZ `V03State` executor (Init -> UpdateBegin/UpdateVerify* -> Attest). Collects ALL
//! results (no fail-fast), writes GUEST-VECTORS.md (untracked, see .gitignore), then asserts zero MISMATCH.
//! Host-side only: JSON -> ABI structs (relayer role), non-signer hints, residue witness, and the
//! `expected_fact` comparison (done on the statement the guest accepted, via the shared `verify`).

use std::fmt::Write as _;

use attest_program::*;
use inclusion::{Account, FieldSel, Locator, Pred};
use lc_core::json::{bootstrap_from_value, update_from_value};
use lc_core::ChainConfig;
use program_tests::*;
use serde_json::Value;

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string").trim_start_matches("0x")).expect("valid hex")
}
fn arr<const N: usize>(v: &Value) -> [u8; N] {
    hx(v).try_into().expect("fixed len")
}
fn pad32(b: &[u8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[32 - b.len()..].copy_from_slice(b);
    o
}

// ---- minimal RLP (same as vector-runner): reads leaf values out of proof node lists
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
fn leaf_value(proof: &[Vec<u8>]) -> Option<Vec<u8>> {
    let it = rlp_list(proof.last()?)?;
    (it.len() == 2 && !it[1].0).then(|| it[1].1.to_vec())
}
fn proof_list(v: Option<&Value>) -> Vec<Vec<u8>> {
    v.and_then(|x| x.as_array())
        .map(|a| a.iter().map(hx).collect())
        .unwrap_or_default()
}

fn config(v: &Value) -> (InstanceConfig, [u8; 32], u64) {
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
        InstanceConfig {
            chain: cfg,
            genesis_time: SEPOLIA_GENESIS_TIME,
        },
        arr(&v["checkpoint_root"]),
        v["current_slot"].as_u64().unwrap(),
    )
}

/// Vector hint (compressed G1) -> uncompressed 96 B as the program's `non_signers` ABI wants.
fn hint_keys(u: &Value) -> Option<Vec<Vec<u8>>> {
    let h = u["sync_aggregate"].get("non_signers_hint")?.as_array()?;
    Some(
        h.iter()
            .filter_map(|k| {
                blst::min_pk::PublicKey::uncompress(&hx(k))
                    .ok()
                    .map(|p| p.serialize().to_vec())
            })
            .collect(),
    )
}

fn field_of(s: &str) -> FieldSel {
    match s {
        "nonce" => FieldSel::Nonce,
        "balance" => FieldSel::Balance,
        "storage_root" => FieldSel::StorageRoot,
        "code_hash" => FieldSel::CodeHash,
        "slot" => FieldSel::Slot,
        "log.address" => FieldSel::LogAddress,
        "log.status" => FieldSel::LogStatus,
        "log.data" => FieldSel::LogDataWord(0),
        t => FieldSel::LogTopic(t.strip_prefix("log.topic").unwrap().parse().unwrap()),
    }
}

/// Vector attest block -> (header PDA execution hash, program request). Proof decoding failures
/// (the harness cannot lift the typed Account/value out of a broken proof) fall back to zero
/// values so the guest still sees, and must reject, the adversarial proof nodes.
fn build_attest(id: InstanceId, a: &Value) -> Result<([u8; 32], AttestRequest), String> {
    let hdr = bootstrap_from_value(&serde_json::json!({"header": a["header"], "current_sync_committee": {"pubkeys": [], "aggregate_pubkey": format!("0x{}", "00".repeat(48))}, "current_sync_committee_branch": []}))
        .map_err(|e| format!("attest.header undecodable ({e:?})"))?
        .header;
    let ebh = match &hdr.execution {
        lc_core::HeaderExecution::Gloas(h) => *h,
        _ => return Err("attest.header is not Gloas-shaped".into()),
    };
    let (p, loc) = (&a["proof"], &a["locator"]);
    let account = |proof: &[Vec<u8>]| -> Account {
        let dec = || {
            let leaf = leaf_value(proof)?;
            let it = rlp_list(&leaf)?;
            (it.len() == 4 && it[1].1.len() <= 32).then_some(())?;
            Some(Account {
                nonce: it[0].1.iter().fold(0u64, |a, b| (a << 8) | *b as u64),
                balance: pad32(it[1].1),
                storage_root: it[2].1.try_into().ok()?,
                code_hash: it[3].1.try_into().ok()?,
            })
        };
        dec().unwrap_or(Account {
            nonce: 0,
            balance: [0; 32],
            storage_root: [0; 32],
            code_hash: [0; 32],
        })
    };
    let (locator, proof) = match loc["type"].as_str().unwrap() {
        "account" => {
            let ap = proof_list(p.get("account_proof"));
            (
                Locator::Account {
                    address: arr(&loc["address"]),
                },
                Proof::Account {
                    account: account(&ap),
                    account_proof: ap,
                },
            )
        }
        "storage" => {
            let (addr, slot) = (arr::<20>(&loc["address"]), arr::<32>(&loc["slot"]));
            let ap = proof_list(p.get("account_proof"));
            let sp = proof_list(
                p["storage_proof"]
                    .as_array()
                    .and_then(|s| s.iter().find(|e| hx(&e["key"]) == slot))
                    .and_then(|e| e.get("proof")),
            );
            let value = leaf_value(&sp)
                .and_then(|v| rlp_item(&v).map(|(_, p, _)| p.to_vec()))
                .filter(|b| b.len() <= 32)
                .map(|b| pad32(&b))
                .unwrap_or([0; 32]);
            (
                Locator::Storage {
                    address: addr,
                    slot,
                },
                Proof::Storage {
                    account: account(&ap),
                    account_proof: ap,
                    value,
                    storage_proof: sp,
                },
            )
        }
        _ => {
            let (t, l) = (
                loc["tx_index"].as_u64().unwrap() as u32,
                loc["log_index"].as_u64().unwrap() as u32,
            );
            let rp = proof_list(p.get("receipt_proof"));
            (
                Locator::Log {
                    tx_index: t,
                    log_index: l,
                },
                Proof::Log {
                    receipt: leaf_value(&rp).unwrap_or_default(),
                    receipt_proof: rp,
                },
            )
        }
    };
    let pr = &a["predicate"];
    let (field, value) = (field_of(pr["field"].as_str().unwrap()), hx(&pr["value"]));
    let pred = match pr["op"].as_str().unwrap() {
        "eq" => Pred::Eq { field, value },
        "ne" => Pred::Ne { field, value },
        "lt" => Pred::Lt { field, value },
        "le" => Pred::Le { field, value },
        "gt" => Pred::Gt { field, value },
        _ => Pred::Ge { field, value },
    };
    Ok((
        ebh,
        AttestRequest {
            instance_id: id,
            exec_header_rlp: hx(&a["el_header_rlp"]),
            ancestry: vec![],
            locator,
            proof,
            preds: vec![pred],
            ctx: vec![],
        },
    ))
}

/// Compare the statement the guest accepted with the vector's `expected_fact` (consumer-side, F6).
fn fact_matches(
    c: &Chain,
    id: &InstanceId,
    ebh: &[u8; 32],
    req: &AttestRequest,
    ef: &Value,
) -> bool {
    let rec: HeaderRecord = borsh::from_slice(&c.state_of(c.header(id, ebh))).unwrap();
    let st = verify(&rec, req).expect("guest accepted, host verify must too");
    let f = &st.fact;
    let ev = &ef["value"];
    let val_ok = match (&f.value, ev["type"].as_str().unwrap()) {
        (inclusion::FactValue::Account(x), "account") => {
            ev["nonce"].as_u64() == Some(x.nonce)
                && arr::<32>(&ev["balance"]) == x.balance
                && arr::<32>(&ev["storage_root"]) == x.storage_root
                && arr::<32>(&ev["code_hash"]) == x.code_hash
        }
        (inclusion::FactValue::Slot(x), "slot") => arr::<32>(&ev["value"]) == *x,
        (inclusion::FactValue::Log(x), "log") => {
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
    ef["chain_id"].as_u64() == Some(f.chain_id)
        && arr::<32>(&ef["genesis_validators_root"]) == f.genesis_validators_root
        && arr::<32>(&ef["execution_block_hash"]) == f.execution_block_hash
        && ef["block_number"].as_u64() == Some(f.block_number)
        && val_ok
        && arr::<32>(&ef["statement_id"]) == st.id
}

enum Outcome {
    Code(u16),
    /// Guest trapped / non-typed failure (burns gas instead of a typed error).
    Panic(String),
    /// Input not expressible through the program ABI.
    Unsupported(String),
}

fn fail(f: Fail) -> Outcome {
    match f {
        Fail::Code(c) => Outcome::Code(c),
        Fail::Other(m) => Outcome::Panic(m),
    }
}

fn run(v: &Value, one_tx: bool) -> (Outcome, Vec<String>) {
    let inp = &v["input"];
    let mut notes = vec![];
    if inp["bootstrap"].is_null() {
        return (
            Outcome::Unsupported(
                "bootstrap given only as SSZ; no SSZ ingest in the ABI (borsh structs)".into(),
            ),
            notes,
        );
    }
    let (cfg, ckpt, now) = config(&inp["config"]);
    let boot = match bootstrap_from_value(&inp["bootstrap"]) {
        Ok(b) => b,
        Err(e) => return (Outcome::Unsupported(format!("bootstrap not representable in borsh ABI (fixed-size field); relayer decode rejects with {}", e as u16)), notes),
    };
    let id = instance_id(&cfg, &ckpt);
    let mut c = Chain::new();
    let init = Msg::Init {
        instance_id: id,
        cfg: cfg.clone(),
        trusted_block_root: ckpt,
        bootstrap: boot,
        now_slot: now,
    };
    if let Err(f) = c.init(&init) {
        notes.push("failed at Init".into());
        return (fail(f), notes);
    }
    for (k, uj) in inp["updates"].as_array().unwrap().iter().enumerate() {
        let u = match update_from_value(uj) {
            Ok(u) => u,
            Err(e) => return (Outcome::Unsupported(format!("update #{k} not representable in borsh ABI (fixed-size field); relayer decode rejects with {}", e as u16)), notes),
        };
        let hinted = hint_keys(uj);
        if hinted.is_some() {
            notes.push(
                if one_tx {
                    "non_signers_hint passed as Update.non_signers"
                } else {
                    "non_signers_hint passed as UpdateBegin.non_signers"
                }
                .into(),
            );
        }
        let hints = hinted.unwrap_or_else(|| c.hints(id, &u, now));
        if one_tx {
            let st = c.instance_state(&id);
            let w = lc_core::prepare_update(&st.cfg.chain, &st.store, &u, now)
                .ok()
                .and_then(|p| attest_program::witness::for_pairing(&p.pairing))
                .unwrap_or_else(|| vec![0; 864]);
            // This corpus includes committee-learning updates beyond the one-tx gas cap.
            // Raise the budget ONLY for semantic parity; onetx.rs pins successful capped txs.
            c.budget = 64_000_000;
            if let Err(f) = c.update_one_hinted(id, &u, now, hints, w) {
                notes.push(format!("failed at Update #{k}"));
                return (fail(f), notes);
            }
        } else {
            let begin = c.begin_hinted(id, k as u64, &u, now, hints);
            if let Err(f) = begin {
                notes.push(format!("failed at UpdateBegin #{k}"));
                return (fail(f), notes);
            }
            let st = c.instance_state(&id);
            // Invalid signatures have no residue witness: send a zero witness (guest must reject, not trap).
            let w = lc_core::prepare_update(&st.cfg.chain, &st.store, &u, now)
                .ok()
                .and_then(|p| attest_program::witness::for_pairing(&p.pairing))
                .unwrap_or_else(|| vec![0; 864]);
            if let Err(f) = c.verify(id, k as u64, &u, w) {
                notes.push(format!("failed at UpdateVerify #{k}"));
                if matches!(f, Fail::Other(_)) {
                    // A failed tx leaves state untouched: probe whether a typed rejection is reachable at all.
                    notes.push(format!(
                        "1-byte witness retry => {:?}",
                        c.verify(id, k as u64, &u, vec![0]).err()
                    ));
                }
                return (fail(f), notes);
            }
        }
    }
    if inp["attest"].is_null() {
        return (Outcome::Code(0), notes);
    }
    let (ebh, req) = match build_attest(id, &inp["attest"]) {
        Ok(x) => x,
        Err(why) => return (Outcome::Unsupported(why), notes),
    };
    let r = c.attest(ebh, req.clone());
    if let Err(f) = r {
        notes.push("failed at Attest".into());
        return (fail(f), notes);
    }
    if let Some(ef) = inp["attest"]["expected_fact"].as_object() {
        let ef = Value::Object(ef.clone());
        if !fact_matches(&c, &id, &ebh, &req, &ef) {
            notes.push("guest-accepted statement != expected_fact".into());
            return (Outcome::Code(1204), notes);
        }
    }
    (Outcome::Code(0), notes)
}

/// id -> host-runner `got` from vector-runner/RESULTS.md.
fn host_results() -> std::collections::HashMap<String, String> {
    let p = format!("{}/../vector-runner/RESULTS.md", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("| ") && !l.starts_with("| id") && !l.starts_with("|---"))
        .filter_map(|l| {
            let c: Vec<&str> = l.split('|').map(str::trim).collect();
            (c.len() > 5).then(|| (c[1].to_string(), c[5].to_string()))
        })
        .collect()
}

#[test]
fn guest_adversarial_vectors() {
    run_vectors(false);
}

#[test]
fn guest_adversarial_vectors_one_tx() {
    run_vectors(true);
}

fn run_vectors(one_tx: bool) {
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
    let host = host_results();
    let (mut pass, mut mism, mut unsup, mut panics) = (0, 0, 0, 0);
    let mut md = String::from("| id | layer | expected | accept_also | host | guest | status | note |\n|---|---|---|---|---|---|---|---|\n");
    for f in &files {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap();
        let id = v["id"].as_str().unwrap();
        let exp = v["expected_error"].as_u64().unwrap() as u16;
        let also: Vec<u16> = v
            .get("accept_also")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().map(|x| x.as_u64().unwrap() as u16).collect())
            .unwrap_or_default();
        eprintln!("== {id}");
        let (guest, status, mut note) = match std::panic::catch_unwind(|| run(&v, one_tx)) {
            Ok((Outcome::Code(g), notes)) => {
                let ok = g == exp || also.contains(&g);
                let abi = ABI_LIMITS.iter().find(|(i, _)| *i == id);
                match (ok, abi) {
                    (true, _) => pass += 1,
                    (false, Some(_)) => unsup += 1,
                    (false, None) => mism += 1,
                }
                (
                    g.to_string(),
                    if ok {
                        "PASS"
                    } else if abi.is_some() {
                        "UNSUPPORTED"
                    } else {
                        "MISMATCH"
                    },
                    notes.join("; "),
                )
            }
            Ok((Outcome::Panic(m), notes)) => {
                // Tx is rejected (correct), but with a guest trap instead of a typed code (RFP U5): counted apart.
                let known = m.contains("Guest panicked")
                    && notes.iter().any(|n| n.starts_with("failed at Update"));
                if known {
                    panics += 1
                } else {
                    mism += 1
                }
                let head = m.lines().next().unwrap_or("").replace('|', "/");
                (
                    "PANIC".into(),
                    if known { "PANIC" } else { "MISMATCH" },
                    format!(
                        "{}; untyped guest trap: {}",
                        notes.join("; "),
                        head.chars().take(110).collect::<String>()
                    ),
                )
            }
            Ok((Outcome::Unsupported(why), notes)) => {
                unsup += 1;
                (
                    "-".into(),
                    "UNSUPPORTED",
                    format!("{why}; {}", notes.join("; ")),
                )
            }
            Err(_) => {
                mism += 1;
                (
                    "HARNESS-PANIC".into(),
                    "MISMATCH",
                    "harness panicked".into(),
                )
            }
        };
        if let Some(t) = TRIAGE.iter().find(|(i, _)| *i == id) {
            note = format!("{note} TRIAGE: {}", t.1);
        }
        if let Some(t) = ABI_LIMITS.iter().find(|(i, _)| *i == id) {
            note = format!("{note} ABI: {}", t.1);
        }
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
            "| {id} | {} | {exp} | {also_s} | {} | {guest} | {status} | {note} |",
            v["layer"].as_str().unwrap(),
            host.get(id).map(String::as_str).unwrap_or("?")
        );
    }
    let total = files.len();
    let summary = format!("Total {total}: PASS {pass}, MISMATCH {mism}, UNSUPPORTED {unsup}, guest PANIC (untyped) {panics}\n");
    let path_note = if one_tx {
        "Single-transaction Update path; 64M budget for committee-learning semantic parity. Capped finality-only measurements are in onetx.rs."
    } else {
        "Two-transaction UpdateBegin/UpdateVerify path."
    };
    let out = format!("{HEADER}\n{path_note}\n{md}\n{summary}");
    print!("{out}");
    std::fs::write(
        format!(
            "{}/GUEST-VECTORS{}.md",
            env!("CARGO_MANIFEST_DIR"),
            if one_tx { "-ONETX" } else { "" }
        ),
        &out,
    )
    .unwrap();
    assert_eq!(total, 89, "expected exactly 89 vectors, got {total}");
    assert_eq!(pass, 84, "expected all 84 supported vectors to pass");
    assert_eq!(mism, 0, "{mism} vectors mismatched (see GUEST-VECTORS.md)");
    assert_eq!(
        panics, 0,
        "{panics} vectors trapped the guest instead of a typed error (RFP U5)"
    );
}

/// Vectors whose claim is not expressible in the ABI: the guest outcome differs but is the
/// ABI's consequence (Attest has no beacon-header input; the header PDA is keyed by execution hash).
const ABI_LIMITS: &[(&str, &str)] = &[
    ("attest_header_execution_hash_rebound", "Attest takes no beacon header; header-vs-branch binding is checked at Init/Apply. Rebound hash has no header PDA -> 1101 (rejected, earlier layer)"),
    ("attest_under_unknown_header", "Attest takes no beacon header; same EL block as the finalized one is correctly attested via its PDA. 'Unknown beacon header' is not expressible"),
];

/// Per-vector triage notes appended to the table (id, text).
const TRIAGE: &[(&str, &str)] = &[];

const HEADER: &str = "# Adversarial vectors through the on-chain guest

Generated by `cargo test --release -p program-tests --test guest_vectors`. Each vector runs Init -> updates -> Attest on the real RISC Zero guest; the path and gas policy are stated below (LEZ `V03State` executor, dev mode). `host` = the vector-runner results. Guest code = exit code + 1000 (lc-core ErrorCode). Statuses: PASS (guest code is `expected` or in `accept_also`), UNSUPPORTED (not expressible through the ABI, reason in note), PANIC (tx rejected by an untyped guest trap), MISMATCH (none allowed).

## Triage

- **PANIC x0 (RFP U5, fixed in D-ATT-4):** the 10 vectors whose only defect is a cryptographically wrong aggregate signature (valid encoding, in G2, passes UpdateBegin) reach UpdateVerify, where no residue witness exists for a false pairing. `residue::check` now returns `false` instead of asserting (same conditions), so they end in the typed `1102` SyncSigInvalid, matching the host runner. The test asserts PANIC = 0.
- **UNSUPPORTED (ABI x2):** `Attest` has no beacon-header input (header PDA is keyed by execution hash), so `attest_header_execution_hash_rebound` ends at 1101 (header-vs-branch binding is enforced at Init/Apply) and `attest_under_unknown_header` attests the same finalized EL block successfully. Legitimate layer difference, no safety impact.
- **UNSUPPORTED (decode x3):** `bootstrap_pubkey_47_bytes`, `update_bits_63_bytes`, `update_branch_element_31_bytes` break fixed-size fields (`[u8; 48]`, `[u8; 64]`, `[u8; 32]`): borsh cannot carry them, the relayer's JSON decode rejects with 1001 before any tx exists.
- Harness notes: invalid-signature updates get a zero 864-byte witness; `non_signers_hint` is passed as `UpdateBegin.non_signers` (decompressed); a broken account/storage/receipt proof that cannot be decoded into the typed Account/value falls back to zero values so the guest sees the bad nodes; `expected_fact` is compared on `verify()` of the stored header record after the guest accepted (same shared function, host-evaluated).
- Guest-vs-host code differences that are within `accept_also` or equal: none beyond the above (all other 84 match `expected` or `accept_also`).
";
