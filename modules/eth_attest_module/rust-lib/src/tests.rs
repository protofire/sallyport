use crate::produce::{produce, Request, Sources};
use crate::verify::dry_run_json;
use serde_json::{json, Value};

fn fixtures(sub: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fixtures").join(sub)
}
fn load(p: std::path::PathBuf) -> Value {
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))).unwrap()
}

/// Every adversarial vector through the module's dry run. The verdicts are lc-core's: at base
/// 3b1ab5d crates/vector-runner reports PASS 54 / MISMATCH 30 (lc-core rejects most multi-update
/// vectors with 1106), and this port reproduces exactly that. Floor, not equality, so an lc-core fix
/// raises the count without breaking this test. Never a panic.
#[test]
fn adversarial_vectors_match_expected_codes() {
    let mut n = 0;
    let mut bad = vec![];
    for e in std::fs::read_dir(fixtures("adversarial")).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_str().unwrap().to_string();
        if p.extension().is_none_or(|x| x != "json") || name == "schema.json" || name == "index.json" {
            continue;
        }
        let v = load(p);
        if v["input"]["bootstrap"].is_null() {
            continue; // SSZ-only bootstrap: unsupported by lc-core's JSON API (same as vector-runner)
        }
        if v["input"].get("update_ssz").is_some() && v["input"]["updates"].as_array().is_some_and(|a| a.is_empty()) {
            continue;
        }
        n += 1;
        let r = dry_run_json(&v.to_string());
        assert_ne!(r["stage"], json!("panic"), "{name}");
        let got = r["errorCode"].as_u64().unwrap();
        let exp = v["expected_error"].as_u64().unwrap();
        let also: Vec<u64> = v["accept_also"].as_array().map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
        if got != exp && !also.contains(&got) {
            bad.push(format!("{name}: expected {exp} got {got}"));
        }
    }
    assert_eq!(n, 89, "all adversarial vectors run");
    eprintln!("dry-run vs expected: {} of {n} match; mismatches: {bad:#?}", n - bad.len());
    assert!(bad.is_empty(), "dry-run must match every vector: {bad:#?}");
}

#[test]
fn garbage_material_is_malformed_not_panic() {
    for m in ["", "{}", "[]", r#"{"config":{"chain_id":"x"}}"#, r#"{"input":{"config":null}}"#] {
        let r = dry_run_json(m);
        assert_eq!(r["ok"], json!(false), "{m}");
        assert_eq!(r["errorCode"], json!(1001), "{m}: {r}");
    }
}

/// Offline Sources over fixtures/sepolia (fetched via beacon_api_module + EL RPC on 2026-11-04).
struct Fx;
impl Sources for Fx {
    fn lc(&self, endpoint: &str, _p: Value) -> Result<Value, String> {
        let f = match endpoint {
            "getLightClientBootstrap" => "bootstrap.json",
            "getLightClientFinalityUpdate" => "finality_update.json",
            "getLightClientUpdatesByRange" => "updates.json",
            e => return Err(format!("unexpected {e}")),
        };
        Ok(load(fixtures("sepolia").join(f)))
    }
    fn el(&self, method: &str, _p: Value) -> Result<Value, String> {
        let f = match method {
            "eth_getBlockByHash" => "exec_block.json",
            "eth_getProof" => "eth_getProof.json",
            "eth_getBlockReceipts" => "eth_getBlockReceipts.json",
            m => return Err(format!("unexpected {m}")),
        };
        let v = load(fixtures("sepolia").join(f));
        Ok(v.get("result").cloned().unwrap_or(v))
    }
}

fn req(slot: &str, tx: i64, log: i64, predicate: Value) -> Request {
    let ok = load(fixtures("adversarial/ok_attest_account.json"));
    Request {
        chain_id: 11_155_111,
        block_hash: String::new(),
        address: "0x7b79995e5f793a07bc00c21412e50ecae098e7f9".into(),
        slot: slot.into(),
        tx_index: tx,
        log_index: log,
        predicate,
        checkpoint_root: ok["input"]["config"]["checkpoint_root"].as_str().unwrap().into(),
    }
}

#[test]
fn produce_then_verify_round_trip() {
    // WETH account: same fact (statement id) as the adversarial-fixture positive control.
    let ok = load(fixtures("adversarial/ok_attest_account.json"));
    let out = produce(&Fx, &req("", -1, -1, ok["input"]["attest"]["predicate"].clone()));
    assert_eq!(out["ok"], json!(true), "{out}");
    assert_eq!(out["dryRun"]["statementId"], ok["input"]["attest"]["expected_fact"]["statement_id"]);

    // storage slot 0 and a receipt log
    let st = produce(&Fx, &req("0x0", -1, -1, json!({"field":"slot","op":"ge","value":"0x00"})));
    assert_eq!(st["ok"], json!(true), "{st}");
    let lg = load(fixtures("adversarial/ok_attest_log.json"));
    let l = &lg["input"]["attest"];
    let out = produce(&Fx, &req("", l["locator"]["tx_index"].as_i64().unwrap(), l["locator"]["log_index"].as_i64().unwrap(), l["predicate"].clone()));
    assert_eq!(out["ok"], json!(true), "{out}");
    assert_eq!(out["dryRun"]["statementId"], l["expected_fact"]["statement_id"]);

    // a false predicate is 1203, a non-finalized block 1101, missing checkpoint a usage error
    let f = produce(&Fx, &req("", -1, -1, json!({"field":"nonce","op":"gt","value":"0xffffffffffffffff"})));
    assert_eq!(f["dryRun"]["errorCode"], json!(1203));
    let mut r = req("", -1, -1, json!({"field":"nonce","op":"ge","value":"0x00"}));
    r.block_hash = format!("0x{}", "11".repeat(32));
    assert_eq!(produce(&Fx, &r)["errorCode"], json!(1101));
    r.block_hash.clear();
    r.checkpoint_root.clear();
    assert_eq!(produce(&Fx, &r)["errorCode"], json!("bad_request"));
}

/// Review finding: a range update that learns the next committee without advancing finality was
/// dropped (checkpoint taken mid-period, that period's best update finalizes at or before it), so
/// the material could never cross into the next period. Shape only: the slots are edited, so the
/// dry run's signature check is not the point here.
#[test]
fn range_update_that_only_learns_next_committee_is_kept() {
    struct Mid;
    impl Sources for Mid {
        fn lc(&self, endpoint: &str, p: Value) -> Result<Value, String> {
            let set = |v: &mut Value, ptr: &str, slot: u64| *v.pointer_mut(ptr).unwrap() = json!(slot.to_string());
            let boot = 11_505_472; // checkpoint slot, period 1404
            let mut v = Fx.lc(endpoint, p)?;
            match endpoint {
                // best update of period 1404: attested after the checkpoint, finalized at it, carries next committee
                "getLightClientUpdatesByRange" => {
                    let mut u = v[0].clone();
                    set(&mut u, "/data/attested_header/beacon/slot", boot + 64);
                    set(&mut u, "/data/finalized_header/beacon/slot", boot);
                    set(&mut u, "/data/signature_slot", boot + 65);
                    v = json!([u]);
                }
                // latest finality is signed in period 1405
                "getLightClientFinalityUpdate" => {
                    set(&mut v, "/data/attested_header/beacon/slot", 1405 * 8192);
                    set(&mut v, "/data/finalized_header/beacon/slot", 1405 * 8192 - 64);
                    set(&mut v, "/data/signature_slot", 1405 * 8192 + 1);
                }
                _ => {}
            }
            Ok(v)
        }
        fn el(&self, method: &str, p: Value) -> Result<Value, String> {
            Fx.el(method, p)
        }
    }
    let out = produce(&Mid, &req("", -1, -1, json!({"field":"nonce","op":"ge","value":"0x00"})));
    let ups = out["material"]["updates"].as_array().unwrap_or_else(|| panic!("{out}"));
    assert_eq!(ups.len(), 2, "committee-learning update + finality update");
    assert!(!ups[0]["next_sync_committee"].is_null());
    assert_eq!(ups[1]["signature_slot"], json!((1405 * 8192 + 1).to_string()));
}

/// Review finding: the storage value was read from the last proof node whenever it had two items,
/// without checking its key. A zero slot whose exclusion proof ends in another key's leaf then
/// read that leaf's value, and the true fact "slot == 0" was rejected.
#[test]
fn storage_exclusion_ending_in_other_key_leaf_reads_zero() {
    use alloy_primitives::keccak256;
    // One-leaf storage trie: key K -> rlp(5). Node = rlp[ hp(K, leaf) = 0x20 ‖ K, 0x05 ].
    let leaf = |k: [u8; 32]| [&[0xe3, 0xa1, 0x20][..], &k, &[0x05]].concat();
    let slot = [0u8; 32];
    let other = [0x77; 32];
    let node = leaf(other);
    let root = keccak256(&node).0;
    assert_eq!(crate::verify::storage_value(&root, &slot, &[node]).ok(), Some([0; 32]));
    // and a leaf that does hold the slot still reads its value
    let own = leaf(keccak256(slot).0);
    let mut five = [0; 32];
    five[31] = 5;
    assert_eq!(crate::verify::storage_value(&keccak256(&own).0, &slot, &[own]).ok(), Some(five));
}
