//! Integration tests on real Sepolia fixtures. Needs `--features host` (serde_json + RPC→RLP helpers).
#![cfg(feature = "host")]

use inclusion::host::*;
use inclusion::*;
use serde_json::Value;

const WETH: &str = "0x7b79995e5f793a07bc00c21412e50ecae098e7f9";

fn load(rel: &str) -> Value {
    let p = format!("{}/../../fixtures/{rel}", env!("CARGO_MANIFEST_DIR"));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    v["result"].clone()
}
fn h32(v: &Value) -> [u8; 32] {
    let mut o = [0u8; 32];
    let b = hex(v);
    o[32 - b.len()..].copy_from_slice(&b);
    o
}
fn h20(s: &str) -> [u8; 20] {
    hex(&Value::String(s.into())).try_into().unwrap()
}

/// header → (ExecHeader, block hash) for a fixture dir
fn header(dir: &str) -> (ExecHeader, [u8; 32]) {
    let b = load(&format!("{dir}/exec_block.json"));
    let hash = h32(&b["hash"]);
    (
        verify_exec_header(&header_rlp_from_rpc(&b), hash).unwrap(),
        hash,
    )
}

fn account_of(p: &Value) -> Account {
    Account {
        nonce: u64::from_str_radix(p["nonce"].as_str().unwrap().trim_start_matches("0x"), 16)
            .unwrap(),
        balance: h32(&p["balance"]),
        storage_root: h32(&p["storageHash"]),
        code_hash: h32(&p["codeHash"]),
    }
}

fn anchor_fact(hash: [u8; 32], number: u64, locator: Locator, value: FactValue) -> Fact {
    Fact {
        chain_id: 11155111,
        genesis_validators_root: [7; 32],
        execution_block_hash: hash,
        block_number: number,
        locator,
        value,
    }
}

#[test]
fn header_hash_binds_and_decodes() {
    let b = load("sepolia/exec_block.json");
    let rlp = header_rlp_from_rpc(&b);
    let h = verify_exec_header(&rlp, h32(&b["hash"])).unwrap();
    assert_eq!(h.number, 0xb81016);
    assert_eq!(h.timestamp, 0x6aeb3454);
    assert_eq!(h.state_root, h32(&b["stateRoot"]));
    assert_eq!(h.receipts_root, h32(&b["receiptsRoot"]));
    assert_eq!(h.transactions_root, h32(&b["transactionsRoot"]));
    let mut bad = h32(&b["hash"]);
    bad[0] ^= 1;
    assert_eq!(
        verify_exec_header(&rlp, bad).unwrap_err(),
        ErrorCode::ExecutionHeaderMismatch
    );
    // truncated header: still hash-mismatch first, but malformed RLP with correct hash is impossible to construct
    assert!(verify_exec_header(&rlp[..rlp.len() - 1], h32(&b["hash"])).is_err());
    // second fixture block too (different extraData etc.)
    header("inclusion");
}

#[test]
fn weth_account_and_slot0_verify() {
    let (h, _) = header("sepolia");
    let p = load("sepolia/eth_getProof.json");
    let acct = account_of(&p);
    verify_account(
        &h.state_root,
        &h20(WETH),
        &acct,
        &proof_from_rpc(&p["accountProof"]),
    )
    .unwrap();
    let sp = &p["storageProof"][0];
    verify_storage(
        &acct.storage_root,
        &h32(&sp["key"]),
        &h32(&sp["value"]),
        &proof_from_rpc(&sp["proof"]),
    )
    .unwrap();
    // wrong value
    let mut v = h32(&sp["value"]);
    v[31] ^= 1;
    assert_eq!(
        verify_storage(
            &acct.storage_root,
            &h32(&sp["key"]),
            &v,
            &proof_from_rpc(&sp["proof"])
        )
        .unwrap_err(),
        ErrorCode::InclusionInvalid
    );
}

#[test]
fn tampered_node_and_wrong_root_rejected() {
    let (h, _) = header("sepolia");
    let p = load("sepolia/eth_getProof.json");
    let acct = account_of(&p);
    let mut proof = proof_from_rpc(&p["accountProof"]);
    let last = proof.len() - 1;
    let n = proof[last].len();
    proof[last][n - 5] ^= 0xff;
    assert_eq!(
        verify_account(&h.state_root, &h20(WETH), &acct, &proof).unwrap_err(),
        ErrorCode::InclusionInvalid
    );
    let mut root = h.state_root;
    root[0] ^= 1;
    assert_eq!(
        verify_account(
            &root,
            &h20(WETH),
            &acct,
            &proof_from_rpc(&p["accountProof"])
        )
        .unwrap_err(),
        ErrorCode::InclusionInvalid
    );
    // wrong claimed balance
    let mut a2 = acct.clone();
    a2.balance[31] ^= 1;
    assert_eq!(
        verify_account(
            &h.state_root,
            &h20(WETH),
            &a2,
            &proof_from_rpc(&p["accountProof"])
        )
        .unwrap_err(),
        ErrorCode::InclusionInvalid
    );
}

#[test]
fn absent_slot_is_zero() {
    let (h, _) = header("inclusion");
    let p = load("inclusion/weth_getProof.json");
    let acct = account_of(&p);
    verify_account(
        &h.state_root,
        &h20(WETH),
        &acct,
        &proof_from_rpc(&p["accountProof"]),
    )
    .unwrap();
    let sp = &p["storageProof"][1];
    assert_eq!(sp["value"], "0x0");
    verify_storage(
        &acct.storage_root,
        &h32(&sp["key"]),
        &[0; 32],
        &proof_from_rpc(&sp["proof"]),
    )
    .unwrap();
    assert_eq!(
        verify_storage(
            &acct.storage_root,
            &h32(&sp["key"]),
            &[1; 32],
            &proof_from_rpc(&sp["proof"])
        )
        .unwrap_err(),
        ErrorCode::InclusionInvalid
    );
}

#[test]
fn eoa_empty_storage_balance_attestation() {
    let (h, hash) = header("inclusion");
    let p = load("inclusion/eoa_getProof.json");
    let acct = account_of(&p);
    let addr = h20(p["address"].as_str().unwrap());
    assert_eq!(acct.storage_root, EMPTY_ROOT);
    verify_account(
        &h.state_root,
        &addr,
        &acct,
        &proof_from_rpc(&p["accountProof"]),
    )
    .unwrap();
    // empty storage trie: any slot is 0 with an empty proof, nonzero is rejected
    verify_storage::<Vec<u8>>(&acct.storage_root, &[0; 32], &[0; 32], &[]).unwrap();
    assert_eq!(
        verify_storage::<Vec<u8>>(&acct.storage_root, &[0; 32], &[1; 32], &[]).unwrap_err(),
        ErrorCode::InclusionInvalid
    );

    let fact = anchor_fact(
        hash,
        h.number,
        Locator::Account { address: addr },
        FactValue::Account(acct.clone()),
    );
    let mut min = [0u8; 32];
    min[24] = 1; // 2^56 wei
    let st = attest(
        fact.clone(),
        vec![Pred::Ge {
            field: FieldSel::Balance,
            value: min.to_vec(),
        }],
    )
    .unwrap();
    assert_eq!(st.id, statement_id(&fact));
    assert_eq!(
        attest(
            fact,
            vec![Pred::Gt {
                field: FieldSel::Balance,
                value: [0xff; 32].to_vec()
            }]
        )
        .unwrap_err(),
        ErrorCode::PredicateFailed
    );
}

#[test]
fn absent_account_exclusion_proof() {
    let (h, _) = header("inclusion");
    let p = load("inclusion/absent_getProof.json");
    let addr = h20(p["address"].as_str().unwrap());
    let proof = proof_from_rpc(&p["accountProof"]);
    verify_account(&h.state_root, &addr, &Account::empty(), &proof).unwrap();
    let mut a = Account::empty();
    a.balance[31] = 1;
    assert_eq!(
        verify_account(&h.state_root, &addr, &a, &proof).unwrap_err(),
        ErrorCode::InclusionInvalid
    );
}

struct Block {
    hdr: ExecHeader,
    hash: [u8; 32],
    receipts: Vec<Vec<u8>>,
    json: Value,
}
fn receipts_block() -> Block {
    let (hdr, hash) = header("sepolia");
    let json = load("sepolia/eth_getBlockReceipts.json");
    let receipts = json
        .as_array()
        .unwrap()
        .iter()
        .map(receipt_bytes_from_rpc)
        .collect();
    Block {
        hdr,
        hash,
        receipts,
        json,
    }
}

#[test]
fn receipt_trie_root_matches_header() {
    let b = receipts_block();
    let (root, _) = receipt_proof(&b.receipts, 0);
    assert_eq!(root, b.hdr.receipts_root);
}

/// ERC-20 Transfer at block logIndex 0x8 (tx 7) on token 0x07ea…705e
#[test]
fn erc20_transfer_log_verifies_and_predicate_passes() {
    let b = receipts_block();
    let (tx, li) = locate_log(&b.json, 0x8).unwrap();
    assert_eq!(tx, 7);
    let (_, proof) = receipt_proof(&b.receipts, tx);
    let log = verify_receipt_log(
        &b.hdr.receipts_root,
        tx,
        li,
        &b.receipts[tx as usize],
        &proof,
    )
    .unwrap();
    assert_eq!(log.status, 1);
    let token = h20("0x07ea2ff889e6228cded329a09f66e370f12c705e");
    assert_eq!(log.address, token);
    let to = h20("0xbdc1fe97e787ae7f653ffbccd74ec49814fe6aa1");
    let fact = anchor_fact(
        b.hash,
        b.hdr.number,
        Locator::Log {
            tx_index: tx,
            log_index: li,
        },
        FactValue::Log(log),
    );
    let mut min = [0u8; 32];
    min[31] = 1;
    attest(
        fact.clone(),
        erc20_transfer_preds(token, None, Some(to), Some(min)),
    )
    .unwrap();
    // wrong recipient / amount too high → 1203
    assert_eq!(
        attest(
            fact.clone(),
            erc20_transfer_preds(token, None, Some([1; 20]), None)
        )
        .unwrap_err(),
        ErrorCode::PredicateFailed
    );
    assert_eq!(
        attest(
            fact,
            erc20_transfer_preds(token, None, Some(to), Some([0xff; 32]))
        )
        .unwrap_err(),
        ErrorCode::PredicateFailed
    );
}

/// EIP-7708 native ETH transfer log (system address 0xff…fe) at block logIndex 0x6 (tx 2)
#[test]
fn native_eth_transfer_log() {
    let b = receipts_block();
    let (tx, li) = locate_log(&b.json, 0x6).unwrap();
    let (_, proof) = receipt_proof(&b.receipts, tx);
    let log = verify_receipt_log(
        &b.hdr.receipts_root,
        tx,
        li,
        &b.receipts[tx as usize],
        &proof,
    )
    .unwrap();
    let to = h20("0x2f4d5f98f7141f79af4a9142046fa271a36faf53");
    let fact = anchor_fact(
        b.hash,
        b.hdr.number,
        Locator::Log {
            tx_index: tx,
            log_index: li,
        },
        FactValue::Log(log),
    );
    let amt = h32(&Value::String("0x0e35fa931a0000".into()));
    attest(
        fact.clone(),
        native_eth_transfer_preds(None, Some(to), Some(amt)),
    )
    .unwrap();
    let mut more = amt;
    more[31] += 1;
    assert_eq!(
        attest(fact, native_eth_transfer_preds(None, Some(to), Some(more))).unwrap_err(),
        ErrorCode::PredicateFailed
    );
}

#[test]
fn receipt_negatives() {
    let b = receipts_block();
    let (tx, li) = locate_log(&b.json, 0x8).unwrap();
    let (_, proof) = receipt_proof(&b.receipts, tx);
    let r = &b.receipts[tx as usize];
    // log_index past the receipt's logs
    assert_eq!(
        verify_receipt_log(&b.hdr.receipts_root, tx, 99, r, &proof).unwrap_err(),
        ErrorCode::InclusionInvalid
    );
    // receipt of another tx under this tx's key
    assert_eq!(
        verify_receipt_log(&b.hdr.receipts_root, tx, li, &b.receipts[1], &proof).unwrap_err(),
        ErrorCode::InclusionInvalid
    );
    // wrong tx_index for the same proof/receipt
    assert_eq!(
        verify_receipt_log(&b.hdr.receipts_root, tx + 1, li, r, &proof).unwrap_err(),
        ErrorCode::InclusionInvalid
    );
    // tampered receipt byte
    let mut rr = r.clone();
    let n = rr.len();
    rr[n - 1] ^= 1;
    assert_eq!(
        verify_receipt_log(&b.hdr.receipts_root, tx, li, &rr, &proof).unwrap_err(),
        ErrorCode::InclusionInvalid
    );
    // wrong root
    let mut root = b.hdr.receipts_root;
    root[5] ^= 1;
    assert_eq!(
        verify_receipt_log(&root, tx, li, r, &proof).unwrap_err(),
        ErrorCode::InclusionInvalid
    );
    // compact witness (D-GAS-6): every tx's every log equals the explicit form; same negatives
    let rr = &b.hdr.receipts_root;
    for t in 0..b.receipts.len() as u32 {
        let (_, p) = receipt_proof(&b.receipts, t);
        for l in 0..4 {
            assert_eq!(
                verify_receipt_log_compact(rr, t, l, &p),
                verify_receipt_log(rr, t, l, &b.receipts[t as usize], &p)
            );
        }
    }
    let bad = ErrorCode::InclusionInvalid;
    assert_eq!(verify_receipt_log_compact(rr, tx, 99, &proof), Err(bad));
    assert_eq!(verify_receipt_log_compact(rr, tx + 1, li, &proof), Err(bad));
    assert_eq!(verify_receipt_log_compact(&root, tx, li, &proof), Err(bad));
    assert_eq!(
        verify_receipt_log_compact(rr, tx, li, &proof[..proof.len() - 1]),
        Err(bad)
    );
    let mut pp = proof.clone();
    let last = pp.len() - 1;
    let n = pp[last].len();
    pp[last][n - 1] ^= 1;
    assert_eq!(verify_receipt_log_compact(rr, tx, li, &pp), Err(bad));
}

#[test]
fn statement_id_determinism() {
    let b = receipts_block();
    let (tx, li) = locate_log(&b.json, 0x8).unwrap();
    let (_, proof) = receipt_proof(&b.receipts, tx);
    let log = verify_receipt_log(
        &b.hdr.receipts_root,
        tx,
        li,
        &b.receipts[tx as usize],
        &proof,
    )
    .unwrap();
    let f1 = anchor_fact(
        b.hash,
        b.hdr.number,
        Locator::Log {
            tx_index: tx,
            log_index: li,
        },
        FactValue::Log(log.clone()),
    );
    let f2 = f1.clone();
    assert_eq!(statement_id(&f1), statement_id(&f2));
    let f3 = anchor_fact(
        b.hash,
        b.hdr.number,
        Locator::Log {
            tx_index: tx,
            log_index: li + 1,
        },
        FactValue::Log(log),
    );
    assert_ne!(statement_id(&f1), statement_id(&f3));
    let mut f4 = f1.clone();
    f4.chain_id = 1;
    assert_ne!(statement_id(&f1), statement_id(&f4));
    // id is independent of value (identifies the fact location, not the predicate)
    let mut f5 = f1.clone();
    f5.block_number += 1;
    assert_eq!(statement_id(&f1), statement_id(&f5));
}

#[test]
fn pred_semantics() {
    let f = anchor_fact(
        [0; 32],
        1,
        Locator::Storage {
            address: [0; 20],
            slot: [0; 32],
        },
        FactValue::Slot({
            let mut v = [0; 32];
            v[31] = 5;
            v
        }),
    );
    let ok = |p: Pred| eval(&f, &p);
    assert_eq!(
        ok(Pred::Lt {
            field: FieldSel::Slot,
            value: vec![6]
        }),
        Ok(true)
    );
    assert_eq!(
        ok(Pred::Le {
            field: FieldSel::Slot,
            value: vec![5]
        }),
        Ok(true)
    );
    assert_eq!(
        ok(Pred::Gt {
            field: FieldSel::Slot,
            value: vec![5]
        }),
        Ok(false)
    );
    assert_eq!(
        ok(Pred::Ge {
            field: FieldSel::Slot,
            value: vec![0, 5]
        }),
        Ok(true)
    );
    assert_eq!(
        ok(Pred::Ne {
            field: FieldSel::Slot,
            value: vec![5]
        }),
        Ok(true)
    ); // byte-exact, not numeric
    assert_eq!(
        ok(Pred::Lt {
            field: FieldSel::Slot,
            value: vec![1; 33]
        }),
        Err(ErrorCode::Malformed)
    );
    assert_eq!(
        ok(Pred::Eq {
            field: FieldSel::Balance,
            value: vec![]
        }),
        Err(ErrorCode::Malformed)
    );
}

// ---------------------------------------------------------------- ancestry (fixtures/ancestry, relayer `fetch-attest --anchor`)

/// Relayer `AttestMaterial` JSON → (target hash, anchor header rlp, ancestry).
fn ancestry_material(name: &str) -> (Value, [u8; 32], Vec<u8>, Vec<Vec<u8>>) {
    let p = format!(
        "{}/../../fixtures/ancestry/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let m: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let target = h32(&m["block_hash"]);
    let anchor = hex(&m["exec_header_rlp"]);
    let anc = proof_from_rpc(&m["ancestry"]);
    (m, target, anchor, anc)
}

/// Recorded checkpoint of the Sepolia fixtures (bootstrap finalized execution block #12062742).
fn sepolia_anchor() -> [u8; 32] {
    h32(&load("sepolia/exec_block.json")["hash"])
}

#[test]
fn ancestry_reaches_non_checkpoint_deposit() {
    let (m, target, anchor_rlp, anc) = ancestry_material("deposit.json");
    assert_eq!(anc.len(), 10);
    let (h, hash) = verify_ancestry(&anchor_rlp, sepolia_anchor(), &anc).unwrap();
    assert_eq!((hash, h.number), (target, 12_062_732));
    let receipt = hex(&m["receipt"]);
    let log = verify_receipt_log(
        &h.receipts_root,
        0,
        0,
        &receipt,
        &proof_from_rpc(&m["receipt_proof_nodes"]),
    )
    .unwrap();
    assert_eq!(log.topics[0], TRANSFER_TOPIC);
    // empty ancestry = the anchor itself
    let (h0, hash0) = verify_ancestry::<Vec<u8>>(&anchor_rlp, sepolia_anchor(), &[]).unwrap();
    assert_eq!((hash0, h0.number), (sepolia_anchor(), 12_062_742));
}

#[test]
fn ancestry_negatives() {
    let (_, _, anchor_rlp, anc) = ancestry_material("deposit.json");
    // broken link anywhere (target, middle, last-before-anchor) -> 1201
    for i in [0, 4, 9] {
        let mut bad = anc.clone();
        bad[i][40] ^= 1;
        assert_eq!(
            verify_ancestry(&anchor_rlp, sepolia_anchor(), &bad).unwrap_err(),
            ErrorCode::ExecutionHeaderMismatch,
            "i={i}"
        );
    }
    // gap (skipped block) and wrong order -> 1201
    let mut gap = anc.clone();
    gap.remove(5);
    assert_eq!(
        verify_ancestry(&anchor_rlp, sepolia_anchor(), &gap).unwrap_err(),
        ErrorCode::ExecutionHeaderMismatch
    );
    let mut rev = anc.clone();
    rev.reverse();
    assert_eq!(
        verify_ancestry(&anchor_rlp, sepolia_anchor(), &rev).unwrap_err(),
        ErrorCode::ExecutionHeaderMismatch
    );
    // over the bound -> 1001 (checked before any hashing)
    let long = vec![anc[0].clone(); MAX_ANCESTRY + 1];
    assert_eq!(
        verify_ancestry(&anchor_rlp, sepolia_anchor(), &long).unwrap_err(),
        ErrorCode::Malformed
    );
    // a real chain exactly at the bound links (log448.json: MAX_ANCESTRY real Sepolia headers)
    let (_, target, anchor_rlp, at) = ancestry_material("log448.json");
    assert_eq!(at.len(), MAX_ANCESTRY);
    let (h, hash) = verify_ancestry(&anchor_rlp, sepolia_anchor(), &at).unwrap();
    assert_eq!((hash, h.number), (target, 12_062_742 - MAX_ANCESTRY as u64));
    // one more header (a real one prepended would be the same check: length first) -> 1001
    let mut over = at.clone();
    over.insert(0, at[0].clone());
    assert_eq!(
        verify_ancestry(&anchor_rlp, sepolia_anchor(), &over).unwrap_err(),
        ErrorCode::Malformed
    );
    // the 128-header chain fixture still links
    let (_, _, anchor_rlp, chain) = ancestry_material("chain128.json");
    assert_eq!(chain.len(), 128);
    verify_ancestry(&anchor_rlp, sepolia_anchor(), &chain).unwrap();
}

/// StatementId is keyed by the attested block, not the anchor: the same log attested via two
/// different anchors has one id (one nullifier).
#[test]
fn ancestry_statement_id_independent_of_anchor() {
    let (m, target, anchor_rlp, anc) = ancestry_material("deposit.json");
    let receipt = hex(&m["receipt"]);
    let proof = proof_from_rpc(&m["receipt_proof_nodes"]);
    let fact_via = |anchor_rlp: &[u8], anchor: [u8; 32], anc: &[Vec<u8>]| {
        let (h, hash) = verify_ancestry(anchor_rlp, anchor, anc).unwrap();
        let v = verify_receipt_log(&h.receipts_root, 0, 0, &receipt, &proof).unwrap();
        attest(
            anchor_fact(
                hash,
                h.number,
                Locator::Log {
                    tx_index: 0,
                    log_index: 0,
                },
                FactValue::Log(v),
            ),
            vec![],
        )
        .unwrap()
    };
    let a = fact_via(&anchor_rlp, sepolia_anchor(), &anc);
    // anchor #12062737 = anc[5], with ancestry anc[..5]
    let mid = alloy_primitives::keccak256(&anc[5]).0;
    let b = fact_via(&anc[5], mid, &anc[..5]);
    assert_eq!(a.fact.execution_block_hash, target);
    assert_eq!(a.id, b.id);
    assert_eq!(a, b);
}
