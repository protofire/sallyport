use alloy_primitives::{keccak256, B256};
use relayer::{el, receipt};
use serde_json::Value;

fn fx(name: &str) -> Value {
    let p = format!(
        "{}/../../fixtures/sepolia/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_slice::<Value>(&std::fs::read(p).unwrap()).unwrap()["result"].clone()
}

#[test]
fn header_rlp_hashes_to_block_hash() {
    let b = fx("exec_block.json");
    let rlp = el::header_rlp(&b).unwrap();
    assert_eq!(
        format!("{:#x}", keccak256(&rlp)),
        b["hash"].as_str().unwrap()
    );
}

#[test]
fn receipt_proof_matches_receipts_root() {
    let b = fx("exec_block.json");
    let rc = fx("eth_getBlockReceipts.json");
    let root: B256 = b["receiptsRoot"].as_str().unwrap().parse().unwrap();
    let rcs = rc.as_array().unwrap();
    for i in [0, rcs.len() / 2, rcs.len() - 1] {
        let nodes = receipt::prove(rcs, i, root).unwrap();
        assert!(!nodes.is_empty());
        assert_eq!(keccak256(&nodes[0]), root, "first node is the root node");
    }
}

/// Live Sepolia: `cargo test -p relayer -- --ignored`. `EXEC_VERIFIED=<verified_proxy_module
/// endpoint>` routes headers through it (inclusion::host::el_route).
#[test]
#[ignore]
fn live_fetch_attest_latest_finalized() {
    let vp = std::env::var("EXEC_VERIFIED").ok();
    let b = relayer::beacon::Beacon::new(11155111, &[]).unwrap();
    let fin = b.finality_update().unwrap();
    let hash = fin["data"]["finalized_header"]["execution_block_hash"]
        .as_str()
        .unwrap()
        .to_string();
    let m = el::El::new(
        11155111,
        "https://sepolia.gateway.tenderly.co",
        None,
        vp.as_deref(),
    )
    .unwrap()
    .fetch_attest(
        &hash,
        "0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9",
        Some("0x0"),
        None,
    )
    .unwrap();
    assert_eq!(format!("{:#x}", keccak256(&m.exec_header_rlp)), hash);
    assert!(!m.account_proof.is_empty() && !m.storage_proof.is_empty());
    // Ancestry through the same transport: link the finalized block to a block 5 above it.
    let el = el::El::new(
        11155111,
        "https://sepolia.gateway.tenderly.co",
        None,
        vp.as_deref(),
    )
    .unwrap();
    let n = u64::from_str_radix(
        el.block_by_hash(&hash).unwrap()["number"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
        16,
    )
    .unwrap();
    let anchor = el
        .call(
            "eth_getBlockByNumber",
            serde_json::json!([format!("{:#x}", n + 5), false]),
        )
        .unwrap();
    let (anchor_rlp, chain) = el
        .fetch_ancestry(&hash, anchor["hash"].as_str().unwrap(), 448)
        .unwrap();
    assert_eq!(chain.len(), 5);
    assert_eq!(
        format!("{:#x}", keccak256(&anchor_rlp)),
        anchor["hash"].as_str().unwrap()
    );
}
