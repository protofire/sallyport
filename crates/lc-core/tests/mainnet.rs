//! Real mainnet (Fulu = Electra-shape LightClientHeader with ExecutionPayloadHeader) vectors,
//! fixtures/lc-core/mainnet_* (lodestar-mainnet, 2026-11-04), verified with real BLS.
#![cfg(feature = "host-bls")]

use lc_core::host_bls::BlstVerifier;
use lc_core::json::{bootstrap_from_json, update_from_json, updates_from_json};
use lc_core::{
    apply_update, bootstrap, hash_tree_root_header, verify_update, ChainConfig, ErrorCode,
    LightClientUpdate, Store,
};

fn fixture(name: &str) -> String {
    let p = format!(
        "{}/../../fixtures/lc-core/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn trusted_root() -> [u8; 32] {
    let v: serde_json::Value =
        serde_json::from_str(&fixture("mainnet_headers_finalized.json")).unwrap();
    hex::decode(&v["data"]["root"].as_str().unwrap()[2..])
        .unwrap()
        .try_into()
        .unwrap()
}

const NOW: u64 = 15_581_474; // finality update signature slot

fn step(s: &mut Store, u: &LightClientUpdate) -> Result<(), ErrorCode> {
    let v = verify_update(&ChainConfig::mainnet(), s, u, NOW, &BlstVerifier)?;
    apply_update(s, &v)
}

fn boot() -> Store {
    let b = bootstrap_from_json(&fixture("mainnet_bootstrap.json")).unwrap();
    bootstrap(&ChainConfig::mainnet(), &trusted_root(), &b, NOW).unwrap()
}

#[test]
fn electra_shape_bootstrap_update_finality() {
    let mut s = boot();
    let ups = updates_from_json(&fixture("mainnet_updates.json")).unwrap();
    let fin = update_from_json(&fixture("mainnet_finality_update.json")).unwrap();

    assert_eq!(step(&mut s, &ups[0]), Err(ErrorCode::UpdateNotNewer)); // period 1901 < store period
    step(&mut s, &ups[1]).unwrap(); // learns next committee
    assert!(s.next_sync_committee.is_some());
    step(&mut s, &fin).unwrap();
    assert_eq!(s.finalized_header.beacon.slot, 15_581_408);
    let (fh, _) = fin.finalized_header.as_ref().unwrap();
    assert_eq!(
        hash_tree_root_header(&s.finalized_header.beacon),
        hash_tree_root_header(&fh.beacon)
    );
    assert_eq!(
        s.finalized_header.execution_block_hash,
        fh.execution_block_hash()
    );
}

#[test]
fn electra_shape_tampered_payload_header() {
    let s = boot();
    let mut fin = update_from_json(&fixture("mainnet_finality_update.json")).unwrap();
    if let lc_core::HeaderExecution::Electra(p) =
        &mut fin.finalized_header.as_mut().unwrap().0.execution
    {
        p.state_root[0] ^= 1;
    } else {
        panic!("expected Electra-shape header");
    }
    assert_eq!(
        verify_update(&ChainConfig::mainnet(), &s, &fin, NOW, &BlstVerifier),
        Err(ErrorCode::ExecutionHeaderMismatch)
    );
}

#[test]
fn sepolia_config_rejects_mainnet_update() {
    let s = boot();
    let fin = update_from_json(&fixture("mainnet_finality_update.json")).unwrap();
    // Sepolia schedule puts this epoch in Gloas: Electra-shape header is malformed there.
    assert_eq!(
        verify_update(&ChainConfig::sepolia(), &s, &fin, NOW, &BlstVerifier),
        Err(ErrorCode::Malformed)
    );
}
