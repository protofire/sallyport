//! `burn_member` tests: honest proof equals the journal vector; wrong rk, recipient,
//! index, path or root fail. Run with `RISC0_DEV_MODE=1 cargo test -p bridge-prover`.
use bridge_core::{burn_nullifier, ReleaseJournal};
use bridge_prover::{fixture_inputs, prove};

fn assert_rejected(rk: &[u8; 32], index: u64, path: &[[u8; 32]], j: &ReleaseJournal) {
    assert!(prove(rk, index, path, j).is_err(), "non-member was proven");
}

#[test]
fn honest_journal_equals_vector() {
    let (rk, index, path, j, abi) = fixture_inputs().unwrap();
    assert_eq!(j.encode(), abi);
    assert_eq!(j.nb, burn_nullifier(&rk));
    let p = prove(&rk, index, &path, &j).unwrap();
    assert_eq!(p.journal, abi);
    assert_eq!(p.journal.len(), 352);
    if p.fake {
        assert_eq!(&p.seal[..4], &[0xff; 4]);
    }
}

#[test]
fn wrong_rk_fails() {
    let (mut rk, index, path, j, _) = fixture_inputs().unwrap();
    rk[0] ^= 1;
    assert_rejected(&rk, index, &path, &j);
}

#[test]
fn wrong_recipient_fails() {
    let (rk, index, path, mut j, _) = fixture_inputs().unwrap();
    j.recipient[19] ^= 1;
    assert_rejected(&rk, index, &path, &j);
}

#[test]
fn wrong_index_fails() {
    let (rk, _, path, j, _) = fixture_inputs().unwrap();
    assert_rejected(&rk, 1, &path, &j);
    assert_rejected(&rk, 1 << 20, &path, &j);
}

#[test]
fn wrong_path_fails() {
    let (rk, index, mut path, j, _) = fixture_inputs().unwrap();
    path[0][0] ^= 1;
    assert_rejected(&rk, index, &path, &j);
    assert_rejected(&rk, index, &path[..19], &j);
}

#[test]
fn root_mismatch_fails() {
    let (rk, index, path, mut j, _) = fixture_inputs().unwrap();
    j.burn_root = [0x88; 32];
    assert_rejected(&rk, index, &path, &j);
}

#[test]
fn request_mode_round_trip() {
    let (rk, index, path, j, abi) = fixture_inputs().unwrap();
    assert_eq!(bridge_prover::decode_journal(&abi).unwrap(), j);
    let h = |b: &[u8]| format!("0x{}", hex::encode(b));
    let req = serde_json::json!({
        "rk": h(&rk), "index": index,
        "path": path.iter().map(|p| hex::encode(p)).collect::<Vec<_>>(),
        "journal": hex::encode(&abi),
    });
    let out = bridge_prover::prove_request(&req.to_string()).unwrap();
    assert_eq!(out["journal"], h(&abi));
    assert!(out["seal"].as_str().unwrap().len() > 10);
    // a journal whose Nb is not H(rk) is refused, not silently corrected
    let mut bad = abi.clone();
    bad[7 * 32] ^= 1;
    let req = serde_json::json!({ "rk": h(&rk), "index": index,
        "path": req["path"].clone(), "journal": hex::encode(&bad) });
    assert!(bridge_prover::prove_request(&req.to_string()).is_err());
}
