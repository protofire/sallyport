//! Real Sepolia (Gloas) vectors from fixtures/sepolia + fixtures/lc-core, verified with real BLS (blst).
#![cfg(feature = "host-bls")]

use lc_core::host_bls::BlstVerifier;
use lc_core::json::{bootstrap_from_json, update_from_json, updates_from_json};
use lc_core::{
    apply_update, bootstrap, finish_update, hash_tree_root_header, prepare_update, verify_update,
    ChainConfig, ErrorCode, LightClientUpdate, Store, SyncCommittee,
};

fn fixture(path: &str) -> String {
    let p = format!("{}/../../fixtures/{path}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn hex32(s: &str) -> [u8; 32] {
    let v = hex::decode(s.trim_start_matches("0x")).unwrap();
    v.try_into().unwrap()
}

fn json(path: &str) -> serde_json::Value {
    serde_json::from_str(&fixture(path)).unwrap()
}

fn cfg() -> ChainConfig {
    ChainConfig::sepolia()
}

fn trusted_root() -> [u8; 32] {
    hex32(
        json("sepolia/headers_finalized.json")["result"]["data"]["root"]
            .as_str()
            .unwrap(),
    )
}

fn boot_store() -> Store {
    let b = bootstrap_from_json(&fixture("sepolia/bootstrap.json")).unwrap();
    bootstrap(&cfg(), &trusted_root(), &b, NOW).unwrap()
}

fn updates() -> Vec<LightClientUpdate> {
    updates_from_json(&fixture("sepolia/updates.json")).unwrap()
}

fn finality() -> LightClientUpdate {
    update_from_json(&fixture("sepolia/finality_update.json")).unwrap()
}

/// "Now" for the fixtures: the finality update's signature slot.
const NOW: u64 = 11_505_538;

fn step(store: &mut Store, u: &LightClientUpdate) -> Result<(), ErrorCode> {
    let v = verify_update(&cfg(), store, u, NOW, &BlstVerifier)?;
    apply_update(store, &v)
}

#[test]
fn bootstrap_from_trusted_root() {
    let s = boot_store();
    assert_eq!(s.finalized_header.beacon.slot, 11_505_472);
    assert_eq!(
        hash_tree_root_header(&s.finalized_header.beacon),
        trusted_root()
    );
    assert_eq!(
        s.finalized_header.execution_block_hash,
        hex32("0xe419a6ded1029d989b07abdaf3e5636408e5ca69af587198bcff7da5189467b1")
    );
    assert!(s.next_sync_committee.is_none());
}

#[test]
fn bootstrap_wrong_root_rejected() {
    let b = bootstrap_from_json(&fixture("sepolia/bootstrap.json")).unwrap();
    let mut root = trusted_root();
    root[0] ^= 1;
    assert_eq!(
        bootstrap(&cfg(), &root, &b, NOW),
        Err(ErrorCode::BootstrapMismatch)
    );
}

#[test]
fn bootstrap_tampered_committee_rejected() {
    let mut b = bootstrap_from_json(&fixture("sepolia/bootstrap.json")).unwrap();
    b.current_sync_committee.pubkeys[7][5] ^= 1;
    assert_eq!(
        bootstrap(&cfg(), &trusted_root(), &b, NOW),
        Err(ErrorCode::BootstrapMismatch)
    );
}

#[test]
fn bootstrap_then_update_learns_next_committee() {
    let mut s = boot_store();
    let u = &updates()[1]; // period 1404 = bootstrap period
    step(&mut s, u).unwrap();
    assert_eq!(
        s.next_sync_committee.as_ref(),
        u.next_sync_committee.as_ref().map(|(c, _)| c)
    );
    assert_eq!(
        s.finalized_header.beacon.slot, 11_505_472,
        "older finalized header must not regress store"
    );
    // replay of the same update: nothing new to learn
    assert_eq!(step(&mut s, u), Err(ErrorCode::UpdateNotNewer));
}

#[test]
fn finality_update_at_bootstrap_checkpoint_is_not_newer() {
    let mut s = boot_store();
    assert_eq!(step(&mut s, &finality()), Err(ErrorCode::UpdateNotNewer));
}

#[test]
fn update_from_older_period_is_not_newer() {
    let mut s = boot_store();
    assert_eq!(step(&mut s, &updates()[0]), Err(ErrorCode::UpdateNotNewer));
}

/// Full chain with real BLS: 1403 (learn next) -> 1404 (handoff/rotation) -> finality_update.
/// Anchor: committee of period 1403 = update(1402).next_sync_committee (fixtures/lc-core), the store
/// header = update(1403).finalized_header (first slot of 1403). Public providers no longer serve a
/// bootstrap for period 1403, so this anchor is test-only; the chain end is cross-checked against the
/// independently trusted bootstrap (committee) and headers_finalized root (header).
#[test]
fn handoff_chain_1403_1404_finality() {
    let u1402 = &updates_from_json(&fixture("lc-core/sepolia_update_1402.json")).unwrap()[0];
    let ups = updates();
    let (committee_1403, _) = u1402.next_sync_committee.clone().unwrap();
    let (fin_1403, _) = ups[0].finalized_header.clone().unwrap();
    let mut s = Store {
        finalized_header: fin_1403.to_finalized(&cfg()).unwrap(),
        current_sync_committee: committee_1403,
        next_sync_committee: None,
    };
    // Replay each update at its own signature slot: the 1403 anchor is older than Sepolia's
    // 279-epoch ws period at the fixture NOW (a live relayer applies them when they appear).
    let step = |s: &mut Store, u: &LightClientUpdate| {
        apply_update(
            s,
            &verify_update(&cfg(), s, u, u.signature_slot, &BlstVerifier)?,
        )
    };

    step(&mut s, &ups[0]).unwrap();
    assert!(s.next_sync_committee.is_some());
    step(&mut s, &ups[1]).unwrap();
    assert_eq!(s.finalized_header.beacon.slot, 11_501_600);
    let boot = bootstrap_from_json(&fixture("sepolia/bootstrap.json")).unwrap();
    assert_eq!(
        s.current_sync_committee, boot.current_sync_committee,
        "rotated committee == trusted bootstrap"
    );
    assert!(s.next_sync_committee.is_some());

    step(&mut s, &finality()).unwrap();
    assert_eq!(
        hash_tree_root_header(&s.finalized_header.beacon),
        trusted_root()
    );
    assert_eq!(step(&mut s, &finality()), Err(ErrorCode::UpdateNotNewer));
}

#[test]
fn prepare_finish_split_matches_verify() {
    let s = boot_store();
    let u = &updates()[1];
    let p = prepare_update(&cfg(), &s, u, NOW).unwrap();
    assert_eq!(p.pairing.non_signer_pubkeys.len(), 2); // 510/512 participated
    assert_eq!(
        finish_update(p.clone(), false),
        Err(ErrorCode::SyncSigInvalid)
    );
    let ok = lc_core::SigVerifier::verify_sync_aggregate(
        &BlstVerifier,
        &p.pairing.aggregate_pubkey,
        &p.pairing.non_signer_pubkeys,
        &p.pairing.signing_root,
        &p.pairing.signature,
    );
    assert!(ok);
    let via_split = finish_update(p, ok).unwrap();
    let direct = verify_update(&cfg(), &s, u, NOW, &BlstVerifier).unwrap();
    assert_eq!(via_split, direct);
}

#[test]
fn neg_finality_branch_bit_flip() {
    let s = boot_store();
    let mut u = updates()[1].clone();
    u.finalized_header.as_mut().unwrap().1[3][0] ^= 0x01;
    assert_eq!(
        verify_update(&cfg(), &s, &u, NOW, &BlstVerifier),
        Err(ErrorCode::HeaderNotFinalised)
    );
}

#[test]
fn neg_participation_below_threshold() {
    let s = boot_store();
    let mut u = updates()[1].clone();
    let bits = &mut u.sync_aggregate.sync_committee_bits;
    // keep exactly 341 participants
    let mut kept = 0;
    for i in 0..512 {
        if bits[i / 8] >> (i % 8) & 1 == 1 {
            if kept == 341 {
                bits[i / 8] &= !(1 << (i % 8));
            } else {
                kept += 1;
            }
        }
    }
    assert_eq!(
        verify_update(&cfg(), &s, &u, NOW, &BlstVerifier),
        Err(ErrorCode::ParticipationBelowThreshold)
    );
}

#[test]
fn neg_tampered_next_sync_committee() {
    let s = boot_store();
    let mut u = updates()[1].clone();
    u.next_sync_committee.as_mut().unwrap().0.pubkeys[0][10] ^= 1;
    assert_eq!(
        verify_update(&cfg(), &s, &u, NOW, &BlstVerifier),
        Err(ErrorCode::HandoffNotVerified)
    );
}

#[test]
fn neg_tampered_execution_branch() {
    let s = boot_store();
    let mut u = updates()[1].clone();
    u.attested_header.execution_branch[2][31] ^= 1;
    assert_eq!(
        verify_update(&cfg(), &s, &u, NOW, &BlstVerifier),
        Err(ErrorCode::ExecutionHeaderMismatch)
    );
    let mut u = updates()[1].clone();
    u.finalized_header.as_mut().unwrap().0.execution_branch[0][0] ^= 1;
    assert_eq!(
        verify_update(&cfg(), &s, &u, NOW, &BlstVerifier),
        Err(ErrorCode::ExecutionHeaderMismatch)
    );
}

#[test]
fn neg_wrong_genesis_validators_root() {
    let s = boot_store();
    let mut c = cfg();
    c.genesis_validators_root = ChainConfig::mainnet().genesis_validators_root;
    assert_eq!(
        verify_update(&c, &s, &updates()[1], NOW, &BlstVerifier),
        Err(ErrorCode::SyncSigInvalid)
    );
}

#[test]
fn neg_tampered_signature_and_attested_header() {
    let s = boot_store();
    let mut u = updates()[1].clone();
    u.attested_header.beacon.proposer_index += 1; // branches still hold; signed root changes
    assert_eq!(
        verify_update(&cfg(), &s, &u, NOW, &BlstVerifier),
        Err(ErrorCode::SyncSigInvalid)
    );
    let mut u = updates()[1].clone();
    u.sync_aggregate.sync_committee_bits[0] ^= 0x01; // claims a different signer set
    assert_eq!(
        verify_update(&cfg(), &s, &u, NOW, &BlstVerifier),
        Err(ErrorCode::SyncSigInvalid)
    );
}

#[test]
fn bootstrap_stale_vs_fresh() {
    let b = bootstrap_from_json(&fixture("sepolia/bootstrap.json")).unwrap();
    let slot = b.header.beacon.slot;
    let limit = cfg().ws_period_epochs * 32;
    assert!(bootstrap(&cfg(), &trusted_root(), &b, slot + limit).is_ok());
    assert_eq!(
        bootstrap(&cfg(), &trusted_root(), &b, slot + limit + 1),
        Err(ErrorCode::CheckpointStale)
    );
}

#[test]
fn neg_checkpoint_stale() {
    let s = boot_store();
    let stale_now = s.finalized_header.beacon.slot + cfg().ws_period_epochs * 32 + 1;
    assert_eq!(
        verify_update(&cfg(), &s, &updates()[1], stale_now, &BlstVerifier),
        Err(ErrorCode::CheckpointStale)
    );
}

#[test]
fn neg_signature_slot_in_future() {
    let s = boot_store();
    let u = &updates()[1];
    assert_eq!(
        verify_update(&cfg(), &s, u, u.signature_slot - 1, &BlstVerifier),
        Err(ErrorCode::Malformed)
    );
}

#[test]
fn verified_update_rejected_on_changed_store() {
    let mut s = boot_store();
    let u = &updates()[1];
    let v = verify_update(&cfg(), &s, u, NOW, &BlstVerifier).unwrap();
    apply_update(&mut s, &v).unwrap();
    assert_eq!(apply_update(&mut s, &v), Err(ErrorCode::UpdateNotNewer));
}

#[test]
fn store_borsh_roundtrip() {
    let mut s = boot_store();
    step(&mut s, &updates()[1]).unwrap();
    let bytes = borsh::to_vec(&s).unwrap();
    let back: Store = borsh::from_slice(&bytes).unwrap();
    assert_eq!(back, s);
    eprintln!(
        "Store borsh size with next committee: {} bytes",
        bytes.len()
    );
    let c: &SyncCommittee = &s.current_sync_committee;
    assert_eq!(c.pubkeys.len(), 512);
}
