//! Executor-level tests of the RFP-021 programs on real Sepolia/mainnet fixtures, each tx under
//! the 10M-cycle LEZ action cap. Run: `cargo test -p program-tests --release -- --nocapture`.

use attest_program::*;
use consumers::{
    untag, VaultConfig, VaultState, ATTEST_PROGRAM, ERR_ALREADY_CLAIMED, TAG_CREDIT, TAG_VAULT,
};
use inclusion::{FieldSel, Pred, EIP7708_ETH_LOG_ADDRESS};
use lc_core::{ChainConfig, Store};
use program_tests::*;

const A: InstanceId = SEPOLIA_ID;
const B: InstanceId = MAINNET_ID;

fn sepolia_chain() -> Chain {
    let mut c = Chain::new();
    c.init(&sepolia_init()).unwrap();
    c
}

fn slot_eq(v: [u8; 32]) -> Vec<Pred> {
    vec![Pred::Eq {
        field: FieldSel::Slot,
        value: v.to_vec(),
    }]
}

#[test]
fn attest_program_id_is_build_constant() {
    let id = attest_program_id();
    assert_eq!(
        *id.value(),
        ATTEST_PROGRAM,
        "update consumers::ATTEST_PROGRAM to {:?}",
        id.value()
    );
}

#[test]
fn init_from_sepolia_bootstrap() {
    let mut c = Chain::new();
    let cycles = c.init(&sepolia_init()).unwrap();
    let st = c.instance_state(&A);
    assert_eq!(st.store.finalized_header.beacon.slot, 11_505_472);
    let blk = ElBlock::sepolia();
    let rec: HeaderRecord = borsh::from_slice(&c.state_of(c.header(&A, &blk.hash))).unwrap();
    assert_eq!(rec.execution_block_hash, blk.hash);
    assert_eq!(rec.beacon_slot, 11_505_472);
    assert_eq!(rec.chain_id, 11_155_111);
    eprintln!("CYCLES Init {cycles}");
    // no re-init / reconfigure (F9/F13)
    assert_eq!(c.init(&sepolia_init()), Err(Fail::Code(1106)));
    // wrong trusted root
    let Msg::Init {
        cfg,
        mut trusted_block_root,
        bootstrap,
        now_slot,
        ..
    } = sepolia_init()
    else {
        unreachable!()
    };
    trusted_block_root[0] ^= 1;
    let instance_id = instance_id(&cfg, &trusted_block_root);
    assert_eq!(
        c.init(&Msg::Init {
            instance_id,
            cfg,
            trusted_block_root,
            bootstrap,
            now_slot
        }),
        Err(Fail::Code(1107))
    );
}

/// Instance squatting: the id is a function of the full config + checkpoint, so
/// nobody can occupy an id with a weaker config, and the protocol floor is program-enforced.
#[test]
fn init_binds_instance_id_to_config_and_enforces_floor() {
    let Msg::Init {
        cfg,
        trusted_block_root: root,
        bootstrap,
        now_slot,
        ..
    } = sepolia_init()
    else {
        unreachable!()
    };
    assert_eq!(instance_id(&cfg, &root), A);
    let Msg::Init { instance_id: m, .. } = mainnet_init() else {
        unreachable!()
    };
    assert_eq!(m, B);
    let init = |cfg: &InstanceConfig, id: InstanceId| Msg::Init {
        instance_id: id,
        cfg: cfg.clone(),
        trusted_block_root: root,
        bootstrap: bootstrap.clone(),
        now_slot,
    };
    let mut c = Chain::new();
    // caller-chosen id
    assert_eq!(c.init(&init(&cfg, [0xA1; 32])), Err(Fail::Code(1001)));
    // below the 2/3 floor / above 512 / ws period beyond the formula's maximum
    for f in [
        (|x: &mut InstanceConfig| x.chain.min_participation = 1) as fn(&mut InstanceConfig),
        |x| x.chain.min_participation = 341,
        |x| x.chain.min_participation = 513,
        |x| x.chain.ws_period_epochs = MAX_WS_PERIOD_EPOCHS + 1,
    ] {
        let mut weak = cfg.clone();
        f(&mut weak);
        assert_eq!(
            c.init(&init(&weak, instance_id(&weak, &root))),
            Err(Fail::Code(1001))
        );
    }
    // every config field and the root change the id
    let mut ids = std::collections::BTreeSet::from([A]);
    for f in [
        (|x: &mut InstanceConfig| x.chain.min_participation = 400) as fn(&mut InstanceConfig),
        |x| x.chain.ws_period_epochs -= 1,
        |x| x.chain.chain_id += 1,
        |x| x.chain.genesis_validators_root[0] ^= 1,
        |x| x.chain.fork_versions[0].1[3] ^= 1,
        |x| x.chain.electra_fork_epoch += 1,
        |x| x.chain.gloas_fork_epoch += 1,
        |x| x.genesis_time += 1,
    ] {
        let mut other = cfg.clone();
        f(&mut other);
        assert!(ids.insert(instance_id(&other, &root)));
    }
    assert!(ids.insert(instance_id(&cfg, &[0x5A; 32])));
    // same config + root = same id: the second Init hits the existing instance
    c.init(&init(&cfg, A)).unwrap();
    assert_eq!(c.init(&init(&cfg, A)), Err(Fail::Code(1106)));
}

#[test]
fn update_learns_next_committee_then_rejects_replay() {
    let mut c = sepolia_chain();
    let u = &sepolia_updates()[1];
    let (b, v) = c.update(A, 1, u, SEPOLIA_NOW).unwrap();
    eprintln!("CYCLES UpdateBegin(K=2) {b}  UpdateVerify {v}");
    let st = c.instance_state(&A);
    assert_eq!(
        st.store.next_sync_committee.as_ref(),
        u.next_sync_committee.as_ref().map(|(c, _)| c)
    );
    // duplicate / stale -> 1106 (R8), any submitter
    assert_eq!(c.begin(A, 2, u, SEPOLIA_NOW), Err(Fail::Code(1106)));
    assert_eq!(
        c.begin(A, 3, &sepolia_finality(), SEPOLIA_NOW),
        Err(Fail::Code(1106))
    );
    // finished job cannot be verified again
    assert_eq!(c.verify(A, 1, u, vec![0; 864]), Err(Fail::Code(1106)));
}

#[test]
fn update_now_slot_must_match_block_time() {
    let mut c = sepolia_chain();
    let u = &sepolia_updates()[1];
    let inst = c.instance(&A);
    let job = c.seeded(c.attest, job_seed(&A, 9));
    c.timestamp_ms = sepolia_cfg().slot_start_ms(SEPOLIA_NOW + 100); // block 20 min after now_slot
    let r = c.send(
        inst,
        vec![job],
        &Msg::UpdateBegin {
            instance_id: A,
            job_id: 9,
            update: u.clone(),
            non_signers: c.hints(A, u, SEPOLIA_NOW),
            now_slot: SEPOLIA_NOW,
        },
    );
    assert!(
        matches!(r, Err(Fail::Other(ref e)) if e.contains("alidity")),
        "{r:?}"
    );
}

#[test]
fn verify_rejects_bad_signature_set_and_bad_witness() {
    let mut c = sepolia_chain();
    let good = sepolia_updates()[1].clone();
    let st = c.instance_state(&A);
    let w = witness(&st.cfg, &st.store, &good, SEPOLIA_NOW);
    // Non-signers are derived in-program by index from the stored committee: flipping one bit
    // (claiming a different signer set) changes apk, so the honest witness no longer fits.
    let mut u = good.clone();
    u.sync_aggregate.sync_committee_bits[0] ^= 1;
    c.begin(A, 1, &u, SEPOLIA_NOW).unwrap();
    assert_eq!(c.verify(A, 1, &u, w.clone()), Err(Fail::Code(1102)));
    // wrong-length / empty witness -> 1102
    assert_eq!(c.verify(A, 1, &u, vec![]), Err(Fail::Code(1102)));
    // zero witness (c = 0) and a noncanonical coefficient (p > field modulus) are typed 1102, not a trap
    c.begin(A, 2, &good, SEPOLIA_NOW).unwrap();
    assert_eq!(c.verify(A, 2, &good, vec![0; 864]), Err(Fail::Code(1102)));
    assert_eq!(
        c.verify(A, 2, &good, vec![0xFF; 864]),
        Err(Fail::Code(1102))
    );
    // tampered attested header (signed root changes)
    let mut u = good.clone();
    u.attested_header.beacon.proposer_index += 1;
    c.begin(A, 3, &u, SEPOLIA_NOW).unwrap();
    assert_eq!(c.verify(A, 3, &u, w.clone()), Err(Fail::Code(1102)));
    // honest job still verifies
    c.verify(A, 2, &good, w).unwrap();
}

/// Non-signer hints must be exactly the uncompressed stored keys at the indices the program
/// derives from sync_committee_bits: every substitution is rejected (1102).
#[test]
fn non_signer_hints_are_bound_to_stored_keys() {
    use blst::*;
    let mut c = sepolia_chain();
    let u = sepolia_updates()[1].clone();
    let mut good = c.hints(A, &u, SEPOLIA_NOW);
    assert_eq!(good.len(), 4);
    let tail = good.split_off(2); // uncompressed aggregate + signature hints (D-UPD-2)
    let aff = |b: &[u8]| {
        let mut a = blst_p1_affine::default();
        unsafe {
            assert_eq!(
                blst_p1_deserialize(&mut a, b.as_ptr()),
                BLST_ERROR::BLST_SUCCESS
            )
        };
        a
    };
    let ser = |p: &blst_p1| {
        let (mut a, mut o) = (blst_p1_affine::default(), vec![0u8; 96]);
        unsafe {
            blst_p1_to_affine(&mut a, p);
            blst_p1_affine_serialize(o.as_mut_ptr(), &a);
        }
        o
    };
    let (mut s, mut x) = (blst_p1::default(), blst_p1::default());
    unsafe {
        blst_p1_from_affine(&mut x, &aff(&good[0]));
        blst_p1_add_or_double_affine(&mut s, &x, &aff(&good[1]));
    }
    let sum = ser(&s);
    let mut neg = x;
    unsafe { blst_p1_cneg(&mut neg, true) };
    let mut identity = vec![0u8; 96];
    identity[0] = 0x40;
    let cases: Vec<(&str, Vec<Vec<u8>>)> = vec![
        ("sum of two replaces both", vec![sum.clone()]),
        ("sum in place of first", vec![sum, good[1].clone()]),
        (
            "identity appended",
            vec![good[0].clone(), good[1].clone(), identity.clone()],
        ),
        ("identity in place", vec![identity, good[1].clone()]),
        (
            "X and -X appended",
            vec![good[0].clone(), good[1].clone(), good[0].clone(), ser(&neg)],
        ),
        ("key at wrong index", vec![good[1].clone(), good[0].clone()]),
        ("negated key", vec![ser(&neg), good[1].clone()]),
        ("missing", vec![]),
    ];
    for (i, (name, h)) in cases.into_iter().enumerate() {
        assert_eq!(
            c.begin_hinted(A, 10 + i as u64, &u, SEPOLIA_NOW, h.clone()),
            Err(Fail::Code(1102)),
            "{name}"
        );
        assert_eq!(
            c.update_one_hinted(A, &u, SEPOLIA_NOW, h, vec![0; 864]),
            Err(Fail::Code(1102)),
            "single-tx {name}"
        );
    }
    // Compressed encoding + padding decodes to the same point via blst deserialize; only the
    // uncompressed form is accepted for the aggregate (G1) and signature (G2) hints.
    let mut agg_c = vec![0u8; 96];
    let mut sig_c = vec![0u8; 192];
    unsafe {
        blst_p1_affine_compress(agg_c.as_mut_ptr(), &aff(&tail[0]));
        let mut s2 = blst_p2_affine::default();
        assert_eq!(
            blst_p2_deserialize(&mut s2, tail[1].as_ptr()),
            BLST_ERROR::BLST_SUCCESS
        );
        blst_p2_affine_compress(sig_c.as_mut_ptr(), &s2);
    }
    for (i, (name, t)) in [
        (
            "G1 aggregate compressed+padding",
            vec![agg_c, tail[1].clone()],
        ),
        (
            "G2 signature compressed+padding",
            vec![tail[0].clone(), sig_c],
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut h = good.clone();
        h.extend(t);
        assert_eq!(
            c.begin_hinted(A, 30 + i as u64, &u, SEPOLIA_NOW, h.clone()),
            Err(Fail::Code(1102)),
            "{name}"
        );
        assert_eq!(
            c.update_one_hinted(A, &u, SEPOLIA_NOW, h, vec![0; 864]),
            Err(Fail::Code(1102)),
            "single-tx {name}"
        );
    }
    c.begin_hinted(A, 1, &u, SEPOLIA_NOW, good.clone()).unwrap();
    good.extend(tail);
    c.begin_hinted(A, 2, &u, SEPOLIA_NOW, good).unwrap();
}

/// Full handoff through the program: learn next (1403) → rotation + finality (1404) → finality
/// update; ends at the trusted bootstrap root with header records written.
#[test]
fn handoff_chain_records_headers() {
    let mut c = Chain::new();
    let cfg = sepolia_cfg();
    let u1402 =
        &lc_core::json::updates_from_json(&fixture("lc-core/sepolia_update_1402.json")).unwrap()[0];
    let ups = sepolia_updates();
    let (committee_1403, _) = u1402.next_sync_committee.clone().unwrap();
    let (fin_1403, _) = ups[0].finalized_header.clone().unwrap();
    let store = Store {
        finalized_header: fin_1403.to_finalized(&cfg.chain).unwrap(),
        current_sync_committee: committee_1403,
        next_sync_committee: None,
    };
    force_instance(
        &mut c,
        A,
        &InstanceState {
            cfg: cfg.clone(),
            store,
            headers: Frontier::default(),
        },
    );

    let (b0, v0) = c.update(A, 1, &ups[0], ups[0].signature_slot).unwrap();
    let (b1, v1) = c.update(A, 2, &ups[1], ups[1].signature_slot).unwrap();
    let fin = sepolia_finality();
    let (b2, v2) = c.update(A, 3, &fin, fin.signature_slot).unwrap();
    eprintln!("CYCLES handoff Begin/Verify: learn {b0}/{v0} rotate {b1}/{v1} finality {b2}/{v2}");
    let st = c.instance_state(&A);
    let boot = lc_core::json::bootstrap_from_json(&fixture("sepolia/bootstrap.json")).unwrap();
    assert_eq!(st.store.current_sync_committee, boot.current_sync_committee);
    for (f, _) in [
        ups[1].finalized_header.clone().unwrap(),
        sepolia_finality().finalized_header.unwrap(),
    ] {
        let ebh = f.to_finalized(&cfg.chain).unwrap().execution_block_hash;
        let rec: HeaderRecord = borsh::from_slice(&c.state_of(c.header(&A, &ebh))).unwrap();
        assert_eq!(rec.beacon_slot, f.beacon.slot);
    }
    // header written by an update is attestable
    let blk = ElBlock::sepolia();
    let (token, to, amount) = blk.log(1, 1);
    c.attest(
        blk.hash,
        blk.attest_log(
            A,
            1,
            1,
            inclusion::erc20_transfer_preds(token, None, Some(to), Some(amount)),
        ),
    )
    .unwrap();
}

#[test]
fn attest_slot_erc20_log_and_native_eth_log() {
    let mut c = sepolia_chain();
    let blk = ElBlock::sepolia();
    let weth_name = h32("0x577261707065642045746865720000000000000000000000000000000000001a");
    let slot = c
        .attest(blk.hash, weth_slot0(A, slot_eq(weth_name)))
        .unwrap();
    assert_eq!(
        c.attest(blk.hash, weth_slot0(A, slot_eq([1; 32]))),
        Err(Fail::Code(1203))
    );
    let (token, to, amount) = blk.log(1, 1);
    let erc20 = c
        .attest(
            blk.hash,
            blk.attest_log(
                A,
                1,
                1,
                inclusion::erc20_transfer_preds(token, None, Some(to), Some(amount)),
            ),
        )
        .unwrap();
    let (sys, to, amount) = blk.log(2, 0);
    assert_eq!(sys, EIP7708_ETH_LOG_ADDRESS);
    let eth = c
        .attest(
            blk.hash,
            blk.attest_log(
                A,
                2,
                0,
                inclusion::native_eth_transfer_preds(None, Some(to), Some(amount)),
            ),
        )
        .unwrap();
    eprintln!("CYCLES Attest-slot {slot}  Attest-log(erc20) {erc20}  Attest-log(eth) {eth}");
    // tampered receipt -> 1202, tampered header -> 1201
    let mut req = blk.attest_log(A, 1, 1, vec![]);
    if let Proof::Log { receipt, .. } = &mut req.proof {
        receipt[40] ^= 1;
    }
    assert_eq!(c.attest(blk.hash, req), Err(Fail::Code(1202)));
    let mut req = blk.attest_log(A, 1, 1, vec![]);
    req.exec_header_rlp[10] ^= 1;
    assert_eq!(c.attest(blk.hash, req), Err(Fail::Code(1201)));
}

#[test]
fn attest_under_unrecorded_header_is_1101() {
    let mut c = sepolia_chain();
    let other = ElBlock::inclusion_fixture_block(); // real Sepolia block, never finalized into A
    let mut req = weth_slot0(A, vec![]);
    req.exec_header_rlp = other.rlp.clone();
    assert_eq!(c.attest(other.hash, req), Err(Fail::Code(1101)));
}

/// A Transfer log 10 blocks before the recorded checkpoint is attested through the header chain.
#[test]
fn attest_non_checkpoint_deposit_via_ancestry() {
    let mut c = sepolia_chain();
    let anchor = ElBlock::sepolia().hash;
    let d = AncestryLog::load("deposit.json");
    assert_eq!(d.ancestry.len(), 10);
    // the deposit block itself was never recorded
    let mut direct = d.request(A, d.preds());
    direct.exec_header_rlp = d.ancestry[0].clone();
    direct.ancestry.clear();
    assert_eq!(c.attest(d.hash, direct), Err(Fail::Code(1101)));
    let cycles = c.attest(anchor, d.request(A, d.preds())).unwrap();
    eprintln!("CYCLES Attest-log via ancestry(10) {cycles}");
    let rec: HeaderRecord = borsh::from_slice(&c.state_of(c.header(&A, &anchor))).unwrap();
    let st = verify(&rec, &d.request(A, d.preds())).unwrap();
    assert_eq!(
        (st.fact.execution_block_hash, st.fact.block_number),
        (d.hash, 12_062_732)
    );
    // predicates are still checked against the target block's log
    let mut wrong = d.preds();
    wrong.push(Pred::Eq {
        field: FieldSel::LogDataWord(0),
        value: vec![0; 32],
    });
    assert_eq!(c.attest(anchor, d.request(A, wrong)), Err(Fail::Code(1203)));
}

/// Public consumer claim of a non-checkpoint block: Claim names the recorded anchor, the reply comes
/// from the anchor's header PDA, the credit and nullifier are about the target block.
#[test]
fn erc20_claim_via_ancestry_and_replay() {
    let mut c = sepolia_chain();
    let anchor = ElBlock::sepolia().hash;
    let d = AncestryLog::load("deposit.json");
    let (token, to) = (
        h20(d.log["address"].as_str().unwrap()),
        h32(d.log["topics"][2].as_str().unwrap())[12..]
            .try_into()
            .unwrap(),
    );
    let amount = h32(d.log["data"].as_str().unwrap());
    let erc20 = c.erc20;
    c.init_vault(erc20, [9; 32], vault_cfg(A, token, to))
        .unwrap();
    let s = ChainConfig::sepolia();
    let null = c.actor(
        erc20,
        consumers::nullifier_seed(
            &[9; 32],
            &statement_id_for(s.chain_id, s.genesis_validators_root, d.hash, d.tx_index, 0),
        ),
    );
    let claim = |block_hash: [u8; 32], exec_header_rlp: Vec<u8>, ancestry: Vec<Vec<u8>>| {
        consumers::ConsumerMsg::Claim {
            vault_id: [9; 32],
            block_hash,
            exec_header_rlp,
            ancestry,
            tx_index: d.tx_index,
            log_index: 0,
            receipt: d.receipt.clone(),
            receipt_proof: d.receipt_proof.clone(),
            amount,
        }
    };
    let v = c.vault(erc20, [9; 32]);
    // the target block itself was never recorded
    let tgt = c.seeded(c.attest, header_seed(&A, &d.hash));
    assert_eq!(
        c.send(
            v,
            vec![tgt, null],
            &claim(d.hash, d.ancestry[0].clone(), vec![])
        ),
        Err(Fail::Code(1101))
    );
    let hdr = c.seeded(c.attest, header_seed(&A, &anchor));
    let ok = claim(anchor, d.anchor_rlp.clone(), d.ancestry.clone());
    // a receipt that is not the proof's leaf is 1202 (checked by the consumer, D-GAS-6)
    let mut bad = ok.clone();
    if let consumers::ConsumerMsg::Claim { receipt, .. } = &mut bad {
        receipt[40] ^= 1;
    }
    assert_eq!(c.send(v, vec![hdr, null], &bad), Err(Fail::Code(1202)));
    c.send(v, vec![hdr, null], &ok).unwrap();
    let vs: VaultState = untag(TAG_VAULT, &c.state_of(v)).unwrap();
    assert_eq!(
        (vs.claims, vs.credited_total),
        (1, u128::from_be_bytes(amount[16..].try_into().unwrap()))
    );
    let cr: consumers::Credit = untag(TAG_CREDIT, &c.state_of(null)).unwrap();
    assert_eq!(
        cr.eth_sender.to_vec(),
        h32(d.log["topics"][1].as_str().unwrap())[12..].to_vec()
    );
    assert_eq!(
        c.send(v, vec![hdr, null], &ok),
        Err(Fail::Code(ERR_ALREADY_CLAIMED))
    );
}

#[test]
fn ancestry_broken_link_is_1201_and_over_bound_is_1001() {
    let mut c = sepolia_chain();
    let anchor = ElBlock::sepolia().hash;
    let d = AncestryLog::load("deposit.json");
    for i in [0, 5, 9] {
        let mut req = d.request(A, vec![]);
        req.ancestry[i][40] ^= 1;
        assert_eq!(c.attest(anchor, req), Err(Fail::Code(1201)), "link {i}");
    }
    let mut req = d.request(A, vec![]);
    req.ancestry.remove(3);
    assert_eq!(c.attest(anchor, req), Err(Fail::Code(1201)), "gap");
    let mut req = d.request(A, vec![]);
    req.ancestry = vec![d.ancestry[0].clone(); inclusion::MAX_ANCESTRY + 1];
    assert_eq!(c.attest(anchor, req), Err(Fail::Code(1001)));
}

/// Nullifier safety: the StatementId names the attested block, so the same deposit attested via
/// two different recorded anchors yields one id.
#[test]
fn same_fact_via_two_anchors_has_one_statement_id() {
    let mut c = sepolia_chain();
    let anchor = ElBlock::sepolia().hash;
    let d = AncestryLog::load("deposit.json");
    let rec: HeaderRecord = borsh::from_slice(&c.state_of(c.header(&A, &anchor))).unwrap();
    // Second anchor: block #12062737 (= ancestry[5]) recorded as if a checkpoint (test-only seeding;
    // only the hash matters to Attest).
    let mid = alloy_primitives::keccak256(&d.ancestry[5]).0;
    let rec2 = HeaderRecord {
        execution_block_hash: mid,
        beacon_slot: rec.beacon_slot - 5,
        ..rec.clone()
    };
    let a2 = c.seeded(c.attest, header_seed(&A, &mid));
    c.force_actor(a2, borsh::to_vec(&rec2).unwrap());
    let mut via_mid = d.request(A, d.preds());
    via_mid.exec_header_rlp = d.ancestry[5].clone();
    via_mid.ancestry.truncate(5);
    c.attest(anchor, d.request(A, d.preds())).unwrap();
    c.attest(mid, via_mid.clone()).unwrap();
    let s1 = verify(&rec, &d.request(A, d.preds())).unwrap();
    let s2 = verify(&rec2, &via_mid).unwrap();
    assert_eq!(s1.id, s2.id);
    assert_eq!(s1, s2);
    assert_eq!(s1.id, inclusion::statement_id(&s1.fact));
    assert_eq!(s1.fact.execution_block_hash, d.hash);
}

/// Attest cost vs ancestry depth (each row = one tx under the 10M cap). With the risc0 keccak
/// coprocessor (docs/DECISIONS.md D-ATT-7) the bound is 448; software keccak needed 32.
#[test]
fn ancestry_cycle_table() {
    let mut c = sepolia_chain();
    let blk = ElBlock::sepolia();
    let (token, to, amount) = blk.log(1, 1);
    let mut rows = vec![(
        0usize,
        c.attest(
            blk.hash,
            blk.attest_log(
                A,
                1,
                1,
                inclusion::erc20_transfer_preds(token, None, Some(to), Some(amount)),
            ),
        )
        .unwrap(),
    )];
    for name in ["deposit.json", "log32.json", "log128.json", "log448.json"] {
        let l = AncestryLog::load(name);
        rows.push((
            l.ancestry.len(),
            c.attest(blk.hash, l.request(A, l.preds())).unwrap(),
        ));
    }
    assert_eq!(rows[4].0, inclusion::MAX_ANCESTRY);
    eprintln!("\n| Attest log, ancestry headers | cycles | % of 10M |\n|---:|---:|---:|");
    for (n, cy) in &rows {
        eprintln!("| {n} | {cy} | {:.1}% |", *cy as f64 / 1e5);
        assert!(*cy <= MAX_GAS_EXEC);
    }
    let per = (rows[4].1 - rows[0].1) / rows[4].0 as u64;
    eprintln!("per header ≈ {per} cycles");
}

fn vault_cfg(instance_id: InstanceId, token: [u8; 20], vault_address: [u8; 20]) -> VaultConfig {
    let s = ChainConfig::sepolia();
    VaultConfig {
        instance_id,
        chain_id: s.chain_id,
        genesis_validators_root: s.genesis_validators_root,
        token,
        vault_address,
    }
}

#[test]
fn erc20_receiver_claim_replay_and_wrong_amount_recipient() {
    let mut c = sepolia_chain();
    let blk = ElBlock::sepolia();
    let (token, to, amount) = blk.log(1, 1);
    let erc20 = c.erc20;
    c.init_vault(erc20, [1; 32], vault_cfg(A, token, to))
        .unwrap();
    let mut wrong = amount;
    wrong[31] ^= 1;
    assert_eq!(
        c.claim(erc20, [1; 32], A, &blk, 1, 1, wrong),
        Err(Fail::Code(1203))
    );
    let cycles = c.claim(erc20, [1; 32], A, &blk, 1, 1, amount).unwrap();
    eprintln!("CYCLES consumer-claim(erc20) {cycles}");
    let v: VaultState = untag(TAG_VAULT, &c.state_of(c.vault(erc20, [1; 32]))).unwrap();
    assert_eq!(v.claims, 1);
    assert_eq!(
        v.credited_total,
        u128::from_be_bytes(amount[16..].try_into().unwrap())
    );
    assert_eq!(
        c.claim(erc20, [1; 32], A, &blk, 1, 1, amount),
        Err(Fail::Code(ERR_ALREADY_CLAIMED))
    );
    // Another vault with the same config is its own ledger (nullifier keyed on vault_id too):
    // it records its own credit and cannot touch vault [1]'s (see `clone_vault_cannot_steal_deposit`).
    c.init_vault(erc20, [2; 32], vault_cfg(A, token, to))
        .unwrap();
    c.claim(erc20, [2; 32], A, &blk, 1, 1, amount).unwrap();
    assert_eq!(
        c.claim(erc20, [2; 32], A, &blk, 1, 1, amount),
        Err(Fail::Code(ERR_ALREADY_CLAIMED))
    );
    // vault for a different recipient: transfer to `to` is not a deposit to it
    c.init_vault(erc20, [3; 32], vault_cfg(A, token, [0x33; 20]))
        .unwrap();
    assert_eq!(
        c.claim(erc20, [3; 32], A, &blk, 1, 5, amount),
        Err(Fail::Code(1203))
    );
}

/// Review finding: `InitVault` is permissionless and the nullifier was keyed on the statement
/// alone, so anyone could create a clone vault with the identical config, claim each deposit
/// there first, and make the real vault's claim fail 1250 for good. Now each vault has its own
/// nullifier: the clone's claim leaves the real vault's untouched.
#[test]
fn clone_vault_cannot_steal_deposit() {
    let mut c = sepolia_chain();
    let blk = ElBlock::sepolia();
    let (token, to, amount) = blk.log(1, 1);
    let erc20 = c.erc20;
    let (real, clone) = ([1; 32], [0xC0; 32]);
    c.init_vault(erc20, real, vault_cfg(A, token, to)).unwrap();
    c.init_vault(erc20, clone, vault_cfg(A, token, to)).unwrap();
    c.claim(erc20, clone, A, &blk, 1, 1, amount).unwrap(); // front-run into the clone
    c.claim(erc20, real, A, &blk, 1, 1, amount).unwrap();
    let v: VaultState = untag(TAG_VAULT, &c.state_of(c.vault(erc20, real))).unwrap();
    assert_eq!(
        (v.claims, v.credited_total),
        (1, u128::from_be_bytes(amount[16..].try_into().unwrap()))
    );
    assert_eq!(
        c.claim(erc20, real, A, &blk, 1, 1, amount),
        Err(Fail::Code(ERR_ALREADY_CLAIMED))
    );
}

#[test]
fn eth_receiver_claims_eip7708_log() {
    let mut c = sepolia_chain();
    let blk = ElBlock::sepolia();
    let (sys, to, amount) = blk.log(2, 0);
    let eth = c.eth;
    // eth_receiver pins the token to the EIP-7708 system address
    assert_eq!(
        c.init_vault(eth, [1; 32], vault_cfg(A, [0xEE; 20], to)),
        Err(Fail::Code(1001))
    );
    c.init_vault(eth, [1; 32], vault_cfg(A, sys, to)).unwrap();
    let cycles = c.claim(eth, [1; 32], A, &blk, 2, 0, amount).unwrap();
    eprintln!("CYCLES consumer-claim(eth) {cycles}");
    // an ERC-20 log to the same address is not native ETH
    assert_eq!(
        c.claim(eth, [1; 32], A, &blk, 1, 1, blk.log(1, 1).2),
        Err(Fail::Code(1203))
    );
    assert_eq!(
        c.claim(eth, [1; 32], A, &blk, 2, 0, amount),
        Err(Fail::Code(ERR_ALREADY_CLAIMED))
    );
}

#[test]
fn two_instances_do_not_interfere_and_cross_instance_rejected() {
    let mut c = sepolia_chain();
    c.init(&mainnet_init()).unwrap();
    // Sepolia update into the mainnet instance: wrong chain -> rejected
    assert!(c.begin(B, 1, &sepolia_updates()[1], MAINNET_NOW).is_err());
    // mainnet: learn next, then finality advance (records a mainnet header)
    let ups = lc_core::json::updates_from_json(&fixture("lc-core/mainnet_updates.json")).unwrap();
    let fin =
        lc_core::json::update_from_json(&fixture("lc-core/mainnet_finality_update.json")).unwrap();
    c.update(B, 1, &ups[1], MAINNET_NOW).unwrap();
    let (b, v) = c.update(B, 2, &fin, MAINNET_NOW).unwrap();
    eprintln!("CYCLES mainnet finality Begin {b} Verify {v}");
    assert_eq!(
        c.instance_state(&B).store.finalized_header.beacon.slot,
        15_581_408
    );
    assert_eq!(
        c.instance_state(&A).store.finalized_header.beacon.slot,
        11_505_472
    );
    // Sepolia header is not recorded under B: attest via B -> 1101
    let blk = ElBlock::sepolia();
    assert_eq!(
        c.attest(blk.hash, weth_slot0(B, vec![])),
        Err(Fail::Code(1101))
    );
    // vault pinned to B cannot be fed a Sepolia (instance A) statement
    let (token, to, amount) = blk.log(1, 1);
    let erc20 = c.erc20;
    c.init_vault(erc20, [5; 32], vault_cfg(B, token, to))
        .unwrap();
    assert_eq!(
        c.claim(erc20, [5; 32], B, &blk, 1, 1, amount),
        Err(Fail::Code(1101))
    );
    // a second Sepolia instance from the same bootstrap is independent of A
    let Msg::Init {
        mut cfg,
        trusted_block_root,
        bootstrap,
        now_slot,
        ..
    } = sepolia_init()
    else {
        unreachable!()
    };
    cfg.chain.ws_period_epochs -= 1; // another config, so another id
    let a2 = instance_id(&cfg, &trusted_block_root);
    c.init(&Msg::Init {
        instance_id: a2,
        cfg,
        trusted_block_root,
        bootstrap,
        now_slot,
    })
    .unwrap();
    c.update(A, 7, &sepolia_updates()[1], SEPOLIA_NOW).unwrap();
    assert!(c.instance_state(&a2).store.next_sync_committee.is_none());
}

/// F5: the same contract address, storage slot and log locator under a Sepolia-config and a
/// mainnet-config instance. The two statements differ (chain-bound id), each instance answers only
/// for itself, and a consumer bound to one rejects the other's statement.
#[test]
fn f5_same_contract_address_on_sepolia_and_mainnet() {
    let mut c = sepolia_chain();
    c.init(&mainnet_init()).unwrap();
    let blk = ElBlock::sepolia();
    let (token, to, amount) = blk.log(1, 1);
    let (s, m) = (ChainConfig::sepolia(), ChainConfig::mainnet());
    let erc20 = c.erc20;
    let bound = |instance_id, ch: &ChainConfig| VaultConfig {
        instance_id,
        chain_id: ch.chain_id,
        genesis_validators_root: ch.genesis_validators_root,
        token,
        vault_address: to,
    };
    // Mainnet-bound consumer, block finalised only on the Sepolia instance: 1101.
    c.init_vault(erc20, [7; 32], bound(B, &m)).unwrap();
    assert_eq!(
        c.claim(erc20, [7; 32], B, &blk, 1, 1, amount),
        Err(Fail::Code(1101))
    );
    // Same EL block (so same contract address, slot, receipt) also recorded under the mainnet instance.
    let rec_a: HeaderRecord = borsh::from_slice(&c.state_of(c.header(&A, &blk.hash))).unwrap();
    let rec_b = HeaderRecord {
        instance_id: B,
        chain_id: m.chain_id,
        genesis_validators_root: m.genesis_validators_root,
        ..rec_a.clone()
    };
    let hb = c.header(&B, &blk.hash);
    c.force_actor(hb, borsh::to_vec(&rec_b).unwrap());
    let weth = h32("0x577261707065642045746865720000000000000000000000000000000000001a");
    let preds = inclusion::erc20_transfer_preds(token, None, Some(to), Some(amount));
    for (req_a, req_b) in [
        (weth_slot0(A, slot_eq(weth)), weth_slot0(B, slot_eq(weth))),
        (
            blk.attest_log(A, 1, 1, preds.clone()),
            blk.attest_log(B, 1, 1, preds),
        ),
    ] {
        c.attest(blk.hash, req_a.clone()).unwrap();
        c.attest(blk.hash, req_b.clone()).unwrap();
        let (sa, sb) = (
            verify(&rec_a, &req_a).unwrap(),
            verify(&rec_b, &req_b).unwrap(),
        );
        assert_eq!(
            (&sa.fact.locator, &sa.fact.value),
            (&sb.fact.locator, &sb.fact.value)
        );
        assert_eq!(
            (sa.fact.chain_id, sb.fact.chain_id),
            (s.chain_id, m.chain_id)
        );
        assert_ne!(sa.id, sb.id, "statement id is chain-bound");
        // A Sepolia-instance request sent to the mainnet header PDA is refused.
        assert_eq!(
            c.send(hb, vec![], &Msg::Attest(req_a)),
            Err(Fail::Code(1001))
        );
    }
    // Consumers whose chain binding disagrees with the pinned instance reject its statement (1204).
    c.init_vault(erc20, [8; 32], bound(A, &m)).unwrap();
    assert_eq!(
        c.claim(erc20, [8; 32], A, &blk, 1, 1, amount),
        Err(Fail::Code(1204))
    );
    c.init_vault(erc20, [9; 32], bound(B, &s)).unwrap();
    assert_eq!(
        c.claim(erc20, [9; 32], B, &blk, 1, 1, amount),
        Err(Fail::Code(1204))
    );
    // The Sepolia-bound consumer accepts the Sepolia statement.
    c.init_vault(erc20, [6; 32], bound(A, &s)).unwrap();
    c.claim(erc20, [6; 32], A, &blk, 1, 1, amount).unwrap();
}

/// Cycle cost of UpdateBegin vs number of non-signers K (Verify is K-independent: apk is
/// precomputed in Begin). Signatures are invalid for K != 2, which Begin does not check.
#[test]
fn begin_cycles_by_non_signers() {
    let mut rows = vec![];
    for k in [2usize, 20, 30, 64, 128, 170] {
        let mut c = sepolia_chain();
        let mut u = sepolia_updates()[1].clone();
        let bits = &mut u.sync_aggregate.sync_committee_bits;
        let mut missing = 512 - bits.iter().map(|b| b.count_ones() as usize).sum::<usize>();
        for i in 0..512 {
            if missing >= k {
                break;
            }
            if bits[i / 8] >> (i % 8) & 1 == 1 {
                bits[i / 8] &= !(1 << (i % 8));
                missing += 1;
            }
        }
        c.budget = 64_000_000; // measure beyond the cap
        let cycles = c.begin(A, 1, &u, SEPOLIA_NOW).unwrap();
        rows.push((k, cycles));
    }
    for (k, cy) in &rows {
        eprintln!(
            "CYCLES UpdateBegin K={k:<3} {cy:>10} {}",
            if *cy <= MAX_GAS_EXEC {
                "fits"
            } else {
                "OVER 10M"
            }
        );
    }
    // K = 170 is the most non-signers a 342-of-512 update can have: every K must fit the cap.
    for (k, cy) in &rows {
        assert!(
            *cy <= MAX_GAS_EXEC,
            "UpdateBegin K={k}: {cy} cycles > {MAX_GAS_EXEC}"
        );
    }
}

/// Optional inline consumer (D-GAS-7): same credit, nullifier and replay rule as the chained
/// erc20_receiver; the anchor is bound by CheckHeader, so an unrecorded anchor (1101) or a vault
/// pinned to another chain (1204) fails the whole tx and leaves vault and nullifier untouched.
#[test]
fn inline_consumer_claim_binds_header() {
    let mut c = sepolia_chain();
    let blk = ElBlock::sepolia();
    let (token, to, amount) = blk.log(1, 1);
    let p = c.erc20_inline;
    c.init_vault(p, [1; 32], vault_cfg(A, token, to)).unwrap();
    let cycles = c.claim(p, [1; 32], A, &blk, 1, 1, amount).unwrap();
    eprintln!("CYCLES erc20_inline_receiver Claim {cycles}");
    let s = ChainConfig::sepolia();
    let sid = statement_id_for(s.chain_id, s.genesis_validators_root, blk.hash, 1, 1);
    let credit: consumers::Credit = untag(
        TAG_CREDIT,
        &c.state_of(c.actor(p, consumers::nullifier_seed(&[1; 32], &sid))),
    )
    .unwrap();
    assert_eq!(credit.eth_sender, blk.log_from(1, 1));
    assert_eq!(
        c.claim(p, [1; 32], A, &blk, 1, 1, amount),
        Err(Fail::Code(ERR_ALREADY_CLAIMED))
    );
    // vault pinned to another chain id: inline verification passes, CheckHeader rejects
    let mut cfg = vault_cfg(A, token, to);
    cfg.chain_id += 1;
    c.init_vault(p, [2; 32], cfg.clone()).unwrap();
    let v = c.vault(p, [2; 32]);
    let before = c.state_of(v);
    let sid2 = statement_id_for(cfg.chain_id, s.genesis_validators_root, blk.hash, 1, 1);
    let null2 = c.actor(p, consumers::nullifier_seed(&[2; 32], &sid2));
    let hdr = c.seeded(c.attest, header_seed(&A, &blk.hash));
    let (receipt, receipt_proof) = blk.receipt(1);
    let msg = |block_hash, exec_header_rlp: Vec<u8>, ancestry| consumers::ConsumerMsg::Claim {
        vault_id: [2; 32],
        block_hash,
        exec_header_rlp,
        ancestry,
        tx_index: 1,
        log_index: 1,
        receipt: receipt.clone(),
        receipt_proof: receipt_proof.clone(),
        amount,
    };
    assert_eq!(
        c.send(v, vec![hdr, null2], &msg(blk.hash, blk.rlp.clone(), vec![])),
        Err(Fail::Code(1204))
    );
    assert_eq!(c.state_of(v), before);
    assert!(c.state_of(null2).is_empty());
    // unrecorded anchor (the deposit block of the ancestry fixture, claimed directly): 1101
    let d = AncestryLog::load("deposit.json");
    let (dtoken, dto) = (
        h20(d.log["address"].as_str().unwrap()),
        h32(d.log["topics"][2].as_str().unwrap())[12..]
            .try_into()
            .unwrap(),
    );
    let damount = h32(d.log["data"].as_str().unwrap());
    c.init_vault(p, [3; 32], vault_cfg(A, dtoken, dto)).unwrap();
    let v3 = c.vault(p, [3; 32]);
    let before = c.state_of(v3);
    let dsid = statement_id_for(s.chain_id, s.genesis_validators_root, d.hash, d.tx_index, 0);
    let dnull = c.actor(p, consumers::nullifier_seed(&[3; 32], &dsid));
    let tgt = c.seeded(c.attest, header_seed(&A, &d.hash));
    let direct = consumers::ConsumerMsg::Claim {
        vault_id: [3; 32],
        block_hash: d.hash,
        exec_header_rlp: d.ancestry[0].clone(),
        ancestry: vec![],
        tx_index: d.tx_index,
        log_index: 0,
        receipt: d.receipt.clone(),
        receipt_proof: d.receipt_proof.clone(),
        amount: damount,
    };
    assert_eq!(c.send(v3, vec![tgt, dnull], &direct), Err(Fail::Code(1101)));
    assert_eq!(c.state_of(v3), before);
    assert!(c.state_of(dnull).is_empty());
    // the same deposit via the recorded anchor + ancestry is credited
    let anchor = c.seeded(c.attest, header_seed(&A, &blk.hash));
    let via = consumers::ConsumerMsg::Claim {
        vault_id: [3; 32],
        block_hash: blk.hash,
        exec_header_rlp: d.anchor_rlp.clone(),
        ancestry: d.ancestry.clone(),
        tx_index: d.tx_index,
        log_index: 0,
        receipt: d.receipt.clone(),
        receipt_proof: d.receipt_proof.clone(),
        amount: damount,
    };
    c.send(v3, vec![anchor, dnull], &via).unwrap();
    assert!(!c.state_of(dnull).is_empty());
}

/// The same request with the receipt dropped (`Proof::LogCompact`, D-GAS-6).
fn compact(mut req: AttestRequest) -> AttestRequest {
    if let Proof::Log { receipt_proof, .. } = req.proof {
        req.proof = Proof::LogCompact { receipt_proof };
    }
    req
}

/// Compact and explicit receipt witnesses attest the same statement; the compact form rejects a
/// tampered leaf and an exclusion-shaped (wrong tx) proof like the explicit one.
#[test]
fn compact_receipt_witness_same_statement() {
    let mut c = sepolia_chain();
    let blk = ElBlock::sepolia();
    let (token, to, amount) = blk.log(1, 1);
    let preds = inclusion::erc20_transfer_preds(token, None, Some(to), Some(amount));
    let req = blk.attest_log(A, 1, 1, preds.clone());
    let rec: attest_program::HeaderRecord =
        borsh::from_slice(&c.state_of(c.header(&A, &blk.hash))).unwrap();
    let full = attest_program::verify(&rec, &req).unwrap();
    assert_eq!(
        attest_program::verify(&rec, &compact(req.clone())).unwrap(),
        full
    );
    c.attest(blk.hash, compact(req.clone())).unwrap();
    let mut bad = compact(req.clone());
    if let Proof::LogCompact { receipt_proof } = &mut bad.proof {
        let n = receipt_proof.len() - 1;
        let m = receipt_proof[n].len() - 1;
        receipt_proof[n][m] ^= 1;
    }
    assert_eq!(c.attest(blk.hash, bad), Err(Fail::Code(1202)));
    let mut wrong_tx = compact(req);
    wrong_tx.locator = inclusion::Locator::Log {
        tx_index: 2,
        log_index: 1,
    };
    assert_eq!(c.attest(blk.hash, wrong_tx), Err(Fail::Code(1202)));
}

/// One flow, one table (each row = one tx, cap 10,000,000).
#[test]
fn cycle_table() {
    let mut rows: Vec<(&str, u64)> = vec![];
    let mut c = Chain::new();
    rows.push(("Init (Sepolia bootstrap)", c.init(&sepolia_init()).unwrap()));
    let (b, v) = c.update(A, 1, &sepolia_updates()[1], SEPOLIA_NOW).unwrap();
    rows.push(("UpdateBegin (learn next committee, K=2)", b));
    rows.push(("UpdateVerify (Miller + residue + apply)", v));
    let mut m = Chain::new();
    m.init(&mainnet_init()).unwrap();
    let ups = lc_core::json::updates_from_json(&fixture("lc-core/mainnet_updates.json")).unwrap();
    let fin =
        lc_core::json::update_from_json(&fixture("lc-core/mainnet_finality_update.json")).unwrap();
    m.update(B, 1, &ups[1], MAINNET_NOW).unwrap();
    let (b, v) = m.update(B, 2, &fin, MAINNET_NOW).unwrap();
    rows.push(("UpdateBegin (finality only, mainnet)", b));
    rows.push(("UpdateVerify (+ HeaderRecord write)", v));
    let blk = ElBlock::sepolia();
    let weth = h32("0x577261707065642045746865720000000000000000000000000000000000001a");
    rows.push((
        "Attest storage slot (WETH slot 0)",
        c.attest(blk.hash, weth_slot0(A, slot_eq(weth))).unwrap(),
    ));
    let (token, to, amount) = blk.log(1, 1);
    rows.push((
        "Attest ERC-20 Transfer log",
        c.attest(
            blk.hash,
            blk.attest_log(
                A,
                1,
                1,
                inclusion::erc20_transfer_preds(token, None, Some(to), Some(amount)),
            ),
        )
        .unwrap(),
    ));
    let (_, eto, eamount) = blk.log(2, 0);
    rows.push((
        "Attest native ETH (EIP-7708) log",
        c.attest(
            blk.hash,
            blk.attest_log(
                A,
                2,
                0,
                inclusion::native_eth_transfer_preds(None, Some(eto), Some(eamount)),
            ),
        )
        .unwrap(),
    ));
    rows.push((
        "Attest ERC-20 Transfer log (compact witness)",
        c.attest(
            blk.hash,
            compact(blk.attest_log(
                A,
                1,
                1,
                inclusion::erc20_transfer_preds(token, None, Some(to), Some(amount)),
            )),
        )
        .unwrap(),
    ));
    rows.push((
        "Attest native ETH (EIP-7708) log (compact witness)",
        c.attest(
            blk.hash,
            compact(blk.attest_log(
                A,
                2,
                0,
                inclusion::native_eth_transfer_preds(None, Some(eto), Some(eamount)),
            )),
        )
        .unwrap(),
    ));
    let erc20 = c.erc20;
    c.init_vault(erc20, [1; 32], vault_cfg(A, token, to))
        .unwrap();
    rows.push((
        "erc20_receiver Claim (chained Attest + nullifier)",
        c.claim(erc20, [1; 32], A, &blk, 1, 1, amount).unwrap(),
    ));
    let eth = c.eth;
    c.init_vault(eth, [1; 32], vault_cfg(A, EIP7708_ETH_LOG_ADDRESS, eto))
        .unwrap();
    rows.push((
        "eth_receiver Claim (chained Attest + nullifier)",
        c.claim(eth, [1; 32], A, &blk, 2, 0, eamount).unwrap(),
    ));
    let inline = c.erc20_inline;
    c.init_vault(inline, [1; 32], vault_cfg(A, token, to))
        .unwrap();
    rows.push((
        "erc20_inline_receiver Claim (optional: inline verify + CheckHeader)",
        c.claim(inline, [1; 32], A, &blk, 1, 1, amount).unwrap(),
    ));
    eprintln!("\n| instruction (one tx) | cycles | % of 10M |\n|---|---:|---:|");
    for (n, cy) in &rows {
        eprintln!("| {n} | {cy} | {:.1}% |", *cy as f64 / 1e5);
        assert!(*cy <= MAX_GAS_EXEC);
    }
}

/// Front-running: anyone who sees a deposit can submit the claim, so the credit must land
/// on a key fixed by the attested fact (the Transfer log's `from`), never on caller input. The
/// `Claim` message has no recipient field; the attacker below submits the victim's deposit.
#[test]
fn claim_by_third_party_credits_the_proven_sender() {
    let mut c = sepolia_chain();
    let blk = ElBlock::sepolia();
    let (token, to, amount) = blk.log(1, 1);
    let depositor = blk.log_from(1, 1);
    let erc20 = c.erc20;
    c.init_vault(erc20, [1; 32], vault_cfg(A, token, to))
        .unwrap();
    c.claim(erc20, [1; 32], A, &blk, 1, 1, amount).unwrap(); // submitted by a third party
    let sid = statement_id_for(
        11_155_111,
        ChainConfig::sepolia().genesis_validators_root,
        blk.hash,
        1,
        1,
    );
    let credit: consumers::Credit = untag(
        TAG_CREDIT,
        &c.state_of(c.actor(erc20, consumers::nullifier_seed(&[1; 32], &sid))),
    )
    .unwrap();
    assert_eq!(
        credit.eth_sender, depositor,
        "credit must belong to the proven Transfer sender"
    );
    assert_eq!(
        credit.amount,
        u128::from_be_bytes(amount[16..].try_into().unwrap())
    );
    // and it cannot be claimed again to land elsewhere
    assert_eq!(
        c.claim(erc20, [1; 32], A, &blk, 1, 1, amount),
        Err(Fail::Code(ERR_ALREADY_CLAIMED))
    );
    // native ETH: same rule (EIP-7708 log topic 1 = sender)
    let (sys, eto, eamount) = blk.log(2, 0);
    let eth = c.eth;
    c.init_vault(eth, [1; 32], vault_cfg(A, sys, eto)).unwrap();
    c.claim(eth, [1; 32], A, &blk, 2, 0, eamount).unwrap();
    let sid = statement_id_for(
        11_155_111,
        ChainConfig::sepolia().genesis_validators_root,
        blk.hash,
        2,
        0,
    );
    let credit: consumers::Credit = untag(
        TAG_CREDIT,
        &c.state_of(c.actor(eth, consumers::nullifier_seed(&[1; 32], &sid))),
    )
    .unwrap();
    assert_eq!(credit.eth_sender, blk.log_from(2, 0));
}
