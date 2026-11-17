//! Single-transaction update acceptance and LEZ executor gas (all chained actors included).
use attest_program::*;
use lc_core::{LightClientUpdate, Store};
use program_tests::*;

const A: InstanceId = SEPOLIA_ID;
const TARGET: u64 = 9_500_000;

/// Real Sepolia post-handoff state, anchored in the same fixtures as the existing handoff test.
fn finality_chain() -> Chain {
    let cfg = sepolia_cfg();
    let boot = lc_core::json::bootstrap_from_json(&fixture("sepolia/bootstrap.json")).unwrap();
    let u = sepolia_updates().remove(1);
    let store = Store {
        finalized_header: u
            .finalized_header
            .unwrap()
            .0
            .to_finalized(&cfg.chain)
            .unwrap(),
        current_sync_committee: boot.current_sync_committee,
        next_sync_committee: u.next_sync_committee.map(|(c, _)| c),
    };
    let mut c = Chain::new();
    force_instance(
        &mut c,
        A,
        &InstanceState {
            cfg,
            store,
            headers: Frontier::default(),
        },
    );
    c
}

fn send_update(
    c: &mut Chain,
    u: &LightClientUpdate,
    hints: Vec<Vec<u8>>,
    w: Vec<u8>,
    now: u64,
) -> Result<u64, Fail> {
    let st = c.instance_state(&A);
    let mut actors = vec![];
    if let Some((h, _)) = &u.finalized_header {
        if let Ok(f) = h.to_finalized(&st.cfg.chain) {
            actors.push(c.seeded(c.attest, header_seed(&A, &f.execution_block_hash)));
            if f.beacon.slot > st.store.finalized_header.beacon.slot {
                let root = st
                    .headers
                    .clone()
                    .append(header_leaf(&header_record(A, &st.cfg, &f)))
                    .unwrap();
                actors.push(c.seeded(c.attest, hroot_seed(&A, &root)));
            }
        }
    }
    // Appended Borsh variant tag. This wire-level test runs against the old guest too (1001).
    c.send(c.instance(&A), actors, &(9u8, A, u, hints, w, now))
}

#[test]
fn onetx_real_sepolia_finality_matches_split() {
    let mut one = finality_chain();
    let mut split = finality_chain();
    let u = sepolia_finality();
    let st = one.instance_state(&A);
    let w = witness(&st.cfg, &st.store, &u, SEPOLIA_NOW);
    let hints = one.hints(A, &u, SEPOLIA_NOW);
    one.budget = TARGET;
    let cycles = send_update(&mut one, &u, hints, w, SEPOLIA_NOW).unwrap();
    let (b, v) = split.update(A, 1, &u, SEPOLIA_NOW).unwrap();
    assert_eq!(one.instance_state(&A), split.instance_state(&A));
    let st = one.instance_state(&A);
    let hdr = one.header(&A, &st.store.finalized_header.execution_block_hash);
    assert_eq!(one.state_of(hdr), split.state_of(hdr));
    let root = one.actor(one.attest, hroot_seed(&A, &st.headers.root()));
    assert_eq!(one.state_of(root), st.headers.root().to_vec());
    assert!(one.state_of(one.job(&A, 1)).is_empty());
    assert!(cycles <= TARGET);
    eprintln!(
        "CYCLES finality Sepolia K={} Update={cycles} Begin={b} Verify={v}",
        512 - u.sync_aggregate.participants()
    );
    assert_eq!(
        send_update(&mut one, &u, vec![], vec![0; 864], SEPOLIA_NOW),
        Err(Fail::Code(1106))
    );
}

#[test]
fn onetx_real_mainnet_finality_matches_split() {
    let mut c = Chain::new();
    c.init(&mainnet_init()).unwrap();
    let ups = lc_core::json::updates_from_json(&fixture("lc-core/mainnet_updates.json")).unwrap();
    c.update(MAINNET_ID, 1, &ups[1], MAINNET_NOW).unwrap();
    let u =
        lc_core::json::update_from_json(&fixture("lc-core/mainnet_finality_update.json")).unwrap();
    let before = c.instance_state(&MAINNET_ID);
    let w = witness(&before.cfg, &before.store, &u, MAINNET_NOW);
    let hints = c.hints(MAINNET_ID, &u, MAINNET_NOW);
    let p = lc_core::prepare_update(&before.cfg.chain, &before.store, &u, MAINNET_NOW).unwrap();
    assert!(!p.verified.rotate && p.verified.next_sync_committee.is_none());
    let (b, v) = c.update(MAINNET_ID, 2, &u, MAINNET_NOW).unwrap();
    let expected = c.instance_state(&MAINNET_ID);
    // Recreate the exact pre-update state, preserving identical output accounts.
    force_instance(&mut c, MAINNET_ID, &before);
    c.budget = TARGET;
    let cy = c
        .update_one_hinted(MAINNET_ID, &u, MAINNET_NOW, hints, w)
        .unwrap();
    assert_eq!(c.instance_state(&MAINNET_ID), expected);
    assert!(cy <= TARGET);
    eprintln!(
        "CYCLES finality mainnet K={} Update={cy} Begin={b} Verify={v}",
        512 - u.sync_aggregate.participants()
    );
}

#[test]
fn onetx_invalidates_an_older_split_job() {
    let mut c = finality_chain();
    let u = sepolia_finality();
    let st = c.instance_state(&A);
    let w = witness(&st.cfg, &st.store, &u, SEPOLIA_NOW);
    let h = c.hints(A, &u, SEPOLIA_NOW);
    c.begin(A, 7, &u, SEPOLIA_NOW).unwrap();
    send_update(&mut c, &u, h, w.clone(), SEPOLIA_NOW).unwrap();
    let applied = c.instance_state(&A);
    assert_eq!(c.verify(A, 7, &u, w), Err(Fail::Code(1106)));
    assert_eq!(c.instance_state(&A), applied);
    // The failed chained Apply also rolls back UpdateVerify's attempted Job deletion.
    assert!(!c.state_of(c.job(&A, 7)).is_empty());
}

/// Real Sepolia committee-learning update (period 1403, next committee unknown) in one tx.
#[test]
fn onetx_committee_learning_cycles() {
    let mut c = Chain::new();
    c.init(&sepolia_init()).unwrap();
    let u = sepolia_updates().remove(1);
    let before = c.instance_state(&A);
    assert!(before.store.next_sync_committee.is_none());
    let w = witness(&before.cfg, &before.store, &u, SEPOLIA_NOW);
    let h = c.hints(A, &u, SEPOLIA_NOW);
    let k = 512 - u.sync_aggregate.participants();
    assert_eq!(h.len(), k + 2, "non-signers + aggregate + signature hints");
    let (b, v) = c.update(A, 1, &u, SEPOLIA_NOW).unwrap();
    let expected = c.instance_state(&A);
    assert!(expected.store.next_sync_committee.is_some());
    force_instance(&mut c, A, &before);
    c.budget = lez_client::update_gas_limit(k);
    let cy = c
        .update_one_hinted(A, &u, SEPOLIA_NOW, h.clone(), w.clone())
        .unwrap();
    assert_eq!(c.instance_state(&A), expected);
    assert!(cy <= TARGET);
    // Without the trailing aggregate/signature hints the guest decompresses them itself.
    force_instance(&mut c, A, &before);
    let cy_plain = c
        .update_one_hinted(A, &u, SEPOLIA_NOW, h[..k].to_vec(), w.clone())
        .unwrap();
    assert_eq!(c.instance_state(&A), expected);
    assert!(cy_plain <= TARGET);
    eprintln!(
        "CYCLES committee-learning Sepolia K={k} Update={cy} (no agg/sig hints {cy_plain}) Begin={b} Verify={v}"
    );
}

/// Period-1403 anchor (next committee unknown), as in the split-path handoff test.
fn anchor_1403_chain() -> Chain {
    let cfg = sepolia_cfg();
    let u1402 =
        &lc_core::json::updates_from_json(&fixture("lc-core/sepolia_update_1402.json")).unwrap()[0];
    let (committee_1403, _) = u1402.next_sync_committee.clone().unwrap();
    let (fin_1403, _) = sepolia_updates()[0].finalized_header.clone().unwrap();
    let store = Store {
        finalized_header: fin_1403.to_finalized(&cfg.chain).unwrap(),
        current_sync_committee: committee_1403,
        next_sync_committee: None,
    };
    let mut c = Chain::new();
    force_instance(
        &mut c,
        A,
        &InstanceState {
            cfg,
            store,
            headers: Frontier::default(),
        },
    );
    c
}

/// Committee-learning negatives through the single-tx path, then the real learn (1403) →
/// rotation + finality (1404) → finality handoff in three single transactions.
#[test]
fn onetx_committee_learning_rejects_bad_inputs_then_hands_off() {
    let mut c = anchor_1403_chain();
    let ups = sepolia_updates();
    let good = ups[0].clone();
    let now = good.signature_slot;
    let st = c.instance_state(&A);
    let before = c.state_of(c.instance(&A));
    let w = witness(&st.cfg, &st.store, &good, now);
    let hints = c.hints(A, &good, now);
    let k = 512 - good.sync_aggregate.participants();
    assert_eq!(hints.len(), k + 2);
    let mut cases = vec![];
    // Handoff: the period-1404 update while the 1404 committee is still unknown.
    cases.push(("1104 handoff", ups[1].clone(), ups[1].signature_slot, 1104));
    let mut u = good.clone();
    u.next_sync_committee.as_mut().unwrap().1[0][0] ^= 1;
    cases.push(("next committee branch", u, now, 1104));
    let mut u = good.clone();
    u.next_sync_committee.as_mut().unwrap().0.pubkeys[7][5] ^= 1;
    cases.push(("next committee key", u, now, 1104));
    let mut u = good.clone();
    u.next_sync_committee.as_mut().unwrap().0.aggregate_pubkey[5] ^= 1;
    cases.push(("next committee aggregate", u, now, 1104));
    let mut u = good.clone();
    u.next_sync_committee.as_mut().unwrap().0.pubkeys.pop();
    cases.push(("next committee 511 keys", u, now, 1001));
    let mut u = good.clone();
    u.next_sync_committee
        .as_mut()
        .unwrap()
        .0
        .pubkeys
        .push([0xc0; 48]);
    cases.push(("next committee 513 keys", u, now, 1001));
    let mut u = good.clone();
    u.next_sync_committee.as_mut().unwrap().0.pubkeys[3] = {
        let mut inf = [0u8; 48];
        inf[0] = 0xc0;
        inf
    };
    cases.push(("next committee infinity key", u, now, 1001));
    let mut u = good.clone();
    u.sync_aggregate.sync_committee_bits[0] ^= 1;
    cases.push(("wrong signer set", u, now, 1102));
    for (name, u, at, code) in cases {
        let h = c.hints(A, &u, at);
        assert_eq!(
            c.update_one_hinted(A, &u, at, h, w.clone()),
            Err(Fail::Code(code)),
            "{name}"
        );
        assert_eq!(c.state_of(c.instance(&A)), before, "{name} changed state");
    }
    // Aggregate / signature hints: wrong length, another point, off-curve, infinity, negated.
    let mut bad_tails: Vec<(&str, Vec<Vec<u8>>)> = vec![];
    bad_tails.push(("only aggregate hint", hints[..k + 1].to_vec()));
    let mut h = hints.clone();
    h[k] = {
        let mut aff = blst::blst_p1_affine::default();
        let mut out = vec![0u8; 96];
        unsafe {
            blst::blst_p1_uncompress(
                &mut aff,
                st.store.current_sync_committee.pubkeys[0].as_ptr(),
            );
            blst::blst_p1_affine_serialize(out.as_mut_ptr(), &aff);
        }
        out
    };
    bad_tails.push(("aggregate hint = member key", h));
    let mut h = hints.clone();
    h[k + 1][5] ^= 1;
    bad_tails.push(("signature hint off-curve", h));
    let mut h = hints.clone();
    h[k + 1] = vec![0; 192];
    h[k + 1][0] = 0x40;
    bad_tails.push(("signature hint infinity", h));
    let mut h = hints.clone();
    h.swap(k, k + 1);
    bad_tails.push(("aggregate/signature swapped", h));
    let mut h = hints.clone();
    h[k + 1] = {
        // -sig: same x, so it only differs in the compressed sign bit.
        let mut aff = blst::blst_p2_affine::default();
        let mut p = blst::blst_p2::default();
        let mut out = vec![0u8; 192];
        unsafe {
            blst::blst_p2_deserialize(&mut aff, hints[k + 1].as_ptr());
            blst::blst_p2_from_affine(&mut p, &aff);
            blst::blst_p2_cneg(&mut p, true);
            blst::blst_p2_to_affine(&mut aff, &p);
            blst::blst_p2_affine_serialize(out.as_mut_ptr(), &aff);
        }
        out
    };
    bad_tails.push(("signature hint negated", h));
    for (name, h) in bad_tails {
        assert_eq!(
            c.update_one_hinted(A, &good, now, h, w.clone()),
            Err(Fail::Code(1102)),
            "{name}"
        );
        assert_eq!(c.state_of(c.instance(&A)), before, "{name} changed state");
    }
    // learn (1403) → rotation + finality (1404) → finality, each in one tx under the target.
    c.budget = TARGET;
    let mut cycles = vec![];
    for u in [good, ups[1].clone(), sepolia_finality()] {
        let at = u.signature_slot;
        let st = c.instance_state(&A);
        let w = witness(&st.cfg, &st.store, &u, at);
        let h = c.hints(A, &u, at);
        cycles.push(c.update_one_hinted(A, &u, at, h, w).unwrap());
    }
    let st = c.instance_state(&A);
    let boot = lc_core::json::bootstrap_from_json(&fixture("sepolia/bootstrap.json")).unwrap();
    assert_eq!(st.store.current_sync_committee, boot.current_sync_committee);
    assert_eq!(st.store.period(), 1404);
    eprintln!(
        "CYCLES handoff one-tx: learn {} rotate {} finality {}",
        cycles[0], cycles[1], cycles[2]
    );
}

#[derive(Clone, Copy, PartialEq)]
enum Case {
    /// Sepolia/Gloas finality update, both committees stored.
    Sepolia,
    /// Mainnet/Fulu finality update, both committees stored.
    Mainnet,
    /// Sepolia committee-learning update (next committee in the payload, one stored).
    SepoliaLearn,
}

/// Real header/branches; a test-seeded committee of distinct known keys permits VALID
/// aggregate signatures for every K. Never measure a failed verification as a successful tx.
fn signed_case(k: usize, case: Case) -> (Chain, LightClientUpdate, InstanceId, u64) {
    use blst::min_pk::{AggregatePublicKey, AggregateSignature, SecretKey};
    let (mut c, id, now, mut u) = if case == Case::SepoliaLearn {
        let mut c = Chain::new();
        c.init(&sepolia_init()).unwrap();
        (c, A, SEPOLIA_NOW, sepolia_updates().remove(1))
    } else if case == Case::Mainnet {
        let mut c = Chain::new();
        let Msg::Init {
            cfg,
            trusted_block_root,
            bootstrap,
            ..
        } = mainnet_init()
        else {
            unreachable!()
        };
        let mut store =
            lc_core::bootstrap(&cfg.chain, &trusted_block_root, &bootstrap, MAINNET_NOW).unwrap();
        let ups =
            lc_core::json::updates_from_json(&fixture("lc-core/mainnet_updates.json")).unwrap();
        store.next_sync_committee = ups[1].next_sync_committee.clone().map(|(c, _)| c);
        force_instance(
            &mut c,
            MAINNET_ID,
            &InstanceState {
                cfg,
                store,
                headers: Frontier::default(),
            },
        );
        (
            c,
            MAINNET_ID,
            MAINNET_NOW,
            lc_core::json::update_from_json(&fixture("lc-core/mainnet_finality_update.json"))
                .unwrap(),
        )
    } else {
        (finality_chain(), A, SEPOLIA_NOW, sepolia_finality())
    };
    let mut st = c.instance_state(&id);
    u.sync_aggregate.sync_committee_bits = [0xff; 64];
    for i in 0..k {
        u.sync_aggregate.sync_committee_bits[i / 8] &= !(1 << (i % 8));
    }
    let keys: Vec<_> = (0..512u64)
        .map(|i| {
            let mut ikm = [42u8; 32];
            ikm[..8].copy_from_slice(&i.to_le_bytes());
            SecretKey::key_gen(&ikm, &[]).unwrap()
        })
        .collect();
    let pks: Vec<_> = keys.iter().map(|k| k.sk_to_pk()).collect();
    st.store.current_sync_committee = lc_core::SyncCommittee {
        pubkeys: pks.iter().map(|p| p.to_bytes()).collect(),
        aggregate_pubkey: AggregatePublicKey::aggregate(&pks.iter().collect::<Vec<_>>(), true)
            .unwrap()
            .to_public_key()
            .to_bytes(),
    };
    // Exercise the largest valid accumulator carry (2^19 leaves; the 2^20-th append is rejected), with both committees stored.
    st.headers.leaves = (1 << (HEADER_TREE_DEPTH - 1)) - 1;
    st.headers.nodes = [[7; 32]; HEADER_TREE_DEPTH];
    let p = lc_core::prepare_update(&st.cfg.chain, &st.store, &u, now).unwrap();
    let sigs: Vec<_> = keys[k..]
        .iter()
        .map(|k| {
            k.sign(
                &p.pairing.signing_root,
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
                &[],
            )
        })
        .collect();
    u.sync_aggregate.sync_committee_signature =
        AggregateSignature::aggregate(&sigs.iter().collect::<Vec<_>>(), true)
            .unwrap()
            .to_signature()
            .to_bytes();
    force_instance(&mut c, id, &st);
    (c, u, id, now)
}

#[test]
fn onetx_cycles_by_non_signers() {
    for case in [Case::Sepolia, Case::Mainnet, Case::SepoliaLearn] {
        let chain = match case {
            Case::Sepolia => "Sepolia",
            Case::Mainnet => "mainnet",
            Case::SepoliaLearn => "Sepolia committee-learning",
        };
        let mut rows = std::collections::BTreeMap::new();
        let mut measure = |k: usize| -> u64 {
            *rows.entry(k).or_insert_with(|| {
                let (mut c, u, id, now) = signed_case(k, case);
                let st = c.instance_state(&id);
                let w = witness(&st.cfg, &st.store, &u, now);
                let h = c.hints(id, &u, now);
                // Client-routed cases must execute under the gas limit the client declares
                // (<= TARGET). Only the boundary exploration may use a larger budget.
                c.budget = if k <= lez_client::ONE_TX_MAX_NON_SIGNERS {
                    assert!(lez_client::update_gas_limit(k) <= TARGET);
                    lez_client::update_gas_limit(k)
                } else {
                    64_000_000
                };
                let cy = c.update_one_hinted(id, &u, now, h, w).unwrap();
                let after = c.instance_state(&id).store;
                if case == Case::SepoliaLearn {
                    assert!(after.next_sync_committee.is_some());
                } else {
                    assert!(
                        after.finalized_header.beacon.slot > st.store.finalized_header.beacon.slot
                    );
                }
                eprintln!("CYCLES Update {chain} valid K={k} {cy}");
                cy
            })
        };
        for k in [0, 2, 20, 30, 64, 128, 170] {
            measure(k);
        }
        assert!(measure(64) <= TARGET, "committee-learning target K");
        assert!(measure(128) <= TARGET);
        assert!(
            measure(lez_client::ONE_TX_MAX_NON_SIGNERS) <= TARGET,
            "client's automatic one-tx limit"
        );
        let (mut lo, mut hi) = (0, 171);
        assert!(measure(lo) <= TARGET);
        while hi - lo > 1 {
            let mid = (lo + hi) / 2;
            if measure(mid) <= TARGET {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        assert!(measure(lo) <= TARGET);
        if hi <= 170 {
            assert!(measure(hi) > TARGET);
        }
        // Do not assume strict monotonicity across different valid signatures: check every larger K.
        for k in hi..=170 {
            if measure(k) <= TARGET {
                lo = k;
            }
        }
        eprintln!(
            "CYCLES Update {chain} measured max K={lo} at {} cycles; first over target K={}",
            measure(lo),
            lo + 1
        );
    }
}
