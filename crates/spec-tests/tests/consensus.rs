//! consensus-spec-tests (pinned in fetch.sh): ssz_static, light_client/{single_merkle_proof, sync,
//! update_ranking, data_collection} for Electra/Fulu/Gloas, mainnet + minimal presets.
//! Run: SPEC_TESTS_DIR=~/spectests cargo test --release -p spec-tests --test consensus -- --nocapture

use std::path::Path;

use lc_core::json::{bootstrap_from_value, update_from_value};
use lc_core::{ChainConfig, PairingInputs, SigVerifier};
use serde_json::{json, Value};
use spec_tests::*;

const FORKS: [&str; 3] = ["electra", "fulu", "gloas"];

fn cases(p: &Path) -> Vec<std::path::PathBuf> {
    subdirs(p).into_iter().flat_map(|s| subdirs(&s)).collect()
}

/// value.yaml through lc-core's production JSON decoder (Beacon-API shape).
fn json_decode(kind: &str, v: &Value) -> Result<Value, String> {
    let dbg = |x: &dyn std::fmt::Debug| Value::String(format!("{x:?}"));
    match kind {
        "LightClientHeader" => bootstrap_from_value(&json!({"header": v,
            "current_sync_committee": {"pubkeys": [], "aggregate_pubkey": format!("0x{}", "00".repeat(48))},
            "current_sync_committee_branch": []}))
        .map(|b| dbg(&b.header)),
        "LightClientBootstrap" => bootstrap_from_value(v).map(|b| dbg(&b)),
        _ => update_from_value(v).map(|u| dbg(&u)),
    }
    .map_err(|e| format!("{e:?}"))
}

#[test]
fn ssz_static() {
    let base = dir().join("consensus/tests");
    let mut rows = vec![];
    for preset in ["mainnet", "minimal"] {
        let n = if preset == "mainnet" { 512 } else { 32 };
        for fork in FORKS {
            let gloas = fork == "gloas";
            let s = Shape { n, gloas };
            let mut t = Tally::default();
            for tdir in subdirs(&base.join(format!("{preset}/{fork}/ssz_static"))) {
                let kind = tdir.file_name().unwrap().to_str().unwrap().to_string();
                for c in cases(&tdir) {
                    let id = format!(
                        "{preset}/{fork}/{kind}/{}",
                        c.file_name().unwrap().to_str().unwrap()
                    );
                    // SyncCommittee (32 keys) or SyncAggregate bits (Bitvector[32]) inside
                    let committee_in = matches!(
                        kind.as_str(),
                        "SyncCommittee"
                            | "LightClientBootstrap"
                            | "LightClientUpdate"
                            | "LightClientFinalityUpdate"
                    );
                    if kind == "LightClientOptimisticUpdate" {
                        t.unsupported("no optimistic-update path (finality required)");
                        continue;
                    }
                    if kind == "SyncAggregate" {
                        t.unsupported("SyncAggregate never hash_tree_root'ed by lc-core");
                        continue;
                    }
                    if committee_in && n != 512 {
                        t.unsupported("minimal preset: 32-key SyncCommittee / Bitvector[32] bits; lc-core types are 512 keys / [u8; 64]");
                        continue;
                    }
                    let b = snappy(&c.join("serialized.ssz_snappy"));
                    let want = root32(&yaml(&c.join("roots.yaml"))["root"]);
                    let got = match kind.as_str() {
                        "BeaconBlockHeader" => {
                            Ok((None, lc_core::hash_tree_root_header(&beacon(&b))))
                        }
                        "SyncCommittee" => Ok((None, committee_root(&committee(&b)))),
                        "LightClientHeader" => {
                            header(&b, gloas).map(|(h, r)| (Some(format!("{h:?}")), r))
                        }
                        "LightClientBootstrap" => {
                            bootstrap(&b, s).map(|(x, r)| (Some(format!("{x:?}")), r))
                        }
                        "LightClientUpdate" => {
                            update(&b, s, false).map(|(x, r)| (Some(format!("{x:?}")), r))
                        }
                        "LightClientFinalityUpdate" => {
                            update(&b, s, true).map(|(x, r)| (Some(format!("{x:?}")), r))
                        }
                        _ => {
                            t.unsupported(format!("{kind}: not an lc-core container"));
                            continue;
                        }
                    };
                    match got {
                        Err(e) => t.mismatch(format!("{id}: decode {e}")),
                        Ok((_, r)) if r != want => t.mismatch(format!(
                            "{id}: root {} != {}",
                            hex::encode(r),
                            hex::encode(want)
                        )),
                        // the decoded value must equal lc-core's production JSON decode of value.yaml
                        Ok((Some(dbg), _)) => {
                            match json_decode(&kind, &yaml(&c.join("value.yaml"))) {
                                Ok(Value::String(j)) if j == dbg => t.pass(),
                                Ok(_) => {
                                    t.mismatch(format!("{id}: lc-core JSON decode != SSZ decode"))
                                }
                                Err(e) => t.mismatch(format!("{id}: lc-core JSON decode {e}")),
                            }
                        }
                        Ok((None, _)) => t.pass(),
                    }
                }
            }
            rows.push((format!("ssz_static {preset}/{fork}"), t));
        }
    }
    report(
        "ssz_static (host)",
        &rows.iter().map(|(n, t)| (n.clone(), t)).collect::<Vec<_>>(),
    );
}

/// (production (gindex, wire length)) for a single_merkle_proof case.
fn our_gindex(fork: &str, case: &str) -> Option<(u64, usize)> {
    let g = fork == "gloas";
    Some(match case {
        "finality_root_merkle_proof" => {
            if g {
                lc_core::FINALIZED_ROOT_GLOAS
            } else {
                lc_core::FINALIZED_ROOT_ELECTRA
            }
        }
        "current_sync_committee_merkle_proof" => {
            if g {
                lc_core::CURRENT_SC_GLOAS
            } else {
                lc_core::CURRENT_SC_ELECTRA
            }
        }
        "next_sync_committee_merkle_proof" => {
            if g {
                lc_core::NEXT_SC_GLOAS
            } else {
                lc_core::NEXT_SC_ELECTRA
            }
        }
        "execution_merkle_proof" if !g => lc_core::EXECUTION_PAYLOAD,
        "execution_block_hash_merkle_proof" if g => lc_core::EXECUTION_BLOCK_HASH_GLOAS,
        _ => return None,
    })
}

#[test]
fn single_merkle_proof() {
    let base = dir().join("consensus/tests");
    let mut rows = vec![];
    let mut ops = vec![];
    let mut guest_expect = vec![];
    for preset in ["mainnet", "minimal"] {
        for fork in FORKS {
            let mut t = Tally::default();
            for c in cases(&base.join(format!("{preset}/{fork}/light_client/single_merkle_proof")))
            {
                let name = c.file_name().unwrap().to_str().unwrap();
                let id = format!("{preset}/{fork}/{name}");
                let Some((gindex, len)) = our_gindex(fork, name) else {
                    t.unsupported(format!("{name}: gindex not used by lc-core"));
                    continue;
                };
                let p = yaml(&c.join("proof.yaml"));
                let leaf = root32(&p["leaf"]);
                let branch: Vec<_> = p["branch"].as_array().unwrap().iter().map(root32).collect();
                let idx = num(&p["leaf_index"]);
                // Object root folded from the vector's own branch (no full BeaconState/Body hasher
                // here): what is tested is lc-core's gindex, branch length and fold orientation.
                let root = fold_branch(&leaf, &branch, idx);
                let mut bad_leaf = leaf;
                bad_leaf[0] ^= 1;
                // negative control on the top sibling (flipping gindex bit 0 is a no-op in these
                // vectors: the leaf equals its level-0 sibling, e.g. current == next committee)
                let mut bad_branch = branch.clone();
                bad_branch.last_mut().unwrap()[0] ^= 1;
                let ok = idx == gindex
                    && branch.len() == len
                    && lc_core::is_valid_normalized_branch(&leaf, &branch, gindex, &root)
                    && !lc_core::is_valid_normalized_branch(&bad_leaf, &branch, gindex, &root)
                    && !lc_core::is_valid_normalized_branch(&leaf, &bad_branch, gindex, &root);
                if ok {
                    t.pass()
                } else {
                    t.mismatch(format!(
                        "{id}: vector gindex {idx} len {} vs lc-core {gindex}/{len}",
                        branch.len()
                    ));
                }
                ops.push(Op::Branch(leaf, branch.clone(), gindex, root));
                ops.push(Op::Branch(bad_leaf, branch, gindex, root));
                guest_expect.push((id.clone(), 1u8));
                guest_expect.push((id + " (tampered leaf)", 0u8));
            }
            rows.push((format!("single_merkle_proof {preset}/{fork}"), t));
        }
    }
    let mut g = Tally::default();
    for ((id, want), got) in guest_expect.iter().zip(guest(&ops)) {
        if got == [*want] {
            g.pass()
        } else {
            g.mismatch(format!("guest {id}: {got:?}"))
        }
    }
    rows.push((
        "single_merkle_proof guest (zkVM is_valid_normalized_branch, ok+tampered)".into(),
        g,
    ));
    report(
        "single_merkle_proof",
        &rows.iter().map(|(n, t)| (n.clone(), t)).collect::<Vec<_>>(),
    );
}

// ------------------------------------------------------------------ sync (minimal preset only)

const MIN_SLOTS_PER_EPOCH: u64 = 8;
const MIN_SLOTS_PER_PERIOD: u64 = 64;

struct Case {
    cfg: ChainConfig,
    /// GLOAS_FORK_EPOCH (minimal epochs)
    gloas_epoch: u64,
    /// lc-core's 32-slot epochs can express this fork schedule (forks at 0 / never)
    native: bool,
}

fn case_cfg(c: &Path) -> Case {
    let y = yaml(&c.join("config.yaml"));
    let m = yaml(&c.join("meta.yaml"));
    let ep = |k: &str| y.get(k).map(num).unwrap_or(u64::MAX);
    let mut fork_versions: Vec<(u64, [u8; 4])> = [
        "GENESIS",
        "ALTAIR",
        "BELLATRIX",
        "CAPELLA",
        "DENEB",
        "ELECTRA",
        "FULU",
        "GLOAS",
    ]
    .iter()
    .filter_map(|f| {
        let v = y.get(format!("{f}_FORK_VERSION"))?;
        let e = if *f == "GENESIS" {
            0
        } else {
            ep(&format!("{f}_FORK_EPOCH"))
        };
        (e != u64::MAX).then(|| (e, hx(v).try_into().unwrap()))
    })
    .collect();
    fork_versions.sort_by_key(|x| x.0);
    let gloas_epoch = ep("GLOAS_FORK_EPOCH");
    let native = ep("ELECTRA_FORK_EPOCH") == 0 && (gloas_epoch == 0 || gloas_epoch == u64::MAX);
    Case {
        cfg: ChainConfig {
            chain_id: 0,
            genesis_validators_root: root32(&m["genesis_validators_root"]),
            fork_versions,
            electra_fork_epoch: 0,
            gloas_fork_epoch: gloas_epoch,
            min_participation: 1,
            ws_period_epochs: u64::MAX,
        },
        gloas_epoch,
        native,
    }
}

/// Production primitives on one LightClientHeader's execution branch. `native`: through
/// `to_finalized` (lc-core's own fork selection); else the gindex is chosen by the spec's minimal
/// epoch rule and checked with lc-core's hash + branch verifier.
fn exec_ok(k: &Case, h: &lc_core::LightClientHeader) -> bool {
    if k.native {
        return h.to_finalized(&k.cfg).is_ok();
    }
    let gloas_era = h.beacon.slot / MIN_SLOTS_PER_EPOCH >= k.gloas_epoch;
    let (leaf, (g, len)) = match &h.execution {
        lc_core::HeaderExecution::Gloas(x) => (
            *x,
            if gloas_era {
                lc_core::EXECUTION_BLOCK_HASH_GLOAS
            } else {
                lc_core::EXECUTION_BLOCK_HASH_DENEB
            },
        ),
        lc_core::HeaderExecution::Electra(p) => (
            lc_core::hash_tree_root_execution(p),
            lc_core::EXECUTION_PAYLOAD,
        ),
    };
    h.execution_branch.len() == len
        && lc_core::is_valid_normalized_branch(&leaf, &h.execution_branch, g, &h.beacon.body_root)
}

#[test]
fn light_client_sync() {
    let base = dir().join("consensus/tests");
    let (mut comp, mut store, mut sig_host) =
        (Tally::default(), Tally::default(), Tally::default());
    let mut ops = vec![];
    let mut guest_ids = vec![];
    for preset in ["mainnet", "minimal"] {
        for fork in FORKS {
            for c in subdirs(&base.join(format!("{preset}/{fork}/light_client/sync/pyspec_tests")))
            {
                let id = format!(
                    "{preset}/{fork}/{}",
                    c.file_name().unwrap().to_str().unwrap()
                );
                assert_eq!(
                    preset, "minimal",
                    "mainnet sync vectors appeared: extend the harness"
                );
                let k = case_cfg(&c);
                let s = |b: &[u8], kind| Shape {
                    n: 32,
                    gloas: is_gloas_len(b.len(), 32, kind),
                };
                let bb = snappy(&c.join("bootstrap.ssz_snappy"));
                let (boot, _) = bootstrap(&bb, s(&bb, "bootstrap")).unwrap();
                let m = yaml(&c.join("meta.yaml"));
                // bootstrap: header root (lc-core), committee branch (lc-core verifier), execution
                let bh = &boot.header.beacon;
                let gl = s(&bb, "bootstrap").gloas;
                let (g, _) = if gl {
                    lc_core::CURRENT_SC_GLOAS
                } else {
                    lc_core::CURRENT_SC_ELECTRA
                };
                if lc_core::hash_tree_root_header(bh) == root32(&m["trusted_block_root"])
                    && lc_core::is_valid_normalized_branch(
                        &committee_root(&boot.current_sync_committee),
                        &boot.current_sync_committee_branch,
                        g,
                        &bh.state_root,
                    )
                    && exec_ok(&k, &boot.header)
                {
                    comp.pass()
                } else {
                    comp.mismatch(format!("{id}: bootstrap"));
                }
                let mut committees = std::collections::BTreeMap::new();
                committees.insert(
                    bh.slot / MIN_SLOTS_PER_PERIOD,
                    boot.current_sync_committee.clone(),
                );
                let steps = yaml(&c.join("steps.yaml"));
                for (i, st) in steps.as_array().unwrap().iter().enumerate() {
                    let sid = format!("{id} step {i}");
                    let Some(pu) = st.get("process_update") else {
                        let kind = st.as_object().unwrap().keys().next().unwrap().clone();
                        store
                            .unsupported(format!("{kind}: no such operation on-chain (by design)"));
                        continue;
                    };
                    store.unsupported("finalized/optimistic store checks: minimal preset (lc-core period/committee constants are mainnet)");
                    let ub = snappy(&c.join(format!(
                        "{}.ssz_snappy",
                        pu["update"].as_str().unwrap().trim()
                    )));
                    let sh = s(&ub, "update");
                    let (u, _) = match update(&ub, sh, false) {
                        Ok(x) => x,
                        Err(e) => {
                            comp.mismatch(format!("{sid}: decode {e}"));
                            continue;
                        }
                    };
                    let att = &u.attested_header.beacon;
                    let mut ok = exec_ok(&k, &u.attested_header);
                    let genesis = u
                        .finalized_header
                        .as_ref()
                        .is_some_and(|(f, _)| f.beacon.slot == 0);
                    if let Some((f, br)) = u.finalized_header.as_ref().filter(|_| !genesis) {
                        let (g, _) = if sh.gloas {
                            lc_core::FINALIZED_ROOT_GLOAS
                        } else {
                            lc_core::FINALIZED_ROOT_ELECTRA
                        };
                        ok &= exec_ok(&k, f)
                            && lc_core::is_valid_normalized_branch(
                                &lc_core::hash_tree_root_header(&f.beacon),
                                br,
                                g,
                                &att.state_root,
                            );
                    }
                    if let Some((nc, br)) = &u.next_sync_committee {
                        let (g, _) = if sh.gloas {
                            lc_core::NEXT_SC_GLOAS
                        } else {
                            lc_core::NEXT_SC_ELECTRA
                        };
                        ok &= lc_core::is_valid_normalized_branch(
                            &committee_root(nc),
                            br,
                            g,
                            &att.state_root,
                        );
                        committees.insert(att.slot / MIN_SLOTS_PER_PERIOD + 1, nc.clone());
                    }
                    if genesis {
                        comp.unsupported("finalized header at GENESIS_SLOT (spec zero leaf); on-chain finality never points at genesis");
                    } else if ok {
                        comp.pass()
                    } else {
                        comp.mismatch(format!(
                            "{sid}: branch/execution check rejected a spec-valid update"
                        ))
                    }
                    // signature: production signing root + BLS, committee by signature period
                    let Some(com) = committees.get(&(u.signature_slot / MIN_SLOTS_PER_PERIOD))
                    else {
                        sig_host.mismatch(format!("{sid}: no committee for signature period"));
                        continue;
                    };
                    let fv = k
                        .cfg
                        .fork_version_at((u.signature_slot.max(1) - 1) / MIN_SLOTS_PER_EPOCH)
                        .unwrap();
                    let p = PairingInputs {
                        aggregate_pubkey: com.aggregate_pubkey,
                        non_signer_pubkeys: (0..32)
                            .filter(|&i| !u.sync_aggregate.participant(i))
                            .map(|i| com.pubkeys[i])
                            .collect(),
                        signing_root: lc_core::signing_root(
                            &lc_core::hash_tree_root_header(att),
                            fv,
                            &k.cfg.genesis_validators_root,
                        ),
                        signature: u.sync_aggregate.sync_committee_signature,
                    };
                    let w = witness(&p);
                    let (kh, k2) = hint_sets(&p);
                    let v = lc_core::host_bls::BlstVerifier.verify_sync_aggregate(
                        &p.aggregate_pubkey,
                        &p.non_signer_pubkeys,
                        &p.signing_root,
                        &p.signature,
                    );
                    if v && bls_host(&p, &kh, &w) == 2 && bls_host(&p, &k2, &w) == 2 {
                        sig_host.pass()
                    } else {
                        sig_host.mismatch(format!("{sid}: host signature (BlstVerifier {v})"));
                    }
                    ops.push(Op::Bls(p.clone(), kh, w.clone()));
                    ops.push(Op::Bls(p, k2, w));
                    guest_ids.push(format!("{sid} K"));
                    guest_ids.push(format!("{sid} K+2"));
                }
            }
        }
    }
    let mut g = Tally::default();
    for (id, got) in guest_ids.iter().zip(guest(&ops)) {
        if got == [2] {
            g.pass()
        } else {
            g.mismatch(format!("guest {id}: {got:?}"))
        }
    }
    report(
        "light_client/sync (minimal; no mainnet sync vectors are published)",
        &[
            (
                "sync: bootstrap + per-update branches/execution (host lc-core)".into(),
                &comp,
            ),
            (
                "sync: sync-aggregate signature (host: BlstVerifier + bls.rs K, K+2)".into(),
                &sig_host,
            ),
            (
                "sync: sync-aggregate signature (guest zkVM bls.rs K, K+2, residue witness)".into(),
                &g,
            ),
            ("sync: store-state checks".into(), &store),
        ],
    );
}

#[test]
fn update_ranking_and_data_collection() {
    let base = dir().join("consensus/tests");
    let (mut r, mut d) = (Tally::default(), Tally::default());
    for preset in ["mainnet", "minimal"] {
        for fork in FORKS {
            let lc = base.join(format!("{preset}/{fork}/light_client"));
            for _ in subdirs(&lc.join("update_ranking/pyspec_tests")) {
                r.unsupported(
                    "is_better_update: no best_valid_update / force_update on-chain (by design)",
                );
            }
            for _ in subdirs(&lc.join("data_collection/pyspec_tests")) {
                d.unsupported("full-node LC data production, not a verifier function");
            }
        }
    }
    report(
        "update_ranking / data_collection",
        &[
            ("update_ranking".into(), &r),
            ("data_collection".into(), &d),
        ],
    );
}
