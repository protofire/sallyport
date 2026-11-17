//! Real-proving benchmarks for the RFP-021 programs. See docs/BENCHMARKS.md.
//!
//! `cargo run -p bench --release -- <action> [--mode execute|composite|succinct] [--step N] [--po2 N]`
//! Actions: claim, claim-inline, attest-slot, attest-erc20, attest-erc20-compact, attest-eth,
//! update-finality, update-learn, update-k170. Env: RISC0_DEV_MODE must be unset/0.

use std::collections::HashMap;
use std::time::Instant;

use attest_program::*;
use lc_core::{LightClientUpdate, Store};
use lee::program::Program;
use lee_core::account::{AccountId, Actor};
use lee_core::program::{ReceiveInput, Transition};
use program_tests::*;
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts};

include!(concat!(env!("OUT_DIR"), "/methods.rs"));

const A: [u8; 32] = SEPOLIA_ID;

struct Step {
    label: String,
    elf: &'static [u8],
    input: ReceiveInput,
}

fn env_for(input: &ReceiveInput, po2: Option<u32>) -> ExecutorEnv<'static> {
    let mut b = ExecutorEnv::builder();
    if let Some(p) = po2 {
        b.segment_limit_po2(p);
    }
    Program::write_receive_input(input, &mut b).unwrap();
    b.build().unwrap()
}

/// Mini sequencer: runs `root` and its chained sync messages on the executor (no proof), recording
/// every transition's exact `ReceiveInput` (what a prover would be handed).
struct Walker<'a> {
    chain: &'a Chain,
    overlay: HashMap<Actor, Vec<u8>>,
    steps: Vec<Step>,
}

impl Walker<'_> {
    fn elf(&self, program: AccountId) -> (&'static str, &'static [u8]) {
        if program == self.chain.attest {
            ("attest", ATTEST_ELF)
        } else if program == self.chain.erc20 {
            ("erc20_receiver", ERC20_RECEIVER_ELF)
        } else if program == self.chain.erc20_inline {
            ("erc20_inline_receiver", ERC20_INLINE_RECEIVER_ELF)
        } else {
            ("eth_receiver", ETH_RECEIVER_ELF)
        }
    }

    fn run(
        &mut self,
        receiver: Actor,
        from: Option<Actor>,
        auth: bool,
        message: Vec<u8>,
        what: &str,
    ) {
        let pre = self
            .overlay
            .get(&receiver)
            .cloned()
            .unwrap_or_else(|| self.chain.state_of(receiver));
        let input = ReceiveInput {
            receiver,
            from,
            is_authorized: auth,
            pre_state: pre.into(),
            message,
        };
        let (name, elf) = self.elf(receiver.program_account_id);
        let info = default_executor()
            .execute(env_for(&input, None), elf)
            .expect("execute");
        let t: Transition =
            borsh::from_slice(lee_core::from_frame(&info.journal.bytes).unwrap()).unwrap();
        assert!(
            matches!(info.exit_code, risc0_zkvm::ExitCode::Halted(0)),
            "{what}: {:?}",
            info.exit_code
        );
        if let Some(post) = &t.response.post_state {
            self.overlay.insert(receiver, post.to_vec());
        }
        self.steps.push(Step {
            label: format!("{name}:{what}"),
            elf,
            input,
        });
        for m in t.response.sync_messages {
            self.run(m.to, Some(receiver), !m.pda_seeds.is_empty(), m.message, "");
        }
    }
}

fn walk(chain: &Chain, root: Actor, msg: &impl borsh::BorshSerialize, what: &str) -> Vec<Step> {
    let mut w = Walker {
        chain,
        overlay: HashMap::new(),
        steps: vec![],
    };
    w.run(root, None, false, borsh::to_vec(msg).unwrap(), what);
    // Child transitions are unlabeled by the walker; names follow the fixed message order.
    let names: &[&str] = match what {
        "Claim" => &["Claim", "Attest", "AttestReply", "Nullify"],
        "Update" => &["Update", "Write1", "Write2"],
        "ClaimInline" => &["ClaimInline", "CheckHeader", "Nullify"],
        _ => &["Attest"],
    };
    for (s, n) in w.steps.iter_mut().zip(names) {
        s.label = format!("{}:{n}", s.label.split(':').next().unwrap());
    }
    w.steps
}

fn sepolia_chain() -> Chain {
    let mut c = Chain::new();
    c.init(&sepolia_init()).unwrap();
    c
}

fn vault_cfg(token: [u8; 20], vault_address: [u8; 20]) -> consumers::VaultConfig {
    let s = lc_core::ChainConfig::sepolia();
    consumers::VaultConfig {
        instance_id: A,
        chain_id: s.chain_id,
        genesis_validators_root: s.genesis_validators_root,
        token,
        vault_address,
    }
}

/// Copied from program-tests/tests/onetx.rs: real Sepolia post-handoff finality state.
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

/// Copied from onetx.rs `signed_case(k, Case::Sepolia)`: test-seeded committee, VALID aggregate
/// signature with exactly `k` non-signers (real Sepolia finality header and branches).
fn signed_k(k: usize) -> (Chain, LightClientUpdate) {
    use blst::min_pk::{AggregatePublicKey, AggregateSignature, SecretKey};
    let (mut c, mut u) = (finality_chain(), sepolia_finality());
    let mut st = c.instance_state(&A);
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
    st.headers.leaves = (1 << (HEADER_TREE_DEPTH - 1)) - 1;
    st.headers.nodes = [[7; 32]; HEADER_TREE_DEPTH];
    let p = lc_core::prepare_update(&st.cfg.chain, &st.store, &u, SEPOLIA_NOW).unwrap();
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
    force_instance(&mut c, A, &st);
    (c, u)
}

fn steps_for(action: &str) -> Vec<Step> {
    let blk = ElBlock::sepolia();
    let mut c = sepolia_chain();
    let attest_root = |c: &mut Chain, req: attest_program::AttestRequest| {
        let hdr = c.seeded(
            c.attest,
            attest_program::header_seed(&req.instance_id, &blk.hash),
        );
        walk(c, hdr, &Msg::Attest(req), "Attest")
    };
    match action {
        "claim" | "claim-inline" => {
            let inline = action == "claim-inline";
            let (token, to, amount) = blk.log(1, 1);
            let erc20 = if inline { c.erc20_inline } else { c.erc20 };
            c.init_vault(erc20, [1; 32], vault_cfg(token, to)).unwrap();
            let v = c.vault(erc20, [1; 32]);
            let (receipt, receipt_proof) = blk.receipt(1);
            let msg = consumers::ConsumerMsg::Claim {
                vault_id: [1; 32],
                block_hash: blk.hash,
                exec_header_rlp: blk.rlp.clone(),
                ancestry: vec![],
                tx_index: 1,
                log_index: 1,
                receipt,
                receipt_proof,
                amount,
            };
            // declare the nullifier PDA seed so Walker/Chain agree on it (state is read-only here)
            walk(&c, v, &msg, if inline { "ClaimInline" } else { "Claim" })
        }
        "attest-slot" => {
            let weth = h32("0x577261707065642045746865720000000000000000000000000000000000001a");
            let preds = vec![inclusion::Pred::Eq {
                field: inclusion::FieldSel::Slot,
                value: weth.to_vec(),
            }];
            attest_root(&mut c, weth_slot0(A, preds))
        }
        "attest-erc20" => {
            let (token, to, amount) = blk.log(1, 1);
            attest_root(
                &mut c,
                blk.attest_log(
                    A,
                    1,
                    1,
                    inclusion::erc20_transfer_preds(token, None, Some(to), Some(amount)),
                ),
            )
        }
        "attest-erc20-compact" => {
            let (token, to, amount) = blk.log(1, 1);
            let mut req = blk.attest_log(
                A,
                1,
                1,
                inclusion::erc20_transfer_preds(token, None, Some(to), Some(amount)),
            );
            if let attest_program::Proof::Log { receipt_proof, .. } = req.proof {
                req.proof = attest_program::Proof::LogCompact { receipt_proof };
            }
            attest_root(&mut c, req)
        }
        "attest-eth" => {
            let (_, to, amount) = blk.log(2, 0);
            attest_root(
                &mut c,
                blk.attest_log(
                    A,
                    2,
                    0,
                    inclusion::native_eth_transfer_preds(None, Some(to), Some(amount)),
                ),
            )
        }
        "update-finality" | "update-learn" | "update-k170" => {
            let (mut c, u) = match action {
                "update-finality" => (finality_chain(), sepolia_finality()),
                "update-learn" => (sepolia_chain(), sepolia_updates().remove(1)),
                _ => signed_k(170),
            };
            let st = c.instance_state(&A);
            let w = witness(&st.cfg, &st.store, &u, SEPOLIA_NOW);
            let h = c.hints(A, &u, SEPOLIA_NOW);
            c.timestamp_ms = st.cfg.slot_start_ms(SEPOLIA_NOW);
            let inst = c.instance(&A);
            walk(
                &c,
                inst,
                &Msg::Update {
                    instance_id: A,
                    update: u,
                    non_signers: h,
                    witness: w,
                    now_slot: SEPOLIA_NOW,
                },
                "Update",
            )
        }
        other => panic!("unknown action {other}"),
    }
}

#[derive(Default)]
struct Row {
    label: String,
    mode: &'static str,
    exec_cycles: u64,
    exec_segments: usize,
    prove_ms: u128,
    stats: Option<(usize, u64, u64, u64)>,
    receipt_bytes: usize,
    journal_bytes: usize,
}

impl Row {
    fn print(&self, action: &str, step: usize, po2: Option<u32>) {
        let (seg, total, user, paging) = self.stats.unwrap_or((0, 0, 0, 0));
        println!(
            "RESULT action={action} step={step} label={} mode={} po2={} exec_cycles={} exec_segments={} prove_segments={seg} prove_total_cycles={total} prove_user_cycles={user} prove_paging_cycles={paging} prove_ms={} receipt_bytes={} journal_bytes={}",
            self.label.replace(' ', "_"),
            self.mode,
            po2.map_or("default".into(), |p| p.to_string()),
            self.exec_cycles,
            self.exec_segments,
            self.prove_ms,
            self.receipt_bytes,
            self.journal_bytes
        );
    }
}

fn prove_step(
    s: &Step,
    mode: &'static str,
    po2: Option<u32>,
) -> (Row, Option<risc0_zkvm::Receipt>) {
    let info = default_executor()
        .execute(env_for(&s.input, po2), s.elf)
        .unwrap();
    let mut row = Row {
        label: s.label.clone(),
        mode,
        exec_cycles: info.cycles(),
        exec_segments: info.segments.len(),
        ..Default::default()
    };
    let mut receipt = None;
    if mode != "execute" {
        let opts = if mode == "succinct" {
            ProverOpts::succinct()
        } else {
            ProverOpts::default()
        };
        let t = Instant::now();
        let p = default_prover()
            .prove_with_opts(env_for(&s.input, po2), s.elf, &opts)
            .expect("prove");
        row.prove_ms = t.elapsed().as_millis();
        row.stats = Some((
            p.stats.segments,
            p.stats.total_cycles,
            p.stats.user_cycles,
            p.stats.paging_cycles,
        ));
        row.receipt_bytes = borsh::to_vec(&p.receipt.inner).unwrap().len();
        row.journal_bytes = p.receipt.journal.bytes.len();
        p.receipt
            .verify(risc0_zkvm::sha::Digest::from(image_id(s.elf)))
            .expect("receipt verifies");
        receipt = Some(p.receipt);
    }
    (row, receipt)
}

fn image_id(elf: &'static [u8]) -> [u32; 8] {
    Program::new(elf.into()).unwrap().id()
}

fn main() {
    assert!(
        std::env::var("RISC0_DEV_MODE").map_or(true, |v| v == "0" || v.is_empty()),
        "RISC0_DEV_MODE must be off"
    );
    let args: Vec<String> = std::env::args().skip(1).collect();
    let action = args.first().expect("action").clone();
    let opt = |k: &str| {
        args.iter()
            .position(|a| a == k)
            .map(|i| args[i + 1].clone())
    };
    let mode: &'static str = match opt("--mode").as_deref().unwrap_or("composite") {
        "execute" => "execute",
        "succinct" => "succinct",
        _ => "composite",
    };
    let po2: Option<u32> = opt("--po2").map(|v| v.parse().unwrap());
    let only: Option<usize> = opt("--step").map(|v| v.parse().unwrap());

    match action.as_str() {
        _ => {
            let steps = steps_for(&action);
            for (i, s) in steps.iter().enumerate() {
                if only.is_some_and(|o| o != i) {
                    continue;
                }
                prove_step(s, mode, po2).0.print(&action, i, po2);
            }
        }
    }
}
