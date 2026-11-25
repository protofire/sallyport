//! E2E against a local LEZ v0.4.0-rc1 standalone sequencer (see docs/OPERATOR-GUIDE.md).
//! usage: program-e2e <payer_account_id>   (wallet env: LEE_WALLET_HOME_DIR, LEE_WALLET_PASSWORD)
//! Deploys attest (at the ATTEST_DEPLOY_KEY account, which must be imported into the wallet) and
//! erc20_receiver, then: Init → Update (UpdateBegin → UpdateVerify if K > lez_client::ONE_TX_MAX_NON_SIGNERS or E2E_SPLIT_UPDATE=1) → Attest → InitVault → Claim → replay.
//!
//! Live steps (evidence/rfp021-final-run.md; updates are driven by `rfp021 run-relayer`):
//!   program-e2e deploy <payer>
//!   program-e2e init <payer> <update-material.json>   (from `rfp021 fetch-update --bootstrap-root finalized`;
//!     prints the instance id = attest_program::instance_id(cfg, root), the only id Init accepts)
//!   program-e2e header <instance_hex> <execution_block_hash>
//!   program-e2e simulate <tx_hash>...   (read-only local re-execution of included public txs; guest exit code)
//!   program-e2e gas <block_id>...   (cycles = gas_used_exec of the block's fee summary; exact for a lone tx)
//!   program-e2e root <payer> <instance_hex> <ebh>...   (all HeaderRecords in acceptance order; CheckRoot live)
//!   program-e2e claim <payer> <consumer_program> <instance_hex> <vault_id_hex> <attest.json>   (from `rfp021 fetch-attest [--anchor <recorded ebh>]`)
//!   program-e2e private-claim <payer> <erc20_program> <instance_hex> <vault_id_hex> <attest.json> <nk_file> <claimant> <claimant2> <ebh>...
//!     (F8: DepositVault `Deposit(C, amount)` log; `ebh...` = all HeaderRecords in acceptance order;
//!      claimant/claimant2 = funded wallet-owned private accounts; then the same deposit through a second
//!      private vault (vault_id with the last byte ^ 1) must be refused; see evidence/rfp021-final-run.md)

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use attest_program::*;
use borsh::BorshSerialize;
use common::transaction::LeeTransaction;
use consumers::{ConsumerMsg, VaultConfig, VaultState};
use lee::public_transaction::{Message, WitnessSet};
use lee::{AccountId, Actor, PublicAccountEvidence, PublicTransaction};
use lee_core::program::PdaSeed;
use program_loader_core::MAX_SEGMENT_DATA_LEN;
use program_tests::*;
use sequencer_service_rpc::RpcClient as _;
use wallet::program_facades::program_loader::ProgramLoader;
use wallet::WalletCore;

const VAULT: [u8; 32] = [1; 32];

struct E2e {
    w: WalletCore<sequencer_service_rpc::SequencerClient>,
    payer: AccountId,
    log: Vec<(String, String, u64, bool)>,
}

impl E2e {
    async fn deploy(&mut self, header: AccountId, elf: &[u8]) {
        let user_elf = risc0_binfmt::ProgramBinary::decode(elf).unwrap().user_elf;
        let segs: Vec<AccountId> =
            std::iter::repeat_with(|| self.w.create_new_account_public(None).0)
                .take(user_elf.len().div_ceil(MAX_SEGMENT_DATA_LEN))
                .collect();
        self.w.store_persistent_data().unwrap();
        ProgramLoader(&mut self.w)
            .deploy(header, &segs, elf.to_vec(), true, Some(self.payer))
            .await
            .unwrap();
        println!("deployed {header} ({} segments, immutable)", segs.len());
    }

    /// Signed, fee-paying public tx; waits for inclusion and reports whether the action reverted.
    async fn send(
        &mut self,
        name: &str,
        to: Actor,
        mut actors: Vec<Actor>,
        new_pdas: &[(AccountId, [u8; 32])],
        msg: &impl BorshSerialize,
        gas: u64,
    ) -> bool {
        actors.push(to);
        let key = self
            .w
            .get_account_public_signing_key(self.payer)
            .unwrap()
            .clone();
        let nonce = self
            .w
            .get_account_view(Actor::native_balance(self.payer))
            .await
            .unwrap()
            .unwrap_or_default()
            .nonce;
        let mut m =
            Message::try_new(to, actors, BTreeMap::from([(self.payer, nonce)]), msg).unwrap();
        m.admission_evidence = new_pdas
            .iter()
            .map(|(program, seed)| PublicAccountEvidence::Pda {
                program: *program,
                seed: PdaSeed::new(*seed),
            })
            .collect();
        m.fee = Some(lee::FeeDeclaration::new(
            self.payer,
            gas,
            0,
            wallet::max_fee_for(gas),
        ));
        let tx = PublicTransaction::new(m.clone(), WitnessSet::for_message(&m, &[&key]));
        let lee_tx = LeeTransaction::Public(tx);
        let hash = self
            .w
            .client_owned()
            .send_transaction(lee_tx.clone())
            .await
            .unwrap();
        let (_, block_id) = self.w.poll_transaction(hash).await.unwrap();
        let block = self
            .w
            .client_owned()
            .get_block(block_id)
            .await
            .unwrap()
            .unwrap();
        let pos = block
            .body
            .transactions
            .iter()
            .position(|t| *t == lee_tx)
            .unwrap();
        let ok = !block.body.is_reverted(pos);
        println!(
            "{name}: tx {hash} block {block_id} {}",
            if ok { "ok" } else { "REVERTED" }
        );
        self.log
            .push((name.into(), format!("{hash}"), block_id, ok));
        ok
    }

    async fn state(&self, a: Actor) -> Vec<u8> {
        self.w
            .get_account_view(a)
            .await
            .unwrap()
            .map(|acc| acc.data.actor_state(a.program_account_id).to_vec())
            .unwrap_or_default()
    }
}

fn now_slot(genesis: u64) -> u64 {
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - genesis)
        / 12
}

/// Root PDA that `Init` writes: the accumulator root after appending the bootstrap header.
fn first_root(
    attest: AccountId,
    id: InstanceId,
    cfg: &InstanceConfig,
    init: &Msg,
) -> ([u8; 32], Actor) {
    let Msg::Init { bootstrap, .. } = init else {
        unreachable!()
    };
    let f = bootstrap.header.to_finalized(&cfg.chain).unwrap();
    let root = Frontier::default()
        .append(header_leaf(&header_record(id, cfg, &f)))
        .unwrap();
    let seed = hroot_seed(&id, &root);
    (seed, Actor::new(pda(attest, seed), attest))
}

/// risc0 image ids of the deployed guests (Digest hex: u32 words little-endian).
fn print_image_ids() {
    let h = |id: [u32; 8]| {
        id.iter()
            .flat_map(|w| w.to_le_bytes())
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    use program_methods::{
        ATTEST_ID, ERC20_INLINE_RECEIVER_ID, ERC20_RECEIVER_ID, ETH_RECEIVER_ID,
    };
    println!(
        "ImageID attest={}\nImageID erc20_receiver={}\nImageID eth_receiver={}\nImageID erc20_inline_receiver={}",
        h(ATTEST_ID),
        h(ERC20_RECEIVER_ID),
        h(ETH_RECEIVER_ID),
        h(ERC20_INLINE_RECEIVER_ID)
    );
}

fn hexv(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string").trim_start_matches("0x")).expect("hex")
}

async fn live(args: &[String]) {
    let mut w = WalletCore::from_env().unwrap();
    let attest = attest_program_id();
    let pda_of = |program: AccountId, seed: [u8; 32]| Actor::new(pda(program, seed), program);
    let payer = |i: usize| -> AccountId { args[i].trim_start_matches("Public/").parse().unwrap() };
    match args[1].as_str() {
        "deploy" => {
            let mut e = E2e {
                w,
                payer: payer(2),
                log: vec![],
            };
            assert!(
                e.w.get_account_public_signing_key(attest).is_some(),
                "import ATTEST_DEPLOY_KEY into the wallet first"
            );
            e.deploy(attest, ATTEST_ELF).await;
            let erc20 = e.w.create_new_account_public(None).0;
            e.deploy(erc20, ERC20_RECEIVER_ELF).await;
            let eth = e.w.create_new_account_public(None).0;
            e.deploy(eth, ETH_RECEIVER_ELF).await;
            // optional inline consumer: separate program id; never point it at a chained vault's (address, token)
            let inline = e.w.create_new_account_public(None).0;
            e.deploy(inline, ERC20_INLINE_RECEIVER_ELF).await;
            println!("attest={attest} erc20_receiver={erc20} eth_receiver={eth} erc20_inline_receiver={inline}");
            print_image_ids();
        }
        "init" => {
            let mut e = E2e {
                w,
                payer: payer(2),
                log: vec![],
            };
            let m: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&args[3]).unwrap()).unwrap();
            let root = h32(m["bootstrap_root"]
                .as_str()
                .expect("material has bootstrap_root"));
            let bootstrap = lc_core::json::bootstrap_from_value(&m["bootstrap"]).unwrap();
            let cfg = sepolia_cfg();
            let id = instance_id(&cfg, &root);
            let ebh = bootstrap
                .header
                .to_finalized(&cfg.chain)
                .unwrap()
                .execution_block_hash;
            let inst = pda_of(attest, instance_seed(&id));
            let hdr = pda_of(attest, header_seed(&id, &ebh));
            let now = now_slot(cfg.genesis_time);
            let init = Msg::Init {
                instance_id: id,
                cfg: cfg.clone(),
                trusted_block_root: root,
                bootstrap,
                now_slot: now,
            };
            let (root_seed, hroot) = first_root(attest, id, &cfg, &init);
            let ok = e
                .send(
                    "Init",
                    inst,
                    vec![hdr, hroot],
                    &[
                        (attest, instance_seed(&id)),
                        (attest, header_seed(&id, &ebh)),
                        (attest, root_seed),
                    ],
                    &init,
                    5_000_000,
                )
                .await;
            assert!(ok, "Init reverted");
            let st: InstanceState = borsh::from_slice(&e.state(inst).await).unwrap();
            println!("instance_id 0x{}\ninstance {inst:?}\nfinalized slot {} execution_block_hash 0x{} now_slot {now}", hex::encode(id), st.store.finalized_header.beacon.slot, hex::encode(st.store.finalized_header.execution_block_hash));
        }
        "header" => {
            let e = E2e {
                w,
                payer: attest,
                log: vec![],
            };
            let (id, ebh) = (h32(&args[2]), h32(&args[3]));
            let st = e.state(pda_of(attest, header_seed(&id, &ebh))).await;
            if st.is_empty() {
                println!("no HeaderRecord for 0x{}", hex::encode(ebh));
                std::process::exit(1);
            }
            let r: HeaderRecord = borsh::from_slice(&st).unwrap();
            println!(
                "HeaderRecord beacon_slot={} period={} beacon_root=0x{} execution_block_hash=0x{}",
                r.beacon_slot,
                r.period,
                hex::encode(r.beacon_root),
                hex::encode(r.execution_block_hash)
            );
        }
        "root" => {
            // Rebuild the header accumulator from the HeaderRecord PDAs (in acceptance order) and
            // check it against the instance frontier and its root PDA, then CheckRoot live.
            let mut e = E2e {
                w,
                payer: payer(2),
                log: vec![],
            };
            let id = h32(&args[3]);
            let st: InstanceState =
                borsh::from_slice(&e.state(pda_of(attest, instance_seed(&id))).await).unwrap();
            let mut leaves = vec![];
            for ebh in &args[4..] {
                let r: HeaderRecord =
                    borsh::from_slice(&e.state(pda_of(attest, header_seed(&id, &h32(ebh)))).await)
                        .expect("HeaderRecord");
                leaves.push(header_leaf(&r));
            }
            let mut fr = Frontier::default();
            let root = leaves
                .iter()
                .map(|l| fr.append(*l).unwrap())
                .last()
                .expect("at least one block hash");
            let hroot = pda_of(attest, hroot_seed(&id, &root));
            println!("leaves={} on-chain leaves={} root=0x{} matches_frontier={} root_pda={} state_matches={}", leaves.len(), st.headers.leaves, hex::encode(root), root == st.headers.root(), hroot.account_id, e.state(hroot).await == root.to_vec());
            for (i, l) in leaves.iter().enumerate() {
                assert_eq!(
                    merkle_root(*l, i as u64, &merkle_path(&leaves, i)),
                    Some(root),
                    "membership path {i}"
                );
            }
            println!("membership paths ok for all {} headers", leaves.len());
            let ok = e
                .send(
                    "CheckRoot(relayer root)",
                    hroot,
                    vec![],
                    &[],
                    &Msg::CheckRoot {
                        instance_id: id,
                        root,
                    },
                    1_000_000,
                )
                .await;
            let bogus = [0xBD; 32];
            let bad = e
                .send(
                    "CheckRoot(unknown root)",
                    pda_of(attest, hroot_seed(&id, &bogus)),
                    vec![],
                    &[(attest, hroot_seed(&id, &bogus))],
                    &Msg::CheckRoot {
                        instance_id: id,
                        root: bogus,
                    },
                    1_000_000,
                )
                .await;
            assert!(ok && !bad, "known root must pass, unknown must revert");
        }
        "claim" => {
            let mut e = E2e {
                w,
                payer: payer(2),
                log: vec![],
            };
            let program: AccountId = args[3].parse().unwrap();
            let (id, vault_id) = (h32(&args[4]), h32(&args[5]));
            let a: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&args[6]).unwrap()).unwrap();
            let block_hash = h32(a["block_hash"].as_str().unwrap());
            let exec_header_rlp = hexv(&a["exec_header_rlp"]);
            // with `--anchor` material the header is the recorded anchor and `ancestry` links the target to it
            let anchor = alloy_primitives::keccak256(&exec_header_rlp).0;
            let ancestry: Vec<Vec<u8>> = a["ancestry"]
                .as_array()
                .map(|v| v.iter().map(hexv).collect())
                .unwrap_or_default();
            let (tx_index, log_index) = (
                a["tx_index"].as_u64().unwrap() as u32,
                a["log_index"].as_u64().unwrap() as u32,
            );
            let log = &a["log"];
            let token = h20(log["address"].as_str().unwrap());
            let to: [u8; 20] = h32(log["topics"][2].as_str().unwrap())[12..]
                .try_into()
                .unwrap();
            let amount = h32(log["data"].as_str().unwrap());
            let s = lc_core::ChainConfig::sepolia();
            let vault = pda_of(program, consumers::vault_seed(&vault_id));
            let vcfg = VaultConfig {
                instance_id: id,
                chain_id: s.chain_id,
                genesis_validators_root: s.genesis_validators_root,
                token,
                vault_address: to,
            };
            if e.state(vault).await.is_empty() {
                e.send(
                    "InitVault",
                    vault,
                    vec![],
                    &[(program, consumers::vault_seed(&vault_id))],
                    &ConsumerMsg::InitVault {
                        vault_id,
                        cfg: vcfg,
                    },
                    2_000_000,
                )
                .await;
            }
            let claim = ConsumerMsg::Claim {
                vault_id,
                block_hash: anchor,
                exec_header_rlp,
                ancestry: ancestry.clone(),
                tx_index,
                log_index,
                receipt: hexv(&a["receipt"]),
                receipt_proof: a["receipt_proof_nodes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(hexv)
                    .collect(),
                amount,
            };
            let hdr = pda_of(attest, header_seed(&id, &anchor));
            println!(
                "claim target 0x{} via {} ancestry headers, anchor 0x{}",
                hex::encode(block_hash),
                ancestry.len(),
                hex::encode(anchor)
            );
            let sid = statement_id_for(
                s.chain_id,
                s.genesis_validators_root,
                block_hash,
                tx_index,
                log_index,
            );
            let null = pda_of(program, consumers::nullifier_seed(&vault_id, &sid));
            let ok = e
                .send(
                    "Claim",
                    vault,
                    vec![hdr, null],
                    &[],
                    &claim,
                    lez_client::CLAIM_GAS,
                )
                .await;
            let v: VaultState =
                consumers::untag(consumers::TAG_VAULT, &e.state(vault).await).unwrap();
            println!(
                "vault token=0x{} to=0x{} claims={} credited_total={} statement_id=0x{}",
                hex::encode(token),
                hex::encode(to),
                v.claims,
                v.credited_total,
                hex::encode(sid)
            );
            if let Some(c) =
                consumers::untag::<consumers::Credit>(consumers::TAG_CREDIT, &e.state(null).await)
            {
                println!(
                    "credit eth_sender=0x{} amount={} (nullifier PDA {})",
                    hex::encode(c.eth_sender),
                    c.amount,
                    null.account_id
                );
            }
            let replay_ok = e
                .send(
                    "Claim replay",
                    vault,
                    vec![hdr, null],
                    &[],
                    &claim,
                    lez_client::CLAIM_GAS,
                )
                .await;
            assert!(ok && !replay_ok, "claim must apply and replay must revert");
            println!("\n| step | tx hash | block | result |\n|---|---|---:|---|");
            for (n, h, b, ok) in &e.log {
                println!(
                    "| {n} | `{h}` | {b} | {} |",
                    if *ok { "ok" } else { "reverted" }
                );
            }
        }
        "private-claim" => private_claim(w, attest, args).await,
        "simulate" => {
            // Read-only: re-execute included public txs (e.g. reverted replays) locally with LEZ's
            // own `simulate_public_transaction`, over the current states of their declared actors
            // and the deployed program bytecode, and print the guest exit (code = error - 1000).
            use lee::privacy_preserving_transaction::circuit::{
                Dependency, ProgramCatalog, ProgramKind,
            };
            for h in &args[2..] {
                let hash = h.parse().expect("tx hash");
                let (tx, block) = w
                    .client_owned()
                    .get_transaction(hash)
                    .await
                    .unwrap()
                    .expect("tx not found");
                let common::transaction::LeeTransaction::Public(tx) = tx else {
                    panic!("{h}: not a public tx")
                };
                let mut states = std::collections::HashMap::new();
                let mut programs = ProgramCatalog::default();
                for a in &tx.message().public_context.actors {
                    let data = w
                        .get_account_view(*a)
                        .await
                        .unwrap()
                        .map(|acc| acc.data.actor_state(a.program_account_id).clone())
                        .unwrap_or_else(lee_core::account::ActorState::empty);
                    states.insert(*a, data);
                    if !programs.programs.contains_key(&a.program_account_id) {
                        if let Some(program) = ProgramLoader(&mut w)
                            .program(a.program_account_id)
                            .await
                            .unwrap()
                        {
                            programs.programs.insert(
                                a.program_account_id,
                                Dependency {
                                    program,
                                    kind: ProgramKind::Disclosed,
                                },
                            );
                        }
                    }
                }
                let sim = lee::Simulation {
                    public_actor_states: states,
                    admitted_accounts: None,
                };
                let budget = tx.message().fee.map_or(10_000_000, |f| f.gas_limit);
                let (cycles, r) = lee::simulate_public_transaction(&tx, &sim, &programs, budget);
                let exit = match &r {
                    Err(lee::error::LeeError::ProgramExitedWithCode { code, .. }) => {
                        format!("exit {code} = error {}", 1000 + code)
                    }
                    Err(e) => format!("error: {e}"),
                    Ok(()) => "ok".into(),
                };
                println!("simulate {h} (block {block}): cycles={cycles} {exit}");
            }
        }
        "gas" => {
            // LEZ has no receipts: the block's forced fee tx (last) carries BlockFeeSummary
            // {gas_used_exec = sum of charged cycles of its user txs, gas_used_stor, ..}, so a
            // tx alone in its block has exactly that many cycles.
            for b in &args[2..] {
                let id: u64 = b.parse().expect("block id");
                let block = w
                    .client_owned()
                    .get_block(id)
                    .await
                    .unwrap()
                    .expect("block");
                let txs = &block.body.transactions;
                let exempt = |t: &common::transaction::LeeTransaction| matches!(t, common::transaction::LeeTransaction::Public(p) if p.message().fee.is_none());
                // borsh Distribute { summary: {u64, u64, u128, u128}, payout: u128, producer: [u8; 32] } = 97 bytes
                let m = txs
                    .iter()
                    .filter(|t| exempt(t))
                    .filter_map(|t| t.public_call())
                    .map(|(_, m)| m)
                    .find(|m| m.len() == 97 && m[0] == 0)
                    .unwrap_or_else(|| panic!("block {id}: no fee Distribute tx"));
                let u = |i: usize| u64::from_le_bytes(m[i..i + 8].try_into().unwrap());
                let user: Vec<String> = txs
                    .iter()
                    .enumerate()
                    .filter(|(_, t)| !exempt(t))
                    .map(|(i, t)| {
                        // declared gas_limit of a public tx (what the sender reserved, not what it used)
                        let limit = match t {
                            common::transaction::LeeTransaction::Public(p) => p
                                .message()
                                .fee
                                .as_ref()
                                .map(|f| format!(" gas_limit={}", f.gas_limit)),
                            _ => None,
                        };
                        format!(
                            "{}{}{}",
                            t.hash(),
                            limit.unwrap_or_default(),
                            if block.body.is_reverted(i) {
                                " (reverted)"
                            } else {
                                ""
                            }
                        )
                    })
                    .collect();
                println!(
                    "block {id} gas_used_exec={} gas_used_stor={} charged_txs={} [{}]",
                    u(1),
                    u(9),
                    user.len(),
                    user.join(", ")
                );
            }
        }
        other => panic!("unknown command {other}"),
    }
}

/// F8 live: two private accounts race the same `nk` (both proven against the pre-claim state, so the
/// sequencer must reject one: replay), then a third attempt after inclusion is refused by the
/// wallet's simulation. Prints the public footprint of the winning tx and before/after states of
/// every public account it names.
async fn private_claim(
    w: WalletCore<sequencer_service_rpc::SequencerClient>,
    attest: AccountId,
    args: &[String],
) {
    use consumers::{cfg_hash, commit, pnf, private_request, vault_seed, PrivateVaultConfig};
    use lee::privacy_preserving_transaction::circuit::ProgramCatalog;
    use lee::program::Program;
    use lee::BoundaryStep;
    use wallet::{AccountIdentity, AccountMention};

    let pda_of = |program: AccountId, seed: [u8; 32]| Actor::new(pda(program, seed), program);
    let parse = |s: &String| -> AccountId { s.rsplit('/').next().unwrap().parse().unwrap() };
    let (payer, program, id, vault_id) = (
        parse(&args[2]),
        parse(&args[3]),
        h32(&args[4]),
        h32(&args[5]),
    );
    let a: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&args[6]).unwrap()).unwrap();
    let nk = h32(std::fs::read_to_string(&args[7]).unwrap().trim());
    let claimants = [parse(&args[8]), parse(&args[9])];
    let block_hash = h32(a["block_hash"].as_str().unwrap());
    let (tx_index, log_index) = (
        a["tx_index"].as_u64().unwrap() as u32,
        a["log_index"].as_u64().unwrap() as u32,
    );
    let log = &a["log"];
    let s = lc_core::ChainConfig::sepolia();
    let cfg = PrivateVaultConfig {
        instance_id: id,
        chain_id: s.chain_id,
        genesis_validators_root: s.genesis_validators_root,
        deposit_contract: h20(log["address"].as_str().unwrap()),
        deposit_topic0: h32(log["topics"][0].as_str().unwrap()),
        denomination: h32(log["data"].as_str().unwrap()),
    };
    assert_eq!(
        h32(log["topics"][1].as_str().unwrap()),
        commit(&nk),
        "nk does not open this deposit's commitment"
    );

    // 1. vault (public InitPrivateVault, once)
    let mut e = E2e {
        w,
        payer,
        log: vec![],
    };
    let vault = pda_of(program, vault_seed(&vault_id));
    if e.state(vault).await.is_empty() {
        let ok = e
            .send(
                "InitPrivateVault",
                vault,
                vec![],
                &[(program, vault_seed(&vault_id))],
                &ConsumerMsg::InitPrivateVault {
                    vault_id,
                    cfg: cfg.clone(),
                },
                2_000_000,
            )
            .await;
        assert!(ok, "InitPrivateVault reverted");
    }
    assert_eq!(
        e.state(vault).await,
        consumers::tagged(consumers::TAG_PRIVATE_VAULT, &cfg),
        "vault holds a different config"
    );

    // 2. header accumulator: leaves from HeaderRecords; claim against the instance's latest root
    let st: InstanceState =
        borsh::from_slice(&e.state(pda_of(attest, instance_seed(&id))).await).unwrap();
    let mut recs = vec![];
    for ebh in &args[10..] {
        recs.push(
            borsh::from_slice::<HeaderRecord>(
                &e.state(pda_of(attest, header_seed(&id, &h32(ebh)))).await,
            )
            .expect("HeaderRecord"),
        );
    }
    let leaves: Vec<[u8; 32]> = recs.iter().map(header_leaf).collect();
    let mut fr = Frontier::default();
    let root = leaves
        .iter()
        .map(|l| fr.append(*l).unwrap())
        .last()
        .unwrap();
    assert_eq!(
        root,
        st.headers.root(),
        "pass every HeaderRecord in acceptance order (root must be the latest)"
    );
    let hroot = pda_of(attest, hroot_seed(&id, &root));
    assert_eq!(e.state(hroot).await, root.to_vec(), "root PDA missing");
    let ancestry: Vec<Vec<u8>> = a["ancestry"]
        .as_array()
        .map(|v| v.iter().map(hexv).collect())
        .unwrap_or_default();
    let claim_at = |index: usize| ConsumerMsg::PrivateClaim {
        vault_id,
        cfg: cfg.clone(),
        header: recs[index].clone(),
        header_index: index as u64,
        header_path: merkle_path(&leaves, index),
        exec_header_rlp: hexv(&a["exec_header_rlp"]),
        ancestry: ancestry.clone(),
        tx_index,
        log_index,
        receipt: hexv(&a["receipt"]),
        receipt_proof: a["receipt_proof_nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(hexv)
            .collect(),
        nk,
    };
    // anchor = the recorded header the material's header chain ends in (host pre-check of the same verify the guest runs)
    let (index, stmt) = (0..recs.len())
        .find_map(|i| {
            attest_program::verify(&recs[i], &private_request(&cfg, &claim_at(i)).unwrap())
                .ok()
                .map(|st| (i, st))
        })
        .expect("no recorded header anchors this deposit (fetch-attest --anchor <recorded ebh>)");
    assert_eq!(
        stmt.fact.execution_block_hash, block_hash,
        "statement must be about the deposit block"
    );
    let msg = claim_at(index);
    let n = pnf(&nk);
    let null = pda_of(program, n);
    println!("deposit block 0x{} via {} ancestry headers to anchor 0x{} = leaf {index} of {}; root 0x{}; statement_id 0x{}; N 0x{} (PDA {})", hex::encode(block_hash), ancestry.len(), hex::encode(recs[index].execution_block_hash), leaves.len(), hex::encode(root), hex::encode(stmt.id), hex::encode(n), null.account_id);

    // 3. private txs via the LEZ wallet (dev-mode proofs if RISC0_DEV_MODE=1)
    let catalog = ProgramCatalog::from([
        (attest, Program::new(ATTEST_ELF.into()).unwrap()),
        (program, Program::new(ERC20_RECEIVER_ELF.into()).unwrap()),
    ]);
    let mention_at = |claimant: AccountId, vault_id: [u8; 32]| -> Vec<AccountMention> {
        vec![
            AccountIdentity::PrivateOwned(claimant).select_program_actor_state(program),
            AccountIdentity::PublicPda {
                program,
                seed: PdaSeed::new(vault_seed(&vault_id)),
            }
            .select_program_actor_state(program),
            AccountIdentity::PublicPda {
                program: attest,
                seed: PdaSeed::new(hroot_seed(&id, &root)),
            }
            .select_program_actor_state(attest),
            AccountIdentity::PublicPda {
                program,
                seed: PdaSeed::new(n),
            }
            .select_program_actor_state(program),
        ]
    };
    let mention = |claimant: AccountId| mention_at(claimant, vault_id);
    let data = borsh::to_vec(&msg).unwrap();
    e.w.sync_to_latest_block().await.unwrap();
    let watched = [vault, hroot, null];
    let mut before = vec![];
    for x in watched {
        before.push(e.state(x).await);
    }
    let (r0, r1) = tokio::join!(
        e.w.send_privacy_preserving_tx(mention(claimants[0]), 0, data.clone(), &catalog),
        e.w.send_privacy_preserving_tx(mention(claimants[1]), 0, data.clone(), &catalog),
    );
    let mut won = None;
    for (who, r) in claimants.iter().zip([r0, r1]) {
        let hash = match r {
            Ok((hash, _)) => hash,
            Err(err) => {
                println!("PrivateClaim by {who}: rejected at submission: {err}");
                continue;
            }
        };
        match e.w.poll_transaction(hash).await {
            Ok((tx, block_id)) => {
                let block =
                    e.w.client_owned()
                        .get_block(block_id)
                        .await
                        .unwrap()
                        .unwrap();
                let pos = block
                    .body
                    .transactions
                    .iter()
                    .position(|t| *t == tx)
                    .unwrap();
                let ok = !block.body.is_reverted(pos);
                println!(
                    "PrivateClaim by {who}: tx {hash} block {block_id} {}",
                    if ok { "ok" } else { "REVERTED" }
                );
                if ok {
                    won = Some((tx, hash, block_id));
                }
            }
            Err(err) => println!("PrivateClaim by {who}: tx {hash} not included: {err}"),
        }
    }
    let (tx, hash, block_id) = won.expect("one private claim must land");
    let common::transaction::LeeTransaction::PrivacyPreserving(pp) = &tx else {
        panic!("not a privacy-preserving tx")
    };

    // 4. third attempt after inclusion: the wallet's simulation against live state must refuse (1250)
    e.w.sync_to_latest_block().await.unwrap();
    match e
        .w
        .send_privacy_preserving_tx(mention(claimants[1]), 0, data.clone(), &catalog)
        .await
    {
        Ok((h, _)) => panic!("replay after inclusion was accepted: {h}"),
        Err(err) => println!("replay after inclusion (same nk): refused before submission: {err}"),
    }
    // 4b. same deposit through a second private vault with the same config: the nullifier is global (D-PRIV-3)
    let mut vault2_id = vault_id;
    vault2_id[31] ^= 1;
    let vault2 = pda_of(program, vault_seed(&vault2_id));
    if e.state(vault2).await.is_empty() {
        let ok = e
            .send(
                "InitPrivateVault (second vault)",
                vault2,
                vec![],
                &[(program, vault_seed(&vault2_id))],
                &ConsumerMsg::InitPrivateVault {
                    vault_id: vault2_id,
                    cfg: cfg.clone(),
                },
                2_000_000,
            )
            .await;
        assert!(ok, "second InitPrivateVault reverted");
    }
    let mut msg2 = msg.clone();
    if let ConsumerMsg::PrivateClaim { vault_id: v, .. } = &mut msg2 {
        *v = vault2_id;
    }
    e.w.sync_to_latest_block().await.unwrap();
    match e
        .w
        .send_privacy_preserving_tx(
            mention_at(claimants[1], vault2_id),
            0,
            borsh::to_vec(&msg2).unwrap(),
            &catalog,
        )
        .await
    {
        Ok((h, _)) => {
            let (tx2, b2) =
                e.w.poll_transaction(h)
                    .await
                    .expect("second-vault claim not included");
            let block = e.w.client_owned().get_block(b2).await.unwrap().unwrap();
            let pos = block
                .body
                .transactions
                .iter()
                .position(|t| *t == tx2)
                .unwrap();
            assert!(
                block.body.is_reverted(pos),
                "second-vault claim credited the same deposit twice: {h}"
            );
            println!(
                "second-vault claim (same nk, vault 0x{}): tx {h} block {b2} REVERTED",
                hex::encode(vault2_id)
            );
        }
        Err(err) => println!(
            "second-vault claim (same nk, vault 0x{}): refused before submission: {err}",
            hex::encode(vault2_id)
        ),
    }

    // 5. public footprint of the winning tx
    let m = &pp.message;
    println!(
        "\nFOOTPRINT tx {hash} (block {block_id}), {} bytes borsh",
        borsh::to_vec(pp).unwrap().len()
    );
    for a in &m.public_context.actors {
        println!(
            "  public actor {} (program {})",
            a.account_id, a.program_account_id
        );
    }
    println!(
        "  public_root: {}",
        if m.execution.public_root.is_some() {
            "PUBLIC"
        } else {
            "none (private root call)"
        }
    );
    println!("  private_actions: {}  async_messages: {}  recovery_bindings: {}  nonces: {}  admission_evidence: {}", m.execution.private_actions.len(), m.execution.async_messages.len(), m.execution.recovery_bindings.len(), m.nonces.len(), m.admission_evidence.len());
    println!(
        "  fee: {:?}",
        m.fee
            .as_ref()
            .map(|_| "proven fee transfer (refund to blinded alias)")
    );
    let redeem = borsh::to_vec(&ConsumerMsg::RedeemCheck {
        vault_id,
        cfg_hash: cfg_hash(&cfg),
        root,
        nullifier: n,
    })
    .unwrap();
    for b in &m.execution.boundary {
        match b {
            BoundaryStep::PrivateToPublic(d) | BoundaryStep::PublicToPrivate(d) => {
                let dir = if matches!(b, BoundaryStep::PrivateToPublic(_)) {
                    "PrivateToPublic"
                } else {
                    "PublicToPrivate"
                };
                let what = if d.envelope.message == redeem {
                    "RedeemCheck{vault_id, cfg_hash, root, N}".to_string()
                } else {
                    format!("{} bytes", d.envelope.message.len())
                };
                let from = d.envelope.from.account_id;
                println!(
                    "  boundary {dir}: to {} msg {what}; sender {} (claimant? {})",
                    d.envelope.to.account_id,
                    from,
                    claimants.contains(&from)
                );
            }
            other => println!("  boundary {other:?}"),
        }
    }
    for (x, b) in watched.iter().zip(&before) {
        let after = e.state(*x).await;
        println!(
            "  state {} : {} -> {}",
            x.account_id,
            if b.is_empty() {
                "empty".into()
            } else {
                format!("{} B", b.len())
            },
            if after == *b {
                "unchanged".into()
            } else {
                format!(
                    "{:?}",
                    if after.len() <= 4 {
                        hex::encode(&after)
                    } else {
                        format!("{} B", after.len())
                    }
                )
            }
        );
    }
    let mut hay = borsh::to_vec(pp).unwrap();
    hay.extend(e.state(null).await);
    let hdr = pda(attest, header_seed(&id, &block_hash));
    let needles: Vec<(&str, Vec<u8>)> = vec![
        ("block hash", block_hash.to_vec()),
        ("header PDA", hdr.value().to_vec()),
        (
            "anchor block hash",
            recs[index].execution_block_hash.to_vec(),
        ),
        (
            "anchor header PDA",
            pda(attest, header_seed(&id, &recs[index].execution_block_hash))
                .value()
                .to_vec(),
        ),
        ("anchor header leaf", leaves[index].to_vec()),
        ("statement_id", stmt.id.to_vec()),
        (
            "H(statement_id)",
            consumers::nullifier_seed(&vault_id, &stmt.id).to_vec(),
        ),
        ("claimant 1", claimants[0].value().to_vec()),
        ("claimant 2", claimants[1].value().to_vec()),
        ("commitment C", commit(&nk).to_vec()),
        ("nk", nk.to_vec()),
        ("receipt", hexv(&a["receipt"])[..48].to_vec()),
        ("deposit contract", cfg.deposit_contract.to_vec()),
    ];
    for (name, needle) in &needles {
        let hit = hay.windows(needle.len()).any(|w| w == needle.as_slice());
        println!(
            "  byte search {name}: {}",
            if hit { "FOUND (leak)" } else { "absent" }
        );
        assert!(!hit, "{name} leaked");
    }
    if let Some(log) = e.log.first() {
        println!("\nInitPrivateVault tx {} block {}", log.1, log.2);
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("image-ids") {
        return print_image_ids();
    }
    if matches!(
        args.get(1).map(String::as_str),
        Some(
            "deploy" | "init" | "header" | "root" | "claim" | "private-claim" | "gas" | "simulate"
        )
    ) {
        return live(&args).await;
    }
    let payer: AccountId = std::env::args()
        .nth(1)
        .expect("payer account id")
        .parse()
        .unwrap();
    let mut e = E2e {
        w: WalletCore::from_env().unwrap(),
        payer,
        log: vec![],
    };
    let attest = attest_program_id();
    assert!(
        e.w.get_account_public_signing_key(attest).is_some(),
        "import ATTEST_DEPLOY_KEY into the wallet first"
    );
    e.deploy(attest, ATTEST_ELF).await;
    let erc20 = e.w.create_new_account_public(None).0;
    e.deploy(erc20, ERC20_RECEIVER_ELF).await;

    let pda_of = |program: AccountId, seed: [u8; 32]| Actor::new(pda(program, seed), program);
    let blk = ElBlock::sepolia();
    let inst = pda_of(attest, instance_seed(&SEPOLIA_ID));
    let hdr = pda_of(attest, header_seed(&SEPOLIA_ID, &blk.hash));

    // Init (Sepolia bootstrap; now_slot from wall clock)
    let Msg::Init {
        instance_id,
        cfg,
        trusted_block_root,
        bootstrap,
        ..
    } = sepolia_init()
    else {
        unreachable!()
    };
    let now = now_slot(cfg.genesis_time);
    let init = Msg::Init {
        instance_id,
        cfg: cfg.clone(),
        trusted_block_root,
        bootstrap,
        now_slot: now,
    };
    let (root_seed, hroot) = first_root(attest, SEPOLIA_ID, &cfg, &init);
    e.send(
        "Init",
        inst,
        vec![hdr, hroot],
        &[
            (attest, instance_seed(&SEPOLIA_ID)),
            (attest, header_seed(&SEPOLIA_ID, &blk.hash)),
            (attest, root_seed),
        ],
        &init,
        5_000_000,
    )
    .await;
    let st: InstanceState = borsh::from_slice(&e.state(inst).await).unwrap();
    println!(
        "instance finalized slot {}",
        st.store.finalized_header.beacon.slot
    );

    // One update: learn the next sync committee (2 txs)
    let u = sepolia_updates()[1].clone();
    let now = now_slot(cfg.genesis_time);
    let p = lc_core::prepare_update(&cfg.chain, &st.store, &u, now).unwrap();
    let hints = attest_program::bls::uncompress_non_signers(&p.pairing);
    let w = attest_program::witness::for_pairing(&p.pairing).unwrap();
    let job = pda_of(attest, job_seed(&SEPOLIA_ID, 1));
    // Same routing as lez-client; E2E_SPLIT_UPDATE=1 forces the UpdateBegin/UpdateVerify fallback.
    if lez_client::prefers_single_tx(&u) && std::env::var_os("E2E_SPLIT_UPDATE").is_none() {
        e.send(
            "Update",
            inst,
            vec![],
            &[],
            &Msg::Update {
                instance_id: SEPOLIA_ID,
                update: u,
                non_signers: hints,
                witness: w,
                now_slot: now,
            },
            10_000_000,
        )
        .await;
    } else {
        let begin = Msg::UpdateBegin {
            instance_id: SEPOLIA_ID,
            job_id: 1,
            update: u,
            non_signers: hints,
            now_slot: now,
        };
        e.send(
            "UpdateBegin",
            inst,
            vec![job],
            &[(attest, job_seed(&SEPOLIA_ID, 1))],
            &begin,
            10_000_000,
        )
        .await;
        e.send(
            "UpdateVerify",
            job,
            vec![inst],
            &[],
            &Msg::UpdateVerify {
                instance_id: SEPOLIA_ID,
                job_id: 1,
                witness: w,
            },
            10_000_000,
        )
        .await;
    }
    let st: InstanceState = borsh::from_slice(&e.state(inst).await).unwrap();
    println!(
        "next sync committee known: {}",
        st.store.next_sync_committee.is_some()
    );

    // Root Attest: WETH slot 0 == "Wrapped Ether" under the recorded header
    let weth = h32("0x577261707065642045746865720000000000000000000000000000000000001a");
    let preds = vec![inclusion::Pred::Eq {
        field: inclusion::FieldSel::Slot,
        value: weth.to_vec(),
    }];
    e.send(
        "Attest(WETH slot0)",
        hdr,
        vec![],
        &[],
        &Msg::Attest(weth_slot0(SEPOLIA_ID, preds)),
        5_000_000,
    )
    .await;

    // Consumer: vault for the ERC-20 Transfer in tx 1 log 1, claim, replay
    let (token, to, amount) = blk.log(1, 1);
    let vault = pda_of(erc20, consumers::vault_seed(&VAULT));
    let s = lc_core::ChainConfig::sepolia();
    let vcfg = VaultConfig {
        instance_id: SEPOLIA_ID,
        chain_id: s.chain_id,
        genesis_validators_root: s.genesis_validators_root,
        token,
        vault_address: to,
    };
    e.send(
        "InitVault",
        vault,
        vec![],
        &[(erc20, consumers::vault_seed(&VAULT))],
        &ConsumerMsg::InitVault {
            vault_id: VAULT,
            cfg: vcfg,
        },
        2_000_000,
    )
    .await;
    let (receipt, receipt_proof) = blk.receipt(1);
    let claim = ConsumerMsg::Claim {
        vault_id: VAULT,
        block_hash: blk.hash,
        exec_header_rlp: blk.rlp.clone(),
        ancestry: vec![],
        tx_index: 1,
        log_index: 1,
        receipt,
        receipt_proof,
        amount,
    };
    let sid = statement_id_for(s.chain_id, s.genesis_validators_root, blk.hash, 1, 1);
    let null = pda_of(erc20, consumers::nullifier_seed(&VAULT, &sid));
    e.send(
        "Claim(erc20)",
        vault,
        vec![hdr, null],
        &[],
        &claim,
        lez_client::CLAIM_GAS,
    )
    .await;
    let v: VaultState = consumers::untag(consumers::TAG_VAULT, &e.state(vault).await).unwrap();
    println!(
        "vault claims={} credited_total={}",
        v.claims, v.credited_total
    );
    let replay_ok = e
        .send(
            "Claim replay",
            vault,
            vec![hdr, null],
            &[],
            &claim,
            lez_client::CLAIM_GAS,
        )
        .await;
    assert!(!replay_ok, "replay must revert");

    println!("\n| step | tx hash | block | result |\n|---|---|---:|---|");
    for (n, h, b, ok) in &e.log {
        println!(
            "| {n} | `{h}` | {b} | {} |",
            if *ok { "ok" } else { "reverted" }
        );
    }
}
