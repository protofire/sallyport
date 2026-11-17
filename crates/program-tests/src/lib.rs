//! Executor harness (LEZ `V03State`, no sequencer) and fixture/tx builders shared by the tests
//! and the e2e client. Every tx runs under the LEZ action cap `MAX_GAS_EXEC` (10M cycles).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use attest_program::*;
use borsh::BorshSerialize;
use inclusion::host::{header_rlp_from_rpc, proof_from_rpc, receipt_bytes_from_rpc, receipt_proof};
use inclusion::{Account, Locator, Pred};
use lc_core::{ChainConfig, LightClientUpdate, Store};
use lee::error::LeeError;
use lee::privacy_preserving_transaction::circuit::ProgramCatalog;
use lee::privacy_preserving_transaction::{Message as PpMessage, WitnessSet as PpWitnessSet};
use lee::program::Program;
use lee::public_transaction::{Message, WitnessSet};
use lee::{
    AccountId, Actor, ActorState, PrivacyPreservingTransaction, ProvingInput,
    PublicAccountEvidence, PublicExecutionContext, PublicTransaction, RootCall, SenderPresentation,
    Simulation, TransactionEntry, V03State, ValidatedStateDiff,
};
use lee_core::account::{Account as LeeAccount, Nonce};
use lee_core::encryption::ViewingPublicKey;
use lee_core::program::PdaSeed;
use lee_core::{
    AuthorizationSecretKey, Commitment, NullifierPublicKey, NullifierSecretKey, NullifierWitness,
    PrivateWitness, RegularKey, WitnessKind, DUMMY_COMMITMENT_HASH,
};
use serde_json::{json, Value};

pub use program_methods::{
    ATTEST_ELF, ERC20_INLINE_RECEIVER_ELF, ERC20_RECEIVER_ELF, ETH_RECEIVER_ELF,
};

/// `MAX_GAS_EXEC` (lez/programs/fee/core/src/market.rs:15): per-tx action-phase cap.
pub const MAX_GAS_EXEC: u64 = 10_000_000;
pub const SEPOLIA_GENESIS_TIME: u64 = 1_655_733_600;
pub const MAINNET_GENESIS_TIME: u64 = 1_606_824_023;
/// "Now" for the Sepolia fixtures: finality update signature slot.
pub const SEPOLIA_NOW: u64 = 11_505_538;
pub const MAINNET_NOW: u64 = 15_581_474;

pub fn fixture(path: &str) -> String {
    let p = format!("{}/../../fixtures/{path}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

pub fn json(path: &str) -> Value {
    serde_json::from_str(&fixture(path)).unwrap()
}

pub fn h32(s: &str) -> [u8; 32] {
    let b = hex::decode(s.trim_start_matches("0x")).unwrap();
    let mut o = [0u8; 32];
    o[32 - b.len()..].copy_from_slice(&b);
    o
}

pub fn h20(s: &str) -> [u8; 20] {
    hex::decode(s.trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap()
}

pub fn attest_program_id() -> AccountId {
    let sk = lee::PrivateKey::try_new(consumers::ATTEST_DEPLOY_KEY).unwrap();
    AccountId::from(&lee::PublicKey::new_from_private_key(&sk))
}

pub fn pda(program: AccountId, seed: [u8; 32]) -> AccountId {
    AccountId::for_public_pda(&program, &PdaSeed::new(seed))
}

pub fn sepolia_cfg() -> InstanceConfig {
    InstanceConfig {
        chain: ChainConfig::sepolia(),
        genesis_time: SEPOLIA_GENESIS_TIME,
    }
}

pub fn mainnet_cfg() -> InstanceConfig {
    InstanceConfig {
        chain: ChainConfig::mainnet(),
        genesis_time: MAINNET_GENESIS_TIME,
    }
}

// ------------------------------------------------------------------ messages

/// Instance id of [`sepolia_init`] / [`mainnet_init`] (asserted against `instance_id()` in executor tests).
pub const SEPOLIA_ID: InstanceId = [
    136, 152, 46, 235, 234, 238, 143, 8, 100, 247, 89, 104, 202, 65, 243, 65, 2, 72, 12, 16, 68,
    128, 207, 139, 207, 8, 127, 89, 172, 203, 169, 38,
];
pub const MAINNET_ID: InstanceId = [
    63, 89, 241, 46, 129, 167, 55, 160, 77, 220, 133, 241, 11, 115, 150, 117, 159, 174, 137, 35,
    184, 52, 181, 178, 48, 201, 126, 245, 111, 215, 34, 56,
];

/// Init of the Sepolia fixture instance (id derived from config + checkpoint, as the program requires).
pub fn sepolia_init() -> Msg {
    let root = h32(
        json("sepolia/headers_finalized.json")["result"]["data"]["root"]
            .as_str()
            .unwrap(),
    );
    Msg::Init {
        instance_id: instance_id(&sepolia_cfg(), &root),
        cfg: sepolia_cfg(),
        trusted_block_root: root,
        bootstrap: lc_core::json::bootstrap_from_json(&fixture("sepolia/bootstrap.json")).unwrap(),
        now_slot: SEPOLIA_NOW,
    }
}

pub fn mainnet_init() -> Msg {
    let root = h32(
        json("lc-core/mainnet_headers_finalized.json")["data"]["root"]
            .as_str()
            .unwrap(),
    );
    Msg::Init {
        instance_id: instance_id(&mainnet_cfg(), &root),
        cfg: mainnet_cfg(),
        trusted_block_root: root,
        bootstrap: lc_core::json::bootstrap_from_json(&fixture("lc-core/mainnet_bootstrap.json"))
            .unwrap(),
        now_slot: MAINNET_NOW,
    }
}

pub fn sepolia_updates() -> Vec<LightClientUpdate> {
    lc_core::json::updates_from_json(&fixture("sepolia/updates.json")).unwrap()
}

pub fn sepolia_finality() -> LightClientUpdate {
    lc_core::json::update_from_json(&fixture("sepolia/finality_update.json")).unwrap()
}

/// Residue witness for `update` against `store` (relayer side, host).
pub fn witness(
    cfg: &InstanceConfig,
    store: &Store,
    update: &LightClientUpdate,
    now: u64,
) -> Vec<u8> {
    let p = lc_core::prepare_update(&cfg.chain, store, update, now).unwrap();
    attest_program::witness::for_pairing(&p.pairing).expect("valid signature")
}

/// The Sepolia fixture EL block (= bootstrap finalized execution block).
pub struct ElBlock {
    pub hash: [u8; 32],
    pub rlp: Vec<u8>,
    receipts: Value,
}

impl ElBlock {
    pub fn sepolia() -> Self {
        let b = json("sepolia/exec_block.json")["result"].clone();
        Self {
            hash: h32(b["hash"].as_str().unwrap()),
            rlp: header_rlp_from_rpc(&b),
            receipts: json("sepolia/eth_getBlockReceipts.json")["result"].clone(),
        }
    }

    pub fn inclusion_fixture_block() -> Self {
        let b = json("inclusion/exec_block.json")["result"].clone();
        Self {
            hash: h32(b["hash"].as_str().unwrap()),
            rlp: header_rlp_from_rpc(&b),
            receipts: Value::Null,
        }
    }

    /// (receipt, proof) for tx `tx_index`.
    pub fn receipt(&self, tx_index: u32) -> (Vec<u8>, Vec<Vec<u8>>) {
        let all: Vec<Vec<u8>> = self
            .receipts
            .as_array()
            .unwrap()
            .iter()
            .map(receipt_bytes_from_rpc)
            .collect();
        let (_, proof) = receipt_proof(&all, tx_index);
        (all[tx_index as usize].clone(), proof)
    }

    /// Log `log_index` (within the receipt) of tx `tx_index`: (address, to, amount word).
    pub fn log(&self, tx_index: u32, log_index: u32) -> ([u8; 20], [u8; 20], [u8; 32]) {
        let l = &self.receipts[tx_index as usize]["logs"][log_index as usize];
        let to = h32(l["topics"][2].as_str().unwrap());
        (
            h20(l["address"].as_str().unwrap()),
            to[12..].try_into().unwrap(),
            h32(l["data"].as_str().unwrap()),
        )
    }

    /// `from` (topic 1) of log `log_index` of tx `tx_index`.
    pub fn log_from(&self, tx_index: u32, log_index: u32) -> [u8; 20] {
        let t = h32(
            self.receipts[tx_index as usize]["logs"][log_index as usize]["topics"][1]
                .as_str()
                .unwrap(),
        );
        t[12..].try_into().unwrap()
    }

    /// Synthetic block: the Sepolia fixture header with `receiptsRoot` replaced by the root of
    /// `receipts` (RPC JSON); hash = keccak(rlp). No Ethereum needed.
    pub fn synthetic(receipts: Value) -> Self {
        let mut b = json("sepolia/exec_block.json")["result"].clone();
        let all: Vec<Vec<u8>> = receipts
            .as_array()
            .unwrap()
            .iter()
            .map(receipt_bytes_from_rpc)
            .collect();
        b["receiptsRoot"] = Value::String(format!("0x{}", hex::encode(receipt_proof(&all, 0).0)));
        let rlp = header_rlp_from_rpc(&b);
        Self {
            hash: alloy_primitives::keccak256(&rlp).0,
            rlp,
            receipts,
        }
    }

    pub fn attest_log(
        &self,
        instance_id: InstanceId,
        tx_index: u32,
        log_index: u32,
        preds: Vec<Pred>,
    ) -> AttestRequest {
        let (receipt, receipt_proof) = self.receipt(tx_index);
        AttestRequest {
            instance_id,
            exec_header_rlp: self.rlp.clone(),
            locator: Locator::Log {
                tx_index,
                log_index,
            },
            proof: Proof::Log {
                receipt,
                receipt_proof,
            },
            preds,
            ctx: vec![],
            ancestry: vec![],
        }
    }
}

/// Relayer `fetch-attest` output under `fixtures/ancestry/` (real Sepolia, anchor = [`ElBlock::sepolia`]).
pub struct AncestryLog {
    /// Attested (target) block hash.
    pub hash: [u8; 32],
    pub anchor_rlp: Vec<u8>,
    pub ancestry: Vec<Vec<u8>>,
    pub tx_index: u32,
    pub receipt: Vec<u8>,
    pub receipt_proof: Vec<Vec<u8>>,
    pub log: Value,
}

impl AncestryLog {
    /// `name` made with `--anchor` (ancestry included), or a plain target fetch whose ancestry is
    /// the tail of `chain128.json` (the 128 headers below the anchor).
    pub fn load(name: &str) -> Self {
        let m = json(&format!("ancestry/{name}"));
        let hash = h32(m["block_hash"].as_str().unwrap());
        let (anchor_rlp, ancestry) = if m["ancestry"].is_array() {
            (
                inclusion::host::hex(&m["exec_header_rlp"]),
                proof_from_rpc(&m["ancestry"]),
            )
        } else {
            let c = json("ancestry/chain128.json");
            let chain = proof_from_rpc(&c["ancestry"]);
            let start = chain
                .iter()
                .position(|h| alloy_primitives::keccak256(h).0 == hash)
                .expect("target in chain128");
            (
                inclusion::host::hex(&c["exec_header_rlp"]),
                chain[start..].to_vec(),
            )
        };
        Self {
            hash,
            anchor_rlp,
            ancestry,
            tx_index: m["tx_index"].as_u64().unwrap() as u32,
            receipt: inclusion::host::hex(&m["receipt"]),
            receipt_proof: proof_from_rpc(&m["receipt_proof_nodes"]),
            log: m["log"].clone(),
        }
    }

    /// Attest log 0 of `tx_index` with `preds`, anchored at the recorded Sepolia fixture block.
    pub fn request(&self, instance_id: InstanceId, preds: Vec<Pred>) -> AttestRequest {
        AttestRequest {
            instance_id,
            exec_header_rlp: self.anchor_rlp.clone(),
            locator: Locator::Log {
                tx_index: self.tx_index,
                log_index: 0,
            },
            proof: Proof::Log {
                receipt: self.receipt.clone(),
                receipt_proof: self.receipt_proof.clone(),
            },
            preds,
            ctx: vec![],
            ancestry: self.ancestry.clone(),
        }
    }

    /// Exact-match predicates on the fixture log (address, every topic, data word 0).
    pub fn preds(&self) -> Vec<Pred> {
        use inclusion::FieldSel::*;
        let l = &self.log;
        let mut p = vec![
            Pred::Eq {
                field: LogStatus,
                value: vec![1],
            },
            Pred::Eq {
                field: LogAddress,
                value: h20(l["address"].as_str().unwrap()).to_vec(),
            },
        ];
        for (i, t) in l["topics"].as_array().unwrap().iter().enumerate() {
            p.push(Pred::Eq {
                field: LogTopic(i as u8),
                value: h32(t.as_str().unwrap()).to_vec(),
            });
        }
        p
    }
}

/// WETH (Sepolia) slot 0 under the fixture block: (address, account, account proof, slot, value, storage proof).
pub fn weth_slot0(instance_id: InstanceId, preds: Vec<Pred>) -> AttestRequest {
    let p = json("sepolia/eth_getProof.json")["result"].clone();
    let account = Account {
        nonce: u64::from_str_radix(p["nonce"].as_str().unwrap().trim_start_matches("0x"), 16)
            .unwrap(),
        balance: h32(p["balance"].as_str().unwrap()),
        storage_root: h32(p["storageHash"].as_str().unwrap()),
        code_hash: h32(p["codeHash"].as_str().unwrap()),
    };
    let sp = &p["storageProof"][0];
    AttestRequest {
        instance_id,
        exec_header_rlp: ElBlock::sepolia().rlp,
        locator: Locator::Storage {
            address: h20(p["address"].as_str().unwrap()),
            slot: h32(sp["key"].as_str().unwrap()),
        },
        proof: Proof::Storage {
            account,
            account_proof: proof_from_rpc(&p["accountProof"]),
            value: h32(sp["value"].as_str().unwrap()),
            storage_proof: proof_from_rpc(&sp["proof"]),
        },
        preds,
        ctx: vec![],
        ancestry: vec![],
    }
}

// ------------------------------------------------------------------ executor harness

#[derive(Debug, PartialEq, Eq)]
pub enum Fail {
    /// Error code, docs/CONSUMER-GUIDE.md (program exit code + 1000).
    Code(u16),
    Other(String),
}

pub struct Chain {
    pub state: V03State,
    pub attest: AccountId,
    pub erc20: AccountId,
    pub eth: AccountId,
    /// Optional inline-verifying ERC-20 consumer (D-GAS-7).
    pub erc20_inline: AccountId,
    pub block: u64,
    pub timestamp_ms: u64,
    pub budget: u64,
}

impl Default for Chain {
    fn default() -> Self {
        Self::new()
    }
}

impl Chain {
    pub fn new() -> Self {
        let attest = attest_program_id();
        let erc20 = AccountId::new([0xE2; 32]);
        let eth = AccountId::new([0xE7; 32]);
        let erc20_inline = AccountId::new([0xE3; 32]);
        let p = |elf: &'static [u8]| Program::new(elf.into()).unwrap();
        let state = V03State::new().with_named_programs([
            (attest, p(ATTEST_ELF)),
            (erc20, p(ERC20_RECEIVER_ELF)),
            (eth, p(ETH_RECEIVER_ELF)),
            (erc20_inline, p(ERC20_INLINE_RECEIVER_ELF)),
        ]);
        Self {
            state,
            attest,
            erc20,
            eth,
            erc20_inline,
            block: 1,
            timestamp_ms: sepolia_cfg().slot_start_ms(SEPOLIA_NOW),
            budget: MAX_GAS_EXEC,
        }
    }

    pub fn actor(&self, program: AccountId, seed: [u8; 32]) -> Actor {
        Actor::new(pda(program, seed), program)
    }

    pub fn instance(&self, id: &InstanceId) -> Actor {
        self.actor(self.attest, instance_seed(id))
    }

    pub fn header(&self, id: &InstanceId, ebh: &[u8; 32]) -> Actor {
        self.actor(self.attest, header_seed(id, ebh))
    }

    pub fn job(&self, id: &InstanceId, job_id: u64) -> Actor {
        self.actor(self.attest, job_seed(id, job_id))
    }

    pub fn state_of(&self, a: Actor) -> Vec<u8> {
        self.state
            .get_account_by_id(a.account_id)
            .data
            .actor_state(a.program_account_id)
            .to_vec()
    }

    pub fn instance_state(&self, id: &InstanceId) -> InstanceState {
        borsh::from_slice(&self.state_of(self.instance(id))).unwrap()
    }

    /// Fee-less public tx (executor path) under `self.budget`; returns charged cycles.
    pub fn send(
        &mut self,
        to: Actor,
        actors: Vec<Actor>,
        msg: &impl BorshSerialize,
    ) -> Result<u64, Fail> {
        self.send_with(&[], to, actors, msg)
    }

    /// Public account id of a signing key.
    pub fn signer(key: &lee::PrivateKey) -> AccountId {
        AccountId::from(&lee::PublicKey::new_from_private_key(key))
    }

    /// [`Chain::send`] signed by `key`: its public account is authorized (`ReceiveInput::is_authorized`).
    pub fn send_signed(
        &mut self,
        key: &lee::PrivateKey,
        to: Actor,
        actors: Vec<Actor>,
        msg: &impl BorshSerialize,
    ) -> Result<u64, Fail> {
        self.send_with(&[key], to, actors, msg)
    }

    fn send_with(
        &mut self,
        keys: &[&lee::PrivateKey],
        to: Actor,
        mut actors: Vec<Actor>,
        msg: &impl BorshSerialize,
    ) -> Result<u64, Fail> {
        actors.push(to);
        actors.dedup();
        let nonces = keys
            .iter()
            .map(|k| {
                let id = Self::signer(k);
                (id, self.state.get_account_by_id(id).nonce)
            })
            .collect();
        let mut m = Message::try_new(to, actors.clone(), nonces, msg)
            .map_err(|e| Fail::Other(e.to_string()))?;
        // Evidence for every declared PDA that may not exist yet (programs check the derivation).
        m.admission_evidence = actors
            .iter()
            .filter(|a| self.state.get_account_by_id_ref(a.account_id).is_none())
            .filter_map(|a| {
                self.seed_of(*a).map(|seed| PublicAccountEvidence::Pda {
                    program: a.program_account_id,
                    seed,
                })
            })
            .collect();
        let tx = PublicTransaction::new(m.clone(), WitnessSet::for_message(&m, keys));
        self.block += 1;
        match ValidatedStateDiff::from_public_transaction_with_cycle_budget(
            &tx,
            &self.state,
            self.block,
            self.timestamp_ms,
            self.budget,
        ) {
            Ok((diff, charge)) => {
                self.state
                    .apply_state_diff(diff)
                    .map_err(|e| Fail::Other(e.to_string()))?;
                Ok(charge.cycles)
            }
            Err(LeeError::ProgramExitedWithCode { code, .. }) => {
                Err(Fail::Code(error_from_exit(code)))
            }
            Err(e) => Err(Fail::Other(e.to_string())),
        }
    }

    /// Seeds are registered when actors are built through [`Chain::seeded`].
    fn seed_of(&self, a: Actor) -> Option<PdaSeed> {
        SEEDS.with(|s| s.borrow().get(&a.account_id).copied())
    }

    /// Registers the PDA seed of an actor (so `send` can attach admission evidence).
    pub fn seeded(&self, program: AccountId, seed: [u8; 32]) -> Actor {
        let a = self.actor(program, seed);
        SEEDS.with(|s| s.borrow_mut().insert(a.account_id, PdaSeed::new(seed)));
        a
    }

    pub fn init(&mut self, msg: &Msg) -> Result<u64, Fail> {
        let Msg::Init {
            instance_id,
            bootstrap,
            cfg,
            now_slot,
            ..
        } = msg
        else {
            panic!()
        };
        self.timestamp_ms = cfg.slot_start_ms(*now_slot);
        let ebh = bootstrap
            .header
            .to_finalized(&cfg.chain)
            .map(|f| f.execution_block_hash)
            .unwrap_or([0; 32]);
        let inst = self.seeded(self.attest, instance_seed(instance_id));
        let hdr = self.seeded(self.attest, header_seed(instance_id, &ebh));
        // Init appends its header to the accumulator and writes the first root PDA.
        let mut actors = vec![hdr];
        if let Ok(f) = bootstrap.header.to_finalized(&cfg.chain) {
            let root = Frontier::default()
                .append(header_leaf(&header_record(*instance_id, cfg, &f)))
                .unwrap();
            actors.push(self.seeded(self.attest, hroot_seed(instance_id, &root)));
        }
        self.send(inst, actors, msg)
    }

    /// UpdateBegin + UpdateVerify (residue witness built host-side). Returns (begin, verify) cycles.
    pub fn update(
        &mut self,
        id: InstanceId,
        job_id: u64,
        u: &LightClientUpdate,
        now: u64,
    ) -> Result<(u64, u64), Fail> {
        let st = self.instance_state(&id);
        let w = witness(&st.cfg, &st.store, u, now);
        let begin = self.begin(id, job_id, u, now)?;
        let verify = self.verify(id, job_id, u, w)?;
        Ok((begin, verify))
    }

    /// Relayer hints for UpdateBegin: uncompressed non-signer keys derived from the instance store.
    pub fn hints(&self, id: InstanceId, u: &LightClientUpdate, now: u64) -> Vec<Vec<u8>> {
        let st = self.instance_state(&id);
        match lc_core::prepare_update(&st.cfg.chain, &st.store, u, now) {
            Ok(p) => attest_program::bls::uncompress_non_signers(&p.pairing),
            Err(_) => vec![],
        }
    }

    pub fn begin(
        &mut self,
        id: InstanceId,
        job_id: u64,
        u: &LightClientUpdate,
        now: u64,
    ) -> Result<u64, Fail> {
        let hints = self.hints(id, u, now);
        self.begin_hinted(id, job_id, u, now, hints)
    }

    pub fn begin_hinted(
        &mut self,
        id: InstanceId,
        job_id: u64,
        u: &LightClientUpdate,
        now: u64,
        non_signers: Vec<Vec<u8>>,
    ) -> Result<u64, Fail> {
        let inst = self.instance(&id);
        let job = self.seeded(self.attest, job_seed(&id, job_id));
        let cfg = self.instance_state(&id).cfg;
        self.timestamp_ms = cfg.slot_start_ms(now);
        self.send(
            inst,
            vec![job],
            &Msg::UpdateBegin {
                instance_id: id,
                job_id,
                update: u.clone(),
                non_signers,
                now_slot: now,
            },
        )
    }

    /// `u` only selects the header PDA that may be written (finalized header of the update).
    pub fn verify(
        &mut self,
        id: InstanceId,
        job_id: u64,
        u: &LightClientUpdate,
        witness: Vec<u8>,
    ) -> Result<u64, Fail> {
        let job = self.job(&id, job_id);
        let inst = self.instance(&id);
        let mut actors = self.update_actors(id, u);
        actors.push(inst);
        self.send(
            job,
            actors,
            &Msg::UpdateVerify {
                instance_id: id,
                job_id,
                witness,
            },
        )
    }

    /// Declares every account the common update application can write.
    fn update_actors(&self, id: InstanceId, u: &LightClientUpdate) -> Vec<Actor> {
        let cfg = self.instance_state(&id).cfg;
        let mut actors = vec![];
        if let Some((f, _)) = &u.finalized_header {
            let ebh = f
                .to_finalized(&cfg.chain)
                .map(|f| f.execution_block_hash)
                .unwrap_or([0; 32]);
            actors.push(self.seeded(self.attest, header_seed(&id, &ebh)));
            // Root PDA the Apply would write if finality advances.
            let st = self.instance_state(&id);
            if let Ok(fin) = f.to_finalized(&cfg.chain) {
                if fin.beacon.slot > st.store.finalized_header.beacon.slot {
                    let root = st
                        .headers
                        .clone()
                        .append(header_leaf(&header_record(id, &cfg, &fin)))
                        .unwrap();
                    actors.push(self.seeded(self.attest, hroot_seed(&id, &root)));
                }
            }
        }
        actors
    }

    /// Complete update in one transaction; hints/witness remain untrusted guest inputs.
    pub fn update_one_hinted(
        &mut self,
        id: InstanceId,
        u: &LightClientUpdate,
        now: u64,
        non_signers: Vec<Vec<u8>>,
        witness: Vec<u8>,
    ) -> Result<u64, Fail> {
        self.timestamp_ms = self.instance_state(&id).cfg.slot_start_ms(now);
        let actors = self.update_actors(id, u);
        self.send(
            self.instance(&id),
            actors,
            &Msg::Update {
                instance_id: id,
                update: u.clone(),
                non_signers,
                witness,
                now_slot: now,
            },
        )
    }

    /// Root Attest call (header PDA declared with evidence so a missing record reaches the program).
    pub fn attest(&mut self, ebh: [u8; 32], req: AttestRequest) -> Result<u64, Fail> {
        let hdr = self.seeded(self.attest, header_seed(&req.instance_id, &ebh));
        self.send(hdr, vec![], &Msg::Attest(req))
    }

    pub fn vault(&self, program: AccountId, vault_id: [u8; 32]) -> Actor {
        self.seeded(program, consumers::vault_seed(&vault_id))
    }

    pub fn init_vault(
        &mut self,
        program: AccountId,
        vault_id: [u8; 32],
        cfg: consumers::VaultConfig,
    ) -> Result<u64, Fail> {
        let v = self.vault(program, vault_id);
        self.send(
            v,
            vec![],
            &consumers::ConsumerMsg::InitVault { vault_id, cfg },
        )
    }

    /// Claim: declares vault, attest header PDA, and the nullifier PDA the claim will create.
    pub fn claim(
        &mut self,
        program: AccountId,
        vault_id: [u8; 32],
        instance_id: InstanceId,
        block: &ElBlock,
        tx_index: u32,
        log_index: u32,
        amount: [u8; 32],
    ) -> Result<u64, Fail> {
        let v = self.vault(program, vault_id);
        let hdr = self.seeded(self.attest, header_seed(&instance_id, &block.hash));
        let (receipt, receipt_proof) = block.receipt(tx_index);
        let msg = consumers::ConsumerMsg::Claim {
            vault_id,
            block_hash: block.hash,
            exec_header_rlp: block.rlp.clone(),
            ancestry: vec![],
            tx_index,
            log_index,
            receipt,
            receipt_proof,
            amount,
        };
        // statement id is a function of (chain, gvr, block hash, locator): predictable by the claimant
        let cfg = sepolia_cfg().chain;
        let sid = statement_id_for(
            cfg.chain_id,
            cfg.genesis_validators_root,
            block.hash,
            tx_index,
            log_index,
        );
        let null = self.actor(program, consumers::nullifier_seed(&vault_id, &sid));
        self.send(v, vec![hdr, null], &msg)
    }
}

/// RPC-shaped receipt with one `Deposit(bytes32 indexed C, uint256 amount)` log.
pub fn deposit_receipt(
    contract: [u8; 20],
    topic0: [u8; 32],
    c: [u8; 32],
    amount: [u8; 32],
) -> Value {
    let x = |b: &[u8]| format!("0x{}", hex::encode(b));
    json!({
        "type": "0x2", "status": "0x1", "cumulativeGasUsed": "0x5208", "logsBloom": x(&[0; 256]),
        "logs": [{ "address": x(&contract), "topics": [x(&topic0), x(&c)], "data": x(&amount) }]
    })
}

/// A private LEZ account (regular, authorized key), created by the tx that first touches it.
pub struct Claimant {
    ask: AuthorizationSecretKey,
    vpk: ViewingPublicKey,
    pub id: AccountId,
}

impl Claimant {
    pub fn new(seed: u8) -> Self {
        let ask = AuthorizationSecretKey([seed; 32]);
        let vpk = ViewingPublicKey::from_seed(&[seed ^ 0x55; 32], &[seed ^ 0xAA; 32]);
        let id = AccountId::for_regular_private_account(
            &NullifierPublicKey::from(&NullifierSecretKey::from(&ask)),
            &vpk,
        );
        Self { ask, vpk, id }
    }

    /// Commitment of this (newly initialized) account holding `state` for `program`.
    pub fn commitment(&self, program: AccountId, state: Vec<u8>) -> Commitment {
        let acct = LeeAccount {
            nonce: Nonce::default()
                .private_account_nonce_increment(&NullifierSecretKey::from(&self.ask)),
            ..LeeAccount::default().with_actor_state(program, ActorState::from(state))
        };
        Commitment::new(&self.id, &acct)
    }
}

/// What a settled private tx did to public state.
pub struct Settled {
    /// Public accounts whose bytes changed.
    pub changed: BTreeSet<AccountId>,
    pub events: usize,
    /// Cycles of the public part (what the fee is priced on).
    pub public_cycles: u64,
}

impl Chain {
    /// Test-only: write `bytes` as `a`'s actor state (seeding records the update path would write).
    pub fn force_actor(&mut self, a: Actor, bytes: Vec<u8>) {
        let acct = lee::Account::default().with_actor_state(a.program_account_id, bytes.into());
        let state = std::mem::replace(&mut self.state, V03State::new());
        self.state = state.with_public_accounts([(a.account_id, acct)]);
    }

    /// Dev-mode prove of a private root call `msg` to `(claimant, program)` (sender `Blinded`),
    /// simulating the public part against current state plus `assume` (a wallet's view).
    pub fn prove_private(
        &self,
        claimant: &Claimant,
        program: AccountId,
        msg: &impl BorshSerialize,
        public_actors: Vec<Actor>,
        evidence: Vec<(AccountId, [u8; 32])>,
        assume: Vec<(Actor, Vec<u8>)>,
        blind: [u8; 32],
    ) -> Result<PrivacyPreservingTransaction, lee::error::LeeError> {
        let mut states: HashMap<Actor, ActorState> = public_actors
            .iter()
            .map(|a| (*a, self.state_of(*a).into()))
            .collect();
        states.extend(assume.into_iter().map(|(a, s)| (a, s.into())));
        let witness = PrivateWitness {
            vpk: claimant.vpk.clone(),
            random_seed: blind,
            kind: WitnessKind::Regular(RegularKey::Authorized(claimant.ask)),
            nullifier: NullifierWitness::Init {
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
            address_openings: BTreeSet::new(),
        };
        let input = ProvingInput {
            claims: Vec::new(),
            root: TransactionEntry::Sync(RootCall {
                to: Actor::new(claimant.id, program),
                message: borsh::to_vec(msg).unwrap(),
            }),
            public_context: PublicExecutionContext::new(public_actors, []),
            private_witnesses: vec![witness],
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
            recoveries: Vec::new(),
            private_promotions: BTreeSet::new(),
            fee: None,
        };
        let p = |elf: &'static [u8]| Program::new(elf.into()).unwrap();
        let catalog = ProgramCatalog::from([
            (self.attest, p(ATTEST_ELF)),
            (self.erc20, p(ERC20_RECEIVER_ELF)),
            (self.eth, p(ETH_RECEIVER_ELF)),
        ]);
        let (out, proof) = lee::execute_and_prove(
            input,
            &Simulation {
                public_actor_states: states,
                admitted_accounts: None,
            },
            &catalog,
            |_| SenderPresentation::Blinded(blind),
            |_, _| false,
            |b| {
                Err(lee::error::LeeError::InvalidInput(format!(
                    "no seal for {:?}",
                    b.to
                )))
            },
        )?;
        let message = PpMessage {
            admission_evidence: evidence
                .into_iter()
                .map(|(program, seed)| PublicAccountEvidence::Pda {
                    program,
                    seed: PdaSeed::new(seed),
                })
                .collect(),
            ..PpMessage::from_circuit_output(BTreeMap::new(), out)
        };
        let ws = PpWitnessSet::for_message(&message, proof, &[]);
        Ok(PrivacyPreservingTransaction::new(message, ws))
    }

    /// Validate and apply a private tx in the current block (does not advance `block`).
    pub fn settle_private(&mut self, tx: &PrivacyPreservingTransaction) -> Result<Settled, Fail> {
        match ValidatedStateDiff::from_privacy_preserving_transaction_metered(
            tx,
            &self.state,
            self.block,
            self.timestamp_ms,
            self.budget,
        ) {
            Ok((diff, charge)) => {
                let changed = diff
                    .public_diff()
                    .iter()
                    .filter(|(id, a)| self.state.get_account_by_id(**id) != **a)
                    .map(|(id, _)| *id)
                    .collect();
                let events = self
                    .state
                    .apply_state_diff(diff)
                    .map_err(|e| Fail::Other(e.to_string()))?
                    .len();
                Ok(Settled {
                    changed,
                    events,
                    public_cycles: charge.cycles,
                })
            }
            Err(LeeError::ProgramExitedWithCode { code, .. }) => {
                Err(Fail::Code(error_from_exit(code)))
            }
            Err(e) => Err(Fail::Other(e.to_string())),
        }
    }

    /// Whether a private account commitment is in the commitment set.
    pub fn has_commitment(&self, c: &Commitment) -> bool {
        self.state.get_proof_for_commitment(c).is_some()
    }
}

pub fn statement_id_for(
    chain_id: u64,
    gvr: [u8; 32],
    ebh: [u8; 32],
    tx_index: u32,
    log_index: u32,
) -> [u8; 32] {
    let f = inclusion::Fact {
        chain_id,
        genesis_validators_root: gvr,
        execution_block_hash: ebh,
        block_number: 0,
        locator: Locator::Log {
            tx_index,
            log_index,
        },
        value: inclusion::FactValue::Slot([0; 32]),
    };
    inclusion::statement_id(&f)
}

thread_local! {
    static SEEDS: std::cell::RefCell<std::collections::HashMap<AccountId, PdaSeed>> = Default::default();
}

/// Test-only: place an instance at an arbitrary store (lc-core's 1403 anchor; no bootstrap for
/// period 1403 is served anymore). Exercises the real update path for a committee rotation.
pub fn force_instance(chain: &mut Chain, id: InstanceId, st: &InstanceState) {
    let a = chain.instance(&id);
    chain.force_actor(a, borsh::to_vec(st).unwrap());
}
