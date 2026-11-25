//! RFP-022 bridge program executor/PP tests, dev-mode proofs (`RISC0_DEV_MODE=1`),
//! synthetic Ethereum block with `Deposit(C, token, CONFIG_ID, d)` logs (docs/ARCHITECTURE.md §3).
//! `REAL_BURN_PROOF=1` with dev mode off runs the one real `Burn` proof (`real_burn_proof`).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use attest_program::{header_leaf, hroot_seed, merkle_path, merkle_root, HeaderRecord};
use bridge::host::{self, PrivateCall};
use bridge_core::{
    self as bc, BridgeConfig, BridgeMsg, Cfg, Holdings, Tok, TokenEntry, TokenState,
};
use lc_core::ChainConfig;
use lee::privacy_preserving_transaction::circuit::ProgramCatalog;
use lee::privacy_preserving_transaction::{Message as PpMessage, WitnessSet as PpWitnessSet};
use lee::program::Program;
use lee::public_transaction::{Message, WitnessSet};
use lee::{
    AccountId, Actor, ActorState, BoundaryStep, DummyOutput, MessageBody, MessageWitness,
    PrivacyPreservingTransaction, ProvingInput, PublicAccountEvidence, PublicExecutionContext,
    PublicTransaction, Publication, PublicationMode, Recipient, RecipientEncryption, RootCall,
    SenderPresentation, Simulation, TransactionEntry, V03State, ValidatedStateDiff,
};
use lee_core::account::Account as LeeAccount;
use lee_core::encryption::{EphemeralSecretKey, ViewingPublicKey};
use lee_core::program::PdaSeed;
use lee_core::{
    AuthorizationSecretKey, Commitment, NullifierPublicKey, NullifierSecretKey, NullifierWitness,
    PrivateAccountKind, PrivateWitness, RegularKey, WitnessKind, DUMMY_COMMITMENT_HASH,
};
use program_methods::{BRIDGE_ELF, BRIDGE_ID};
use program_tests::*;

const A_ID: attest_program::InstanceId = SEPOLIA_ID;
const VAULT: [u8; 20] = [0xDE; 20];
const TOK: Tok = [0x7A; 20];
const TOK2: Tok = [0x7B; 20];
const D: u128 = 100;
const D2: u128 = 200;
/// LEZ-side fees are 0 by rule (fees are charged at release on Ethereum, docs/ARCHITECTURE.md §3.6): a non-zero
/// LEZ fee would strand a single deposit (mint `d - fee_mint` < burn `d + fee_burn`).
const FEE_MINT: u128 = 0;
const FEE_BURN: u128 = 0;
const ADMIN_KEY: [u8; 32] = [0xAD; 32];
const FREEZER_KEY: [u8; 32] = [0xF2; 32];

/// `bridge_program_id`: the account of the image-derived deploy key ([`host::deploy_key`]).
fn bridge_id() -> AccountId {
    key_id(host::deploy_key(BRIDGE_ID))
}

fn key(k: [u8; 32]) -> lee::PrivateKey {
    lee::PrivateKey::try_new(k).unwrap()
}

fn key_id(k: [u8; 32]) -> AccountId {
    AccountId::from(&lee::PublicKey::new_from_private_key(&key(k)))
}

fn entry() -> TokenEntry {
    TokenEntry {
        tok: TOK,
        decimals: 6,
        denoms: vec![bc::DenomEntry {
            d: D,
            fee_mint: FEE_MINT,
            fee_burn: FEE_BURN,
        }],
        supply_cap: 10 * D,
        mint_open: true,
        paused_mint: false,
        paused_burn: false,
    }
}

fn bridge_cfg(salt: u8) -> BridgeConfig {
    let s = ChainConfig::sepolia();
    BridgeConfig {
        instance_id: A_ID,
        evm_chain_id: s.chain_id,
        genesis_validators_root: s.genesis_validators_root,
        vault: VAULT,
        deposit_topic0: bc::deposit_topic0(),
        zone_id: bc::local_zone_id(),
        bridge_program_id: *bridge_id().value(),
        admin: key_id(ADMIN_KEY),
        freezer: key_id(FREEZER_KEY),
        salt: [salt; 32],
    }
}

fn word_u(v: u128) -> [u8; 32] {
    let mut w = [0; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

fn word_a(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0; 32];
    w[12..].copy_from_slice(a);
    w
}

/// RPC receipt with one `Deposit(bytes32 indexed C, address indexed token, bytes32 indexed configId, uint256 amount)`.
fn deposit(nk: &[u8; 32], tok: Tok, cfg: Cfg, d: u128) -> serde_json::Value {
    let x = |b: &[u8]| format!("0x{}", hex::encode(b));
    serde_json::json!({
        "type": "0x2", "status": "0x1", "cumulativeGasUsed": "0x5208", "logsBloom": x(&[0; 256]),
        "logs": [{ "address": x(&VAULT),
                   "topics": [x(&bc::deposit_topic0()), x(&bc::commit(nk)), x(&word_a(&tok)), x(&cfg)],
                   "data": x(&word_u(d)) }]
    })
}

fn nk(i: u8) -> [u8; 32] {
    [i; 32]
}

/// Deposits in the synthetic block, by tx index.
fn deposits() -> Vec<([u8; 32], Tok, Cfg, u128)> {
    let cfg = bc::config_id(&bridge_cfg(0));
    vec![
        (nk(1), TOK, cfg, D),                           // 0
        (nk(2), TOK, cfg, D),                           // 1
        (nk(3), TOK, cfg, D),                           // 2
        (nk(4), TOK, cfg, D),                           // 3
        (nk(5), TOK2, cfg, D),                          // 4: wrong token topic / unlisted
        (nk(6), TOK, bc::config_id(&bridge_cfg(1)), D), // 5: look-alike config topic
        (nk(7), TOK, cfg, D2),                          // 6: denom not registered
        (nk(8), TOK, cfg, D),                           // 7
        (nk(9), TOK, cfg, D),                           // 8
    ]
}

// ------------------------------------------------------------------ private holders

/// A private LEZ account whose bridge holdings the test tracks (to rebuild its commitment).
struct Holder {
    ask: AuthorizationSecretKey,
    nsk: NullifierSecretKey,
    npk: NullifierPublicKey,
    vpk: ViewingPublicKey,
    vd: [u8; 32],
    vz: [u8; 32],
    id: AccountId,
    acct: Option<LeeAccount>,
    h: Holdings,
}

impl Holder {
    fn new(seed: u8) -> Self {
        let ask = AuthorizationSecretKey([seed; 32]);
        let nsk = NullifierSecretKey::from(&ask);
        let npk = NullifierPublicKey::from(&nsk);
        let (vd, vz) = ([seed ^ 0x55; 32], [seed ^ 0xAA; 32]);
        let vpk = ViewingPublicKey::from_seed(&vd, &vz);
        let id = AccountId::for_regular_private_account(&npk, &vpk);
        Self {
            ask,
            nsk,
            npk,
            vpk,
            vd,
            vz,
            id,
            acct: None,
            h: Holdings::new(),
        }
    }

    fn witness(&self, state: &V03State, blind: [u8; 32]) -> PrivateWitness {
        PrivateWitness {
            vpk: self.vpk.clone(),
            random_seed: blind,
            kind: WitnessKind::Regular(RegularKey::Authorized(self.ask)),
            nullifier: match &self.acct {
                None => NullifierWitness::Init {
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
                Some(a) => NullifierWitness::Update {
                    account: a.clone(),
                    membership_proof: state
                        .get_proof_for_commitment(&Commitment::new(&self.id, a))
                        .expect("holder commitment on chain"),
                },
            },
            address_openings: BTreeSet::new(),
        }
    }

    /// The account after a settled tx left `h` as its bridge state.
    fn next(&self, h: &Holdings) -> LeeAccount {
        let prev = self.acct.clone().unwrap_or_default();
        LeeAccount {
            nonce: prev.nonce.private_account_nonce_increment(&self.nsk),
            ..prev.with_actor_state(bridge_id(), ActorState::from(borsh::to_vec(h).unwrap()))
        }
    }

    fn commit(&mut self, h: Holdings) {
        self.acct = Some(self.next(&h));
        self.h = h;
    }

    fn on_chain(&self, c: &Chain) -> bool {
        self.acct
            .as_ref()
            .is_some_and(|a| c.has_commitment(&Commitment::new(&self.id, a)))
    }

    fn bal(&self, cfg: &Cfg, tok: &Tok) -> u128 {
        self.h.get(&(*cfg, *tok)).copied().unwrap_or(0)
    }

    fn recipient(&self) -> Recipient {
        Recipient {
            npk: self.npk.clone(),
            vpk: self.vpk.clone(),
            kind: PrivateAccountKind::Regular,
            opening: None,
        }
    }
}

fn with(h: &Holdings, cfg: Cfg, tok: Tok, delta: i128) -> Holdings {
    let mut h = h.clone();
    let b = h.entry((cfg, tok)).or_insert(0);
    *b = (*b as i128 + delta) as u128;
    if *b == 0 {
        h.remove(&(cfg, tok));
    }
    h
}

// ------------------------------------------------------------------ fixture

struct Fx {
    c: Chain,
    bridge: AccountId,
    bc: BridgeConfig,
    cfg: Cfg,
    blk: ElBlock,
    rec: HeaderRecord,
    leaves: Vec<[u8; 32]>,
    root: [u8; 32],
    blinds: u8,
    /// One-shot wallet assumptions for the next `prove` (actor states it believes exist).
    assume: Vec<(Actor, Vec<u8>)>,
}

fn setup() -> Fx {
    setup_with(entry())
}

fn setup_with(e: TokenEntry) -> Fx {
    let bridge = bridge_id();
    let mut c = Chain::with_programs([(bridge, Program::new(BRIDGE_ELF.into()).unwrap())]);
    c.init(&sepolia_init()).unwrap();
    let blk = ElBlock::synthetic(serde_json::Value::Array(
        deposits()
            .iter()
            .map(|(n, t, cfg, d)| deposit(n, *t, *cfg, *d))
            .collect(),
    ));
    let mut st = c.instance_state(&A_ID);
    let s = ChainConfig::sepolia();
    let slot = st.store.finalized_header.beacon.slot + 32;
    let rec = HeaderRecord {
        instance_id: A_ID,
        chain_id: s.chain_id,
        genesis_validators_root: s.genesis_validators_root,
        beacon_slot: slot,
        beacon_root: [0x5B; 32],
        execution_block_hash: blk.hash,
        period: lc_core::period_at_slot(slot),
    };
    let leaves = vec![
        header_leaf(&attest_program::header_record(
            A_ID,
            &st.cfg,
            &st.store.finalized_header,
        )),
        header_leaf(&rec),
    ];
    let root = st.headers.append(leaves[1]).unwrap();
    force_instance(&mut c, A_ID, &st);
    let hdr = c.header(&A_ID, &blk.hash);
    c.force_actor(hdr, borsh::to_vec(&rec).unwrap());
    let hroot = c.actor(c.attest, hroot_seed(&A_ID, &root));
    c.force_actor(hroot, root.to_vec());
    let bcfg = bridge_cfg(0);
    let cfg = bc::config_id(&bcfg);
    let mut fx = Fx {
        c,
        bridge,
        bc: bcfg.clone(),
        cfg,
        blk,
        rec,
        leaves,
        root,
        blinds: 0,
        assume: vec![],
    };
    fx.init_config(&bcfg).unwrap();
    fx.admin(ADMIN_KEY, bc::AdminOp::RegisterToken { cfg, entry: e })
        .unwrap();
    fx
}

impl Fx {
    fn config_actor(&self, cfg: &Cfg) -> Actor {
        self.c.seeded(self.bridge, bc::config_seed(cfg))
    }

    fn token_actor(&self, cfg: &Cfg, tok: &Tok) -> Actor {
        self.c.seeded(self.bridge, bc::token_seed(cfg, tok))
    }

    fn init_config(&mut self, b: &BridgeConfig) -> Result<u64, Fail> {
        let to = self.config_actor(&bc::config_id(b));
        self.c.send(to, vec![], &BridgeMsg::InitConfig(b.clone()))
    }

    fn token_state(&self) -> TokenState {
        borsh::from_slice(&self.c.state_of(self.token_actor(&self.cfg, &TOK))).unwrap()
    }

    fn config_state(&self) -> bc::ConfigState {
        borsh::from_slice(&self.c.state_of(self.config_actor(&self.cfg))).unwrap()
    }

    /// Public tx signed by `k` to `to` (nonce from state).
    fn signed(
        &mut self,
        k: [u8; 32],
        to: Actor,
        actors: Vec<Actor>,
        msg: &BridgeMsg,
    ) -> Result<u64, Fail> {
        self.signed_ev(k, to, actors, msg, &[])
    }

    fn signed_ev(
        &mut self,
        k: [u8; 32],
        to: Actor,
        mut actors: Vec<Actor>,
        msg: &BridgeMsg,
        ev: &[(AccountId, [u8; 32])],
    ) -> Result<u64, Fail> {
        let sk = key(k);
        let pk = lee::PublicKey::new_from_private_key(&sk);
        let id = AccountId::from(&pk);
        actors.push(to);
        let nonce = self.c.state.get_account_by_id(id).nonce;
        let mut m = Message::try_new(to, actors.clone(), BTreeMap::from([(id, nonce)]), msg)
            .map_err(|e| Fail::Other(e.to_string()))?;
        m.admission_evidence = actors
            .iter()
            .filter(|a| self.c.state.get_account_by_id_ref(a.account_id).is_none())
            .filter_map(|a| {
                if a.account_id == id {
                    return Some(PublicAccountEvidence::Key(pk.clone()));
                }
                let known = ev.iter().find(|(p, s)| {
                    *p == a.program_account_id
                        && AccountId::for_public_pda(p, &PdaSeed::new(*s)) == a.account_id
                });
                known
                    .map(|(_, s)| *s)
                    .or_else(|| seed_for(self, a))
                    .map(|seed| PublicAccountEvidence::Pda {
                        program: a.program_account_id,
                        seed: PdaSeed::new(seed),
                    })
            })
            .collect();
        let tx = PublicTransaction::new(m.clone(), WitnessSet::for_message(&m, &[&sk]));
        self.c.block += 1;
        match ValidatedStateDiff::from_public_transaction_with_cycle_budget(
            &tx,
            &self.c.state,
            self.c.block,
            self.c.timestamp_ms,
            self.c.budget,
        ) {
            Ok((diff, charge)) => {
                self.c
                    .state
                    .apply_state_diff(diff)
                    .map_err(|e| Fail::Other(e.to_string()))?;
                Ok(charge.cycles)
            }
            Err(lee::error::LeeError::ProgramExitedWithCode { code, .. }) => {
                Err(Fail::Code(attest_program::error_from_exit(code)))
            }
            Err(e) => Err(Fail::Other(e.to_string())),
        }
    }

    /// Admin/Freeze op through the seat route of the signer `k`.
    fn admin_op(&mut self, k: [u8; 32], msg: BridgeMsg, tok: Option<Tok>) -> Result<u64, Fail> {
        let seat = Actor::new(key_id(k), self.bridge);
        let mut actors = vec![self.config_actor(&self.cfg)];
        actors.extend(tok.map(|t| self.token_actor(&self.cfg, &t)));
        self.signed(k, seat, actors, &msg)
    }

    fn admin(&mut self, k: [u8; 32], op: bc::AdminOp) -> Result<u64, Fail> {
        let tok = match &op {
            bc::AdminOp::RegisterToken { entry, .. } | bc::AdminOp::UpdateToken { entry, .. } => {
                entry.tok
            }
        };
        self.admin_op(k, BridgeMsg::Admin(op), Some(tok))
    }

    fn freeze(&mut self, k: [u8; 32], op: bc::FreezeOp) -> Result<u64, Fail> {
        let tok = match &op {
            bc::FreezeOp::Token { tok, .. } => Some(*tok),
            bc::FreezeOp::Global { .. } => None,
        };
        self.admin_op(k, BridgeMsg::Freeze(op), tok)
    }

    fn claim_msg(&self, tx_index: u32, e: &TokenEntry, d: u128) -> BridgeMsg {
        let (receipt, receipt_proof) = self.blk.receipt(tx_index);
        BridgeMsg::Claim {
            bridge_cfg: self.bc.clone(),
            token_entry: e.clone(),
            d,
            header: self.rec.clone(),
            header_index: 1,
            header_path: merkle_path(&self.leaves, 1),
            exec_header_rlp: self.blk.rlp.clone(),
            ancestry: vec![],
            tx_index,
            log_index: 0,
            receipt,
            receipt_proof,
            nk: deposits()[tx_index as usize].0,
        }
    }

    fn blind(&mut self) -> [u8; 32] {
        self.blinds += 1;
        let mut b = [0xB1; 32];
        b[0] = self.blinds;
        b
    }

    /// Dev-mode prove of a private entry for `who` (sender `Blinded`); async messages are sealed
    /// for the matching `seals`.
    fn prove(
        &mut self,
        who: &Holder,
        root: TransactionEntry<MessageWitness>,
        call: &PrivateCall,
        seals: Vec<Recipient>,
    ) -> Result<PrivacyPreservingTransaction, lee::error::LeeError> {
        let blind = self.blind();
        let c = &self.c;
        let mut states: HashMap<Actor, ActorState> = call
            .public_actors
            .iter()
            .map(|a| (*a, c.state_of(*a).into()))
            .collect();
        states.extend(self.assume.drain(..).map(|(a, s)| (a, s.into())));
        let input = ProvingInput {
            claims: Vec::new(),
            root,
            public_context: PublicExecutionContext::new(call.public_actors.clone(), []),
            private_witnesses: vec![who.witness(&c.state, blind)],
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
            recoveries: Vec::new(),
            private_promotions: BTreeSet::new(),
            fee: None,
        };
        let p = |elf: &'static [u8]| Program::new(elf.into()).unwrap();
        let catalog =
            ProgramCatalog::from([(c.attest, p(ATTEST_ELF)), (self.bridge, p(BRIDGE_ELF))]);
        let (out, proof) = lee::execute_and_prove(
            input,
            &Simulation {
                public_actor_states: states,
                admitted_accounts: None,
            },
            &catalog,
            |_| SenderPresentation::Blinded(blind),
            |_, _| false,
            |bs: &[MessageBody]| {
                bs.iter()
                    .map(|b| {
                        seals
                            .iter()
                            .find(|r| r.address() == b.to.account_id)
                            .map(|r| {
                                PublicationMode::Sealed(RecipientEncryption {
                                    recipient: r.clone(),
                                    esk: EphemeralSecretKey(blind),
                                })
                            })
                            .ok_or_else(|| lee::error::LeeError::InvalidInput("no seal".into()))
                    })
                    .collect()
            },
        )?;
        let message = PpMessage {
            admission_evidence: call
                .evidence
                .iter()
                .map(|(program, seed)| PublicAccountEvidence::Pda {
                    program: *program,
                    seed: PdaSeed::new(*seed),
                })
                .collect(),
            ..PpMessage::from_circuit_output(BTreeMap::new(), out)
        };
        let ws = PpWitnessSet::for_message(&message, proof, &[]);
        Ok(PrivacyPreservingTransaction::new(message, ws))
    }

    fn prove_call(
        &mut self,
        who: &Holder,
        call: &PrivateCall,
        seals: Vec<Recipient>,
    ) -> Result<PrivacyPreservingTransaction, lee::error::LeeError> {
        let root = TransactionEntry::Sync(RootCall {
            to: Actor::new(who.id, self.bridge),
            message: borsh::to_vec(&call.msg).unwrap(),
        });
        self.prove(who, root, call, seals)
    }

    fn claim_call(&self, tx_index: u32, e: &TokenEntry, d: u128) -> PrivateCall {
        host::claim(self.bridge, self.claim_msg(tx_index, e, d)).unwrap()
    }

    /// Proves and settles a claim of deposit `tx_index`; updates the holder on success.
    fn claim(&mut self, who: &mut Holder, tx_index: u32) -> Result<Settled, Fail> {
        let call = self.claim_call(tx_index, &entry(), D);
        let tx = self
            .prove_call(who, &call, vec![])
            .map_err(|e| Fail::Other(format!("{e:?}")))?;
        let s = self.c.settle_private(&tx)?;
        let h = with(&who.h, self.cfg, TOK, (D - FEE_MINT) as i128);
        who.commit(h);
        Ok(s)
    }

    fn burn_call(&self, index: u64, b: [u8; 32]) -> PrivateCall {
        host::burn(self.bridge, &self.bc, &entry(), D, index, b)
    }
}

fn seed_for(fx: &Fx, a: &Actor) -> Option<[u8; 32]> {
    // PDAs the bridge tests declare through `config_actor`/`token_actor`: config and token seeds
    let cands = [
        bc::config_seed(&fx.cfg),
        bc::token_seed(&fx.cfg, &TOK),
        bc::token_seed(&fx.cfg, &TOK2),
    ];
    cands.into_iter().find(|s| {
        AccountId::for_public_pda(&a.program_account_id, &PdaSeed::new(*s)) == a.account_id
    })
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn tx_bytes(c: &Chain, tx: &PrivacyPreservingTransaction, s: &Settled) -> Vec<u8> {
    let mut hay = borsh::to_vec(tx).unwrap();
    for id in &s.changed {
        hay.extend(id.value());
        hay.extend(borsh::to_vec(&c.state.get_account_by_id(*id)).unwrap());
    }
    for (_, p) in c.state.publications_from(0) {
        hay.extend(borsh::to_vec(&p).unwrap());
    }
    hay
}

fn code_in(e: &lee::error::LeeError, code: u16) -> bool {
    matches!(e, lee::error::LeeError::ProgramExitedWithCode { code: c, .. } if bridge::error_from_exit(*c) == code)
        || format!("{e:?}").contains(&format!("code: {}", code - 1000))
}

/// What the harness reports for bridge error `code` (it maps exit `x` to `1000 + x`; the guest
/// exits 1301–1308 as 45–52, decoded by `bridge::error_from_exit`).
fn w(code: u16) -> u16 {
    assert_eq!(
        bridge::error_from_exit(u32::from((code - 1000) % 256)),
        code
    );
    1000 + (code - 1000) % 256
}

fn private_fails(fx: &mut Fx, who: &Holder, call: &PrivateCall, code: u16) {
    let before = fx.c.state.clone();
    let e = fx.prove_call(who, call, vec![]).unwrap_err();
    assert!(code_in(&e, code), "want {code}: {e:?}");
    assert!(fx.c.state == before);
}

// ------------------------------------------------------------------ spike + transfer

/// SPIKE / Transfer (2 txs, docs/ARCHITECTURE.md §3.5): A's private `Transfer` debits A and seals a pending
/// `Credit` to B's private address; B finds it with its keys, applies it with an async-root tx
/// (`receive_pending_message_with` at executor level). `to`, npk, vpk never appear in the clear.
#[test]
fn transfer_two_tx_private_to_foreign_private() {
    let mut fx = setup();
    let (mut a, mut b) = (Holder::new(0x41), Holder::new(0x42));
    fx.claim(&mut a, 0).unwrap();
    fx.claim(&mut a, 1).unwrap();
    let start = a.bal(&fx.cfg, &TOK);
    assert_eq!(start, 2 * (D - FEE_MINT));
    // tx 1: send
    let call = host::transfer(fx.cfg, TOK, 40, b.id);
    let tx = fx.prove_call(&a, &call, vec![b.recipient()]).unwrap();
    let pubs_before = fx.c.state.publications_from(0).count();
    let s = fx.c.settle_private(&tx).unwrap();
    a.commit(with(&a.h, fx.cfg, TOK, -40));
    assert!(a.on_chain(&fx.c), "A debited");
    assert!(s.changed.is_empty(), "no public account written");
    let pubs: Vec<_> = fx.c.state.publications_from(0).collect();
    assert_eq!(pubs.len(), pubs_before + 1);
    let (pos, sealed) = pubs.last().unwrap().clone();
    let Publication::Sealed(sealed) = sealed else {
        panic!("credit must be sealed")
    };
    // byte scan: recipient address and keys, sender, plaintext Credit
    let hay = tx_bytes(&fx.c, &tx, &s);
    let credit = borsh::to_vec(&BridgeMsg::Credit {
        cfg: fx.cfg,
        tok: TOK,
        amount: 40,
    })
    .unwrap();
    for (name, needle) in [
        ("to", b.id.value().to_vec()),
        ("npk", b.npk.to_byte_array().to_vec()),
        ("vpk", b.vpk.to_bytes()[..64].to_vec()),
        ("sender", a.id.value().to_vec()),
        ("credit plaintext", credit.clone()),
        ("cfg", fx.cfg.to_vec()),
    ] {
        assert!(!contains(&hay, &needle), "{name} leaked");
    }
    // pending: listed for B (owned_pending_messages = opens with B's keys), not for A
    let (body, recip, rho) = sealed
        .open(b.npk.clone(), &b.vd, &b.vz)
        .expect("B opens it");
    assert!(sealed.open(a.npk.clone(), &a.vd, &a.vz).is_none());
    assert_eq!(body.to, Actor::new(b.id, fx.bridge));
    assert_eq!(body.message, credit);
    assert_eq!(recip.address(), b.id);
    assert_eq!(body.from.program_account_id, fx.bridge);
    assert_ne!(body.from.account_id, a.id, "sender is blinded");
    assert!(!b.on_chain(&fx.c));
    // tx 2: B receives
    let witness = MessageWitness {
        body: body.clone(),
        rho: Some(rho),
        membership_proof: fx.c.state.get_proof_for_position(pos).unwrap(),
        filler: DummyOutput::default(),
    };
    let empty = host::transfer(fx.cfg, TOK, 0, b.id); // only for its (empty) public actors
    let rx = fx
        .prove(&b, TransactionEntry::Async(witness.clone()), &empty, vec![])
        .unwrap();
    let s2 = fx.c.settle_private(&rx).unwrap();
    b.commit(with(&b.h, fx.cfg, TOK, 40));
    assert!(b.on_chain(&fx.c), "B credited 40");
    assert!(s2.changed.is_empty());
    let hay2 = tx_bytes(&fx.c, &rx, &s2);
    assert!(!contains(&hay2, b.id.value()) && !contains(&hay2, &credit));
    // receiving twice is refused (message nullifier spent)
    let mut b2 = Holder::new(0x42);
    b2.acct = b.acct.clone();
    b2.h = b.h.clone();
    let again = fx.prove(&b2, TransactionEntry::Async(witness), &empty, vec![]);
    if let Ok(t) = again {
        assert!(fx.c.settle_private(&t).is_err(), "double receive");
    }
    eprintln!(
        "SPIKE transfer: send changed={} receive changed={} sealed pos={pos}",
        s.changed.len(),
        s2.changed.len()
    );
}

/// A forged `Credit` (public tx, no bridge sender) is 1306; overdraft transfer is 1305.
#[test]
fn credit_forged_and_transfer_overdraft() {
    let mut fx = setup();
    let mut a = Holder::new(0x43);
    fx.claim(&mut a, 0).unwrap();
    let victim = fx.c.seeded(fx.bridge, [0x99; 32]);
    let credit = BridgeMsg::Credit {
        cfg: fx.cfg,
        tok: TOK,
        amount: 1_000,
    };
    assert_eq!(fx.c.send(victim, vec![], &credit), Err(Fail::Code(w(1306))));
    // signed public account crediting itself: still not from the bridge
    let seat = Actor::new(key_id([0x31; 32]), fx.bridge);
    assert_eq!(
        fx.signed([0x31; 32], seat, vec![], &credit),
        Err(Fail::Code(w(1306)))
    );
    let b = Holder::new(0x44);
    let call = host::transfer(fx.cfg, TOK, D + 1, b.id); // A holds exactly D
    let e = fx.prove_call(&a, &call, vec![b.recipient()]).unwrap_err();
    assert!(code_in(&e, 1305), "{e:?}");
}

// ------------------------------------------------------------------ claim

#[test]
fn claim_mints_privately_and_leaks_nothing() {
    let mut fx = setup();
    let mut a = Holder::new(0x45);
    let call = fx.claim_call(0, &entry(), D);
    let tx = fx.prove_call(&a, &call, vec![]).unwrap();
    let s = fx.c.settle_private(&tx).unwrap();
    a.commit(with(&a.h, fx.cfg, TOK, (D - FEE_MINT) as i128));
    assert!(a.on_chain(&fx.c), "balance d - fee_mint");
    let ts = fx.token_state();
    assert_eq!((ts.supply, ts.fees), (D, FEE_MINT));
    let n = bc::pnf(&nk(1));
    assert_eq!(
        fx.c.state_of(Actor::new(bc::n_pda(&fx.bridge, &n), fx.bridge)),
        vec![1]
    );
    let tp = bc::token_pda(&fx.bridge, &fx.cfg, &TOK);
    assert_eq!(s.changed, [bc::n_pda(&fx.bridge, &n), tp].into());
    assert_eq!(s.events, 0);
    assert!(tx.message.execution.public_root.is_none());
    let crossings: Vec<_> = tx
        .message
        .execution
        .boundary
        .iter()
        .filter_map(|b| match b {
            BoundaryStep::PrivateToPublic(d) | BoundaryStep::PublicToPrivate(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(crossings.len(), 1);
    assert_ne!(crossings[0].envelope.from.account_id, a.id, "blinded");
    let hay = tx_bytes(&fx.c, &tx, &s);
    let mut req_preds = bridge::claim_preds(&fx.bc, &fx.cfg, &TOK, D, &nk(1));
    let (receipt, receipt_proof) = fx.blk.receipt(0);
    let req = attest_program::AttestRequest {
        instance_id: A_ID,
        exec_header_rlp: fx.blk.rlp.clone(),
        ancestry: vec![],
        locator: inclusion::Locator::Log {
            tx_index: 0,
            log_index: 0,
        },
        proof: attest_program::Proof::Log {
            receipt: receipt.clone(),
            receipt_proof,
        },
        preds: std::mem::take(&mut req_preds),
        ctx: vec![],
    };
    let sid = attest_program::verify(&fx.rec, &req).unwrap().id;
    for (name, needle) in [
        ("block hash", fx.blk.hash.to_vec()),
        (
            "header PDA",
            fx.c.header(&A_ID, &fx.blk.hash).account_id.value().to_vec(),
        ),
        ("header leaf", header_leaf(&fx.rec).to_vec()),
        ("statement_id", sid.to_vec()),
        ("C", bc::commit(&nk(1)).to_vec()),
        ("nk", nk(1).to_vec()),
        ("receipt", receipt[..48].to_vec()),
        ("claimant", a.id.value().to_vec()),
    ] {
        assert!(!contains(&hay, &needle), "{name} leaked");
    }
    eprintln!(
        "CYCLES claim public part (config hop + CheckRoot + MintCheck + Spend) {}",
        s.public_cycles
    );
}

/// Replay of the same deposit by another holder → 1250, no balance.
#[test]
fn claim_replay_is_1250() {
    let mut fx = setup();
    let (mut a, b) = (Holder::new(0x46), Holder::new(0x47));
    let call = fx.claim_call(0, &entry(), D);
    let t2 = fx.prove_call(&b, &call, vec![]).unwrap(); // proven before A lands
    fx.claim(&mut a, 0).unwrap();
    assert_eq!(fx.c.settle_private(&t2).err(), Some(Fail::Code(1250)));
    assert_eq!(fx.token_state().supply, D);
}

/// Unknown header root → 1101 at settlement; state untouched.
#[test]
fn claim_unknown_root_is_1101() {
    let mut fx = setup();
    let a = Holder::new(0x48);
    let fake_leaves = [fx.leaves[0], fx.leaves[1], [0xFA; 32]];
    let mut msg = fx.claim_msg(0, &entry(), D);
    if let BridgeMsg::Claim { header_path, .. } = &mut msg {
        *header_path = merkle_path(&fake_leaves, 1);
    }
    let call = host::claim(fx.bridge, msg).unwrap();
    let fake_root = host::claim_root(&call.msg).unwrap();
    // a wallet that assumes the root PDA exists proves; settlement refuses
    let hroot = fx.c.actor(fx.c.attest, hroot_seed(&A_ID, &fake_root));
    fx.assume.push((hroot, fake_root.to_vec()));
    let mut tx = fx.prove_call(&a, &call, vec![]).unwrap();
    tx.message
        .admission_evidence
        .push(PublicAccountEvidence::Pda {
            program: fx.c.attest,
            seed: PdaSeed::new(hroot_seed(&A_ID, &fake_root)),
        });
    let before = fx.c.state.clone();
    assert_eq!(fx.c.settle_private(&tx).err(), Some(Fail::Code(1101)));
    assert!(fx.c.state == before);
}

/// Token topic ≠ claimed token, topic3 ≠ cfg (look-alike config), same deposit under a second
/// config: all 1203 in the private transition (no proof, nothing written).
#[test]
fn claim_wrong_topics_are_1203() {
    let mut fx = setup();
    let a = Holder::new(0x49);
    // deposit 4 has token TOK2 but claims TOK
    let call = fx.claim_call(4, &entry(), D);
    private_fails(&mut fx, &a, &call, 1203);
    // deposit 5 names another config id in topic3
    let call = fx.claim_call(5, &entry(), D);
    private_fails(&mut fx, &a, &call, 1203);
    // a second config (look-alike, other salt) claiming deposit 0 of the first
    let b2 = bridge_cfg(1);
    fx.init_config(&b2).unwrap();
    let mut msg = fx.claim_msg(0, &entry(), D);
    if let BridgeMsg::Claim { bridge_cfg, .. } = &mut msg {
        *bridge_cfg = b2;
    }
    let call = host::claim(fx.bridge, msg).unwrap();
    private_fails(&mut fx, &a, &call, 1203);
}

/// Unlisted token → 1301; denom not registered → 1302; delisted (mint_open=false) → 1301.
#[test]
fn claim_unlisted_and_denom() {
    let mut fx = setup();
    let a = Holder::new(0x4A);
    let mut e2 = entry();
    e2.tok = TOK2;
    let call = fx.claim_call(4, &e2, D);
    private_fails(&mut fx, &a, &call, 1301);
    let mut e3 = entry();
    e3.denoms.push(bc::DenomEntry {
        d: D2,
        fee_mint: 0,
        fee_burn: 0,
    });
    let call = fx.claim_call(6, &e3, D2);
    private_fails(&mut fx, &a, &call, 1302);
    let mut e = entry();
    e.mint_open = false;
    fx.admin(
        ADMIN_KEY,
        bc::AdminOp::UpdateToken {
            cfg: fx.cfg,
            entry: e,
        },
    )
    .unwrap();
    let call = fx.claim_call(0, &entry(), D);
    private_fails(&mut fx, &a, &call, 1301);
}

/// Supply cap → 1303; token and global mint pause → 1304 (each proven before the change, refused
/// at settlement); a private side using another fee → 1308. None leaves an N PDA or a balance (R1).
#[test]
fn claim_cap_pause_and_stale_fee() {
    let mut e = entry();
    e.supply_cap = D;
    let mut fx = setup_with(e.clone());
    let (mut a, b) = (Holder::new(0x4B), Holder::new(0x4C));
    let call1 = fx.claim_call(1, &entry(), D);
    let t1 = fx.prove_call(&b, &call1, vec![]).unwrap();
    fx.claim(&mut a, 0).unwrap();
    let n1 = Actor::new(bc::n_pda(&fx.bridge, &bc::pnf(&nk(2))), fx.bridge);
    let before = fx.c.state.clone();
    assert_eq!(fx.c.settle_private(&t1).err(), Some(Fail::Code(w(1303))));
    assert!(fx.c.state == before && fx.c.state_of(n1).is_empty());
    // raise the cap, then pause the token
    e.supply_cap = 10 * D;
    fx.admin(
        ADMIN_KEY,
        bc::AdminOp::UpdateToken {
            cfg: fx.cfg,
            entry: e.clone(),
        },
    )
    .unwrap();
    let t1 = fx.prove_call(&b, &call1, vec![]).unwrap();
    fx.freeze(
        FREEZER_KEY,
        bc::FreezeOp::Token {
            cfg: fx.cfg,
            tok: TOK,
            paused_mint: true,
            paused_burn: false,
        },
    )
    .unwrap();
    assert_eq!(fx.c.settle_private(&t1).err(), Some(Fail::Code(w(1304))));
    fx.freeze(
        FREEZER_KEY,
        bc::FreezeOp::Token {
            cfg: fx.cfg,
            tok: TOK,
            paused_mint: false,
            paused_burn: false,
        },
    )
    .unwrap();
    let t1 = fx.prove_call(&b, &call1, vec![]).unwrap();
    fx.freeze(
        FREEZER_KEY,
        bc::FreezeOp::Global {
            cfg: fx.cfg,
            paused_mint: true,
            paused_burn: false,
        },
    )
    .unwrap();
    assert!(fx.config_state().paused_mint);
    assert_eq!(fx.c.settle_private(&t1).err(), Some(Fail::Code(w(1304))));
    fx.freeze(
        FREEZER_KEY,
        bc::FreezeOp::Global {
            cfg: fx.cfg,
            paused_mint: false,
            paused_burn: false,
        },
    )
    .unwrap();
    // stale/forged fee: the private side used an entry whose fee differs from the token PDA's
    let mut ef = e;
    ef.denoms[0].fee_mint = 3;
    let call = fx.claim_call(1, &ef, D);
    private_fails(&mut fx, &b, &call, 1308);
    assert!(fx.c.state_of(n1).is_empty());
}

/// F14: `UpdateToken` cannot lift (or set) a per-token pause the freezer set; only `Freeze` writes
/// the pause flags.
#[test]
fn update_token_keeps_freezer_pauses() {
    let mut fx = setup();
    fx.freeze(
        FREEZER_KEY,
        bc::FreezeOp::Token {
            cfg: fx.cfg,
            tok: TOK,
            paused_mint: true,
            paused_burn: true,
        },
    )
    .unwrap();
    let mut e = entry();
    e.supply_cap = 9 * D; // a routine admin update built from an unpaused entry
    fx.admin(
        ADMIN_KEY,
        bc::AdminOp::UpdateToken {
            cfg: fx.cfg,
            entry: e,
        },
    )
    .unwrap();
    let ts = fx.token_state();
    assert_eq!(ts.entry.supply_cap, 9 * D, "the update itself applies");
    assert!(
        ts.entry.paused_mint && ts.entry.paused_burn,
        "admin lifted the freezer's pause"
    );
    let a = Holder::new(0x4D);
    let call = fx.claim_call(0, &ts.entry, D);
    private_fails(&mut fx, &a, &call, 1304);
    // and an admin update cannot set a pause either
    fx.freeze(
        FREEZER_KEY,
        bc::FreezeOp::Token {
            cfg: fx.cfg,
            tok: TOK,
            paused_mint: false,
            paused_burn: false,
        },
    )
    .unwrap();
    let mut e = entry();
    e.paused_mint = true;
    fx.admin(
        ADMIN_KEY,
        bc::AdminOp::UpdateToken {
            cfg: fx.cfg,
            entry: e,
        },
    )
    .unwrap();
    assert!(!fx.token_state().entry.paused_mint);
}

/// F13 fee model: LEZ fees must be 0 (register and update refuse a non-zero fee with 1001), so one
/// deposit always yields exactly one burnable `d`; fees are charged once, at release.
#[test]
fn lez_fees_zero_and_one_deposit_exits() {
    let mut fx = setup();
    for (fm, fb) in [(1, 0), (0, 2)] {
        let mut e = entry();
        e.tok = TOK2;
        e.denoms[0].fee_mint = fm;
        e.denoms[0].fee_burn = fb;
        assert_eq!(
            fx.admin(
                ADMIN_KEY,
                bc::AdminOp::RegisterToken {
                    cfg: fx.cfg,
                    entry: e.clone(),
                },
            ),
            Err(Fail::Code(1001)),
            "register with fee ({fm}, {fb})"
        );
        e.tok = TOK;
        assert_eq!(
            fx.admin(
                ADMIN_KEY,
                bc::AdminOp::UpdateToken {
                    cfg: fx.cfg,
                    entry: e,
                },
            ),
            Err(Fail::Code(1001)),
            "update with fee ({fm}, {fb})"
        );
    }
    let mut a = Holder::new(0x4E);
    fx.claim(&mut a, 0).unwrap();
    let tx = fx
        .prove_call(&a, &fx.burn_call(0, burn_b(1)), vec![])
        .unwrap();
    fx.c.settle_private(&tx).unwrap();
    a.commit(with(&a.h, fx.cfg, TOK, -(D as i128)));
    assert!(
        a.on_chain(&fx.c),
        "one deposit burned in full, nothing stranded"
    );
    let ts = fx.token_state();
    assert_eq!((ts.supply, ts.fees), (0, 0));
}

// ------------------------------------------------------------------ forged messages, admin

/// Every internal message sent directly by a public tx (or a signed public bridge actor) is
/// refused with 1306 and changes nothing.
#[test]
fn forged_direct_messages_are_1306() {
    let mut fx = setup();
    let cfg = fx.cfg;
    let cp = fx.config_actor(&cfg);
    let tp = fx.token_actor(&cfg, &TOK);
    let n = [0x5A; 32];
    let np = fx.c.seeded(fx.bridge, n);
    let lp = fx.c.seeded(fx.bridge, bc::leaf_seed(&cfg, &TOK, D, 0));
    let mint = BridgeMsg::MintCheck {
        cfg_hash: cfg,
        tok: TOK,
        d: D,
        fee_mint: FEE_MINT,
        root: fx.root,
        n,
    };
    let rec = BridgeMsg::RecordBurn {
        cfg_hash: cfg,
        tok: TOK,
        d: D,
        fee_burn: FEE_BURN,
        b: [1; 32],
        index: 0,
    };
    let hroot = fx.c.actor(fx.c.attest, hroot_seed(&A_ID, &fx.root));
    let before = fx.c.state.clone();
    for (to, extra, m) in [
        (cp, vec![hroot, tp, np], mint.clone()),
        (tp, vec![np], mint.clone()),
        (cp, vec![tp, lp], rec.clone()),
        (tp, vec![lp], rec.clone()),
        (np, vec![], BridgeMsg::Spend { cfg, tok: TOK, n }),
        (
            lp,
            vec![],
            BridgeMsg::WriteLeaf {
                cfg,
                tok: TOK,
                d: D,
                index: 0,
                b: [1; 32],
            },
        ),
        (
            tp,
            vec![],
            BridgeMsg::Admin(bc::AdminOp::UpdateToken {
                cfg,
                entry: entry(),
            }),
        ),
        (
            tp,
            vec![],
            BridgeMsg::Freeze(bc::FreezeOp::Token {
                cfg,
                tok: TOK,
                paused_mint: true,
                paused_burn: true,
            }),
        ),
        (
            cp,
            vec![],
            BridgeMsg::Freeze(bc::FreezeOp::Global {
                cfg,
                paused_mint: true,
                paused_burn: true,
            }),
        ),
    ] {
        assert_eq!(fx.c.send(to, extra, &m), Err(Fail::Code(w(1306))), "{m:?}");
    }
    // a signed public bridge actor (seat) cannot inject MintCheck/RecordBurn either: the config
    // hop accepts any bridge actor, so this pins the only emitters (Claim/Burn) by test
    let seat = Actor::new(key_id([0x32; 32]), fx.bridge);
    for m in [mint, rec] {
        assert!(fx
            .signed([0x32; 32], seat, vec![cp, tp, hroot, np, lp], &m)
            .is_err());
    }
    assert!(fx.c.state == before);
}

/// Roles: non-admin seat 1306; freezer cannot register; admin cannot freeze; unsigned seat 1306;
/// mismatched InitConfig 1001.
#[test]
fn admin_and_freeze_roles() {
    let mut fx = setup();
    let mut e2 = entry();
    e2.tok = TOK2;
    let reg = bc::AdminOp::RegisterToken {
        cfg: fx.cfg,
        entry: e2.clone(),
    };
    assert_eq!(fx.admin([0x33; 32], reg.clone()), Err(Fail::Code(w(1306))));
    assert_eq!(fx.admin(FREEZER_KEY, reg.clone()), Err(Fail::Code(w(1306))));
    let fr = bc::FreezeOp::Global {
        cfg: fx.cfg,
        paused_mint: true,
        paused_burn: true,
    };
    assert_eq!(fx.freeze(ADMIN_KEY, fr.clone()), Err(Fail::Code(w(1306))));
    // unsigned seat
    let seat = Actor::new(key_id(ADMIN_KEY), fx.bridge);
    let cp = fx.config_actor(&fx.cfg);
    let tp2 = fx.token_actor(&fx.cfg, &TOK2);
    assert_eq!(
        fx.c.send(seat, vec![cp, tp2], &BridgeMsg::Admin(reg.clone())),
        Err(Fail::Code(w(1306)))
    );
    fx.admin(ADMIN_KEY, reg).unwrap();
    fx.freeze(FREEZER_KEY, fr).unwrap();
    assert!(fx.config_state().paused_burn);
    // mismatched InitConfig: wrong program id / wrong topic0
    let mut b = bridge_cfg(7);
    b.bridge_program_id = [9; 32];
    assert_eq!(fx.init_config(&b), Err(Fail::Code(1001)));
    let mut b = bridge_cfg(8);
    b.deposit_topic0 = [1; 32];
    assert_eq!(fx.init_config(&b), Err(Fail::Code(1001)));
    // re-init of an existing config
    assert_eq!(fx.init_config(&bridge_cfg(0)), Err(Fail::Code(1001)));
}

// ------------------------------------------------------------------ burn

fn burn_b(j: u8) -> [u8; 32] {
    bc::burn_commitment(&[j; 32], &[0x55; 20])
}

#[test]
fn burn_debits_appends_and_writes_leaf() {
    let mut fx = setup();
    let mut a = Holder::new(0x50);
    fx.claim(&mut a, 0).unwrap();
    fx.claim(&mut a, 1).unwrap();
    let b = burn_b(1);
    let idx = host::next_index(&fx.token_state(), D);
    assert_eq!(idx, 0);
    let call = fx.burn_call(idx, b);
    let tx = fx.prove_call(&a, &call, vec![]).unwrap();
    let s = fx.c.settle_private(&tx).unwrap();
    a.commit(with(&a.h, fx.cfg, TOK, -((D + FEE_BURN) as i128)));
    assert!(a.on_chain(&fx.c));
    let ts = fx.token_state();
    assert_eq!((ts.supply, ts.fees), (D, 2 * FEE_MINT + FEE_BURN));
    let f = &ts.trees.iter().find(|(d, _)| *d == D).unwrap().1;
    assert_eq!(f.leaves, 1);
    assert_eq!(f.root(), merkle_root(b, 0, &merkle_path(&[b], 0)).unwrap());
    let lp = Actor::new(bc::leaf_pda(&fx.bridge, &fx.cfg, &TOK, D, 0), fx.bridge);
    assert_eq!(fx.c.state_of(lp), b.to_vec());
    assert_eq!(
        s.changed,
        [lp.account_id, bc::token_pda(&fx.bridge, &fx.cfg, &TOK)].into()
    );
    let hay = tx_bytes(&fx.c, &tx, &s);
    for (name, needle) in [
        ("recipient", vec![0x55; 20]),
        ("rk", vec![1; 32]),
        ("Nb", bc::burn_nullifier(&[1; 32]).to_vec()),
        ("holder", a.id.value().to_vec()),
    ] {
        assert!(!contains(&hay, &needle), "{name} leaked");
    }
    eprintln!(
        "CYCLES burn public part (config hop + RecordBurn + WriteLeaf) {}",
        s.public_cycles
    );
}

/// Insufficient balance 1305; burn frozen 1304 (token and global); a delisted token still burns.
#[test]
fn burn_guards() {
    let mut fx = setup();
    let mut a = Holder::new(0x51);
    let call = fx.burn_call(0, burn_b(1));
    private_fails(&mut fx, &a, &call, 1305); // nothing claimed yet
    fx.claim(&mut a, 1).unwrap();
    let t = fx.prove_call(&a, &call, vec![]).unwrap();
    fx.freeze(
        FREEZER_KEY,
        bc::FreezeOp::Token {
            cfg: fx.cfg,
            tok: TOK,
            paused_mint: false,
            paused_burn: true,
        },
    )
    .unwrap();
    assert_eq!(fx.c.settle_private(&t).err(), Some(Fail::Code(w(1304))));
    fx.freeze(
        FREEZER_KEY,
        bc::FreezeOp::Token {
            cfg: fx.cfg,
            tok: TOK,
            paused_mint: false,
            paused_burn: false,
        },
    )
    .unwrap();
    let t = fx.prove_call(&a, &call, vec![]).unwrap();
    fx.freeze(
        FREEZER_KEY,
        bc::FreezeOp::Global {
            cfg: fx.cfg,
            paused_mint: false,
            paused_burn: true,
        },
    )
    .unwrap();
    assert_eq!(fx.c.settle_private(&t).err(), Some(Fail::Code(w(1304))));
    fx.freeze(
        FREEZER_KEY,
        bc::FreezeOp::Global {
            cfg: fx.cfg,
            paused_mint: false,
            paused_burn: false,
        },
    )
    .unwrap();
    let mut e = entry();
    e.mint_open = false;
    fx.admin(
        ADMIN_KEY,
        bc::AdminOp::UpdateToken {
            cfg: fx.cfg,
            entry: e,
        },
    )
    .unwrap();
    let t = fx.prove_call(&a, &call, vec![]).unwrap();
    fx.c.settle_private(&t).unwrap();
}

/// Two burners of the same (tok, d) proven on the same state: the first lands, the second is
/// refused with no balance change, re-proves with the next index and lands.
#[test]
fn two_burners_same_index() {
    let mut fx = setup();
    let (mut a, mut b) = (Holder::new(0x52), Holder::new(0x53));
    fx.claim(&mut a, 0).unwrap();
    fx.claim(&mut a, 1).unwrap();
    fx.claim(&mut b, 2).unwrap();
    fx.claim(&mut b, 3).unwrap();
    let ta = fx
        .prove_call(&a, &fx.burn_call(0, burn_b(1)), vec![])
        .unwrap();
    let tb = fx
        .prove_call(&b, &fx.burn_call(0, burn_b(2)), vec![])
        .unwrap();
    fx.c.settle_private(&ta).unwrap();
    a.commit(with(&a.h, fx.cfg, TOK, -((D + FEE_BURN) as i128)));
    let before = fx.c.state.clone();
    assert!(fx.c.settle_private(&tb).is_err());
    assert!(fx.c.state == before && b.on_chain(&fx.c), "B unchanged");
    let idx = host::next_index(&fx.token_state(), D);
    assert_eq!(idx, 1);
    let tb = fx
        .prove_call(&b, &fx.burn_call(idx, burn_b(2)), vec![])
        .unwrap();
    fx.c.settle_private(&tb).unwrap();
    let f = fx.token_state().trees[0].1.clone();
    let leaves = [burn_b(1), burn_b(2)];
    assert_eq!(
        f.root(),
        merkle_root(leaves[1], 1, &merkle_path(&leaves, 1)).unwrap()
    );
}

/// Capacity boundary (Frontier capacity 2^20 - 1 leaves, attest-program 66f8568): with
/// 2^20 - 2 leaves, the append at index 2^20 - 2 lands with the right root; the next burn
/// (index 2^20 - 1) is 1307 and changes nothing.
#[test]
fn burn_tree_capacity_boundary() {
    let mut fx = setup();
    let mut a = Holder::new(0x54);
    for i in 0..4 {
        fx.claim(&mut a, i).unwrap();
    }
    const DEPTH: usize = bc::BURN_TREE_DEPTH;
    let mut zeros = vec![[0u8; 32]];
    for h in 0..DEPTH {
        let z = zeros[h];
        zeros.push(sha(&z, &z));
    }
    let mut st = fx.token_state();
    let mut f = bc::Frontier::default();
    f.leaves = (1u64 << DEPTH) - 2;
    for h in 1..DEPTH {
        f.nodes[h] = zeros[h];
    }
    st.trees = vec![(D, f)];
    let tp = fx.token_actor(&fx.cfg, &TOK);
    fx.c.force_actor(tp, borsh::to_vec(&st).unwrap());
    let idx = (1u64 << DEPTH) - 2;
    let b = burn_b(9);
    let t = fx
        .prove_call(&a, &fx.burn_call(idx, b), vec![])
        .expect("last leaf fits");
    fx.c.settle_private(&t).unwrap();
    a.commit(with(&a.h, fx.cfg, TOK, -((D + FEE_BURN) as i128)));
    let got = fx.token_state().trees[0].1.root();
    assert_eq!(got, merkle_root(b, idx, &zeros[..DEPTH]).unwrap());
    let call = fx.burn_call(idx + 1, burn_b(10));
    private_fails(&mut fx, &a, &call, 1307);
}

fn sha(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::new()
        .chain_update(l)
        .chain_update(r)
        .finalize()
        .into()
}

/// Transaction bytes without the proof. A real succinct receipt carries a random sample of the
/// recursion circuit's fixed Merkle nodes (FRI queries), so any two real proofs share some 32-byte
/// windows by chance, across holders as often as within one (checked 2026-11-25); the receipt's
/// zero knowledge is RISC Zero's guarantee, not something a byte scan can test.
fn public_bytes(t: &PrivacyPreservingTransaction) -> Vec<u8> {
    borsh::to_vec(&(&t.message, t.witness_set.signatures_and_public_keys())).unwrap()
}

/// Claim, transfer and burn by one holder share no public byte beyond what any holder's
/// claim/transfer/burn also carries (program ids, image ids, token, config-derived PDAs).
#[test]
fn cross_operation_unlinkable() {
    let mut fx = setup();
    let ops = |fx: &mut Fx, h: &mut Holder, deps: [u32; 2], idx: u64, j: u8| -> Vec<Vec<u8>> {
        let other = Holder::new(j ^ 0x80);
        let mut out = vec![];
        let c1 = fx.claim_call(deps[0], &entry(), D);
        let t1 = fx.prove_call(h, &c1, vec![]).unwrap();
        fx.c.settle_private(&t1).unwrap();
        h.commit(with(&h.h, fx.cfg, TOK, (D - FEE_MINT) as i128));
        out.push(public_bytes(&t1));
        fx.claim(h, deps[1]).unwrap();
        let c2 = host::transfer(fx.cfg, TOK, 10, other.id);
        let t2 = fx.prove_call(h, &c2, vec![other.recipient()]).unwrap();
        fx.c.settle_private(&t2).unwrap();
        h.commit(with(&h.h, fx.cfg, TOK, -10));
        out.push(public_bytes(&t2));
        let c3 = fx.burn_call(idx, burn_b(j));
        let t3 = fx.prove_call(h, &c3, vec![]).unwrap();
        fx.c.settle_private(&t3).unwrap();
        h.commit(with(&h.h, fx.cfg, TOK, -((D + FEE_BURN) as i128)));
        out.push(public_bytes(&t3));
        out
    };
    let win =
        |x: &[u8]| -> BTreeSet<[u8; 32]> { x.windows(32).map(|w| w.try_into().unwrap()).collect() };
    let (mut a, mut c) = (Holder::new(0x55), Holder::new(0x56));
    let ta = ops(&mut fx, &mut a, [0, 1], 0, 3);
    let tc = ops(&mut fx, &mut c, [2, 3], 1, 4);
    let baseline: BTreeSet<[u8; 32]> = tc.iter().flat_map(|x| win(x)).collect();
    let w1 = win(&ta[0]);
    let shared: Vec<_> = ta[1..]
        .iter()
        .flat_map(|x| win(x))
        .filter(|w| w1.contains(w) && !baseline.contains(w))
        .collect();
    assert!(
        shared.is_empty(),
        "A's claim shares {} windows with A's transfer/burn, e.g. {}",
        shared.len(),
        shared.first().map(hex::encode).unwrap_or_default()
    );
}

/// Supply invariant over a fixed claim/burn sequence: supply = Σ minted − Σ burned ≤ cap.
#[test]
fn supply_invariant() {
    let mut fx = setup();
    let mut a = Holder::new(0x57);
    let (mut minted, mut burned) = (0u128, 0u128);
    for (step, i) in [(0, 0u32), (0, 1), (1, 0), (0, 2), (0, 3), (1, 1), (1, 2)] {
        if step == 0 {
            fx.claim(&mut a, i).unwrap();
            minted += D;
        } else {
            let idx = host::next_index(&fx.token_state(), D);
            let t = fx.prove_call(&a, &fx.burn_call(idx, burn_b(i as u8 + 20)), vec![]);
            match t {
                Ok(t) => {
                    fx.c.settle_private(&t).unwrap();
                    a.commit(with(&a.h, fx.cfg, TOK, -((D + FEE_BURN) as i128)));
                    burned += D;
                }
                Err(e) => assert!(code_in(&e, 1305), "{e:?}"),
            }
        }
        let ts = fx.token_state();
        assert_eq!(ts.supply, minted - burned);
        assert!(ts.supply <= ts.entry.supply_cap);
    }
}

// ------------------------------------------------------------------ cycles, program id

/// Cycle table: private transitions measured as signed public root calls (same guest code);
/// public parts are the settled private txs' public cycles.
#[test]
fn bridge_cycles() {
    let mut fx = setup();
    let seat_key = [0x60; 32];
    let seat = Actor::new(key_id(seat_key), fx.bridge);
    let call = fx.claim_call(0, &entry(), D);
    let claim_total = fx
        .signed_ev(
            seat_key,
            seat,
            call.public_actors.clone(),
            &call.msg,
            &call.evidence,
        )
        .unwrap();
    let mut fx2 = setup();
    let mut a = Holder::new(0x61);
    let pub_claim = fx2.claim(&mut a, 0).unwrap().public_cycles;
    fx2.claim(&mut a, 1).unwrap();
    let burn = fx2.burn_call(0, burn_b(1));
    let t = fx2.prove_call(&a, &burn, vec![]).unwrap();
    let pub_burn = fx2.c.settle_private(&t).unwrap().public_cycles;
    // Burn as public needs holdings on the seat: one more public claim first
    let call1 = fx.claim_call(1, &entry(), D);
    fx.signed_ev(
        seat_key,
        seat,
        call1.public_actors.clone(),
        &call1.msg,
        &call1.evidence,
    )
    .unwrap();
    let bc2 = fx.burn_call(0, burn_b(2));
    let burn_total = fx
        .signed_ev(
            seat_key,
            seat,
            bc2.public_actors.clone(),
            &bc2.msg,
            &bc2.evidence,
        )
        .unwrap();
    eprintln!("CYCLES | step | total (as public) | public part | private transition |");
    eprintln!(
        "CYCLES | Claim  | {claim_total} | {pub_claim} | ~{} |",
        claim_total - pub_claim
    );
    eprintln!(
        "CYCLES | Burn   | {burn_total} | {pub_burn} | ~{} |",
        burn_total - pub_burn
    );
    eprintln!("CYCLES | MintCheck (config hop + token PDA + CheckRoot + Spend) | {pub_claim} |");
    eprintln!("CYCLES | RecordBurn (config hop + token PDA + WriteLeaf) | {pub_burn} |");
    assert!(claim_total <= MAX_GAS_EXEC);
}

#[test]
fn bridge_program_id() {
    let id = bridge_id();
    eprintln!(
        "BRIDGE_ID image {}\nbridge_program_id 0x{}",
        BRIDGE_ID
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        hex::encode(id.value())
    );
    assert_eq!(bridge_cfg(0).bridge_program_id, *id.value());
}

/// P4 evidence: one `Burn` PP tx proven for real (dev mode off for the burn only; the setup
/// claims stay dev mode) and accepted by settlement with proof checking on. Run on the prover host:
/// `cargo test --release -p program-tests --test bridge real_burn_proof -- --ignored --nocapture`
/// under `/usr/bin/time -v` for peak RAM.
#[test]
#[ignore = "real proof, minutes; run explicitly"]
fn real_burn_proof() {
    std::env::set_var("RISC0_DEV_MODE", "1");
    let mut fx = setup();
    let mut a = Holder::new(0x70);
    fx.claim(&mut a, 0).unwrap();
    fx.claim(&mut a, 1).unwrap();
    let call = fx.burn_call(0, burn_b(1));
    std::env::set_var("RISC0_DEV_MODE", "0");
    let t0 = std::time::Instant::now();
    let tx = fx.prove_call(&a, &call, vec![]).unwrap();
    let prove = t0.elapsed();
    let t1 = std::time::Instant::now();
    fx.c.settle_private(&tx).expect("real proof accepted");
    eprintln!(
        "REAL_BURN prove {:.1}s verify+settle {:.2}s tx {} bytes",
        prove.as_secs_f64(),
        t1.elapsed().as_secs_f64(),
        borsh::to_vec(&tx).unwrap().len()
    );
    assert_eq!(fx.token_state().trees[0].1.leaves, 1);
}
