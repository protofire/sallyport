//! F8 private-claim prototype (docs/PRIVACY.md section 4), synthetic Ethereum block. The tests run
//! with dev-mode proofs by default (`RISC0_DEV_MODE=1`, no prover compiled in) and with real
//! proofs when built with `--features lee/prove` and `RISC0_DEV_MODE` unset. The claimant's root call is private; the
//! consumer verifies inline with `attest_program::verify` (the same core as `Msg::Attest`) and
//! sends only `RedeemCheck{vault_id, cfg_hash, root, nullifier}` across the boundary.

use attest_program::*;
use consumers::{
    cfg_hash, commit, pnf, private_request, tagged, vault_seed, ConsumerMsg, PrivateBalance,
    PrivateVaultConfig, ERR_ALREADY_CLAIMED, TAG_BALANCE, TAG_SPENT,
};
use lc_core::ChainConfig;
use lee::{Actor, BoundaryStep, PrivacyPreservingTransaction};
use program_tests::*;

const A: InstanceId = SEPOLIA_ID;
const VAULT: [u8; 32] = [0x77; 32];
const VAULT2: [u8; 32] = [0x78; 32];
const DEPOSIT: [u8; 20] = [0xDE; 20];
const TOPIC0: [u8; 32] = [0xD0; 32]; // stands in for keccak("Deposit(bytes32,uint256)")
const DENOM: u128 = 100;
const NKS: [[u8; 32]; 3] = [[0x11; 32], [0x22; 32], [0x33; 32]];
/// An attacker's own deposit contract: tx `ATTACKER_TX` of the block deposits `ATTACKER_NK` there.
const ATTACKER_DEPOSIT: [u8; 20] = [0xBA; 20];
const ATTACKER_NK: [u8; 32] = [0x44; 32];
const ATTACKER_TX: u32 = 3;

fn denom() -> [u8; 32] {
    let mut d = [0; 32];
    d[16..].copy_from_slice(&DENOM.to_be_bytes());
    d
}

struct Fx {
    c: Chain,
    cfg: PrivateVaultConfig,
    blk: ElBlock,
    rec: HeaderRecord,
    leaves: Vec<[u8; 32]>,
    root: [u8; 32],
    /// Private vault the claims go through.
    vault: [u8; 32],
}

/// Instance A from the real Sepolia bootstrap; then one synthetic block (one deposit receipt per
/// nk in `NKS`) is accepted the way `Apply` would: header PDA, accumulator leaf, root PDA.
fn setup() -> Fx {
    let mut c = Chain::new();
    c.init(&sepolia_init()).unwrap();
    let receipts = NKS
        .iter()
        .map(|nk| deposit_receipt(DEPOSIT, TOPIC0, commit(nk), denom()))
        .chain([deposit_receipt(
            ATTACKER_DEPOSIT,
            TOPIC0,
            commit(&ATTACKER_NK),
            denom(),
        )])
        .collect();
    let blk = ElBlock::synthetic(serde_json::Value::Array(receipts));
    let mut st = c.instance_state(&A);
    let s = ChainConfig::sepolia();
    let slot = st.store.finalized_header.beacon.slot + 32;
    let rec = HeaderRecord {
        instance_id: A,
        chain_id: s.chain_id,
        genesis_validators_root: s.genesis_validators_root,
        beacon_slot: slot,
        beacon_root: [0x5B; 32],
        execution_block_hash: blk.hash,
        period: lc_core::period_at_slot(slot),
    };
    let leaves = vec![
        header_leaf(&header_record(A, &st.cfg, &st.store.finalized_header)),
        header_leaf(&rec),
    ];
    let root = st.headers.append(leaves[1]).unwrap();
    force_instance(&mut c, A, &st);
    let (hdr, hroot) = (
        c.header(&A, &blk.hash),
        c.actor(c.attest, hroot_seed(&A, &root)),
    );
    c.force_actor(hdr, borsh::to_vec(&rec).unwrap());
    c.force_actor(hroot, root.to_vec());
    let cfg = PrivateVaultConfig {
        instance_id: A,
        chain_id: s.chain_id,
        genesis_validators_root: s.genesis_validators_root,
        deposit_contract: DEPOSIT,
        deposit_topic0: TOPIC0,
        denomination: denom(),
    };
    let v = c.vault(c.erc20, VAULT);
    c.send(
        v,
        vec![],
        &ConsumerMsg::InitPrivateVault {
            vault_id: VAULT,
            cfg: cfg.clone(),
        },
    )
    .unwrap();
    Fx {
        c,
        cfg,
        blk,
        rec,
        leaves,
        root,
        vault: VAULT,
    }
}

impl Fx {
    fn msg(&self, tx_index: u32, nk: [u8; 32], leaves: &[[u8; 32]]) -> ConsumerMsg {
        let (receipt, receipt_proof) = self.blk.receipt(tx_index);
        ConsumerMsg::PrivateClaim {
            vault_id: self.vault,
            cfg: self.cfg.clone(),
            header: self.rec.clone(),
            header_index: 1,
            header_path: merkle_path(leaves, 1),
            exec_header_rlp: self.blk.rlp.clone(),
            ancestry: vec![],
            tx_index,
            log_index: 0,
            receipt,
            receipt_proof,
            nk,
        }
    }

    /// Public actors of the private claim: {vault PDA, root PDA, nullifier PDA}.
    fn actors(&self, root: [u8; 32], nk: &[u8; 32]) -> Vec<Actor> {
        let c = &self.c;
        vec![
            c.actor(c.erc20, vault_seed(&self.vault)),
            c.actor(c.attest, hroot_seed(&A, &root)),
            c.actor(c.erc20, pnf(nk)),
        ]
    }

    fn prove_with(
        &self,
        who: &Claimant,
        msg: &ConsumerMsg,
        root: [u8; 32],
        nk: &[u8; 32],
        assume: Vec<(Actor, Vec<u8>)>,
    ) -> Result<PrivacyPreservingTransaction, lee::error::LeeError> {
        let mut blind = pnf(nk); // any fresh 32 bytes per (claimant, nk)
        blind
            .iter_mut()
            .zip(who.id.value())
            .for_each(|(b, w)| *b ^= w);
        self.c.prove_private(
            who,
            self.c.erc20,
            msg,
            self.actors(root, nk),
            vec![(self.c.erc20, pnf(nk))],
            assume,
            blind,
        )
    }

    fn prove(&self, who: &Claimant, tx_index: u32, nk: [u8; 32]) -> PrivacyPreservingTransaction {
        self.prove_with(
            who,
            &self.msg(tx_index, nk, &self.leaves),
            self.root,
            &nk,
            vec![],
        )
        .unwrap()
    }

    fn balance(&self, who: &Claimant, amount: u128) -> bool {
        let bal = PrivateBalance {
            cfg_hash: cfg_hash(&self.cfg),
            amount,
        };
        self.c
            .has_commitment(&who.commitment(self.c.erc20, tagged(TAG_BALANCE, &bal)))
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Header accumulator on the update path: Init writes the first root PDA; `CheckRoot` accepts
/// it and rejects an unknown root with 1101 (no state change, no event).
#[test]
fn init_writes_root_pda_and_check_root() {
    let mut c = Chain::new();
    c.init(&sepolia_init()).unwrap();
    let st = c.instance_state(&A);
    assert_eq!(st.headers.leaves, 1);
    let root = st.headers.root();
    assert_eq!(
        root,
        Frontier::default()
            .append(header_leaf(&header_record(
                A,
                &st.cfg,
                &st.store.finalized_header
            )))
            .unwrap()
    );
    let hroot = c.actor(c.attest, hroot_seed(&A, &root));
    assert_eq!(c.state_of(hroot), root.to_vec());
    c.send(
        hroot,
        vec![],
        &Msg::CheckRoot {
            instance_id: A,
            root,
        },
    )
    .unwrap();
    let bogus = c.seeded(c.attest, hroot_seed(&A, &[9; 32]));
    assert_eq!(
        c.send(
            bogus,
            vec![],
            &Msg::CheckRoot {
                instance_id: A,
                root: [9; 32]
            }
        ),
        Err(Fail::Code(1101))
    );
    // root PDAs are internal-write only
    assert_eq!(
        c.send(
            bogus,
            vec![],
            &Msg::WriteRoot {
                instance_id: A,
                root: [9; 32]
            }
        ),
        Err(Fail::Code(1001))
    );
}

/// One verification core: the public `Attest` root call on the synthetic header returns exactly
/// the statement the private consumer computes with `attest_program::verify`.
#[test]
fn public_attest_and_private_verify_share_the_core() {
    let mut fx = setup();
    let req = private_request(&fx.cfg, &fx.msg(0, NKS[0], &fx.leaves)).unwrap();
    let stmt = verify(&fx.rec, &req).unwrap();
    assert_eq!(stmt.fact.execution_block_hash, fx.blk.hash);
    let ebh = fx.blk.hash;
    fx.c.attest(ebh, req.clone()).unwrap();
    // wrong nk: the commitment predicate fails, host-side before any proving (1203)
    let wrong = private_request(&fx.cfg, &fx.msg(0, [0xEE; 32], &fx.leaves)).unwrap();
    assert_eq!(verify(&fx.rec, &wrong), Err(1203));
    assert_eq!(fx.c.attest(ebh, wrong), Err(Fail::Code(1203)));
}

/// F8 evidence (a)(b)(c): private credit; public diff = one new nullifier PDA; boundary =
/// one `RedeemCheck`; no events; nothing ties the tx to the block, deposit, statement or account.
#[test]
fn private_claim_credits_privately_and_leaks_nothing() {
    let mut fx = setup();
    let who = Claimant::new(0x41);
    let nk = NKS[0];
    let tx = fx.prove(&who, 0, nk);
    let n = pnf(&nk);
    let n_pda = fx.c.actor(fx.c.erc20, n).account_id;
    let s = fx.c.settle_private(&tx).unwrap();
    // (a) the claimant's private account now holds DENOM under the consumer program
    assert!(fx.balance(&who, DENOM));
    // (b) public footprint
    let actors: std::collections::BTreeSet<_> =
        tx.message.public_context.actors.iter().copied().collect();
    assert_eq!(actors, fx.actors(fx.root, &nk).into_iter().collect());
    assert_eq!(
        s.changed,
        [n_pda].into(),
        "only the nullifier PDA is written"
    );
    assert_eq!(fx.c.state_of(fx.c.actor(fx.c.erc20, n)), vec![TAG_SPENT]);
    assert!(
        tx.message.execution.public_root.is_none(),
        "root call is private"
    );
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
    let redeem = ConsumerMsg::RedeemCheck {
        vault_id: VAULT,
        cfg_hash: cfg_hash(&fx.cfg),
        root: fx.root,
        nullifier: n,
    };
    assert_eq!(
        crossings[0].envelope.message,
        borsh::to_vec(&redeem).unwrap(),
        "boundary carries only vault, cfg hash, root, nullifier"
    );
    assert_ne!(
        crossings[0].envelope.from.account_id, who.id,
        "sender is blinded"
    );
    // byte search over the whole serialized tx and the written state
    let mut hay = borsh::to_vec(&tx).unwrap();
    for id in &s.changed {
        hay.extend(id.value());
        hay.extend(
            fx.c.state
                .get_account_by_id(*id)
                .data
                .actor_state(fx.c.erc20)
                .to_vec(),
        );
    }
    let sid = verify(
        &fx.rec,
        &private_request(&fx.cfg, &fx.msg(0, nk, &fx.leaves)).unwrap(),
    )
    .unwrap()
    .id;
    let (receipt, _) = fx.blk.receipt(0);
    let needles: Vec<(&str, Vec<u8>)> = vec![
        ("block hash", fx.blk.hash.to_vec()),
        (
            "header PDA",
            fx.c.header(&A, &fx.blk.hash).account_id.value().to_vec(),
        ),
        ("header leaf", header_leaf(&fx.rec).to_vec()),
        ("statement_id", sid.to_vec()),
        (
            "H(statement_id)",
            consumers::nullifier_seed(&VAULT, &sid).to_vec(),
        ),
        (
            "public-path nullifier PDA",
            fx.c.actor(fx.c.erc20, consumers::nullifier_seed(&VAULT, &sid))
                .account_id
                .value()
                .to_vec(),
        ),
        ("claimant account", who.id.value().to_vec()),
        ("commitment C", commit(&nk).to_vec()),
        ("nk", nk.to_vec()),
        ("receipt", receipt[..48].to_vec()),
    ];
    for (name, needle) in &needles {
        assert!(!contains(&hay, needle), "{name} leaked");
    }
    // (c) no events
    assert_eq!(s.events, 0);
    eprintln!("LEAK public footprint: actors={{vault, root PDA, N PDA}} changed={{N}} boundary=1 RedeemCheck events=0; tx {} bytes", hay.len());
    eprintln!("CYCLES private-claim public part {}", s.public_cycles);
}

/// (d) the same nk under another private account → 1250, and that account gets nothing.
#[test]
fn private_replay_same_nk_is_1250() {
    let mut fx = setup();
    let (a, b) = (Claimant::new(0x41), Claimant::new(0x42));
    let t1 = fx.prove(&a, 0, NKS[0]);
    let t2 = fx.prove(&b, 0, NKS[0]); // proven before t1 lands (wallet view without N)
                                      // Griefing: N is visible in the pending tx's boundary; a direct public RedeemCheck cannot burn it.
    let n = pnf(&NKS[0]);
    let mut acts = fx.actors(fx.root, &NKS[0]);
    acts[2] = fx.c.seeded(fx.c.erc20, n);
    let redeem = ConsumerMsg::RedeemCheck {
        vault_id: VAULT,
        cfg_hash: cfg_hash(&fx.cfg),
        root: fx.root,
        nullifier: n,
    };
    assert_eq!(
        fx.c.send(acts[0], acts[1..].to_vec(), &redeem),
        Err(Fail::Code(1001))
    );
    fx.c.settle_private(&t1).unwrap();
    assert_eq!(
        fx.c.settle_private(&t2).err(),
        Some(Fail::Code(ERR_ALREADY_CLAIMED))
    );
    assert!(!fx.balance(&b, DENOM));
    // and a fresh proof against the live state is refused before settlement
    assert!(fx
        .prove_with(&b, &fx.msg(0, NKS[0], &fx.leaves), fx.root, &NKS[0], vec![])
        .is_err());
}

/// The same deposit (same nk) through a second private vault with the same config: the
/// nullifier must be global, not per vault, else one deposit is credited once per vault.
#[test]
fn same_deposit_via_second_vault_is_1250() {
    let mut fx = setup();
    let v2 = fx.c.vault(fx.c.erc20, VAULT2);
    fx.c.send(
        v2,
        vec![],
        &ConsumerMsg::InitPrivateVault {
            vault_id: VAULT2,
            cfg: fx.cfg.clone(),
        },
    )
    .unwrap();
    let (a, b) = (Claimant::new(0x48), Claimant::new(0x49));
    let t1 = fx.prove(&a, 0, NKS[0]);
    fx.vault = VAULT2;
    let t2 = fx.prove(&b, 0, NKS[0]); // proven before t1 lands
    fx.c.settle_private(&t1).unwrap();
    assert_eq!(
        fx.c.settle_private(&t2).err(),
        Some(Fail::Code(ERR_ALREADY_CLAIMED))
    );
    assert!(!fx.balance(&b, DENOM));
}

/// (e) a root the instance never wrote → 1101 at settlement, no private action applied.
#[test]
fn unknown_root_is_1101_and_applies_nothing() {
    let mut fx = setup();
    let who = Claimant::new(0x43);
    let fake = [fx.leaves[0], fx.leaves[1], [0xFA; 32]]; // tree with an unaccepted extra leaf
    let mut fr = Frontier::default();
    let fake_root = fake.iter().map(|l| fr.append(*l).unwrap()).last().unwrap();
    let msg = fx.msg(0, NKS[0], &fake);
    // honest simulation fails up front
    assert!(fx
        .prove_with(&who, &msg, fake_root, &NKS[0], vec![])
        .is_err());
    // a wallet that wrongly assumes the root exists can prove, but settlement refuses it
    let hroot = fx.c.actor(fx.c.attest, hroot_seed(&A, &fake_root));
    let tx = fx
        .prove_with(
            &who,
            &msg,
            fake_root,
            &NKS[0],
            vec![(hroot, fake_root.to_vec())],
        )
        .unwrap();
    let before = fx.c.state.clone();
    // The root PDA does not exist and nobody may create it here, so LEZ refuses to admit it.
    assert!(
        matches!(fx.c.settle_private(&tx), Err(Fail::Other(ref e)) if e.contains("execution rules"))
    );
    assert!(fx.c.state == before);
    // Same tx with admission evidence for the root PDA reaches CheckRoot: 1101.
    let mut tx = tx;
    tx.message
        .admission_evidence
        .push(lee::PublicAccountEvidence::Pda {
            program: fx.c.attest,
            seed: lee_core::program::PdaSeed::new(hroot_seed(&A, &fake_root)),
        });
    assert_eq!(fx.c.settle_private(&tx).err(), Some(Fail::Code(1101)));
    assert!(!fx.balance(&who, DENOM));
    assert!(fx.c.state == before, "state untouched");
}

/// (f) R11: two claims proven against the same root settle in one block in reverse order, after
/// a newer header (and root) landed in between.
#[test]
fn two_claims_same_root_settle_in_either_order() {
    let mut fx = setup();
    let (a, b) = (Claimant::new(0x44), Claimant::new(0x45));
    let ta = fx.prove(&a, 0, NKS[0]);
    let tb = fx.prove(&b, 1, NKS[1]);
    // a later header is accepted before inclusion: the old root PDA stays valid
    let mut st = fx.c.instance_state(&A);
    let r2 = st.headers.append([0x99; 32]).unwrap();
    force_instance(&mut fx.c, A, &st);
    let hr2 = fx.c.actor(fx.c.attest, hroot_seed(&A, &r2));
    fx.c.force_actor(hr2, r2.to_vec());
    fx.c.settle_private(&tb).unwrap();
    fx.c.settle_private(&ta).unwrap(); // same block id: settle_private does not advance it
    assert!(fx.balance(&a, DENOM) && fx.balance(&b, DENOM));
}

/// (g) wrong nk: the commitment predicate fails (1203) in the private transition, so no proof.
#[test]
fn wrong_nk_fails_before_proving() {
    let fx = setup();
    let who = Claimant::new(0x46);
    let wrong = [0xEE; 32];
    let msg = fx.msg(0, wrong, &fx.leaves);
    assert_eq!(
        verify(&fx.rec, &private_request(&fx.cfg, &msg).unwrap()),
        Err(1203)
    );
    let err = fx
        .prove_with(&who, &msg, fx.root, &wrong, vec![])
        .unwrap_err();
    assert!(format!("{err:?}").contains("203"), "{err:?}");
}

/// Dev-mode cycle count of the private transition: the same `PrivateClaim` run as a public root
/// call (on a signed public account) minus the public part of the private tx. Real proving time: P4, separate.
#[test]
fn private_claim_cycles() {
    let mut fx = setup();
    let tx = fx.prove(&Claimant::new(0x47), 2, NKS[2]);
    let public = fx.c.settle_private(&tx).unwrap().public_cycles;
    let mut fx2 = setup();
    let key = lee::PrivateKey::try_new([0xC1; 32]).unwrap();
    let host = Actor::new(Chain::signer(&key), fx2.c.erc20);
    let mut actors = fx2.actors(fx2.root, &NKS[2]);
    actors[2] = fx2.c.seeded(fx2.c.erc20, pnf(&NKS[2]));
    let total = fx2
        .c
        .send_signed(&key, host, actors, &fx2.msg(2, NKS[2], &fx2.leaves))
        .unwrap();
    eprintln!("CYCLES private-claim total(as public) {total}  public part {public}  private transition ~{}", total - public);
    assert!(total <= MAX_GAS_EXEC);
}

/// Review finding (squat): a `PrivateClaim` sent as a public root call to someone else's empty
/// consumer PDA used to write a balance there, so the victim's later `Nullify` (or `InitVault`)
/// hit non-empty state and failed for good. The attacker pays with one junk deposit to their own
/// contract through their own private vault. Now the receiver must be authorized: 1001, and the
/// victim's claim and vault init still work.
#[test]
fn private_claim_cannot_squat_public_pdas() {
    let mut fx = setup();
    // Attacker's vault: its own deposit contract, so it can prove a matching deposit.
    let cfg = PrivateVaultConfig {
        deposit_contract: ATTACKER_DEPOSIT,
        ..fx.cfg.clone()
    };
    let av = fx.c.vault(fx.c.erc20, VAULT2);
    fx.c.send(
        av,
        vec![],
        &ConsumerMsg::InitPrivateVault {
            vault_id: VAULT2,
            cfg: cfg.clone(),
        },
    )
    .unwrap();
    // Victim: a public ERC-20 vault expecting a real Sepolia transfer (block recorded at Init).
    let blk = ElBlock::sepolia();
    let (token, to, amount) = blk.log(1, 1);
    let s = ChainConfig::sepolia();
    let victim = consumers::VaultConfig {
        instance_id: A,
        chain_id: s.chain_id,
        genesis_validators_root: s.genesis_validators_root,
        token,
        vault_address: to,
    };
    const VICTIM: [u8; 32] = [0x5A; 32];
    const UNINIT: [u8; 32] = [0x5B; 32];
    fx.c.init_vault(fx.c.erc20, VICTIM, victim.clone()).unwrap();
    let sid = statement_id_for(s.chain_id, s.genesis_validators_root, blk.hash, 1, 1);
    fx.cfg = cfg;
    fx.vault = VAULT2;
    let attack = fx.msg(ATTACKER_TX, ATTACKER_NK, &fx.leaves);
    let mut actors = fx.actors(fx.root, &ATTACKER_NK);
    actors[2] = fx.c.seeded(fx.c.erc20, pnf(&ATTACKER_NK));
    for target in [
        fx.c.seeded(fx.c.erc20, consumers::nullifier_seed(&VICTIM, &sid)),
        fx.c.vault(fx.c.erc20, UNINIT),
    ] {
        assert_eq!(
            fx.c.send(target, actors.clone(), &attack),
            Err(Fail::Code(1001)),
            "squat on {target:?}"
        );
        assert!(fx.c.state_of(target).is_empty());
    }
    fx.c.claim(fx.c.erc20, VICTIM, A, &blk, 1, 1, amount)
        .unwrap();
    fx.c.init_vault(fx.c.erc20, UNINIT, victim).unwrap();
}

/// Review finding: the private balance was a bare u128, so a vault with any config (the
/// attacker's own deposit contract) credited the same balance as a real vault. A balance now
/// belongs to one vault config: a claim through another config is refused (1001).
#[test]
fn private_balance_is_bound_to_vault_config() {
    let mut fx = setup();
    let key = lee::PrivateKey::try_new([0x61; 32]).unwrap();
    let me = Actor::new(Chain::signer(&key), fx.c.erc20);
    let claim = |fx: &mut Fx, tx: u32, nk: [u8; 32]| {
        let mut actors = fx.actors(fx.root, &nk);
        actors[2] = fx.c.seeded(fx.c.erc20, pnf(&nk));
        let m = fx.msg(tx, nk, &fx.leaves);
        fx.c.send_signed(&key, me, actors, &m)
    };
    claim(&mut fx, 2, NKS[2]).unwrap();
    let real = fx.c.state_of(me);
    let bad = PrivateVaultConfig {
        deposit_contract: ATTACKER_DEPOSIT,
        ..fx.cfg.clone()
    };
    let bv = fx.c.vault(fx.c.erc20, VAULT2);
    fx.c.send(
        bv,
        vec![],
        &ConsumerMsg::InitPrivateVault {
            vault_id: VAULT2,
            cfg: bad.clone(),
        },
    )
    .unwrap();
    fx.cfg = bad;
    fx.vault = VAULT2;
    assert_eq!(
        claim(&mut fx, ATTACKER_TX, ATTACKER_NK),
        Err(Fail::Code(1001))
    );
    assert_eq!(fx.c.state_of(me), real, "balance unchanged");
}
