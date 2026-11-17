//! Example consumers of the attestation program: `erc20_receiver` (ERC-20 Transfer to a vault
//! address) and `eth_receiver` (native ETH via the EIP-7708 Transfer log from 0xff…fe).
//!
//! Flow, all inside the claimant's one tx (F7): `Claim` → chained `Attest` to the attest
//! program's header PDA → `AttestReply` back to the vault actor → checks → `Nullify` to
//! `PDA(sha256("rfp021/nullifier/v2" ‖ vault_id ‖ statement_id))`, which fails if it already
//! exists (replay). Every state this program writes starts with a type tag (`TAG_*`).
//! The credit is recorded against the Ethereum `from` of the proven Transfer log: the claim has
//! no recipient input, so a third party who submits someone else's deposit cannot redirect it.
//! The attest program id is a build-time constant ([`ATTEST_PROGRAM`]), never state (VS3).

use attest_program::view::Cur;
use attest_program::{AttestRequest, HeaderRecord, InstanceId, Proof};
use borsh::{BorshDeserialize, BorshSerialize};
use inclusion::{Locator, Pred};
use sha2::{Digest, Sha256};

/// Account id of the deployed attest program: `AccountId::from(&PublicKey(ATTEST_DEPLOY_KEY))`
/// (program-tests asserts this derivation; e2e deploys the program header at this key's account).
/// shortcut: fixed dev key, rebuild consumers with the real deployment address before any real use.
pub const ATTEST_PROGRAM: [u8; 32] = [
    53, 5, 143, 163, 220, 65, 131, 0, 238, 139, 161, 237, 74, 225, 222, 38, 226, 76, 39, 25, 142,
    2, 224, 127, 176, 35, 26, 113, 218, 206, 114, 32,
];
/// Dev-only deploy key for the attest program header account (public on purpose: the deployed
/// program is immutable, the key only chooses the address).
pub const ATTEST_DEPLOY_KEY: [u8; 32] = [0x21; 32];

/// Consumer-local error (not in docs/CONSUMER-GUIDE.md): statement already credited.
pub const ERR_ALREADY_CLAIMED: u16 = 1250;

pub fn vault_seed(vault_id: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"rfp021/vault")
        .chain_update(vault_id)
        .finalize()
        .into()
}

/// Per vault: `InitVault` is permissionless, so a statement-only nullifier would let a clone vault
/// (same config) claim each deposit first and block the real vault for good.
pub fn nullifier_seed(vault_id: &[u8; 32], statement_id: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"rfp021/nullifier/v2")
        .chain_update(vault_id)
        .chain_update(statement_id)
        .finalize()
        .into()
}

/// First byte of every state this program writes, so one kind never decodes as another.
pub const TAG_VAULT: u8 = 0xA1;
pub const TAG_PRIVATE_VAULT: u8 = 0xA2;
/// Public nullifier (holds the [`Credit`]).
pub const TAG_CREDIT: u8 = 0xA3;
/// Private nullifier (spent marker, no payload).
pub const TAG_SPENT: u8 = 0xA4;
pub const TAG_BALANCE: u8 = 0xA5;

/// `tag ‖ borsh(v)`.
pub fn tagged<T: BorshSerialize>(tag: u8, v: &T) -> Vec<u8> {
    let mut b = vec![tag];
    borsh::to_writer(&mut b, v).unwrap();
    b
}

/// Inverse of [`tagged`]; `None` on another tag or bad borsh.
pub fn untag<T: BorshDeserialize>(tag: u8, b: &[u8]) -> Option<T> {
    match b.split_first() {
        Some((&t, rest)) if t == tag => borsh::from_slice(rest).ok(),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VaultConfig {
    /// Pinned attest instance (F15): replies from any other instance are rejected.
    pub instance_id: InstanceId,
    pub chain_id: u64,
    pub genesis_validators_root: [u8; 32],
    /// ERC-20 token (eth_receiver: must be the EIP-7708 system address).
    pub token: [u8; 20],
    /// Ethereum recipient that deposits must be sent to.
    pub vault_address: [u8; 20],
}

/// Private vault (F8, docs/PRIVACY.md section 3): deposits are `Deposit(bytes32 indexed C,
/// uint256 amount)` logs of `deposit_contract` with `C = commit(nk)` and a fixed denomination.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PrivateVaultConfig {
    pub instance_id: InstanceId,
    pub chain_id: u64,
    pub genesis_validators_root: [u8; 32],
    pub deposit_contract: [u8; 20],
    pub deposit_topic0: [u8; 32],
    /// uint256 BE; must fit in u128.
    pub denomination: [u8; 32],
}

/// Deposit commitment the depositor puts in the Ethereum event: `sha256("rfp021/commit" ‖ nk)`.
pub fn commit(nk: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"rfp021/commit")
        .chain_update(nk)
        .finalize()
        .into()
}

/// Private nullifier `sha256("rfp021/pnf/v2" ‖ nk)`: unlinkable to the deposit without `nk`.
/// Independent of the vault, so a deposit is spent at most once across all private vaults of
/// this program (v1 included `vault_id`: one deposit was creditable once per vault; DECISIONS.md).
pub fn pnf(nk: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"rfp021/pnf/v2")
        .chain_update(nk)
        .finalize()
        .into()
}

pub fn cfg_hash(cfg: &PrivateVaultConfig) -> [u8; 32] {
    Sha256::digest(borsh::to_vec(cfg).unwrap()).into()
}

fn private_preds(cfg: &PrivateVaultConfig, nk: &[u8; 32]) -> Vec<Pred> {
    use inclusion::FieldSel::*;
    let eq = |field, value: &[u8]| Pred::Eq {
        field,
        value: value.to_vec(),
    };
    vec![
        eq(LogStatus, &[1]),
        eq(LogAddress, &cfg.deposit_contract),
        eq(LogTopic(0), &cfg.deposit_topic0),
        eq(LogTopic(1), &commit(nk)),
        eq(LogDataWord(0), &cfg.denomination),
    ]
}

/// The verification request a `PrivateClaim` checks inline (hosts use it to pre-check before proving).
pub fn private_request(cfg: &PrivateVaultConfig, m: &ConsumerMsg) -> Option<AttestRequest> {
    let ConsumerMsg::PrivateClaim {
        exec_header_rlp,
        ancestry,
        tx_index,
        log_index,
        receipt,
        receipt_proof,
        nk,
        ..
    } = m
    else {
        return None;
    };
    Some(AttestRequest {
        instance_id: cfg.instance_id,
        exec_header_rlp: exec_header_rlp.clone(),
        ancestry: ancestry.clone(),
        locator: Locator::Log {
            tx_index: *tx_index,
            log_index: *log_index,
        },
        proof: Proof::Log {
            receipt: receipt.clone(),
            receipt_proof: receipt_proof.clone(),
        },
        preds: private_preds(cfg, nk),
        ctx: vec![],
    })
}

/// A claimant's private balance, bound to the private vault config it was credited under: a vault
/// with another config (another deposit contract, denomination or instance) cannot add to it.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PrivateBalance {
    pub cfg_hash: [u8; 32],
    pub amount: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VaultState {
    pub cfg: VaultConfig,
    pub credited_total: u128,
    pub claims: u64,
}

/// Nullifier record = the credit, held by the Ethereum sender proven in the Transfer log.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Credit {
    pub vault_id: [u8; 32],
    pub statement_id: [u8; 32],
    /// `from` of the attested Transfer log (topic 1): the only key the credit can belong to.
    pub eth_sender: [u8; 20],
    pub amount: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ConsumerMsg {
    InitVault {
        vault_id: [u8; 32],
        cfg: VaultConfig,
    },
    Claim {
        vault_id: [u8; 32],
        /// Recorded block whose header PDA is called (the anchor when `ancestry` is non-empty).
        block_hash: [u8; 32],
        exec_header_rlp: Vec<u8>,
        /// Parent-hash chain from the attested block to `block_hash` (`AttestRequest::ancestry`); empty = `block_hash` itself.
        ancestry: Vec<Vec<u8>>,
        tx_index: u32,
        log_index: u32,
        receipt: Vec<u8>,
        receipt_proof: Vec<Vec<u8>>,
        /// Exact transferred amount (uint256 BE) that must be in the log.
        amount: [u8; 32],
    },
    /// Internal: vault → nullifier PDA.
    Nullify(Credit),
    // ---- private path (F8) ----
    InitPrivateVault {
        vault_id: [u8; 32],
        cfg: PrivateVaultConfig,
    },
    /// Root call to the claimant's **private** account. Verifies inline with
    /// `attest_program::verify`, credits `denomination` to the account's private balance (u128),
    /// then sends only `RedeemCheck` across the boundary.
    PrivateClaim {
        vault_id: [u8; 32],
        cfg: PrivateVaultConfig,
        header: HeaderRecord,
        header_index: u64,
        header_path: Vec<[u8; 32]>,
        exec_header_rlp: Vec<u8>,
        /// Parent-hash chain from the deposit block to the recorded header (`AttestRequest::ancestry`); empty = the recorded block.
        ancestry: Vec<Vec<u8>>,
        tx_index: u32,
        log_index: u32,
        receipt: Vec<u8>,
        receipt_proof: Vec<Vec<u8>>,
        nk: [u8; 32],
    },
    /// Private actor of this program → public private-vault PDA.
    RedeemCheck {
        vault_id: [u8; 32],
        cfg_hash: [u8; 32],
        root: [u8; 32],
        nullifier: [u8; 32],
    },
    /// Internal: private vault → `PDA(nullifier)`; fails 1250 if already spent.
    Spend {
        vault_id: [u8; 32],
        nullifier: [u8; 32],
    },
}

/// Context echoed by the attest program.
#[derive(BorshSerialize, BorshDeserialize)]
struct Ctx {
    vault_id: [u8; 32],
    amount: [u8; 32],
    /// Header PDA the request was sent to: with ancestry the reply comes from the anchor, not the fact's block.
    anchor: [u8; 32],
}

fn preds(cfg: &VaultConfig, amount: [u8; 32]) -> Vec<Pred> {
    let mut p = inclusion::erc20_transfer_preds(cfg.token, None, Some(cfg.vault_address), None);
    p.push(Pred::Eq {
        field: inclusion::FieldSel::LogDataWord(0),
        value: amount.to_vec(),
    });
    p
}

/// The chained Attest request a `Claim` produces (also used by hosts to build the same call). The
/// receipt travels as the proof's final leaf (`Proof::LogCompact`, D-GAS-6); the consumer checks
/// the claim's `receipt` against that leaf before sending.
pub fn attest_request(cfg: &VaultConfig, m: &ConsumerMsg) -> Option<AttestRequest> {
    let ConsumerMsg::Claim {
        vault_id,
        block_hash,
        exec_header_rlp,
        ancestry,
        tx_index,
        log_index,
        receipt_proof,
        amount,
        ..
    } = m
    else {
        return None;
    };
    Some(AttestRequest {
        instance_id: cfg.instance_id,
        exec_header_rlp: exec_header_rlp.clone(),
        ancestry: ancestry.clone(),
        locator: Locator::Log {
            tx_index: *tx_index,
            log_index: *log_index,
        },
        proof: Proof::LogCompact {
            receipt_proof: receipt_proof.clone(),
        },
        preds: preds(cfg, *amount),
        ctx: borsh::to_vec(&Ctx {
            vault_id: *vault_id,
            amount: *amount,
            anchor: *block_hash,
        })
        .unwrap(),
    })
}

/// Borsh variant index of [`ConsumerMsg::Claim`].
pub const MSG_CLAIM: u8 = 1;

/// `borsh(Msg::Attest(attest_request(cfg, claim)))` for `claim_body` = borsh(`ConsumerMsg::Claim`)
/// without its variant byte, built by copying the claim's byte spans once instead of
/// decode + clone + encode (gas, D-GAS-4). Returns (vault_id, block_hash, message, receipt_ok),
/// receipt_ok = the claim's receipt is the proof's final leaf (else the claim is 1202); `None` iff
/// the borsh decode of the claim would fail.
pub fn claim_attest_msg(
    cfg: &VaultConfig,
    claim_body: &[u8],
) -> Option<([u8; 32], [u8; 32], Vec<u8>, bool)> {
    let mut c = Cur(claim_body);
    let vault_id = c.arr()?;
    let block_hash = c.arr()?;
    let head = c.0; // exec_header_rlp ‖ ancestry: same borsh bytes in both messages
    c.bytes()?;
    c.vecs()?;
    let head = &head[..head.len() - c.0.len()];
    let idx = c.take(8)?; // tx_index ‖ log_index
    let receipt = c.bytes()?;
    let proof = c.0; // receipt_proof
    let nodes = c.vecs()?;
    let proof = &proof[..proof.len() - c.0.len()];
    let amount = c.arr()?;
    c.end()?;
    // The receipt is the proof's final leaf: forward the compact witness (D-GAS-6), keeping the
    // explicit form's "receipt == proven leaf" rule here (same 1202 the attest program returned).
    let receipt_ok = inclusion::receipt_is_last_leaf(receipt, &nodes);
    let ctx = borsh::to_vec(&Ctx {
        vault_id,
        amount,
        anchor: block_hash,
    })
    .ok()?;
    let preds = borsh::to_vec(&preds(cfg, amount)).ok()?;
    let mut m =
        Vec::with_capacity(36 + head.len() + 10 + proof.len() + preds.len() + 4 + ctx.len());
    m.push(attest_program::view::MSG_ATTEST);
    m.extend_from_slice(&cfg.instance_id);
    m.extend_from_slice(head);
    m.push(2); // Locator::Log
    m.extend_from_slice(idx);
    m.push(3); // Proof::LogCompact
    m.extend_from_slice(proof);
    m.extend_from_slice(&preds);
    borsh::to_writer(&mut m, &ctx).ok()?;
    Some((vault_id, block_hash, m, receipt_ok))
}

/// The request an inline-verifying `Claim` checks itself (optional pattern, D-GAS-7): borrowed
/// from `claim_body` (borsh `ConsumerMsg::Claim` without its variant byte), the same request as
/// [`attest_request`] but with the explicit receipt. Returns (block_hash, request, ctx bytes);
/// `None` iff the borsh decode of the claim would fail.
pub fn claim_request<'a>(
    cfg: &VaultConfig,
    claim_body: &'a [u8],
) -> Option<([u8; 32], attest_program::AttestRequestRef<'a>, Vec<u8>)> {
    let mut c = Cur(claim_body);
    let vault_id = c.arr()?;
    let block_hash = c.arr()?;
    let exec_header_rlp = c.bytes()?;
    let ancestry = c.vecs()?;
    let tx_index = u32::from_le_bytes(c.arr()?);
    let log_index = u32::from_le_bytes(c.arr()?);
    let receipt = c.bytes()?;
    let receipt_proof = c.vecs()?;
    let amount = c.arr()?;
    c.end()?;
    let ctx = borsh::to_vec(&Ctx {
        vault_id,
        amount,
        anchor: block_hash,
    })
    .ok()?;
    let req = attest_program::AttestRequestRef {
        instance_id: cfg.instance_id,
        exec_header_rlp,
        ancestry,
        locator: Locator::Log {
            tx_index,
            log_index,
        },
        proof: attest_program::ProofRef::Log {
            receipt,
            receipt_proof,
        },
        preds: preds(cfg, amount),
        ctx: &[],
    };
    Some((block_hash, req, ctx))
}

#[cfg(feature = "guest")]
pub mod program {
    use super::*;
    use attest_program::view::AttestReplyRef;
    use attest_program::{header_leaf, header_seed, hroot_seed, merkle_root, Msg};
    use lee_core::account::{AccountId, Actor};
    use lee_core::program::{PdaSeed, ReceiveInput, Response, SyncMessage};
    use risc0_zkvm::guest::env;

    const MALFORMED: u16 = 1001;
    const INCLUSION_INVALID: u16 = 1202;
    const PREDICATE_FAILED: u16 = 1203;
    const STATEMENT_MISMATCH: u16 = 1204;

    fn fail(code: u16) -> ! {
        env::exit((code - 1000) as u8)
    }

    fn decode<T: BorshDeserialize>(b: &[u8]) -> T {
        borsh::from_slice(b).unwrap_or_else(|_| fail(MALFORMED))
    }

    fn state<T: BorshDeserialize>(tag: u8, b: &[u8]) -> T {
        untag(tag, b).unwrap_or_else(|| fail(MALFORMED))
    }

    fn pda(program: &AccountId, seed: [u8; 32]) -> AccountId {
        AccountId::for_public_pda(program, &PdaSeed::new(seed))
    }

    fn require_at(input: &ReceiveInput, seed: [u8; 32]) {
        if input.receiver.account_id != pda(&input.receiver.program_account_id, seed) {
            fail(MALFORMED);
        }
    }

    /// `fixed_token`: eth_receiver pins the EIP-7708 address; erc20_receiver takes it from config.
    pub fn handle(input: &ReceiveInput, message: &[u8], fixed_token: Option<[u8; 20]>) -> Response {
        let attest = AccountId::new(ATTEST_PROGRAM);
        let me = input.receiver.program_account_id;
        if let Some(from) = input.from.filter(|f| f.program_account_id == attest) {
            return on_reply(
                input,
                from,
                attest_program::view::AttestReplyRef::decode(message)
                    .unwrap_or_else(|| fail(MALFORMED)),
            );
        }
        if let Some((&MSG_CLAIM, body)) = message.split_first() {
            return claim(input, attest, body);
        }
        match decode::<ConsumerMsg>(message) {
            ConsumerMsg::InitVault { vault_id, cfg } => {
                require_at(input, vault_seed(&vault_id));
                if !input.pre_state.is_empty() || fixed_token.is_some_and(|t| t != cfg.token) {
                    fail(MALFORMED);
                }
                Response::set_state(tagged(
                    TAG_VAULT,
                    &VaultState {
                        cfg,
                        credited_total: 0,
                        claims: 0,
                    },
                ))
            }
            ConsumerMsg::Claim { .. } => unreachable!("MSG_CLAIM fast path above"),
            ConsumerMsg::InitPrivateVault { vault_id, cfg } => {
                require_at(input, vault_seed(&vault_id));
                if !input.pre_state.is_empty() || fixed_token.is_some() {
                    fail(MALFORMED);
                }
                Response::set_state(tagged(TAG_PRIVATE_VAULT, &cfg))
            }
            m @ ConsumerMsg::PrivateClaim { .. } => private_claim(input, m),
            ConsumerMsg::RedeemCheck {
                vault_id,
                cfg_hash,
                root,
                nullifier,
            } => {
                require_at(input, vault_seed(&vault_id));
                // Only this program's (private) actors, which verified first, may redeem.
                if !input.from.is_some_and(|f| f.program_account_id == me)
                    || input.pre_state.is_empty()
                {
                    fail(MALFORMED);
                }
                let cfg: PrivateVaultConfig = state(TAG_PRIVATE_VAULT, &input.pre_state);
                if <[u8; 32]>::from(Sha256::digest(&input.pre_state[1..])) != cfg_hash {
                    fail(STATEMENT_MISMATCH);
                }
                let hroot = Actor::new(pda(&attest, hroot_seed(&cfg.instance_id, &root)), attest);
                Response::keep_state()
                    .send(SyncMessage::new(
                        hroot,
                        &Msg::CheckRoot {
                            instance_id: cfg.instance_id,
                            root,
                        },
                    ))
                    .send(
                        SyncMessage::new(
                            Actor::new(pda(&me, nullifier), me),
                            &ConsumerMsg::Spend {
                                vault_id,
                                nullifier,
                            },
                        )
                        .with_pda_seeds([PdaSeed::new(nullifier)]),
                    )
            }
            ConsumerMsg::Spend {
                vault_id,
                nullifier,
            } => {
                require_at(input, nullifier);
                let ok = input.from.is_some_and(|f| {
                    f.program_account_id == me && f.account_id == pda(&me, vault_seed(&vault_id))
                });
                if !ok {
                    fail(MALFORMED);
                }
                if !input.pre_state.is_empty() {
                    fail(ERR_ALREADY_CLAIMED);
                }
                Response::set_state(vec![TAG_SPENT])
            }
            ConsumerMsg::Nullify(c) => {
                require_at(input, nullifier_seed(&c.vault_id, &c.statement_id));
                let ok = input.from.is_some_and(|f| {
                    f.program_account_id == me && f.account_id == pda(&me, vault_seed(&c.vault_id))
                });
                if !ok {
                    fail(MALFORMED);
                }
                if !input.pre_state.is_empty() {
                    fail(ERR_ALREADY_CLAIMED);
                }
                Response::set_state(tagged(TAG_CREDIT, &c))
            }
        }
    }

    /// `Claim` → chained `Attest` to the anchor's header PDA. Every failure here is 1001.
    fn claim(input: &ReceiveInput, attest: AccountId, body: &[u8]) -> Response {
        let vault_id: [u8; 32] = body
            .get(..32)
            .and_then(|v| v.try_into().ok())
            .unwrap_or_else(|| fail(MALFORMED));
        require_at(input, vault_seed(&vault_id));
        if input.pre_state.is_empty() {
            fail(MALFORMED);
        }
        let st: VaultState = state(TAG_VAULT, &input.pre_state);
        let (_, block_hash, message, receipt_ok) =
            claim_attest_msg(&st.cfg, body).unwrap_or_else(|| fail(MALFORMED));
        if !receipt_ok {
            fail(INCLUSION_INVALID);
        }
        let header = pda(&attest, header_seed(&st.cfg.instance_id, &block_hash));
        Response::keep_state().send(SyncMessage {
            to: Actor::new(header, attest),
            message,
            pda_seeds: Default::default(),
        })
    }

    /// Optional inline pattern (docs/CONSUMER-GUIDE.md, D-GAS-7; binary `erc20_inline_receiver`):
    /// `Claim` runs the shared verification core here instead of chaining `Attest`, binds the
    /// anchor with `CheckHeader` in the same transaction, then applies the same reply checks and
    /// nullifier as the chained path. Every other message is [`handle`].
    pub fn handle_inline(
        input: &ReceiveInput,
        message: &[u8],
        fixed_token: Option<[u8; 20]>,
    ) -> Response {
        let attest = AccountId::new(ATTEST_PROGRAM);
        match message.split_first() {
            Some((&MSG_CLAIM, body))
                if !input.from.is_some_and(|f| f.program_account_id == attest) =>
            {
                claim_inline(input, attest, body)
            }
            _ => handle(input, message, fixed_token),
        }
    }

    fn claim_inline(input: &ReceiveInput, attest: AccountId, body: &[u8]) -> Response {
        let vault_id: [u8; 32] = body
            .get(..32)
            .and_then(|v| v.try_into().ok())
            .unwrap_or_else(|| fail(MALFORMED));
        require_at(input, vault_seed(&vault_id));
        if input.pre_state.is_empty() {
            fail(MALFORMED);
        }
        let cfg = state::<VaultState>(TAG_VAULT, &input.pre_state).cfg;
        let (block_hash, req, ctx) = claim_request(&cfg, body).unwrap_or_else(|| fail(MALFORMED));
        let statement =
            attest_program::verify_at(cfg.chain_id, cfg.genesis_validators_root, block_hash, &req)
                .unwrap_or_else(|c| fail(c));
        let header = Actor::new(
            pda(&attest, header_seed(&cfg.instance_id, &block_hash)),
            attest,
        );
        // Unproven until CheckHeader succeeds: it runs first, and any failure reverts the whole tx.
        let mut r = on_reply(
            input,
            header,
            AttestReplyRef {
                instance_id: cfg.instance_id,
                statement_id: statement.id,
                fact: statement.fact,
                ctx: &ctx,
            },
        );
        r.sync_messages.insert(
            0,
            SyncMessage::new(
                header,
                &Msg::CheckHeader {
                    instance_id: cfg.instance_id,
                    chain_id: cfg.chain_id,
                    genesis_validators_root: cfg.genesis_validators_root,
                    execution_block_hash: block_hash,
                },
            ),
        );
        r
    }

    /// Runs in the claimant's private transition: nothing here is published except `RedeemCheck`.
    fn private_claim(input: &ReceiveInput, m: ConsumerMsg) -> Response {
        let ConsumerMsg::PrivateClaim {
            vault_id,
            cfg,
            header,
            header_index,
            header_path,
            nk,
            ..
        } = &m
        else {
            unreachable!()
        };
        // The balance lands on the receiver: only its owner may claim into it, else anyone could
        // write a balance onto another actor's empty PDA (a nullifier or vault) and block it.
        if !input.is_authorized {
            fail(MALFORMED);
        }
        let me = input.receiver.program_account_id;
        let vault = pda(&me, vault_seed(vault_id));
        if input.receiver.account_id == vault {
            fail(MALFORMED);
        }
        if header.instance_id != cfg.instance_id
            || header.chain_id != cfg.chain_id
            || header.genesis_validators_root != cfg.genesis_validators_root
        {
            fail(STATEMENT_MISMATCH);
        }
        let root = merkle_root(header_leaf(header), *header_index, header_path)
            .unwrap_or_else(|| fail(MALFORMED));
        let ConsumerMsg::PrivateClaim {
            exec_header_rlp,
            ancestry,
            tx_index,
            log_index,
            receipt,
            receipt_proof,
            ..
        } = &m
        else {
            unreachable!()
        };
        // = private_request(cfg, &m).view(), without cloning the proof (D-GAS-3)
        let req = attest_program::AttestRequestRef {
            instance_id: cfg.instance_id,
            exec_header_rlp,
            ancestry: ancestry.iter().map(Vec::as_slice).collect(),
            locator: Locator::Log {
                tx_index: *tx_index,
                log_index: *log_index,
            },
            proof: attest_program::ProofRef::Log {
                receipt,
                receipt_proof: receipt_proof.iter().map(Vec::as_slice).collect(),
            },
            preds: private_preds(cfg, nk),
            ctx: &[],
        };
        attest_program::verify_ref(header, &req).unwrap_or_else(|c| fail(c));
        if cfg.denomination[..16] != [0; 16] {
            fail(MALFORMED);
        }
        let cfg_hash = cfg_hash(cfg);
        let mut bal = if input.pre_state.is_empty() {
            PrivateBalance {
                cfg_hash,
                amount: 0,
            }
        } else {
            state(TAG_BALANCE, &input.pre_state)
        };
        if bal.cfg_hash != cfg_hash {
            fail(MALFORMED); // shortcut: one asset per account; use another account per config
        }
        bal.amount = bal
            .amount
            .checked_add(u128::from_be_bytes(
                cfg.denomination[16..].try_into().unwrap(),
            ))
            .unwrap_or_else(|| fail(MALFORMED));
        let redeem = ConsumerMsg::RedeemCheck {
            vault_id: *vault_id,
            cfg_hash,
            root,
            nullifier: pnf(nk),
        };
        Response::set_state(tagged(TAG_BALANCE, &bal))
            .send(SyncMessage::new(Actor::new(vault, me), &redeem))
    }

    fn on_reply(input: &ReceiveInput, from: Actor, r: AttestReplyRef) -> Response {
        let ctx: Ctx = decode(r.ctx);
        require_at(input, vault_seed(&ctx.vault_id));
        let mut st: VaultState = state(TAG_VAULT, &input.pre_state);
        let f = &r.fact;
        // Instance binding: the reply must come from the pinned instance's header PDA we called (the
        // attest program checked the fact's block against that recorded header, directly or via ancestry).
        let expected = pda(
            &from.program_account_id,
            header_seed(&st.cfg.instance_id, &ctx.anchor),
        );
        if from.account_id != expected
            || r.instance_id != st.cfg.instance_id
            || f.chain_id != st.cfg.chain_id
            || f.genesis_validators_root != st.cfg.genesis_validators_root
            || r.statement_id != inclusion::statement_id(f)
        {
            fail(STATEMENT_MISMATCH);
        }
        // Re-check our own predicates on the proven fact (do not trust the echoed preds).
        // (= inclusion::attest(..).is_err() without re-hashing the statement id checked above)
        if !preds(&st.cfg, ctx.amount)
            .iter()
            .all(|p| inclusion::eval(f, p) == Ok(true))
        {
            fail(PREDICATE_FAILED);
        }
        if ctx.amount[..16] != [0; 16] {
            fail(MALFORMED);
        }
        // Credit holder = proven Transfer `from` (topic 1, a left-padded address).
        let from = match &f.value {
            inclusion::FactValue::Log(l) => l
                .topics
                .get(1)
                .copied()
                .unwrap_or_else(|| fail(PREDICATE_FAILED)),
            _ => fail(MALFORMED),
        };
        if from[..12] != [0; 12] {
            fail(MALFORMED);
        }
        let eth_sender: [u8; 20] = from[12..].try_into().unwrap();
        let amount = u128::from_be_bytes(ctx.amount[16..].try_into().unwrap());
        st.credited_total = st
            .credited_total
            .checked_add(amount)
            .unwrap_or_else(|| fail(MALFORMED));
        st.claims += 1;
        let me = input.receiver.program_account_id;
        let seed = nullifier_seed(&ctx.vault_id, &r.statement_id);
        let credit = Credit {
            vault_id: ctx.vault_id,
            statement_id: r.statement_id,
            eth_sender,
            amount,
        };
        Response::set_state(tagged(TAG_VAULT, &st)).send(
            SyncMessage::new(
                Actor::new(pda(&me, seed), me),
                &ConsumerMsg::Nullify(credit),
            )
            .with_pda_seeds([PdaSeed::new(seed)]),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each state kind decodes only under its own tag.
    #[test]
    fn state_tags_are_distinct() {
        let tags = [
            TAG_VAULT,
            TAG_PRIVATE_VAULT,
            TAG_CREDIT,
            TAG_SPENT,
            TAG_BALANCE,
        ];
        assert!(tags.iter().enumerate().all(|(i, t)| !tags[..i].contains(t)));
        let b = tagged(
            TAG_BALANCE,
            &PrivateBalance {
                cfg_hash: [1; 32],
                amount: 5,
            },
        );
        assert!(untag::<PrivateBalance>(TAG_BALANCE, &b).is_some());
        assert!(tags
            .iter()
            .filter(|&&t| t != TAG_BALANCE)
            .all(|&t| untag::<PrivateBalance>(t, &b).is_none()));
        assert!(untag::<u128>(TAG_BALANCE, &[]).is_none());
    }

    #[test]
    fn claim_attest_msg_is_borsh_of_attest_request() {
        let cfg = VaultConfig {
            instance_id: [1; 32],
            chain_id: 11_155_111,
            genesis_validators_root: [2; 32],
            token: [3; 20],
            vault_address: [4; 20],
        };
        let m = ConsumerMsg::Claim {
            vault_id: [5; 32],
            block_hash: [6; 32],
            exec_header_rlp: vec![7; 600],
            ancestry: vec![vec![8; 500], vec![]],
            tx_index: 0x0102_0304,
            log_index: 9,
            receipt: vec![10; 300],
            receipt_proof: vec![vec![11; 532], vec![12; 40]],
            amount: [13; 32],
        };
        let b = borsh::to_vec(&m).unwrap();
        assert_eq!(b[0], MSG_CLAIM);
        let want = borsh::to_vec(&attest_program::Msg::Attest(
            attest_request(&cfg, &m).unwrap(),
        ));
        assert_eq!(
            claim_attest_msg(&cfg, &b[1..]),
            Some(([5; 32], [6; 32], want.unwrap(), false))
        );
        for n in 0..b.len() {
            assert_eq!(claim_attest_msg(&cfg, &b[1..n.max(1)]), None, "len {n}");
        }
        let mut t = b.clone();
        t.push(0);
        assert_eq!(claim_attest_msg(&cfg, &t[1..]), None);
    }
}
