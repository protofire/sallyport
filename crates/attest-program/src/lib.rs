//! RFP-021 attestation program for LEZ v0.4 (actor model).
//!
//! One immutable program, many instances. Every account is a public PDA of this program with a
//! domain-separated seed ([`instance_seed`], [`header_seed`], [`job_seed`]):
//! - Instance actor: [`InstanceState`] (immutable [`InstanceConfig`] + lc-core `Store`).
//! - Header actor: [`HeaderRecord`], written once when a finalized header is accepted, never mutated.
//! - Job actor: [`Job`], pairing inputs carried from `UpdateBegin` to `UpdateVerify`.
//! - Header-root actor ([`hroot_seed`]): write-once marker that a root of the instance's header
//!   accumulator ([`Frontier`]) existed. Private consumers prove header membership against it
//!   ([`Msg::CheckRoot`]) instead of touching the per-block header PDA (docs/PRIVACY.md).
//!
//! [`verify`] is the single verification core: `Msg::Attest` and private consumers both call it.
//!
//! Errors: the guest exits with `code - 1000` (risc0 exit codes are u8), so LEZ reports
//! `ProgramExitedWithCode { code }` and the error in docs/CONSUMER-GUIDE.md is `1000 + code` ([`error_from_exit`]).

use borsh::{BorshDeserialize, BorshSerialize};
use inclusion::{
    verify_account, verify_ancestry, verify_receipt_log, verify_storage, Account, Fact, FactValue,
    Locator, Pred, Statement,
};
use lc_core::{
    hash_tree_root_header, period_at_slot, ChainConfig, ErrorCode, FinalizedHeader,
    LightClientBootstrap, LightClientUpdate, Root, Store, VerifiedUpdate,
};
use sha2::{Digest, Sha256};

#[cfg(any(feature = "guest", feature = "witness"))]
pub mod bls;
#[cfg(feature = "entry")]
pub mod entry;
pub mod view;
pub use view::{AttestRequestRef, ProofRef};
#[cfg(feature = "guest")]
pub mod program;
#[cfg(any(feature = "guest", feature = "witness"))]
pub mod residue;
#[cfg(feature = "witness")]
pub mod witness;

pub type InstanceId = [u8; 32];

fn seed(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The only id `Init` accepts: `sha256("rfp021/instance-id" ‖ borsh(InstanceConfig) ‖ trusted_block_root)`
/// (`borsh(InstanceConfig)` = `borsh(ChainConfig) ‖ genesis_time`), so pinning an id pins the full config and checkpoint.
pub fn instance_id(cfg: &InstanceConfig, trusted_block_root: &Root) -> InstanceId {
    seed(
        b"rfp021/instance-id",
        &[&borsh::to_vec(cfg).unwrap(), trusted_block_root],
    )
}

pub fn instance_seed(instance_id: &InstanceId) -> [u8; 32] {
    seed(b"rfp021/instance", &[instance_id])
}

pub fn header_seed(instance_id: &InstanceId, execution_block_hash: &Root) -> [u8; 32] {
    seed(b"rfp021/header", &[instance_id, execution_block_hash])
}

pub fn job_seed(instance_id: &InstanceId, job_id: u64) -> [u8; 32] {
    seed(b"rfp021/job", &[instance_id, &job_id.to_le_bytes()])
}

pub fn hroot_seed(instance_id: &InstanceId, root: &Root) -> [u8; 32] {
    seed(b"rfp021/hroot", &[instance_id, root])
}

/// Accumulator leaf of a header record.
pub fn header_leaf(rec: &HeaderRecord) -> [u8; 32] {
    seed(b"rfp021/hleaf", &[&borsh::to_vec(rec).unwrap()])
}

/// Depth of the header accumulator (2^20 ≈ 1M finalized headers per instance).
pub const HEADER_TREE_DEPTH: usize = 20;

fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(l)
        .chain_update(r)
        .finalize()
        .into()
}

/// Incremental sha256 Merkle tree (deposit-contract style): `nodes[h]` is the left sibling
/// waiting at height `h`; empty subtrees hash from a zero leaf.
#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Frontier {
    pub leaves: u64,
    pub nodes: [[u8; 32]; HEADER_TREE_DEPTH],
}

impl Frontier {
    /// Appends `leaf` and returns the new root; `None` when the tree is full.
    /// Capacity is 2^DEPTH - 1: the 2^DEPTH-th append would leave `leaves` with all-zero low
    /// bits, so `root()` would return the empty root and the last leaf would be unprovable.
    pub fn append(&mut self, leaf: [u8; 32]) -> Option<[u8; 32]> {
        if self.leaves + 1 >= 1 << HEADER_TREE_DEPTH {
            return None;
        }
        self.leaves += 1;
        let (mut n, mut size) = (leaf, self.leaves);
        for h in 0..HEADER_TREE_DEPTH {
            if size & 1 == 1 {
                self.nodes[h] = n;
                break;
            }
            n = node(&self.nodes[h], &n);
            size >>= 1;
        }
        Some(self.root())
    }

    pub fn root(&self) -> [u8; 32] {
        let (mut n, mut zero, mut size) = ([0u8; 32], [0u8; 32], self.leaves);
        for h in 0..HEADER_TREE_DEPTH {
            n = if size & 1 == 1 {
                node(&self.nodes[h], &n)
            } else {
                node(&n, &zero)
            };
            zero = node(&zero, &zero);
            size >>= 1;
        }
        n
    }
}

/// Root from a leaf, its index and exactly [`HEADER_TREE_DEPTH`] siblings (bottom-up).
pub fn merkle_root(leaf: [u8; 32], index: u64, siblings: &[[u8; 32]]) -> Option<[u8; 32]> {
    if siblings.len() != HEADER_TREE_DEPTH || index >= 1 << HEADER_TREE_DEPTH {
        return None;
    }
    Some(siblings.iter().enumerate().fold(leaf, |n, (h, s)| {
        if index >> h & 1 == 1 {
            node(s, &n)
        } else {
            node(&n, s)
        }
    }))
}

/// Host helper: sibling path of leaf `i` in the tree of `leaves` (zero-padded).
pub fn merkle_path(leaves: &[[u8; 32]], mut i: usize) -> Vec<[u8; 32]> {
    let (mut level, mut zero, mut path) = (leaves.to_vec(), [0u8; 32], vec![]);
    for _ in 0..HEADER_TREE_DEPTH {
        path.push(*level.get(i ^ 1).unwrap_or(&zero));
        level = level
            .chunks(2)
            .map(|c| node(&c[0], c.get(1).unwrap_or(&zero)))
            .collect();
        zero = node(&zero, &zero);
        i >>= 1;
    }
    path
}

/// Header record of finalized header `f` accepted by `instance_id`.
pub fn header_record(
    instance_id: InstanceId,
    cfg: &InstanceConfig,
    f: &FinalizedHeader,
) -> HeaderRecord {
    HeaderRecord {
        instance_id,
        chain_id: cfg.chain.chain_id,
        genesis_validators_root: cfg.chain.genesis_validators_root,
        beacon_slot: f.beacon.slot,
        beacon_root: hash_tree_root_header(&f.beacon),
        execution_block_hash: f.execution_block_hash,
        period: period_at_slot(f.beacon.slot),
    }
}

/// The verification core shared by `Msg::Attest` and private consumers: binds the EL header to
/// `rec` (directly, or an ancestor of it via `req.ancestry`), checks the proof against the locator, builds the `Fact` and evaluates `req.preds`.
/// Errors are the codes of docs/CONSUMER-GUIDE.md. The caller must have established that `rec` is a header the
/// instance accepted (header PDA state, or accumulator membership + `CheckRoot`).
pub fn verify(rec: &HeaderRecord, req: &AttestRequest) -> Result<Statement, u16> {
    verify_ref(rec, &req.view())
}

/// [`verify`] over a borrowed request (what `Msg::Attest` decodes, D-GAS-3).
pub fn verify_ref(rec: &HeaderRecord, req: &AttestRequestRef) -> Result<Statement, u16> {
    if rec.instance_id != req.instance_id {
        return Err(ErrorCode::HeaderNotFinalised as u16);
    }
    verify_at(
        rec.chain_id,
        rec.genesis_validators_root,
        rec.execution_block_hash,
        req,
    )
}

/// The body of [`verify_ref`] against a *claimed* anchor `(chain_id, genesis_validators_root,
/// anchor_hash)`. Nothing here proves the anchor was finalised: a caller must bind it to the
/// instance's header record, e.g. an inline-verifying consumer chains [`Msg::CheckHeader`] in the
/// same transaction (docs/CONSUMER-GUIDE.md, inline pattern; D-GAS-7).
pub fn verify_at(
    chain_id: u64,
    genesis_validators_root: Root,
    anchor_hash: Root,
    req: &AttestRequestRef,
) -> Result<Statement, u16> {
    let c = |e: inclusion::ErrorCode| e as u16;
    // `block_hash` is the attested block's: the StatementId must not depend on the anchor used.
    let (h, block_hash) =
        verify_ancestry(req.exec_header_rlp, anchor_hash, &req.ancestry).map_err(c)?;
    let value = match (&req.locator, &req.proof) {
        (
            Locator::Account { address },
            ProofRef::Account {
                account,
                account_proof,
            },
        ) => {
            verify_account(&h.state_root, address, account, account_proof).map_err(c)?;
            FactValue::Account(account.clone())
        }
        (
            Locator::Storage { address, slot },
            ProofRef::Storage {
                account,
                account_proof,
                value,
                storage_proof,
            },
        ) => {
            verify_account(&h.state_root, address, account, account_proof).map_err(c)?;
            verify_storage(&account.storage_root, slot, value, storage_proof).map_err(c)?;
            FactValue::Slot(*value)
        }
        (
            Locator::Log {
                tx_index,
                log_index,
            },
            ProofRef::Log {
                receipt,
                receipt_proof,
            },
        ) => FactValue::Log(
            verify_receipt_log(
                &h.receipts_root,
                *tx_index,
                *log_index,
                receipt,
                receipt_proof,
            )
            .map_err(c)?,
        ),
        (
            Locator::Log {
                tx_index,
                log_index,
            },
            ProofRef::LogCompact { receipt_proof },
        ) => FactValue::Log(
            inclusion::verify_receipt_log_compact(
                &h.receipts_root,
                *tx_index,
                *log_index,
                receipt_proof,
            )
            .map_err(c)?,
        ),
        _ => return Err(ErrorCode::Malformed as u16),
    };
    let fact = Fact {
        chain_id,
        genesis_validators_root,
        execution_block_hash: block_hash,
        block_number: h.number,
        locator: req.locator.clone(),
        value,
    };
    inclusion::attest(fact, req.preds.clone()).map_err(c)
}

/// Error code (docs/CONSUMER-GUIDE.md) from a LEZ `ProgramExitedWithCode { code }` of this program.
pub fn error_from_exit(code: u32) -> u16 {
    1000 + code as u16
}

/// Instance configuration, fixed at `Init` (no instruction can change it: F9/F13).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct InstanceConfig {
    pub chain: ChainConfig,
    /// Beacon genesis time (unix seconds): binds `now_slot` to the LEZ block timestamp.
    pub genesis_time: u64,
}

/// Protocol floor on `ChainConfig::min_participation`: ⌈2/3 · 512⌉ sync-committee signers.
pub const MIN_PARTICIPATION_FLOOR: u16 = 342;
/// Upper bound on `ChainConfig::ws_period_epochs`: the maximum of `lc_core::compute_ws_period_epochs`
/// over all balances (256 + ⌊10·t / (200·δ)⌋ peaks at 3_558 just below a churn-increment step).
pub const MAX_WS_PERIOD_EPOCHS: u64 = 3_558;

impl InstanceConfig {
    pub fn slot_start_ms(&self, slot: u64) -> u64 {
        self.genesis_time
            .saturating_add(slot.saturating_mul(12))
            .saturating_mul(1000)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct InstanceState {
    pub cfg: InstanceConfig,
    pub store: Store,
    /// Accumulator of every [`HeaderRecord`] this instance wrote, in acceptance order.
    pub headers: Frontier,
}

/// A finalized execution block accepted by an instance. Carries the chain binding so `Attest`
/// (which only sees this actor's state) can build the `Fact` without reading the instance.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct HeaderRecord {
    pub instance_id: InstanceId,
    pub chain_id: u64,
    pub genesis_validators_root: Root,
    pub beacon_slot: u64,
    pub beacon_root: Root,
    pub execution_block_hash: Root,
    pub period: u64,
}

/// Update in flight between `UpdateBegin` and `UpdateVerify`. Points are blst serialized
/// (uncompressed affine); `apk` is already `aggregate - non_signers`, `sig` already
/// subgroup-checked, `h` = hash_to_G2(signing_root).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Job {
    pub instance_id: InstanceId,
    pub job_id: u64,
    pub verified: VerifiedUpdate,
    pub apk: Vec<u8>,
    pub h: Vec<u8>,
    pub sig: Vec<u8>,
}

/// Proof material matching a [`Locator`] (kinds must agree, else 1001).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Proof {
    Account {
        account: Account,
        account_proof: Vec<Vec<u8>>,
    },
    Storage {
        account: Account,
        account_proof: Vec<Vec<u8>>,
        value: [u8; 32],
        storage_proof: Vec<Vec<u8>>,
    },
    Log {
        receipt: Vec<u8>,
        receipt_proof: Vec<Vec<u8>>,
    },
    /// `Log` without the receipt: it is the value of the proven final leaf, which the proof already
    /// carries (same checks, ~1 KB less; D-GAS-6). Appended variant: existing tags unchanged.
    LogCompact { receipt_proof: Vec<Vec<u8>> },
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AttestRequest {
    pub instance_id: InstanceId,
    /// RLP of the recorded block's EL header (keccak must equal the record's `execution_block_hash`).
    pub exec_header_rlp: Vec<u8>,
    /// Header RLPs [H_target, …, H_anchor-1] linking an earlier finalized block to the recorded
    /// one by parentHash; the proof is then checked against H_target. Empty = the recorded block.
    /// At most `inclusion::MAX_ANCESTRY` (else 1001); a broken link is 1201.
    pub ancestry: Vec<Vec<u8>>,
    pub locator: Locator,
    pub proof: Proof,
    pub preds: Vec<Pred>,
    /// Opaque caller context echoed in [`AttestReply`] (callback pattern of the actor model).
    pub ctx: Vec<u8>,
}

/// Sent back to the calling actor (chained call), or emitted as an event for a root call.
/// The sender is the header actor `PDA(attest, header_seed(instance_id, block_hash))`, which is
/// what binds the reply to an instance.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AttestReply {
    pub instance_id: InstanceId,
    pub statement: Statement,
    pub ctx: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Msg {
    /// Root → Instance PDA. Permissionless, once per instance_id.
    Init {
        instance_id: InstanceId,
        cfg: InstanceConfig,
        trusted_block_root: Root,
        bootstrap: LightClientBootstrap,
        /// Current beacon slot, bound to the LEZ block time like `UpdateBegin.now_slot`
        /// (input of the weak-subjectivity check once lc-core's bootstrap takes it).
        now_slot: u64,
    },
    /// Root → Instance PDA. lc-core prepare_update + BLS pre-work, writes the Job PDA.
    UpdateBegin {
        instance_id: InstanceId,
        job_id: u64,
        update: LightClientUpdate,
        /// Uncompressed (96 B) form of each non-signer key, in index order, optionally followed by
        /// the uncompressed aggregate key (96 B) and signature (192 B). Hints only: each must
        /// compress to the stored committee key at the index the program derives from the bits
        /// (resp. the stored aggregate / the update's signature bytes).
        non_signers: Vec<Vec<u8>>,
        /// Current beacon slot; the tx is only valid while the LEZ block time is within
        /// [`NOW_TOLERANCE_MS`] of it (weak-subjectivity check input).
        now_slot: u64,
    },
    /// Root → Job PDA. Pairing check, then apply to the instance and record the header.
    /// `witness` = 864-byte residue witness (c ∈ Fp12, s ∈ Fp6), built off-chain by `witness::for_pairing`.
    UpdateVerify {
        instance_id: InstanceId,
        job_id: u64,
        witness: Vec<u8>,
    },
    /// Root or chained → Header PDA.
    Attest(AttestRequest),
    // ---- internal: accepted only from this program's own actors at their PDA ----
    WriteJob(Job),
    Apply {
        instance_id: InstanceId,
        job_id: u64,
        verified: VerifiedUpdate,
    },
    WriteHeader(HeaderRecord),
    /// Internal: Instance → `PDA(hroot_seed(instance_id, root))`, write-once, after each append.
    WriteRoot {
        instance_id: InstanceId,
        root: Root,
    },
    /// Root or chained → root PDA. Fails 1101 unless `root` was a header-accumulator root of
    /// `instance_id`; no state change, no reply, no event.
    CheckRoot {
        instance_id: InstanceId,
        root: Root,
    },
    /// Root → Instance PDA. Prepare, verify the BLS residue witness and apply atomically.
    /// Appended to preserve existing Borsh tags. Use the split path when this exceeds gas.
    Update {
        instance_id: InstanceId,
        update: LightClientUpdate,
        /// Same indexed, recompression-checked hints as `UpdateBegin.non_signers`.
        non_signers: Vec<Vec<u8>>,
        /// Same 864-byte residue witness as `UpdateVerify.witness`.
        witness: Vec<u8>,
        /// Bound to the LEZ block timestamp exactly as in `UpdateBegin`.
        now_slot: u64,
    },
    /// Header PDA (`header_seed(instance_id, execution_block_hash)`): succeeds only if that
    /// header record exists and carries exactly this instance, chain and genesis validators root
    /// (else 1101 / 1204). For consumers that verify inline with [`verify_at`] (D-GAS-7).
    CheckHeader {
        instance_id: InstanceId,
        chain_id: u64,
        genesis_validators_root: Root,
        execution_block_hash: Root,
    },
}

pub const NOW_TOLERANCE_MS: u64 = 120_000;

/// Event selector for a root-call attestation (`sha256("rfp021::Attested")[..8]`).
pub fn attested_selector() -> [u8; 8] {
    // = sha256("rfp021::Attested")[..8], a constant instead of a hash per call (test below)
    [146, 3, 235, 40, 138, 11, 20, 160]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_selector_is_domain_hash_prefix() {
        assert_eq!(
            attested_selector().as_slice(),
            &seed(b"rfp021::Attested", &[])[..8]
        );
    }

    #[test]
    fn max_ws_period_is_the_formula_maximum() {
        const I: u64 = 1_000_000_000;
        // peaks sit just below each churn-increment step; below 128 increments the churn is constant
        let peak = (128..200_000u64)
            .map(|k| lc_core::compute_ws_period_epochs((k + 1) * I * 65_536 - 1))
            .max()
            .unwrap();
        assert_eq!(peak, MAX_WS_PERIOD_EPOCHS);
        assert!(lc_core::compute_ws_period_epochs(128 * I * 65_536) <= MAX_WS_PERIOD_EPOCHS);
        assert!(lc_core::MAINNET_WS_PERIOD_EPOCHS <= MAX_WS_PERIOD_EPOCHS);
    }

    #[test]
    fn frontier_root_matches_paths() {
        let leaves: Vec<[u8; 32]> = (0u8..7).map(|i| [i + 1; 32]).collect();
        let mut f = Frontier::default();
        assert_eq!(
            f.root(),
            merkle_root([0; 32], 0, &merkle_path(&[], 0)).unwrap()
        );
        for n in 1..=leaves.len() {
            let root = f.append(leaves[n - 1]).unwrap();
            assert_eq!(root, f.root());
            for (i, l) in leaves[..n].iter().enumerate() {
                assert_eq!(
                    merkle_root(*l, i as u64, &merkle_path(&leaves[..n], i)),
                    Some(root),
                    "n={n} i={i}"
                );
            }
            assert_ne!(
                merkle_root([0xFF; 32], 0, &merkle_path(&leaves[..n], 0)),
                Some(root)
            );
        }
        assert_eq!(merkle_root(leaves[0], 0, &[[0; 32]; 3]), None);
    }

    #[test]
    fn frontier_rejects_final_leaf() {
        let mut f = Frontier {
            leaves: (1 << HEADER_TREE_DEPTH) - 2,
            nodes: [[7; 32]; HEADER_TREE_DEPTH],
        };
        assert!(f.append([1; 32]).is_some());
        let full = f.clone();
        assert_eq!(f.append([2; 32]), None);
        assert_eq!(f, full);
    }
}
