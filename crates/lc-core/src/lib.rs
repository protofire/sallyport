//! Ethereum light-client verification core (Altair sync protocol) for Electra/Fulu and Gloas headers.
//!
//! Pure Rust, no threads/fs/net/randomness; sha256 via `sha2` (risc0-patchable). BLS is behind
//! [`SigVerifier`]; [`prepare_update`] does everything except the pairing and returns its exact
//! inputs, [`finish_update`] consumes the pairing result, so the pairing can run in another tx.

use borsh::{BorshDeserialize, BorshSerialize};

mod ssz;
mod sync;

#[cfg(feature = "host-bls")]
pub mod host_bls;
#[cfg(feature = "json")]
pub mod json;

/// Production SSZ primitives and gindex table, exported for crates/spec-tests (consensus-spec-tests).
#[doc(hidden)]
pub use ssz::{hash_tree_root_execution, is_valid_normalized_branch};
pub use ssz::{hash_tree_root_header, hash_tree_root_sync_committee, signing_root};
#[doc(hidden)]
pub use ssz::{sha256_pair, sha256_syscall};
pub use sync::{
    apply_update, bootstrap, finish_update, prepare_update, verify_update, PairingInputs,
    PreparedUpdate, VerifiedUpdate,
};
#[doc(hidden)]
pub use sync::{
    CURRENT_SC_ELECTRA, CURRENT_SC_GLOAS, EXECUTION_BLOCK_HASH_DENEB, EXECUTION_BLOCK_HASH_GLOAS,
    EXECUTION_PAYLOAD, FINALIZED_ROOT_ELECTRA, FINALIZED_ROOT_GLOAS, NEXT_SC_ELECTRA,
    NEXT_SC_GLOAS,
};

pub type Root = [u8; 32];
pub type BlsPubkey = [u8; 48];
pub type BlsSignature = [u8; 96];

pub const SLOTS_PER_EPOCH: u64 = 32;
pub const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;
pub const SYNC_COMMITTEE_SIZE: usize = 512;
pub const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [7, 0, 0, 0];

/// Stable error codes (docs/CONSUMER-GUIDE.md).
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Malformed = 1001,
    ChainMismatch = 1002,
    ForkUnsupported = 1003,
    HeaderNotFinalised = 1101,
    SyncSigInvalid = 1102,
    ParticipationBelowThreshold = 1103,
    HandoffNotVerified = 1104,
    CheckpointStale = 1105,
    UpdateNotNewer = 1106,
    BootstrapMismatch = 1107,
    ExecutionHeaderMismatch = 1201,
    InclusionInvalid = 1202,
    PredicateFailed = 1203,
    StatementMismatch = 1204,
}

/// Chain binding, fixed at instance init (docs/ARCHITECTURE.md). `electra_fork_epoch` is an lc-core
/// addition (see DECISIONS.md): it selects the Electra/Fulu gindices; earlier forks are rejected (1003).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub genesis_validators_root: Root,
    /// (activation epoch, fork version), ascending by epoch.
    pub fork_versions: Vec<(u64, [u8; 4])>,
    pub electra_fork_epoch: u64,
    pub gloas_fork_epoch: u64,
    /// Minimum sync-committee participants (342 = ceil(2/3 * 512)).
    pub min_participation: u16,
    pub ws_period_epochs: u64,
}

/// Weak-subjectivity period (epochs) per consensus-specs Electra `compute_weak_subjectivity_period`
/// (supersedes phase0's): `MIN_VALIDATOR_WITHDRAWABILITY_DELAY + SAFETY_DECAY * t // (2 * delta * 100)`,
/// `t` = total active balance (gwei), `delta` = `get_balance_churn_limit` (mainnet preset constants).
pub fn compute_ws_period_epochs(total_active_gwei: u64) -> u64 {
    const INCREMENT: u64 = 1_000_000_000;
    let churn = (128 * INCREMENT).max(total_active_gwei / 65_536);
    let delta = churn - churn % INCREMENT;
    256 + (10 * total_active_gwei as u128 / (2 * delta as u128 * 100)) as u64
}

/// Sepolia: 60_733 ETH active (1_874 validators, Lighthouse `validator_inclusion`, epoch 359_557,
/// 2026-11-04) -> 279 epochs (~29.8 h). Recompute when the validator set changes (DECISIONS.md).
pub const SEPOLIA_WS_PERIOD_EPOCHS: u64 = 279;
/// Mainnet: 44_233_271 ETH active (812_949 validators, epoch 486_926, 2026-11-04) -> 3_537 epochs (~15.7 d).
pub const MAINNET_WS_PERIOD_EPOCHS: u64 = 3_537;

impl ChainConfig {
    /// Sepolia; fork schedule from fixtures/sepolia/fork_schedule.json (lodestar, 2026-11-04).
    pub fn sepolia() -> Self {
        Self {
            chain_id: 11_155_111,
            genesis_validators_root: hex_root(
                "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078",
            ),
            fork_versions: vec![
                (0, [0x90, 0, 0, 0x69]),
                (50, [0x90, 0, 0, 0x70]),
                (100, [0x90, 0, 0, 0x71]),
                (56_832, [0x90, 0, 0, 0x72]),
                (132_608, [0x90, 0, 0, 0x73]),
                (222_464, [0x90, 0, 0, 0x74]),
                (272_640, [0x90, 0, 0, 0x75]),
                (353_024, [0x90, 0, 0, 0x76]),
            ],
            electra_fork_epoch: 222_464,
            gloas_fork_epoch: 353_024,
            min_participation: 342,
            ws_period_epochs: SEPOLIA_WS_PERIOD_EPOCHS,
        }
    }

    /// Mainnet (Fulu; Gloas not scheduled as of 2026-11-04).
    pub fn mainnet() -> Self {
        Self {
            chain_id: 1,
            genesis_validators_root: hex_root(
                "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            ),
            fork_versions: vec![
                (0, [0, 0, 0, 0]),
                (74_240, [1, 0, 0, 0]),
                (144_896, [2, 0, 0, 0]),
                (194_048, [3, 0, 0, 0]),
                (269_568, [4, 0, 0, 0]),
                (364_032, [5, 0, 0, 0]),
                (411_392, [6, 0, 0, 0]),
            ],
            electra_fork_epoch: 364_032,
            gloas_fork_epoch: u64::MAX,
            min_participation: 342,
            ws_period_epochs: MAINNET_WS_PERIOD_EPOCHS,
        }
    }

    /// Fork version active at `epoch` (last entry with activation <= epoch).
    pub fn fork_version_at(&self, epoch: u64) -> Option<[u8; 4]> {
        self.fork_versions
            .iter()
            .rev()
            .find(|(e, _)| *e <= epoch)
            .map(|(_, v)| *v)
    }
}

fn hex_root(s: &str) -> Root {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

pub fn epoch_at_slot(slot: u64) -> u64 {
    slot / SLOTS_PER_EPOCH
}

pub fn period_at_slot(slot: u64) -> u64 {
    epoch_at_slot(slot) / EPOCHS_PER_SYNC_COMMITTEE_PERIOD
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: Root,
    pub state_root: Root,
    pub body_root: Root,
}

/// Deneb/Electra/Fulu `ExecutionPayloadHeader` (17 fields; same SSZ shape in all three).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ExecutionPayloadHeader {
    pub parent_hash: Root,
    pub fee_recipient: [u8; 20],
    pub state_root: Root,
    pub receipts_root: Root,
    pub logs_bloom: [u8; 256],
    pub prev_randao: Root,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    /// SSZ ByteList[32]; longer is Malformed.
    pub extra_data: Vec<u8>,
    /// uint256, little-endian (SSZ encoding).
    pub base_fee_per_gas: [u8; 32],
    pub block_hash: Root,
    pub transactions_root: Root,
    pub withdrawals_root: Root,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
}

/// Execution part of a `LightClientHeader`; the variant is the wire shape.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum HeaderExecution {
    /// Electra/Fulu: full payload header, `execution_branch` proves it at body gindex 25 (depth 4).
    Electra(Box<ExecutionPayloadHeader>),
    /// Gloas: `execution_block_hash` = `signed_execution_payload_bid.message.parent_block_hash`
    /// (gindex 2856, depth 11). NOTE: the *parent* EL block of this beacon block's bid.
    Gloas(Root),
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct LightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution: HeaderExecution,
    pub execution_branch: Vec<Root>,
}

impl LightClientHeader {
    pub fn execution_block_hash(&self) -> Root {
        match &self.execution {
            HeaderExecution::Electra(h) => h.block_hash,
            HeaderExecution::Gloas(h) => *h,
        }
    }

    /// Validates the execution branch (1201) and compacts to the stored form.
    pub fn to_finalized(&self, cfg: &ChainConfig) -> Result<FinalizedHeader, ErrorCode> {
        Ok(FinalizedHeader {
            beacon: self.beacon.clone(),
            execution_block_hash: sync::checked_execution_hash(cfg, self)?,
        })
    }
}

/// Compact verified header kept in the [`Store`]: beacon header + its (branch-verified) EL block hash.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct FinalizedHeader {
    pub beacon: BeaconBlockHeader,
    pub execution_block_hash: Root,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCommittee {
    /// Exactly 512 compressed G1 pubkeys (checked on use).
    pub pubkeys: Vec<BlsPubkey>,
    pub aggregate_pubkey: BlsPubkey,
}

/// Borsh layout identical to the derived one (`u32` count, then the keys, then the aggregate), but the
/// 24.6 KB of keys move in one read/write: the derived element-wise path costs ~15 cycles/byte in the
/// zkvm (~0.75 M per stored Store). More than `SYNC_COMMITTEE_SIZE` keys is refused at decode time
/// (1001, as `check_committee_len` would) instead of being allocated.
impl BorshSerialize for SyncCommittee {
    fn serialize<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        (self.pubkeys.len() as u32).serialize(w)?;
        w.write_all(self.pubkeys.as_flattened())?;
        w.write_all(&self.aggregate_pubkey)
    }
}

impl BorshDeserialize for SyncCommittee {
    fn deserialize_reader<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        let n = u32::deserialize_reader(r)? as usize;
        if n > SYNC_COMMITTEE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "sync committee too large",
            ));
        }
        let mut pubkeys = vec![[0u8; 48]; n];
        r.read_exact(pubkeys.as_flattened_mut())?;
        let mut aggregate_pubkey = [0u8; 48];
        r.read_exact(&mut aggregate_pubkey)?;
        Ok(Self {
            pubkeys,
            aggregate_pubkey,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SyncAggregate {
    /// Bitvector[512], SSZ bit order (bit i = byte i/8, bit i%8).
    pub sync_committee_bits: [u8; 64],
    pub sync_committee_signature: BlsSignature,
}

impl SyncAggregate {
    pub fn participant(&self, i: usize) -> bool {
        self.sync_committee_bits[i / 8] >> (i % 8) & 1 == 1
    }

    pub fn participants(&self) -> usize {
        self.sync_committee_bits
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct LightClientBootstrap {
    pub header: LightClientHeader,
    pub current_sync_committee: SyncCommittee,
    pub current_sync_committee_branch: Vec<Root>,
}

/// `LightClientUpdate` / `LightClientFinalityUpdate` in one type. `None` = absent (or zero branch
/// on the wire, which the spec treats as absent).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct LightClientUpdate {
    pub attested_header: LightClientHeader,
    pub next_sync_committee: Option<(SyncCommittee, Vec<Root>)>,
    pub finalized_header: Option<(LightClientHeader, Vec<Root>)>,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: u64,
}

/// On-chain light-client state. Only finalized data (no optimistic header, no best_valid_update /
/// force_update: an on-chain verifier never accepts < min_participation).
/// Borsh size: ~24.7 KB per committee, ~49.4 KB with `next_sync_committee` known.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Store {
    pub finalized_header: FinalizedHeader,
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: Option<SyncCommittee>,
}

impl Store {
    pub fn period(&self) -> u64 {
        period_at_slot(self.finalized_header.beacon.slot)
    }
}

/// BLS sync-aggregate check: `signature` verifies over `signing_root` under
/// `committee_aggregate_pubkey - sum(non_signer_pubkeys)` (eth2 FastAggregateVerify, POP DST).
/// Must reject invalid encodings, an infinity aggregate key, and signatures outside G2's subgroup.
pub trait SigVerifier {
    fn verify_sync_aggregate(
        &self,
        committee_aggregate_pubkey: &BlsPubkey,
        non_signer_pubkeys: &[BlsPubkey],
        signing_root: &Root,
        signature: &BlsSignature,
    ) -> bool;
}

#[cfg(test)]
mod ws_tests {
    use super::*;

    #[test]
    fn sync_committee_borsh_matches_derived_layout() {
        #[derive(BorshSerialize, BorshDeserialize)]
        struct Derived {
            pubkeys: Vec<BlsPubkey>,
            aggregate_pubkey: BlsPubkey,
        }
        for n in [0usize, 1, 3, SYNC_COMMITTEE_SIZE] {
            let pubkeys: Vec<BlsPubkey> = (0..n).map(|i| [i as u8; 48]).collect();
            let c = SyncCommittee {
                pubkeys: pubkeys.clone(),
                aggregate_pubkey: [9; 48],
            };
            let d = Derived {
                pubkeys,
                aggregate_pubkey: [9; 48],
            };
            let bytes = borsh::to_vec(&c).unwrap();
            assert_eq!(bytes, borsh::to_vec(&d).unwrap());
            assert_eq!(borsh::from_slice::<SyncCommittee>(&bytes).unwrap(), c);
        }
        let mut too_many = borsh::to_vec(&(SYNC_COMMITTEE_SIZE as u32 + 1)).unwrap();
        too_many.extend(vec![0u8; 48 * (SYNC_COMMITTEE_SIZE + 2)]);
        assert!(borsh::from_slice::<SyncCommittee>(&too_many).is_err());
        assert!(borsh::from_slice::<SyncCommittee>(&borsh::to_vec(&2u32).unwrap()).is_err());
    }

    #[test]
    fn ws_period_matches_measured_inputs() {
        assert_eq!(
            compute_ws_period_epochs(60_733_000_000_000),
            SEPOLIA_WS_PERIOD_EPOCHS
        );
        assert_eq!(
            compute_ws_period_epochs(44_233_271_000_000_000),
            MAINNET_WS_PERIOD_EPOCHS
        );
        // Large-stake limit: churn scales with t, so the period saturates at 256 + 3276.
        assert_eq!(compute_ws_period_epochs(u64::MAX / 16), 256 + 3276);
    }
}
