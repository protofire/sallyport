//! Altair sync protocol (validate/apply_light_client_update) with Electra and Gloas gindices.
//! Structure follows a16z/helios `consensus-core` (rev 2af9b41) and the consensus-specs.

use crate::ssz::{
    hash_tree_root_execution, hash_tree_root_header, hash_tree_root_sync_committee,
    is_valid_normalized_branch, signing_root,
};
use crate::{
    epoch_at_slot, period_at_slot, BlsPubkey, BlsSignature, ChainConfig, ErrorCode,
    FinalizedHeader, HeaderExecution, LightClientBootstrap, LightClientHeader, LightClientUpdate,
    Root, SigVerifier, Store, SyncCommittee, SYNC_COMMITTEE_SIZE,
};
use borsh::{BorshDeserialize, BorshSerialize};
use ErrorCode::*;

// (gindex, branch length on the wire) per fork; consensus-specs electra/gloas light-client/sync-protocol.md.
pub const FINALIZED_ROOT_ELECTRA: (u64, usize) = (169, 7);
pub const FINALIZED_ROOT_GLOAS: (u64, usize) = (735, 9);
pub const CURRENT_SC_ELECTRA: (u64, usize) = (86, 6);
pub const CURRENT_SC_GLOAS: (u64, usize) = (2945, 11);
pub const NEXT_SC_ELECTRA: (u64, usize) = (87, 6);
pub const NEXT_SC_GLOAS: (u64, usize) = (2946, 11);
/// capella.BeaconBlockBody.execution_payload
pub const EXECUTION_PAYLOAD: (u64, usize) = (25, 4);
/// deneb.BeaconBlockBody.execution_payload.block_hash, in an upgraded (Gloas-shape) header.
pub const EXECUTION_BLOCK_HASH_DENEB: (u64, usize) = (812, 11);
/// BeaconBlockBody.signed_execution_payload_bid.message.parent_block_hash
pub const EXECUTION_BLOCK_HASH_GLOAS: (u64, usize) = (2856, 11);

fn by_fork(
    cfg: &ChainConfig,
    slot: u64,
    electra: (u64, usize),
    gloas: (u64, usize),
) -> Result<(u64, usize), ErrorCode> {
    let epoch = epoch_at_slot(slot);
    if epoch >= cfg.gloas_fork_epoch {
        Ok(gloas)
    } else if epoch >= cfg.electra_fork_epoch {
        Ok(electra)
    } else {
        Err(ForkUnsupported)
    }
}

/// Checks `branch` has the fork's wire length (else 1001) and proves `leaf` at `gindex` under `root`.
fn check_branch(
    leaf: &Root,
    branch: &[Root],
    (gindex, len): (u64, usize),
    root: &Root,
    err: ErrorCode,
) -> Result<(), ErrorCode> {
    if branch.len() != len {
        return Err(Malformed);
    }
    if is_valid_normalized_branch(leaf, branch, gindex, root) {
        Ok(())
    } else {
        Err(err)
    }
}

/// `is_valid_light_client_header` for the header's own epoch; returns its EL block hash.
pub(crate) fn checked_execution_hash(
    cfg: &ChainConfig,
    h: &LightClientHeader,
) -> Result<Root, ErrorCode> {
    let epoch = epoch_at_slot(h.beacon.slot);
    let body = &h.beacon.body_root;
    match &h.execution {
        HeaderExecution::Gloas(hash) => {
            let g = by_fork(
                cfg,
                h.beacon.slot,
                EXECUTION_BLOCK_HASH_DENEB,
                EXECUTION_BLOCK_HASH_GLOAS,
            )?;
            check_branch(hash, &h.execution_branch, g, body, ExecutionHeaderMismatch)?;
            Ok(*hash)
        }
        HeaderExecution::Electra(p) => {
            if epoch >= cfg.gloas_fork_epoch {
                return Err(Malformed); // Gloas-era headers have no payload header
            }
            if epoch < cfg.electra_fork_epoch {
                return Err(ForkUnsupported);
            }
            if p.extra_data.len() > 32 {
                return Err(Malformed);
            }
            check_branch(
                &hash_tree_root_execution(p),
                &h.execution_branch,
                EXECUTION_PAYLOAD,
                body,
                ExecutionHeaderMismatch,
            )?;
            Ok(p.block_hash)
        }
    }
}

/// Committee admission: 512 keys, none (nor the aggregate) the G1 infinity encoding. Byte compare
/// only; stands in for KeyValidate, which the in-guest residue kernel cannot do per key.
fn check_committee_len(c: &SyncCommittee) -> Result<(), ErrorCode> {
    const INFINITY: [u8; 48] = {
        let mut b = [0u8; 48];
        b[0] = 0xc0;
        b
    };
    if c.pubkeys.len() == SYNC_COMMITTEE_SIZE
        && c.aggregate_pubkey != INFINITY
        && !c.pubkeys.contains(&INFINITY)
    {
        Ok(())
    } else {
        Err(Malformed)
    }
}

/// Weak-subjectivity rule shared by `bootstrap` and `prepare_update` (1105).
fn check_not_stale(cfg: &ChainConfig, slot: u64, current_slot_hint: u64) -> Result<(), ErrorCode> {
    if current_slot_hint.saturating_sub(slot)
        > cfg.ws_period_epochs.saturating_mul(crate::SLOTS_PER_EPOCH)
    {
        return Err(CheckpointStale);
    }
    Ok(())
}

/// `initialize_light_client_store`: header must hash to `trusted_block_root` and be within the
/// weak-subjectivity period of `current_slot_hint` (else 1105).
pub fn bootstrap(
    cfg: &ChainConfig,
    trusted_block_root: &Root,
    b: &LightClientBootstrap,
    current_slot_hint: u64,
) -> Result<Store, ErrorCode> {
    let beacon = &b.header.beacon;
    check_not_stale(cfg, beacon.slot, current_slot_hint)?;
    if &hash_tree_root_header(beacon) != trusted_block_root {
        return Err(BootstrapMismatch);
    }
    check_committee_len(&b.current_sync_committee)?;
    let execution_block_hash = checked_execution_hash(cfg, &b.header)?;
    check_branch(
        &hash_tree_root_sync_committee(&b.current_sync_committee),
        &b.current_sync_committee_branch,
        by_fork(cfg, beacon.slot, CURRENT_SC_ELECTRA, CURRENT_SC_GLOAS)?,
        &beacon.state_root,
        BootstrapMismatch,
    )?;
    Ok(Store {
        finalized_header: FinalizedHeader {
            beacon: beacon.clone(),
            execution_block_hash,
        },
        current_sync_committee: b.current_sync_committee.clone(),
        next_sync_committee: None,
    })
}

/// Exact inputs of the BLS check (see [`SigVerifier`]).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PairingInputs {
    pub aggregate_pubkey: BlsPubkey,
    pub non_signer_pubkeys: Vec<BlsPubkey>,
    pub signing_root: Root,
    pub signature: BlsSignature,
}

/// Store transition of an update that passed every check. Bound to the store it was verified
/// against (finalized root + whether next committee was known); [`apply_update`] re-checks that.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VerifiedUpdate {
    pub base_finalized_root: Root,
    pub base_next_known: bool,
    /// current <- next, next <- `next_sync_committee`.
    pub rotate: bool,
    /// New `store.next_sync_committee` when `rotate` or when next was unknown; else None (unused).
    pub next_sync_committee: Option<SyncCommittee>,
    /// New finalized header when the update advances finality.
    pub finalized_header: Option<FinalizedHeader>,
}

/// Everything verified except the pairing.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PreparedUpdate {
    pub pairing: PairingInputs,
    pub verified: VerifiedUpdate,
}

/// `validate_light_client_update` minus the pairing, plus on-chain rules: finality required,
/// participation >= cfg.min_participation, update must advance finality or supply the unknown next
/// committee (else 1106), weak-subjectivity staleness against `current_slot_hint` (1105).
pub fn prepare_update(
    cfg: &ChainConfig,
    store: &Store,
    u: &LightClientUpdate,
    current_slot_hint: u64,
) -> Result<PreparedUpdate, ErrorCode> {
    let store_slot = store.finalized_header.beacon.slot;
    check_not_stale(cfg, store_slot, current_slot_hint)?;
    let att = &u.attested_header.beacon;
    let (fin, fin_branch) = u.finalized_header.as_ref().ok_or(HeaderNotFinalised)?;
    if !(current_slot_hint >= u.signature_slot
        && u.signature_slot > att.slot
        && att.slot >= fin.beacon.slot)
    {
        return Err(Malformed);
    }
    if u.sync_aggregate.participants() < cfg.min_participation as usize {
        return Err(ParticipationBelowThreshold);
    }

    let store_period = store.period();
    let sig_period = period_at_slot(u.signature_slot);
    let att_period = period_at_slot(att.slot);
    let fin_period = period_at_slot(fin.beacon.slot);
    let next_known = store.next_sync_committee.is_some();
    if sig_period < store_period {
        return Err(UpdateNotNewer);
    }
    if sig_period > store_period + next_known as u64 {
        return Err(HandoffNotVerified);
    }
    let advances = fin.beacon.slot > store_slot;
    let learns_next = !next_known
        && u.next_sync_committee.is_some()
        && fin_period == att_period
        && att_period == store_period;
    if !(advances || learns_next) {
        return Err(UpdateNotNewer);
    }

    checked_execution_hash(cfg, &u.attested_header)?;
    let fin_hash = checked_execution_hash(cfg, fin)?;
    check_branch(
        &hash_tree_root_header(&fin.beacon),
        fin_branch,
        by_fork(cfg, att.slot, FINALIZED_ROOT_ELECTRA, FINALIZED_ROOT_GLOAS)?,
        &att.state_root,
        HeaderNotFinalised,
    )?;

    if let Some((c, branch)) = &u.next_sync_committee {
        check_committee_len(c)?;
        check_branch(
            &hash_tree_root_sync_committee(c),
            branch,
            by_fork(cfg, att.slot, NEXT_SC_ELECTRA, NEXT_SC_GLOAS)?,
            &att.state_root,
            HandoffNotVerified,
        )?;
        if att_period == store_period && store.next_sync_committee.as_ref().is_some_and(|k| k != c)
        {
            return Err(HandoffNotVerified);
        }
    }

    let committee = match (sig_period == store_period, &store.next_sync_committee) {
        (true, _) => &store.current_sync_committee,
        (false, Some(next)) => next,
        (false, None) => return Err(HandoffNotVerified), // unreachable: period check above
    };
    let non_signer_pubkeys = (0..SYNC_COMMITTEE_SIZE)
        .filter(|&i| !u.sync_aggregate.participant(i))
        .map(|i| committee.pubkeys[i])
        .collect();
    let fork_version = cfg
        .fork_version_at(epoch_at_slot(u.signature_slot.max(1) - 1))
        .ok_or(ForkUnsupported)?;

    // apply_light_client_update
    let rotate = next_known && fin_period == store_period + 1;
    let next_update = u.next_sync_committee.as_ref().map(|(c, _)| c.clone());
    Ok(PreparedUpdate {
        pairing: PairingInputs {
            aggregate_pubkey: committee.aggregate_pubkey,
            non_signer_pubkeys,
            signing_root: signing_root(
                &hash_tree_root_header(att),
                fork_version,
                &cfg.genesis_validators_root,
            ),
            signature: u.sync_aggregate.sync_committee_signature,
        },
        verified: VerifiedUpdate {
            base_finalized_root: hash_tree_root_header(&store.finalized_header.beacon),
            base_next_known: next_known,
            rotate,
            next_sync_committee: if rotate || !next_known {
                next_update
            } else {
                None
            },
            finalized_header: advances.then(|| FinalizedHeader {
                beacon: fin.beacon.clone(),
                execution_block_hash: fin_hash,
            }),
        },
    })
}

/// Consumes the pairing result for a [`PreparedUpdate`].
pub fn finish_update(
    p: PreparedUpdate,
    signature_valid: bool,
) -> Result<VerifiedUpdate, ErrorCode> {
    if signature_valid {
        Ok(p.verified)
    } else {
        Err(SyncSigInvalid)
    }
}

/// [`prepare_update`] + pairing via `sig` + [`finish_update`].
pub fn verify_update(
    cfg: &ChainConfig,
    store: &Store,
    u: &LightClientUpdate,
    current_slot_hint: u64,
    sig: &dyn SigVerifier,
) -> Result<VerifiedUpdate, ErrorCode> {
    let p = prepare_update(cfg, store, u, current_slot_hint)?;
    let ok = sig.verify_sync_aggregate(
        &p.pairing.aggregate_pubkey,
        &p.pairing.non_signer_pubkeys,
        &p.pairing.signing_root,
        &p.pairing.signature,
    );
    finish_update(p, ok)
}

/// Applies a [`VerifiedUpdate`]; 1106 if the store moved since it was verified.
pub fn apply_update(store: &mut Store, v: &VerifiedUpdate) -> Result<(), ErrorCode> {
    if hash_tree_root_header(&store.finalized_header.beacon) != v.base_finalized_root
        || store.next_sync_committee.is_some() != v.base_next_known
    {
        return Err(UpdateNotNewer);
    }
    if v.rotate {
        store.current_sync_committee =
            store.next_sync_committee.take().ok_or(HandoffNotVerified)?;
        store.next_sync_committee = v.next_sync_committee.clone();
    } else if !v.base_next_known {
        store.next_sync_committee = v.next_sync_committee.clone();
    }
    if let Some(f) = &v.finalized_header {
        store.finalized_header = f.clone();
    }
    Ok(())
}
