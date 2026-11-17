//! Beacon-API JSON (`/eth/v1/beacon/light_client/*`, with or without the `{version, data}` wrapper)
//! -> lc-core types. Any shape/encoding problem is `Malformed`.

use crate::{
    BeaconBlockHeader, ErrorCode, ExecutionPayloadHeader, HeaderExecution, LightClientBootstrap,
    LightClientHeader, LightClientUpdate, Root, SyncAggregate, SyncCommittee,
};
use serde_json::Value;

type R<T> = Result<T, ErrorCode>;

fn parse(s: &str) -> R<Value> {
    serde_json::from_str(s).map_err(|_| ErrorCode::Malformed)
}

fn data(v: &Value) -> &Value {
    v.get("data").unwrap_or(v)
}

fn field<'a>(v: &'a Value, k: &str) -> R<&'a Value> {
    v.get(k).ok_or(ErrorCode::Malformed)
}

fn bytes(v: &Value) -> R<Vec<u8>> {
    let s = v.as_str().ok_or(ErrorCode::Malformed)?;
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|_| ErrorCode::Malformed)
}

fn fixed<const N: usize>(v: &Value) -> R<[u8; N]> {
    bytes(v)?.try_into().map_err(|_| ErrorCode::Malformed)
}

fn num(v: &Value) -> R<u64> {
    v.as_str()
        .ok_or(ErrorCode::Malformed)?
        .parse()
        .map_err(|_| ErrorCode::Malformed)
}

/// Decimal string -> uint256 little-endian.
fn u256_le(v: &Value) -> R<[u8; 32]> {
    let s = v.as_str().ok_or(ErrorCode::Malformed)?;
    if s.is_empty() {
        return Err(ErrorCode::Malformed);
    }
    let mut out = [0u8; 32];
    for d in s.bytes() {
        let mut carry = (d as char).to_digit(10).ok_or(ErrorCode::Malformed)?;
        for b in out.iter_mut() {
            let x = *b as u32 * 10 + carry;
            *b = x as u8;
            carry = x >> 8;
        }
        if carry != 0 {
            return Err(ErrorCode::Malformed);
        }
    }
    Ok(out)
}

fn roots(v: &Value) -> R<Vec<Root>> {
    v.as_array()
        .ok_or(ErrorCode::Malformed)?
        .iter()
        .map(fixed::<32>)
        .collect()
}

fn beacon(v: &Value) -> R<BeaconBlockHeader> {
    Ok(BeaconBlockHeader {
        slot: num(field(v, "slot")?)?,
        proposer_index: num(field(v, "proposer_index")?)?,
        parent_root: fixed(field(v, "parent_root")?)?,
        state_root: fixed(field(v, "state_root")?)?,
        body_root: fixed(field(v, "body_root")?)?,
    })
}

fn payload(v: &Value) -> R<ExecutionPayloadHeader> {
    Ok(ExecutionPayloadHeader {
        parent_hash: fixed(field(v, "parent_hash")?)?,
        fee_recipient: fixed(field(v, "fee_recipient")?)?,
        state_root: fixed(field(v, "state_root")?)?,
        receipts_root: fixed(field(v, "receipts_root")?)?,
        logs_bloom: fixed(field(v, "logs_bloom")?)?,
        prev_randao: fixed(field(v, "prev_randao")?)?,
        block_number: num(field(v, "block_number")?)?,
        gas_limit: num(field(v, "gas_limit")?)?,
        gas_used: num(field(v, "gas_used")?)?,
        timestamp: num(field(v, "timestamp")?)?,
        extra_data: bytes(field(v, "extra_data")?)?,
        base_fee_per_gas: u256_le(field(v, "base_fee_per_gas")?)?,
        block_hash: fixed(field(v, "block_hash")?)?,
        transactions_root: fixed(field(v, "transactions_root")?)?,
        withdrawals_root: fixed(field(v, "withdrawals_root")?)?,
        blob_gas_used: num(field(v, "blob_gas_used")?)?,
        excess_blob_gas: num(field(v, "excess_blob_gas")?)?,
    })
}

fn header(v: &Value) -> R<LightClientHeader> {
    let execution = match (v.get("execution_block_hash"), v.get("execution")) {
        (Some(h), None) => HeaderExecution::Gloas(fixed(h)?),
        (None, Some(p)) => HeaderExecution::Electra(Box::new(payload(p)?)),
        _ => return Err(ErrorCode::Malformed),
    };
    Ok(LightClientHeader {
        beacon: beacon(field(v, "beacon")?)?,
        execution,
        execution_branch: roots(field(v, "execution_branch")?)?,
    })
}

fn committee(v: &Value) -> R<SyncCommittee> {
    Ok(SyncCommittee {
        pubkeys: field(v, "pubkeys")?
            .as_array()
            .ok_or(ErrorCode::Malformed)?
            .iter()
            .map(fixed::<48>)
            .collect::<R<_>>()?,
        aggregate_pubkey: fixed(field(v, "aggregate_pubkey")?)?,
    })
}

/// Spec: an all-zero branch means "field absent" (is_sync_committee_update / is_finality_update).
fn present(branch: &[Root]) -> bool {
    branch.iter().any(|n| n != &[0u8; 32])
}

pub fn bootstrap_from_value(v: &Value) -> R<LightClientBootstrap> {
    let d = data(v);
    Ok(LightClientBootstrap {
        header: header(field(d, "header")?)?,
        current_sync_committee: committee(field(d, "current_sync_committee")?)?,
        current_sync_committee_branch: roots(field(d, "current_sync_committee_branch")?)?,
    })
}

/// Accepts LightClientUpdate and LightClientFinalityUpdate (and Optimistic: no finality -> None).
pub fn update_from_value(v: &Value) -> R<LightClientUpdate> {
    let d = data(v);
    let next_sync_committee = match d.get("next_sync_committee") {
        Some(c) => {
            let branch = roots(field(d, "next_sync_committee_branch")?)?;
            present(&branch)
                .then(|| committee(c).map(|c| (c, branch)))
                .transpose()?
        }
        None => None,
    };
    let finalized_header = match d.get("finalized_header") {
        Some(h) => {
            let branch = roots(field(d, "finality_branch")?)?;
            present(&branch)
                .then(|| header(h).map(|h| (h, branch)))
                .transpose()?
        }
        None => None,
    };
    let agg = field(d, "sync_aggregate")?;
    Ok(LightClientUpdate {
        attested_header: header(field(d, "attested_header")?)?,
        next_sync_committee,
        finalized_header,
        sync_aggregate: SyncAggregate {
            sync_committee_bits: fixed(field(agg, "sync_committee_bits")?)?,
            sync_committee_signature: fixed(field(agg, "sync_committee_signature")?)?,
        },
        signature_slot: num(field(d, "signature_slot")?)?,
    })
}

pub fn bootstrap_from_json(s: &str) -> R<LightClientBootstrap> {
    bootstrap_from_value(&parse(s)?)
}

pub fn update_from_json(s: &str) -> R<LightClientUpdate> {
    update_from_value(&parse(s)?)
}

/// `/eth/v1/beacon/light_client/updates` response (JSON array).
pub fn updates_from_json(s: &str) -> R<Vec<LightClientUpdate>> {
    parse(s)?
        .as_array()
        .ok_or(ErrorCode::Malformed)?
        .iter()
        .map(update_from_value)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u256_decimal() {
        assert_eq!(
            u256_le(&Value::from("66500436")).unwrap()[..4],
            66500436u32.to_le_bytes()
        );
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert_eq!(u256_le(&Value::from(max)).unwrap(), [0xff; 32]);
        let over = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        assert!(u256_le(&Value::from(over)).is_err());
        assert!(u256_le(&Value::from("12a")).is_err());
    }
}
