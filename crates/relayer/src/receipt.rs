use alloy_primitives::{Address, Bloom, Bytes, B256};
use alloy_rlp::{Encodable, RlpEncodable};
use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles};
use anyhow::{anyhow, bail, Result};
use serde_json::Value;

#[derive(RlpEncodable)]
struct LogR {
    address: Address,
    topics: Vec<B256>,
    data: Bytes,
}
#[derive(RlpEncodable)]
struct ReceiptR {
    status: bool,
    cumulative_gas_used: u64,
    bloom: Bloom,
    logs: Vec<LogR>,
}

fn hex_u64(v: &Value, k: &str) -> Result<u64> {
    u64::from_str_radix(
        v[k].as_str()
            .ok_or_else(|| anyhow!("missing {k}"))?
            .trim_start_matches("0x"),
        16,
    )
    .map_err(|e| anyhow!("{k}: {e}"))
}

/// EIP-2718 consensus encoding of one receipt from its RPC JSON.
pub fn encode_receipt(r: &Value) -> Result<Vec<u8>> {
    let parse = |v: &Value, k: &str| -> Result<String> {
        Ok(v[k]
            .as_str()
            .ok_or_else(|| anyhow!("missing {k}"))?
            .to_string())
    };
    let logs = r["logs"]
        .as_array()
        .ok_or_else(|| anyhow!("logs"))?
        .iter()
        .map(|l| {
            Ok(LogR {
                address: parse(l, "address")?.parse().map_err(|_| anyhow!("addr"))?,
                topics: l["topics"]
                    .as_array()
                    .ok_or_else(|| anyhow!("topics"))?
                    .iter()
                    .map(|t| {
                        t.as_str()
                            .unwrap_or_default()
                            .parse()
                            .map_err(|_| anyhow!("topic"))
                    })
                    .collect::<Result<_>>()?,
                data: parse(l, "data")?.parse().map_err(|_| anyhow!("data"))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let rc = ReceiptR {
        status: hex_u64(r, "status")? == 1,
        cumulative_gas_used: hex_u64(r, "cumulativeGasUsed")?,
        bloom: parse(r, "logsBloom")?
            .parse()
            .map_err(|_| anyhow!("bloom"))?,
        logs,
    };
    let mut out = Vec::new();
    let ty = hex_u64(r, "type")?;
    if ty != 0 {
        out.push(ty as u8);
    }
    rc.encode(&mut out);
    Ok(out)
}

/// Proof nodes (root-to-leaf) for receipt `tx_index`; fails unless the rebuilt trie root == `expected_root`.
pub fn prove(receipts: &[Value], tx_index: usize, expected_root: B256) -> Result<Vec<Bytes>> {
    if tx_index >= receipts.len() {
        bail!(
            "tx_index {tx_index} out of range ({} receipts)",
            receipts.len()
        );
    }
    let mut leaves: Vec<(Nibbles, Vec<u8>)> = receipts
        .iter()
        .enumerate()
        .map(|(i, r)| Ok((Nibbles::unpack(alloy_rlp::encode(i)), encode_receipt(r)?)))
        .collect::<Result<_>>()?;
    leaves.sort_by(|a, b| a.0.cmp(&b.0));
    let target = Nibbles::unpack(alloy_rlp::encode(tx_index));
    let mut hb =
        HashBuilder::default().with_proof_retainer(ProofRetainer::new(vec![target.clone()]));
    for (k, v) in &leaves {
        hb.add_leaf(k.clone(), v);
    }
    let root = hb.root();
    if root != expected_root {
        bail!("receipt trie root {root} != header receiptsRoot {expected_root}");
    }
    Ok(hb
        .take_proof_nodes()
        .matching_nodes_sorted(&target)
        .into_iter()
        .map(|(_, n)| n)
        .collect())
}
