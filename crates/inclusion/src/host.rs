//! Host-only: turn JSON-RPC responses into the byte inputs the verifier takes.
use alloc::{string::ToString, vec::Vec};
use alloy_primitives::B256;
use alloy_rlp::Header;
use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles};
use serde_json::Value;

/// How one EL JSON-RPC read is transported (DECISIONS D-MOD-3). `Verified` = through the Logos
/// `verified_proxy_module` (light-client-verified answer); `Raw` = `eth_rpc_module` (forwarded, trusted
/// for nothing: the verifier checks every byte either way).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElRoute {
    Verified,
    Raw,
}

/// The one switch point for EL routing, shared by the Logos module and the relayer.
pub fn el_route(method: &str) -> ElRoute {
    match method {
        "eth_getBlockByHash" | "eth_getBlockByNumber" | "eth_getBlockReceipts" => ElRoute::Verified,
        // eth_getProof: verified_proxy_module has no wrapper for it (nimbus uses it internally only).
        // Add it to the arm above when the module exposes it.
        _ => ElRoute::Raw,
    }
}

/// "0x…" → bytes (odd length allowed for quantities). Panics on non-hex: host fixtures/RPC are trusted input here.
pub fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string").trim_start_matches("0x");
    let s = if s.len() % 2 == 1 {
        "0".to_string() + s
    } else {
        s.to_string()
    };
    alloy_primitives::hex::decode(s).expect("valid hex")
}

fn quantity(v: &Value) -> Vec<u8> {
    let b = hex(v);
    let z = b.iter().take_while(|x| **x == 0).count();
    b[z..].to_vec()
}

fn list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.concat();
    let mut out = Vec::new();
    Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut out);
    out.extend(payload);
    out
}

fn bytes(b: &[u8]) -> Vec<u8> {
    alloy_rlp::encode(b)
}

/// Header RLP from `eth_getBlockByNumber/Hash` result. Field order up to Amsterdam/Gloas
/// (blockAccessListHash, slotNumber); missing optional fields are simply omitted (they're trailing).
pub fn header_rlp_from_rpc(b: &Value) -> Vec<u8> {
    const Q: &[&str] = &[
        "difficulty",
        "number",
        "gasLimit",
        "gasUsed",
        "timestamp",
        "baseFeePerGas",
        "blobGasUsed",
        "excessBlobGas",
        "slotNumber",
    ];
    const ORDER: &[&str] = &[
        "parentHash",
        "sha3Uncles",
        "miner",
        "stateRoot",
        "transactionsRoot",
        "receiptsRoot",
        "logsBloom",
        "difficulty",
        "number",
        "gasLimit",
        "gasUsed",
        "timestamp",
        "extraData",
        "mixHash",
        "nonce",
        "baseFeePerGas",
        "withdrawalsRoot",
        "blobGasUsed",
        "excessBlobGas",
        "parentBeaconBlockRoot",
        "requestsHash",
        "blockAccessListHash",
        "slotNumber",
    ];
    let items: Vec<Vec<u8>> = ORDER
        .iter()
        .take_while(|k| !b[**k].is_null())
        .map(|k| {
            if Q.contains(k) {
                bytes(&quantity(&b[*k]))
            } else {
                bytes(&hex(&b[*k]))
            }
        })
        .collect();
    list(&items)
}

/// Consensus receipt encoding (trie leaf value) from an `eth_getBlockReceipts` entry.
pub fn receipt_bytes_from_rpc(r: &Value) -> Vec<u8> {
    let logs: Vec<Vec<u8>> = r["logs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            let topics: Vec<Vec<u8>> = l["topics"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| bytes(&hex(t)))
                .collect();
            list(&[
                bytes(&hex(&l["address"])),
                list(&topics),
                bytes(&hex(&l["data"])),
            ])
        })
        .collect();
    let body = list(&[
        bytes(&quantity(&r["status"])),
        bytes(&quantity(&r["cumulativeGasUsed"])),
        bytes(&hex(&r["logsBloom"])),
        list(&logs),
    ]);
    let ty = quantity(&r["type"]);
    [ty, body].concat()
}

/// Build the receipts trie (key = rlp(index)) and return (root, proof for `tx_index`).
/// There is no eth_getReceiptProof RPC, so the relayer rebuilds the trie from eth_getBlockReceipts.
pub fn receipt_proof(receipts: &[Vec<u8>], tx_index: u32) -> ([u8; 32], Vec<Vec<u8>>) {
    let target = Nibbles::unpack(alloy_rlp::encode(tx_index));
    let mut leaves: Vec<(Nibbles, &Vec<u8>)> = receipts
        .iter()
        .enumerate()
        .map(|(i, r)| (Nibbles::unpack(alloy_rlp::encode(i as u32)), r))
        .collect();
    leaves.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([target]));
    for (k, v) in &leaves {
        hb.add_leaf(*k, v);
    }
    let root: B256 = hb.root();
    let proof = hb
        .take_proof_nodes()
        .matching_nodes_sorted(&target)
        .into_iter()
        .map(|(_, n)| n.to_vec())
        .collect();
    (root.0, proof)
}

/// `eth_getProof` proof array → node bytes.
pub fn proof_from_rpc(v: &Value) -> Vec<Vec<u8>> {
    v.as_array().unwrap().iter().map(hex).collect()
}

/// Block-wide RPC `logIndex` → (tx_index, index within that receipt's logs).
pub fn locate_log(receipts: &Value, block_log_index: u64) -> Option<(u32, u32)> {
    for r in receipts.as_array()? {
        for (i, l) in r["logs"].as_array()?.iter().enumerate() {
            if u64::from_str_radix(l["logIndex"].as_str()?.trim_start_matches("0x"), 16).ok()?
                == block_log_index
            {
                let tx = u32::from_str_radix(
                    r["transactionIndex"].as_str()?.trim_start_matches("0x"),
                    16,
                )
                .ok()?;
                return Some((tx, i as u32));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{el_route, ElRoute::*};

    /// Pins the EL routing table. Moving eth_getProof to Verified is a one-line change in `el_route`
    /// plus this line.
    #[test]
    fn el_routing_table() {
        for (m, r) in [
            ("eth_getBlockByHash", Verified),
            ("eth_getBlockByNumber", Verified),
            ("eth_getBlockReceipts", Verified),
            ("eth_getProof", Raw),
        ] {
            assert_eq!(el_route(m), r, "{m}");
        }
    }
}
