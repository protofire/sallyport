use alloy_primitives::Bytes;
use serde::{Deserialize, Serialize};

/// Raw LC material; typed parsing happens in lc-core at integration.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UpdateMaterial {
    /// Block root the bootstrap was fetched for (hex), when one was requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<serde_json::Value>,
    pub updates: Vec<serde_json::Value>,
    pub finality_update: serde_json::Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AttestMaterial {
    pub block_hash: String,
    /// Header of `block_hash`, or of the recorded anchor when `ancestry` is non-empty.
    pub exec_header_rlp: Bytes,
    pub account_proof: Vec<Bytes>,
    /// Proof nodes for the single requested slot (empty when no slot requested).
    pub storage_proof: Vec<Bytes>,
    pub receipt_proof_nodes: Vec<Bytes>,
    /// EIP-2718 receipt of `tx_index` (the value the receipt proof ends in).
    #[serde(default)]
    pub receipt: Bytes,
    /// RPC JSON of the requested log (address/topics/data), for building the claim.
    #[serde(default)]
    pub log: serde_json::Value,
    pub tx_index: Option<u32>,
    pub log_index: Option<u32>,
    /// Header RLPs [block, …, anchor-1] when attesting via a later recorded anchor (`--anchor`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestry: Vec<Bytes>,
}
