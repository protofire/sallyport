use crate::material::AttestMaterial;
use crate::receipt;
use alloy_primitives::{keccak256, Bytes, B256, B64, U256};
use alloy_rlp::{Decodable, Encodable, Header};
use anyhow::{anyhow, bail, Result};
use eth_rpc_module::{ChainConfig, EthRpc};
use serde_json::{json, Value};

/// EL reads via the Logos Ethereum core modules, routed per method by `inclusion::host::el_route`
/// (the one switch point, shared with the Logos module): `Verified` methods go to the JSON-RPC
/// endpoint of a running `verified_proxy_module` (its `httpServer`, light-client verified) when
/// `verified` is set; `Raw` ones (eth_getProof) to `url`. Both through `eth_rpc_module::EthRpc`.
/// Everything is checked here anyway (keccak header binding, MPT proofs in the guest).
pub struct El {
    raw: EthRpc,
    verified: Option<EthRpc>,
    chain_id: u64,
}

fn client(chain_id: u64, url: &str, proxy: Option<&str>) -> Result<EthRpc> {
    let mut cfg = ChainConfig::builtin(url);
    cfg.timeout_secs = 60;
    cfg.proxy = proxy.map(String::from);
    cfg.proxy_required = proxy.is_some();
    let mut rpc = EthRpc::new();
    rpc.set_chain_config(chain_id, cfg)
        .map_err(|e| anyhow!(e))?;
    Ok(rpc)
}

impl El {
    /// `proxy`: optional `socks5h://` URL for `url`; when set it is required (fail-closed).
    /// `verified`: the verified_proxy_module endpoint (`localEndpoint()`, loopback, no SOCKS).
    pub fn new(
        chain_id: u64,
        url: &str,
        proxy: Option<&str>,
        verified: Option<&str>,
    ) -> Result<Self> {
        Ok(Self {
            raw: client(chain_id, url, proxy)?,
            verified: verified.map(|v| client(chain_id, v, None)).transpose()?,
            chain_id,
        })
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let rpc = match (inclusion::host::el_route(method), &self.verified) {
            (inclusion::host::ElRoute::Verified, Some(v)) => v,
            _ => &self.raw,
        };
        rpc.rpc_call(self.chain_id, method, params)
            .map_err(|e| anyhow!("{method}: {e}"))
    }

    pub fn block_by_hash(&self, hash: &str) -> Result<Value> {
        let b = self.call("eth_getBlockByHash", json!([hash, false]))?;
        if b.is_null() {
            bail!("block {hash} not found");
        }
        Ok(b)
    }

    /// (anchor header RLP, header RLPs [target, target+1, …, anchor-1]): the `exec_header_rlp` and
    /// `ancestry` of an `AttestRequest` that links a finalized `target` block to a recorded `anchor`.
    /// Linkage is verified on the host.
    pub fn fetch_ancestry(
        &self,
        target_hash: &str,
        anchor_hash: &str,
        max: usize,
    ) -> Result<(Bytes, Vec<Bytes>)> {
        let num = |b: &Value| {
            q(b, "number")?
                .ok_or_else(|| anyhow!("missing number"))
                .map(|n| n.to::<u64>())
        };
        let (target, anchor) = (
            self.block_by_hash(target_hash)?,
            self.block_by_hash(anchor_hash)?,
        );
        let (t, a) = (num(&target)?, num(&anchor)?);
        if t >= a || (a - t) as usize > max {
            bail!("target #{t} must be 1..={max} blocks before anchor #{a}");
        }
        let mut out = Vec::new();
        for n in t..a {
            let b = self.call("eth_getBlockByNumber", json!([format!("{n:#x}"), false]))?;
            out.push(header_rlp(&b)?);
        }
        // Linkage: keccak(H_i) == parentHash(H_{i+1}), ends at the anchor, starts at the target.
        let mut parents: Vec<B256> = out[1..]
            .iter()
            .map(|r| parent_hash(r))
            .collect::<Result<_>>()?;
        parents.push(h(&anchor, "parentHash")?);
        for (i, (r, p)) in out.iter().zip(&parents).enumerate() {
            if keccak256(r) != *p {
                bail!("ancestry broken at #{} (reorg during fetch?)", t + i as u64);
            }
        }
        if keccak256(&out[0])
            != target_hash
                .parse::<B256>()
                .map_err(|_| anyhow!("bad target hash"))?
        {
            bail!("block #{t} is not {target_hash}");
        }
        let anchor_rlp = header_rlp(&anchor)?;
        if keccak256(&anchor_rlp)
            != anchor_hash
                .parse::<B256>()
                .map_err(|_| anyhow!("bad anchor hash"))?
        {
            bail!("keccak(anchor header rlp) != {anchor_hash}");
        }
        Ok((anchor_rlp, out))
    }

    /// Fetches everything the guest needs for one attestation under `block_hash`.
    pub fn fetch_attest(
        &self,
        block_hash: &str,
        address: &str,
        slot: Option<&str>,
        log: Option<(u32, u32)>,
    ) -> Result<AttestMaterial> {
        let block = self.block_by_hash(block_hash)?;
        let rlp = header_rlp(&block)?;
        let want: B256 = block_hash.parse().map_err(|_| anyhow!("bad block hash"))?;
        if keccak256(&rlp) != want {
            bail!(
                "keccak(header rlp) {} != block hash {want}",
                keccak256(&rlp)
            );
        }
        // Many nodes reject short slot quantities; send the canonical 32-byte key.
        let slots: Vec<String> = slot
            .into_iter()
            .map(|s| {
                U256::from_str_radix(s.trim_start_matches("0x"), 16)
                    .map(|v| format!("{:#x}", B256::from(v)))
                    .map_err(|_| anyhow!("--slot: not a hex storage slot"))
            })
            .collect::<Result<_>>()?;
        // Log attestations need no state proof (and old state is pruned on most nodes).
        let proof = if log.is_some() && slot.is_none() {
            json!({"accountProof": [], "storageProof": []})
        } else {
            self.call(
                "eth_getProof",
                json!([address, slots, {"blockHash": block_hash}]),
            )?
        };
        let nodes = |v: &Value| -> Result<Vec<Bytes>> {
            v.as_array()
                .ok_or_else(|| anyhow!("proof not array"))?
                .iter()
                .map(|n| {
                    n.as_str()
                        .ok_or_else(|| anyhow!("node not str"))?
                        .parse()
                        .map_err(|e| anyhow!("{e}"))
                })
                .collect()
        };
        let account_proof = nodes(&proof["accountProof"])?;
        let storage_proof = match proof["storageProof"].get(0) {
            Some(s) => nodes(&s["proof"])?,
            None => vec![],
        };
        let (receipt_proof_nodes, receipt, log_json) = match log {
            Some((tx, li)) => {
                // By number: verified_proxy_module takes a BlockTag, not a hash. Bound to the
                // header by the receipts-root check in receipt::prove.
                let rcpts = self.call("eth_getBlockReceipts", json!([block["number"]]))?;
                let rcpts = rcpts
                    .as_array()
                    .ok_or_else(|| anyhow!("receipts not array"))?;
                let root: B256 = block["receiptsRoot"]
                    .as_str()
                    .unwrap_or_default()
                    .parse()
                    .map_err(|_| anyhow!("bad receiptsRoot"))?;
                let nodes = receipt::prove(rcpts, tx as usize, root)?;
                let r = &rcpts[tx as usize];
                let l = r["logs"]
                    .get(li as usize)
                    .cloned()
                    .ok_or_else(|| anyhow!("tx {tx} has no log {li}"))?;
                (nodes, receipt::encode_receipt(r)?.into(), l)
            }
            None => (vec![], Bytes::new(), Value::Null),
        };
        Ok(AttestMaterial {
            block_hash: block_hash.into(),
            exec_header_rlp: rlp,
            account_proof,
            storage_proof,
            receipt_proof_nodes,
            receipt,
            log: log_json,
            tx_index: log.map(|l| l.0),
            log_index: log.map(|l| l.1),
            ancestry: vec![],
        })
    }
}

fn q(v: &Value, k: &str) -> Result<Option<U256>> {
    match v.get(k).and_then(Value::as_str) {
        None => Ok(None),
        Some(s) => Ok(Some(
            U256::from_str_radix(s.trim_start_matches("0x"), 16)
                .map_err(|e| anyhow!("{k}: {e}"))?,
        )),
    }
}
fn h<T: std::str::FromStr>(v: &Value, k: &str) -> Result<T> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing {k}"))?
        .parse()
        .map_err(|_| anyhow!("bad {k}"))
}

/// First field of a header RLP.
fn parent_hash(rlp: &[u8]) -> Result<B256> {
    let mut buf = rlp;
    Header::decode(&mut buf).map_err(|e| anyhow!("header rlp: {e}"))?;
    B256::decode(&mut buf).map_err(|e| anyhow!("parentHash: {e}"))
}

/// Canonical header RLP built by hand from the RPC JSON: alloy's `Header` lacks the Amsterdam/Gloas
/// trailing fields (blockAccessListHash, slotNumber). Correctness is checked by keccak == block hash.
pub fn header_rlp(b: &Value) -> Result<Bytes> {
    let mut p = Vec::new();
    h::<B256>(b, "parentHash")?.encode(&mut p);
    h::<B256>(b, "sha3Uncles")?.encode(&mut p);
    h::<alloy_primitives::Address>(b, "miner")?.encode(&mut p);
    for k in ["stateRoot", "transactionsRoot", "receiptsRoot"] {
        h::<B256>(b, k)?.encode(&mut p);
    }
    h::<alloy_primitives::Bloom>(b, "logsBloom")?.encode(&mut p);
    for k in ["difficulty", "number", "gasLimit", "gasUsed", "timestamp"] {
        q(b, k)?
            .ok_or_else(|| anyhow!("missing {k}"))?
            .encode(&mut p);
    }
    h::<Bytes>(b, "extraData")?.encode(&mut p);
    h::<B256>(b, "mixHash")?.encode(&mut p);
    h::<B64>(b, "nonce")?.encode(&mut p);
    // Optional trailing fields in fork order; the first absent one ends the header.
    for (k, is_hash) in [
        ("baseFeePerGas", false),
        ("withdrawalsRoot", true),
        ("blobGasUsed", false),
        ("excessBlobGas", false),
        ("parentBeaconBlockRoot", true),
        ("requestsHash", true),
        ("blockAccessListHash", true),
        ("slotNumber", false),
    ] {
        if b.get(k).is_none() {
            break;
        }
        if is_hash {
            h::<B256>(b, k)?.encode(&mut p)
        } else {
            q(b, k)?.unwrap().encode(&mut p)
        }
    }
    let mut out = Vec::new();
    Header {
        list: true,
        payload_length: p.len(),
    }
    .encode(&mut out);
    out.extend(p);
    Ok(out.into())
}
