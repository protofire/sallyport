//! Ethereum side: JSON-RPC, locally signed EIP-1559 transactions (keys never leave the process; no
//! `cast --private-key` on argv), and the `BridgeVault` ABI (static words + one trailing `bytes`).

use std::time::Duration;

use alloy_primitives::{keccak256, U256};
use alloy_rlp::{Encodable, Header};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

pub struct Eth {
    url: String,
    http: reqwest::Client,
    pub chain_id: u64,
    /// Receipt poll interval.
    pub poll: Duration,
}

/// An included transaction.
#[derive(Debug, Clone)]
pub struct TxOut {
    pub hash: String,
    pub block: u64,
    pub ok: bool,
    pub gas_used: u64,
    pub logs: Vec<Value>,
    pub block_hash: String,
    pub tx_index: u32,
}

pub fn h(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

pub fn unhex(v: &Value) -> Result<Vec<u8>> {
    let s = v.as_str().ok_or_else(|| anyhow!("not a hex string: {v}"))?;
    Ok(hex::decode(s.trim_start_matches("0x"))?)
}

pub fn qty(v: &Value) -> Result<u64> {
    let s = v.as_str().ok_or_else(|| anyhow!("not a quantity: {v}"))?;
    Ok(u64::from_str_radix(s.trim_start_matches("0x"), 16)?)
}

pub fn b32(v: &[u8]) -> Result<[u8; 32]> {
    v.try_into()
        .map_err(|_| anyhow!("expected 32 bytes, got {}", v.len()))
}

impl Eth {
    pub async fn new(url: &str) -> Result<Self> {
        let mut e = Self {
            url: url.into(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()?,
            chain_id: 0,
            poll: Duration::from_secs(2),
        };
        e.chain_id = qty(&e.call("eth_chainId", json!([])).await?)?;
        Ok(e)
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let mut last = String::new();
        // transport errors and rate limits are retried (a re-sent raw tx is the same tx)
        for attempt in 0..8 {
            match self.http.post(&self.url).json(&body).send().await {
                Ok(r) if r.status().as_u16() == 429 => last = "HTTP 429".into(),
                Ok(r) => {
                    let v: Value = r
                        .json()
                        .await
                        .with_context(|| format!("{method}: bad JSON"))?;
                    match v.get("error") {
                        Some(e) if e.to_string().contains("rate limit") => last = e.to_string(),
                        Some(e) => bail!("{method}: {e}"),
                        None => return Ok(v["result"].clone()),
                    }
                }
                Err(e) => last = e.to_string(),
            }
            tokio::time::sleep(Duration::from_millis(500 << attempt.min(5))).await;
        }
        Err(anyhow!("{method}: {last}"))
    }

    pub async fn eth_call(&self, to: &[u8; 20], data: &[u8]) -> Result<Vec<u8>> {
        unhex(
            &self
                .call(
                    "eth_call",
                    json!([{"to": h(to), "data": h(data)}, "latest"]),
                )
                .await?,
        )
    }

    pub async fn block_number(&self) -> Result<u64> {
        qty(&self.call("eth_blockNumber", json!([])).await?)
    }

    pub async fn block(&self, tag: &str) -> Result<Value> {
        self.call("eth_getBlockByNumber", json!([tag, false])).await
    }

    pub async fn balance(&self, a: &[u8; 20]) -> Result<U256> {
        let v = self.call("eth_getBalance", json!([h(a), "latest"])).await?;
        Ok(U256::from_str_radix(
            v.as_str().unwrap_or("0x0").trim_start_matches("0x"),
            16,
        )?)
    }

    /// Logs of `address` from `from` to the current head with exact topics (`None` = any), in
    /// ranges of `B22_LOGS_CHUNK` blocks (default 10,000) for range-limited RPCs.
    pub async fn logs(
        &self,
        address: &[u8; 20],
        topics: &[Option<[u8; 32]>],
        from: u64,
    ) -> Result<Vec<Value>> {
        let t: Vec<Value> = topics
            .iter()
            .map(|x| x.map_or(Value::Null, |x| json!(h(&x))))
            .collect();
        let step = match std::env::var("B22_LOGS_CHUNK") {
            Ok(v) => v.parse().context("B22_LOGS_CHUNK: not a block count")?,
            Err(_) => 10_000,
        };
        let mut out = vec![];
        for (a, b) in block_chunks(from, self.block_number().await?, step) {
            let v = self
                .call(
                    "eth_getLogs",
                    json!([{"address": h(address), "topics": t, "fromBlock": format!("{a:#x}"), "toBlock": format!("{b:#x}")}]),
                )
                .await?;
            out.extend(v.as_array().cloned().unwrap_or_default());
        }
        Ok(out)
    }

    /// Signs and sends an EIP-1559 tx from `key`, waits for the receipt. A tx that fails
    /// `eth_estimateGas` is not sent: the revert reason is returned as the error.
    pub async fn send(
        &self,
        key: &[u8; 32],
        to: &[u8; 20],
        value: U256,
        data: &[u8],
    ) -> Result<TxOut> {
        let from = crate::signer_address(key)?;
        let gas = qty(&self
            .call(
                "eth_estimateGas",
                json!([{"from": h(&from), "to": h(to), "value": format!("{value:#x}"), "data": h(data)}]),
            )
            .await?)?;
        let mut nonce = qty(&self
            .call("eth_getTransactionCount", json!([h(&from), "pending"]))
            .await?)?;
        let base = qty(&self.block("latest").await?["baseFeePerGas"]).unwrap_or(1_000_000_000);
        let prio = match self.call("eth_maxPriorityFeePerGas", json!([])).await {
            Ok(v) => qty(&v)?.max(1_000_000),
            Err(_) => 1_000_000_000,
        };
        // load-balanced RPCs can lag on "pending": follow the node's "next nonce N" hint
        let hash = loop {
            let raw = sign_1559(
                key,
                self.chain_id,
                nonce,
                prio,
                2 * base + prio,
                gas * 5 / 4 + 10_000,
                to,
                value,
                data,
            )?;
            match self.call("eth_sendRawTransaction", json!([h(&raw)])).await {
                Ok(v) => break v,
                Err(e) => match e.to_string().split("next nonce ").nth(1).and_then(|r| {
                    r.split(|c: char| !c.is_ascii_digit())
                        .next()?
                        .parse::<u64>()
                        .ok()
                }) {
                    Some(n) if n > nonce => nonce = n,
                    _ => return Err(e),
                },
            }
        };
        let hash = hash.as_str().unwrap_or_default().to_string();
        self.wait(&hash).await
    }

    pub async fn wait(&self, hash: &str) -> Result<TxOut> {
        for _ in 0..600 {
            let r = self
                .call("eth_getTransactionReceipt", json!([hash]))
                .await?;
            if !r.is_null() {
                return Ok(TxOut {
                    hash: hash.into(),
                    block: qty(&r["blockNumber"])?,
                    ok: qty(&r["status"])? == 1,
                    gas_used: qty(&r["gasUsed"])?,
                    logs: r["logs"].as_array().cloned().unwrap_or_default(),
                    block_hash: r["blockHash"].as_str().unwrap_or_default().into(),
                    tx_index: qty(&r["transactionIndex"])? as u32,
                });
            }
            tokio::time::sleep(self.poll).await;
        }
        bail!("tx {hash} not included")
    }
}

/// Raw signed type-2 transaction.
#[allow(clippy::too_many_arguments)]
pub fn sign_1559(
    key: &[u8; 32],
    chain_id: u64,
    nonce: u64,
    prio: u64,
    max_fee: u64,
    gas: u64,
    to: &[u8; 20],
    value: U256,
    data: &[u8],
) -> Result<Vec<u8>> {
    let fields = |out: &mut Vec<u8>| {
        chain_id.encode(out);
        nonce.encode(out);
        prio.encode(out);
        max_fee.encode(out);
        gas.encode(out);
        alloy_primitives::Address::from(*to).encode(out);
        value.encode(out);
        data.encode(out);
        out.push(0xc0); // empty access list
    };
    let list = |payload: Vec<u8>| {
        let mut o = vec![0x02];
        Header {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut o);
        o.extend(payload);
        o
    };
    let mut p = vec![];
    fields(&mut p);
    let digest = keccak256(list(p.clone()));
    let sk = k256::ecdsa::SigningKey::from_slice(key)?;
    let (sig, rec) = sk.sign_prehash_recoverable(digest.as_slice())?;
    let (sig, rec) = match sig.normalize_s() {
        Some(n) => (n, rec.to_byte() ^ 1),
        None => (sig, rec.to_byte()),
    };
    let bytes = sig.to_bytes();
    (rec as u64).encode(&mut p);
    U256::from_be_slice(&bytes[..32]).encode(&mut p);
    U256::from_be_slice(&bytes[32..]).encode(&mut p);
    Ok(list(p))
}

// ---- ABI ----

/// Inclusive block ranges of at most `step` (≥ 1) blocks covering `from..=to`.
pub fn block_chunks(from: u64, to: u64, step: u64) -> Vec<(u64, u64)> {
    let step = step.max(1);
    (from..=to)
        .step_by(step as usize)
        .map(|a| (a, a.saturating_add(step - 1).min(to)))
        .collect()
}

pub fn selector(sig: &str) -> [u8; 4] {
    keccak256(sig.as_bytes())[..4].try_into().unwrap()
}

pub fn w_addr(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

pub fn w_u(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

pub fn w_bool(b: bool) -> [u8; 32] {
    w_u(b as u128)
}

/// `sig(words…, [bytes tail])`: static words then, if `tail` is given, one dynamic `bytes` last.
pub fn abi(sig: &str, words: &[[u8; 32]], tail: Option<&[u8]>) -> Vec<u8> {
    let mut out = selector(sig).to_vec();
    for w in words {
        out.extend(w);
    }
    if let Some(t) = tail {
        out.extend(w_u(32 * (words.len() as u128 + 1)));
        out.extend(w_u(t.len() as u128));
        out.extend(t);
        out.resize(out.len() + (32 - t.len() % 32) % 32, 0);
    }
    out
}

pub fn word(ret: &[u8], i: usize) -> Result<[u8; 32]> {
    ret.get(32 * i..32 * i + 32)
        .ok_or_else(|| anyhow!("short return data ({} bytes)", ret.len()))
        .map(|w| w.try_into().unwrap())
}

pub fn word_u64(ret: &[u8], i: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(word(ret, i)?[24..].try_into().unwrap()))
}

/// Read-only views of a `BridgeVault`.
pub struct Vault<'a> {
    pub eth: &'a Eth,
    pub addr: [u8; 20],
}

impl Vault<'_> {
    async fn get(&self, sig: &str, words: &[[u8; 32]]) -> Result<Vec<u8>> {
        self.eth.eth_call(&self.addr, &abi(sig, words, None)).await
    }

    /// The only source of `cfg` (docs/ARCHITECTURE.md §3.4).
    pub async fn config_id(&self) -> Result<[u8; 32]> {
        word(&self.get("CONFIG_ID()", &[]).await?, 0)
    }

    pub async fn min_lez_depth(&self) -> Result<u64> {
        word_u64(&self.get("effectiveMinLezDepth()", &[]).await?, 0)
    }

    pub async fn spent(&self, nb: &[u8; 32]) -> Result<bool> {
        Ok(word(&self.get("spent(bytes32)", &[*nb]).await?, 0)?[31] == 1)
    }

    pub async fn accepted_at(&self, tok: &[u8; 20], d: u128, root: &[u8; 32]) -> Result<U256> {
        let w = word(
            &self
                .get(
                    "acceptedAt(address,uint256,bytes32)",
                    &[w_addr(tok), w_u(d), *root],
                )
                .await?,
            0,
        )?;
        Ok(U256::from_be_bytes(w))
    }

    /// `effectiveToken(token).releaseDelay` (in force now, a matured queued change included).
    pub async fn release_delay(&self, tok: &[u8; 20]) -> Result<u64> {
        word_u64(
            &self.get("effectiveToken(address)", &[w_addr(tok)]).await?,
            2,
        )
    }

    /// `denoms(token, d).standardFee`.
    pub async fn standard_fee(&self, tok: &[u8; 20], d: u128) -> Result<u128> {
        let w = word(
            &self
                .get("denoms(address,uint256)", &[w_addr(tok), w_u(d)])
                .await?,
            1,
        )?;
        Ok(u128::from_be_bytes(w[16..].try_into().unwrap()))
    }

    /// `pendingTokenAt(token)`: 0 when nothing is queued.
    pub async fn pending_token_at(&self, tok: &[u8; 20]) -> Result<u64> {
        word_u64(
            &self.get("pendingTokenAt(address)", &[w_addr(tok)]).await?,
            0,
        )
    }

    /// `(releaseDelay, depositCap, releaseCap)` of a `TokenConfig` view (`effectiveToken` / `pendingToken`).
    pub async fn token_params(&self, view: &str, tok: &[u8; 20]) -> Result<(u64, u128, u128)> {
        let r = self
            .get(&format!("{view}(address)"), &[w_addr(tok)])
            .await?;
        let u = |i| -> Result<u128> { Ok(u128::from_be_bytes(word(&r, i)?[16..].try_into()?)) };
        Ok((word_u64(&r, 2)?, u(4)?, u(5)?))
    }

    /// `(depositsFrozen, releasesFrozen)`: the global flags `setFrozen` writes.
    pub async fn frozen(&self) -> Result<(bool, bool)> {
        let d = word(&self.get("depositsFrozen()", &[]).await?, 0)?[31] == 1;
        let r = word(&self.get("releasesFrozen()", &[]).await?, 0)?[31] == 1;
        Ok((d, r))
    }

    pub async fn image_id(&self) -> Result<[u8; 32]> {
        word(&self.get("MEMBERSHIP_IMAGE_ID()", &[]).await?, 0)
    }
}

pub const SIG_DEPOSIT: &str = "deposit(address,uint256,bytes32)";
pub const SIG_ACCEPT: &str = "acceptBurnRoot(address,uint256,bytes32,uint64,uint64,bytes32,bytes)";
pub const SIG_RELEASE: &str =
    "release(address,uint256,bytes32,bytes32,address,address,uint256,bytes)";
pub const SIG_REVOKE: &str = "revokeRoot(address,uint256,bytes32)";
pub const SIG_FROZEN: &str = "setFrozen(bool,bool)";
pub const SIG_CANCEL_TOKEN_CHANGE: &str = "cancelTokenChange(address)";
pub const TOKEN_CHANGE_QUEUED: &str = "TokenChangeQueued(address,uint256)";
pub const MIN_DEPTH_CHANGE_QUEUED: &str = "MinLezDepthChangeQueued(uint64,uint256)";

/// `(token, activeAt)` of a `TokenChangeQueued(address indexed token, uint256 activeAt)` log.
pub fn token_change_queued(log: &Value) -> Result<([u8; 20], u64)> {
    let tok: [u8; 20] = unhex(&log["topics"][1])?
        .get(12..32)
        .ok_or_else(|| anyhow!("TokenChangeQueued: bad token topic"))?
        .try_into()?;
    Ok((tok, word_u64(&unhex(&log["data"])?, 0)?))
}
pub const SIG_APPROVE: &str = "approve(address,uint256)";
pub const SIG_BALANCE: &str = "balanceOf(address)";
