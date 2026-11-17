//! Execution-layer inclusion proofs (header RLP, account / storage / receipt-log MPT proofs),
//! predicates over the proven fact, and the deterministic `StatementId` (docs/ARCHITECTURE.md).
//! no_std + alloc so it builds for the risc0 guest.
#![no_std]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "host")]
pub mod host;
#[cfg(all(feature = "risc0-keccak", target_os = "zkvm"))]
mod zkvm_keccak;

use alloc::{borrow::Cow, vec, vec::Vec};
use alloy_primitives::{keccak256, U256};
use alloy_rlp::{Decodable, Encodable, Header};
use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};

/// Subset of `lc-core::ErrorCode` this crate emits; same stable numbers (docs/CONSUMER-GUIDE.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    Malformed = 1001,
    ExecutionHeaderMismatch = 1201,
    InclusionInvalid = 1202,
    PredicateFailed = 1203,
    StatementMismatch = 1204,
}

pub const EMPTY_ROOT: [u8; 32] = alloy_trie::EMPTY_ROOT_HASH.0;
pub const KECCAK_EMPTY: [u8; 32] = alloy_trie::KECCAK_EMPTY.0;
/// keccak256("Transfer(address,address,uint256)")
pub const TRANSFER_TOPIC: [u8; 32] =
    alloy_primitives::b256!("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef").0;
/// EIP-7708 (Amsterdam): every ETH value transfer emits an ERC-20-shaped Transfer log from this address.
pub const EIP7708_ETH_LOG_ADDRESS: [u8; 20] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe,
];

// ---------------------------------------------------------------- header

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ExecHeader {
    pub parent_hash: [u8; 32],
    pub number: u64,
    pub timestamp: u64,
    pub state_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub transactions_root: [u8; 32],
}

/// keccak(rlp) must equal `expected_block_hash`; then read the 15 legacy fields by position.
/// Trailing fork fields (base fee, withdrawals, blob gas, beacon root, requests, BAL hash, slot …) are
/// only required to be well-formed RLP items, so new forks appending fields don't break decoding.
pub fn verify_exec_header(
    rlp: &[u8],
    expected_block_hash: [u8; 32],
) -> Result<ExecHeader, ErrorCode> {
    if keccak256(rlp).0 != expected_block_hash {
        return Err(ErrorCode::ExecutionHeaderMismatch);
    }
    // string items only (no nested lists), whole buffer consumed; first 15 kept (no allocation)
    let mut buf = rlp;
    let mut payload = Header::decode_bytes(&mut buf, true).map_err(|_| ErrorCode::Malformed)?;
    if !buf.is_empty() {
        return Err(ErrorCode::Malformed);
    }
    let mut items = [&[][..]; 15];
    let mut n = 0;
    while !payload.is_empty() {
        let h = Header::decode(&mut payload).map_err(|_| ErrorCode::Malformed)?;
        if h.list || payload.len() < h.payload_length {
            return Err(ErrorCode::Malformed);
        }
        if let Some(it) = items.get_mut(n) {
            *it = &payload[..h.payload_length];
        }
        n += 1;
        payload = &payload[h.payload_length..];
    }
    if n < 15 {
        return Err(ErrorCode::Malformed);
    }
    let h32 = |i: usize| -> Result<[u8; 32], ErrorCode> {
        items[i].try_into().map_err(|_| ErrorCode::Malformed)
    };
    let u = |i: usize| -> Result<u64, ErrorCode> { u64_be(items[i]) };
    Ok(ExecHeader {
        parent_hash: h32(0)?,
        state_root: h32(3)?,
        transactions_root: h32(4)?,
        receipts_root: h32(5)?,
        number: u(8)?,
        timestamp: u(11)?,
    })
}

/// Longest `ancestry` accepted (1001 above it). Bounds Attest cycles; see docs/DECISIONS.md.
pub const MAX_ANCESTRY: usize = 448;

/// Bind `anchor_rlp` to the recorded `anchor_hash`, then walk `ancestry` = RLP headers
/// [H_target, …, H_anchor-1] back by parentHash (keccak(H_i) == parentHash(H_i+1)).
/// Returns the target header and its block hash (the anchor's when `ancestry` is empty).
pub fn verify_ancestry<A: AsRef<[u8]>>(
    anchor_rlp: &[u8],
    anchor_hash: [u8; 32],
    ancestry: &[A],
) -> Result<(ExecHeader, [u8; 32]), ErrorCode> {
    if ancestry.len() > MAX_ANCESTRY {
        return Err(ErrorCode::Malformed);
    }
    let mut hash = anchor_hash;
    let mut h = verify_exec_header(anchor_rlp, hash)?;
    for rlp in ancestry.iter().rev() {
        hash = h.parent_hash;
        h = verify_exec_header(rlp.as_ref(), hash)?;
    }
    Ok((h, hash))
}

/// Items of an RLP list as (is_list, payload); the list must span `buf` exactly.
fn split_list(mut buf: &[u8]) -> Result<Vec<(bool, &[u8])>, ErrorCode> {
    let mut payload = Header::decode_bytes(&mut buf, true).map_err(|_| ErrorCode::Malformed)?;
    if !buf.is_empty() {
        return Err(ErrorCode::Malformed);
    }
    let mut out = Vec::new();
    while !payload.is_empty() {
        let h = Header::decode(&mut payload).map_err(|_| ErrorCode::Malformed)?;
        if payload.len() < h.payload_length {
            return Err(ErrorCode::Malformed);
        }
        out.push((h.list, &payload[..h.payload_length]));
        payload = &payload[h.payload_length..];
    }
    Ok(out)
}

/// Canonical RLP integer payload (no leading zero) → u64.
fn u64_be(p: &[u8]) -> Result<u64, ErrorCode> {
    if p.len() > 8 || p.first() == Some(&0) {
        return Err(ErrorCode::Malformed);
    }
    Ok(p.iter().fold(0u64, |a, b| (a << 8) | *b as u64))
}

// ---------------------------------------------------------------- state proofs

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Account {
    pub nonce: u64,
    pub balance: [u8; 32],
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
}

impl Account {
    /// What a non-existent account reads as.
    pub fn empty() -> Self {
        Account {
            nonce: 0,
            balance: [0; 32],
            storage_root: EMPTY_ROOT,
            code_hash: KECCAK_EMPTY,
        }
    }
}

fn mpt<P: AsRef<[u8]>>(
    root: &[u8; 32],
    key: &[u8],
    value: Option<&[u8]>,
    proof: &[P],
) -> Result<(), ErrorCode> {
    if verify_mpt(root, key, value, proof) {
        Ok(())
    } else {
        Err(ErrorCode::InclusionInvalid)
    }
}

/// One RLP item at the start of `buf`: (is_list, payload, whole encoding, rest).
fn rlp_item(buf: &[u8]) -> Option<(bool, &[u8], &[u8], &[u8])> {
    let mut b = buf;
    let h = Header::decode(&mut b).ok()?;
    if b.len() < h.payload_length {
        return None;
    }
    // header bytes + payload, both <= buf.len() after the check above: cannot overflow
    let enc_len = buf.len() - b.len() + h.payload_length;
    Some((
        h.list,
        &b[..h.payload_length],
        &buf[..enc_len],
        &b[h.payload_length..],
    ))
}

enum Child<'a> {
    Empty,
    Hash(&'a [u8; 32]),
    Inline(&'a [u8]),
}

/// A child reference inside a node: empty string, 32-byte hash, or an embedded (< 32 byte) node.
fn child<'a>(is_list: bool, payload: &'a [u8], enc: &'a [u8]) -> Option<Child<'a>> {
    match (is_list, payload.len()) {
        (false, 0) => Some(Child::Empty),
        (false, 32) => Some(Child::Hash(payload.try_into().ok()?)),
        (true, _) if enc.len() < 32 => Some(Child::Inline(enc)),
        _ => None,
    }
}

/// Slice equality that is fast on rv32 (the platform `memcmp` is a byte
/// loop, ~10 cycles/byte): `a` is read as aligned words, `b` as unaligned words.
fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let n = a.len();
    let head = ((4 - (a.as_ptr() as usize & 3)) & 3).min(n);
    if a[..head] != b[..head] {
        return false;
    }
    let (pa, pb) = (a.as_ptr(), b.as_ptr());
    let mut i = head;
    // SAFETY: `i + 4 <= n` bounds every 4-byte read inside both slices; `pa + head` is 4-aligned.
    while i + 4 <= n {
        let (x, y) = unsafe {
            (
                (pa.add(i) as *const u32).read(),
                (pb.add(i) as *const u32).read_unaligned(),
            )
        };
        if x != y {
            return false;
        }
        i += 4;
    }
    a[i..] == b[i..]
}

/// Merkle-Patricia proof check without copying the proof (gas: replaces alloy-trie's
/// `verify_proof`, see docs/DECISIONS.md D-GAS-1). `value = Some(v)`: `key` maps to the leaf value
/// `v`; `None`: `key` is absent. Every node referenced by hash is the next proof node and must
/// hash to it (nodes < 32 bytes are only accepted embedded in their parent); nothing may follow the
/// node that ends the walk. Stricter than alloy-trie only on shapes no valid trie of fixed or
/// prefix-free keys produces (key ending at a branch, extra nodes after a divergence).
pub fn verify_mpt<P: AsRef<[u8]>>(
    root: &[u8; 32],
    key: &[u8],
    value: Option<&[u8]>,
    proof: &[P],
) -> bool {
    match (mpt_lookup(root, key, proof), value) {
        (Some(Some(a)), Some(b)) => bytes_eq(a, b),
        (Some(None), None) => true,
        _ => false,
    }
}

/// The walk behind [`verify_mpt`]: `Some(Some(v))` = the proof shows `key` maps to the leaf value
/// `v` (borrowed from the proof), `Some(None)` = the proof shows `key` is absent, `None` = invalid
/// proof. Same checks as `verify_mpt`, which is exactly "lookup succeeds and equals `value`".
pub fn mpt_lookup<'a, P: AsRef<[u8]>>(
    root: &[u8; 32],
    key: &[u8],
    proof: &'a [P],
) -> Option<Option<&'a [u8]>> {
    if proof.is_empty() || proof[0].as_ref() == [alloy_rlp::EMPTY_STRING_CODE] {
        return (*root == EMPTY_ROOT).then_some(None);
    }
    let klen = key.len() * 2;
    let nib = |i: usize| (key[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
    let mut pos = 0usize; // key nibbles consumed
    let mut want = root;
    let mut nodes = proof.iter();
    // The walk ended at `found` (a leaf value, or None = key absent): no proof node may follow.
    let end = |found: Option<&'a [u8]>, rest: &mut core::slice::Iter<'a, P>| {
        rest.next().is_none().then_some(found)
    };
    while let Some(node) = nodes.next() {
        let node = node.as_ref();
        if node.len() < 32 || keccak256(node).0 != *want {
            return None;
        }
        let mut cur: &[u8] = node;
        loop {
            let Some((true, items, _, [])) = rlp_item(cur) else {
                return None;
            };
            // first two items decide the node kind
            let Some((l0, p0, e0, r0)) = rlp_item(items) else {
                return None;
            };
            let Some((l1, p1, e1, r1)) = rlp_item(r0) else {
                return None;
            };
            let next = if r1.is_empty() {
                // leaf or extension: [hex-prefix path, value | child]
                let (Some(&first), false) = (p0.first(), l0) else {
                    return None;
                };
                let (flag, odd) = (first >> 4, first & 0x10 != 0);
                if flag > 3 || (!odd && first & 0x0f != 0) {
                    return None;
                }
                // path nibbles: optional low nibble of the first byte, then both nibbles of the rest
                let plen = (p0.len() - 1) * 2 + odd as usize;
                let pnib = |i: usize| {
                    let j = i + !odd as usize + 1; // index in the nibbles of p0, skipping the flag
                    (p0[j / 2] >> (if j % 2 == 0 { 4 } else { 0 })) & 0x0f
                };
                let matches = pos + plen <= klen && (0..plen).all(|i| pnib(i) == nib(pos + i));
                if flag >= 2 {
                    // leaf: its value is a string
                    if l1 {
                        return None;
                    }
                    let found = (matches && pos + plen == klen).then_some(p1);
                    return end(found, &mut nodes);
                }
                if !matches {
                    return end(None, &mut nodes); // diverges inside the extension: absent
                }
                pos += plen;
                child(l1, p1, e1).filter(|c| !matches!(c, Child::Empty))
            } else {
                // branch: 16 children + empty value
                if pos >= klen {
                    return None;
                }
                let n = nib(pos) as usize;
                pos += 1;
                let mut sel = None;
                let (mut l, mut p, mut e, mut r) = (l0, p0, e0, r0);
                for i in 0..16 {
                    if i == n {
                        sel = child(l, p, e);
                    } else if child(l, p, e).is_none() {
                        return None;
                    }
                    let Some(nx) = rlp_item(r) else {
                        return None;
                    };
                    (l, p, e, r) = nx;
                }
                // 17th item (value) must be an empty string and the last one
                if l || !p.is_empty() || !r.is_empty() {
                    return None;
                }
                sel
            };
            match next {
                Some(Child::Empty) => return end(None, &mut nodes),
                Some(Child::Hash(h)) => {
                    want = h;
                    break;
                }
                Some(Child::Inline(n)) => cur = n,
                None => return None,
            }
        }
    }
    None // proof ended on a hash reference
}

/// Prove `account` is the state of `address` under `state_root`. `Account::empty()` is accepted for an
/// absent account (exclusion proof).
pub fn verify_account<P: AsRef<[u8]>>(
    state_root: &[u8; 32],
    address: &[u8; 20],
    account: &Account,
    proof: &[P],
) -> Result<(), ErrorCode> {
    let key = keccak256(address);
    let mut payload = Vec::new();
    account.nonce.encode(&mut payload);
    U256::from_be_bytes(account.balance).encode(&mut payload);
    account.storage_root.encode(&mut payload);
    account.code_hash.encode(&mut payload);
    let mut enc = Vec::new();
    Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut enc);
    enc.extend(payload);
    if *account == Account::empty() && mpt(state_root, key.as_slice(), None, proof).is_ok() {
        return Ok(());
    }
    mpt(state_root, key.as_slice(), Some(&enc), proof)
}

/// Prove storage `slot` holds `value` under `storage_root`. Zero = absent leaf (incl. empty trie with an
/// empty proof).
pub fn verify_storage<P: AsRef<[u8]>>(
    storage_root: &[u8; 32],
    slot: &[u8; 32],
    value: &[u8; 32],
    proof: &[P],
) -> Result<(), ErrorCode> {
    let v = U256::from_be_bytes(*value);
    let expected = if v.is_zero() {
        None
    } else {
        Some(alloy_rlp::encode(v))
    };
    mpt(
        storage_root,
        keccak256(slot).as_slice(),
        expected.as_deref(),
        proof,
    )
}

// ---------------------------------------------------------------- receipts

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct LogValue {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
    pub status: u8,
}

/// Prove `receipt` (consensus encoding: `type || rlp` for typed, plain rlp for legacy) is at key
/// rlp(tx_index) under `receipts_root`, then return its `log_index`-th log (index *within the receipt*).
pub fn verify_receipt_log<P: AsRef<[u8]>>(
    receipts_root: &[u8; 32],
    tx_index: u32,
    log_index: u32,
    receipt: &[u8],
    proof: &[P],
) -> Result<LogValue, ErrorCode> {
    mpt(
        receipts_root,
        &alloy_rlp::encode(tx_index),
        Some(receipt),
        proof,
    )?;
    // proven bytes that don't decode are still a bad receipt claim → InclusionInvalid
    decode_receipt_log(receipt, log_index).map_err(|_| ErrorCode::InclusionInvalid)
}

/// Whether `receipt` is the value of the leaf node that ends `proof` (unauthenticated: a caller
/// that forwards the proof as [`verify_receipt_log_compact`] keeps the explicit form's
/// "receipt == proven leaf" rule; receipts are never embedded, so the leaf is the last node).
pub fn receipt_is_last_leaf<P: AsRef<[u8]>>(receipt: &[u8], proof: &[P]) -> bool {
    let Some((true, items, _, [])) = proof.last().and_then(|n| rlp_item(n.as_ref())) else {
        return false;
    };
    match rlp_item(items).and_then(|(l0, p0, _, r0)| Some((l0, p0, rlp_item(r0)?))) {
        Some((false, [f, ..], (false, value, _, []))) if f >> 4 >= 2 => bytes_eq(value, receipt),
        _ => false,
    }
}

/// [`verify_receipt_log`] without the receipt as a separate witness: the receipt is the value of
/// the proven leaf at rlp(tx_index) (it is in the proof anyway; gas, D-GAS-6). An exclusion proof
/// is InclusionInvalid, as a receipt that does not match the leaf is there.
pub fn verify_receipt_log_compact<P: AsRef<[u8]>>(
    receipts_root: &[u8; 32],
    tx_index: u32,
    log_index: u32,
    proof: &[P],
) -> Result<LogValue, ErrorCode> {
    let Some(Some(receipt)) = mpt_lookup(receipts_root, &alloy_rlp::encode(tx_index), proof) else {
        return Err(ErrorCode::InclusionInvalid);
    };
    decode_receipt_log(receipt, log_index).map_err(|_| ErrorCode::InclusionInvalid)
}

fn decode_receipt_log(receipt: &[u8], log_index: u32) -> Result<LogValue, ErrorCode> {
    let body = match receipt.first() {
        Some(t) if *t < 0x7f => &receipt[1..], // EIP-2718 typed
        Some(t) if *t >= 0xc0 => receipt,      // legacy
        _ => return Err(ErrorCode::Malformed),
    };
    let f = split_list(body)?;
    // [status, cumulativeGasUsed, bloom, logs]; pre-Byzantium 32-byte state root is not supported
    if f.len() != 4 || f[0].0 || f[1].0 || f[2].0 || !f[3].0 {
        return Err(ErrorCode::Malformed);
    }
    let status = match f[0].1 {
        [] => 0,
        [1] => 1,
        _ => return Err(ErrorCode::Malformed),
    };
    let mut logs = f[3].1;
    let mut i = 0u32;
    while !logs.is_empty() {
        let h = Header::decode(&mut logs).map_err(|_| ErrorCode::Malformed)?;
        if !h.list || logs.len() < h.payload_length {
            return Err(ErrorCode::Malformed);
        }
        let (item, rest) = logs.split_at(h.payload_length);
        logs = rest;
        if i == log_index {
            return decode_log(item, status);
        }
        i += 1;
    }
    Err(ErrorCode::InclusionInvalid)
}

/// `payload` = contents of the log list [address, [topics], data].
fn decode_log(mut payload: &[u8], status: u8) -> Result<LogValue, ErrorCode> {
    let m = |_| ErrorCode::Malformed;
    let address: [u8; 20] = Header::decode_bytes(&mut payload, false)
        .map_err(m)?
        .try_into()
        .map_err(|_| ErrorCode::Malformed)?;
    let mut t = Header::decode_bytes(&mut payload, true).map_err(m)?;
    let mut topics = Vec::new();
    while !t.is_empty() {
        topics.push(<[u8; 32]>::decode(&mut t).map_err(m)?);
    }
    let data = Header::decode_bytes(&mut payload, false)
        .map_err(m)?
        .to_vec();
    if !payload.is_empty() {
        return Err(ErrorCode::Malformed);
    }
    Ok(LogValue {
        address,
        topics,
        data,
        status,
    })
}

// ---------------------------------------------------------------- facts, predicates, statements

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Locator {
    Account {
        address: [u8; 20],
    },
    Storage {
        address: [u8; 20],
        slot: [u8; 32],
    },
    /// `log_index` is the position inside the receipt's logs, not the block-wide RPC `logIndex`.
    Log {
        tx_index: u32,
        log_index: u32,
    },
}

/// Tuple variants wrap structs; borsh bytes are identical to the struct-variant form in the design notes (docs/ARCHITECTURE.md).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum FactValue {
    Account(Account),
    Slot([u8; 32]),
    Log(LogValue),
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Fact {
    pub chain_id: u64,
    pub genesis_validators_root: [u8; 32],
    pub execution_block_hash: [u8; 32],
    pub block_number: u64,
    pub locator: Locator,
    pub value: FactValue,
}

/// `sha256("rfp021/fact/v1" || borsh(chain_id, genesis_validators_root, execution_block_hash, locator))`
pub fn statement_id(f: &Fact) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"rfp021/fact/v1");
    h.update(
        borsh::to_vec(&(
            f.chain_id,
            f.genesis_validators_root,
            f.execution_block_hash,
            &f.locator,
        ))
        .unwrap(),
    );
    h.finalize().into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum FieldSel {
    Nonce,
    Balance,
    StorageRoot,
    CodeHash,
    Slot,
    LogAddress,
    LogTopic(u8),
    /// 32-byte ABI word `i` of log data
    LogDataWord(u32),
    LogStatus,
}

/// Eq/Ne: exact byte equality. Lt/Le/Gt/Ge: both sides as ≤32-byte big-endian uints (left zero-padded).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Pred {
    Eq { field: FieldSel, value: Vec<u8> },
    Ne { field: FieldSel, value: Vec<u8> },
    Lt { field: FieldSel, value: Vec<u8> },
    Le { field: FieldSel, value: Vec<u8> },
    Gt { field: FieldSel, value: Vec<u8> },
    Ge { field: FieldSel, value: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Statement {
    pub id: [u8; 32],
    pub fact: Fact,
    pub preds: Vec<Pred>,
}

/// Field bytes, `None` if the field is absent in this log (missing topic / data word). Borrowed
/// from the fact except the nonce (no allocation per predicate).
fn field(f: &Fact, s: FieldSel) -> Result<Option<Cow<'_, [u8]>>, ErrorCode> {
    use FactValue as V;
    use FieldSel as S;
    Ok(Some(Cow::Borrowed(match (&f.value, s) {
        (V::Account(a), S::Nonce) => return Ok(Some(Cow::Owned(a.nonce.to_be_bytes().to_vec()))),
        (V::Account(a), S::Balance) => &a.balance,
        (V::Account(a), S::StorageRoot) => &a.storage_root,
        (V::Account(a), S::CodeHash) => &a.code_hash,
        (V::Slot(v), S::Slot) => v,
        (V::Log(l), S::LogAddress) => &l.address,
        (V::Log(l), S::LogStatus) => core::slice::from_ref(&l.status),
        (V::Log(l), S::LogTopic(i)) => match l.topics.get(i as usize) {
            Some(t) => t,
            None => return Ok(None),
        },
        (V::Log(l), S::LogDataWord(i)) => {
            let start = (i as usize).checked_mul(32).ok_or(ErrorCode::Malformed)?;
            match start.checked_add(32).and_then(|end| l.data.get(start..end)) {
                Some(w) => w,
                None => return Ok(None),
            }
        }
        _ => return Err(ErrorCode::Malformed),
    })))
}

fn pad32(b: &[u8]) -> Result<[u8; 32], ErrorCode> {
    if b.len() > 32 {
        return Err(ErrorCode::Malformed);
    }
    let mut o = [0u8; 32];
    o[32 - b.len()..].copy_from_slice(b);
    Ok(o)
}

/// Evaluate one predicate. A field missing from the log makes the predicate false.
pub fn eval(f: &Fact, p: &Pred) -> Result<bool, ErrorCode> {
    use core::cmp::Ordering::*;
    let (Pred::Eq { field: s, value }
    | Pred::Ne { field: s, value }
    | Pred::Lt { field: s, value }
    | Pred::Le { field: s, value }
    | Pred::Gt { field: s, value }
    | Pred::Ge { field: s, value }) = p;
    let Some(x) = field(f, *s)? else {
        return Ok(false);
    };
    let ord = || -> Result<_, ErrorCode> { Ok(pad32(&x)?.cmp(&pad32(value)?)) };
    Ok(match p {
        Pred::Eq { .. } => *x == **value,
        Pred::Ne { .. } => *x != **value,
        Pred::Lt { .. } => ord()? == Less,
        Pred::Le { .. } => ord()? != Greater,
        Pred::Gt { .. } => ord()? == Greater,
        Pred::Ge { .. } => ord()? != Less,
    })
}

/// All predicates must hold (conjunction) → Statement with its id; otherwise 1203.
pub fn attest(fact: Fact, preds: Vec<Pred>) -> Result<Statement, ErrorCode> {
    for p in &preds {
        if !eval(&fact, p)? {
            return Err(ErrorCode::PredicateFailed);
        }
    }
    Ok(Statement {
        id: statement_id(&fact),
        fact,
        preds,
    })
}

/// Address as an indexed-topic word.
pub fn addr_topic(a: [u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..].copy_from_slice(&a);
    t
}

/// ERC-20 `Transfer(from, to, amount)` emitted by `token`, successful tx; optional from/to/min amount.
pub fn erc20_transfer_preds(
    token: [u8; 20],
    from: Option<[u8; 20]>,
    to: Option<[u8; 20]>,
    min_amount: Option<[u8; 32]>,
) -> Vec<Pred> {
    let mut v = vec![
        Pred::Eq {
            field: FieldSel::LogStatus,
            value: vec![1],
        },
        Pred::Eq {
            field: FieldSel::LogAddress,
            value: token.to_vec(),
        },
        Pred::Eq {
            field: FieldSel::LogTopic(0),
            value: TRANSFER_TOPIC.to_vec(),
        },
    ];
    if let Some(a) = from {
        v.push(Pred::Eq {
            field: FieldSel::LogTopic(1),
            value: addr_topic(a).to_vec(),
        });
    }
    if let Some(a) = to {
        v.push(Pred::Eq {
            field: FieldSel::LogTopic(2),
            value: addr_topic(a).to_vec(),
        });
    }
    if let Some(m) = min_amount {
        v.push(Pred::Ge {
            field: FieldSel::LogDataWord(0),
            value: m.to_vec(),
        });
    }
    v
}

/// Native ETH transfer = EIP-7708 Transfer log from the system address (see docs/DECISIONS.md).
pub fn native_eth_transfer_preds(
    from: Option<[u8; 20]>,
    to: Option<[u8; 20]>,
    min_amount: Option<[u8; 32]>,
) -> Vec<Pred> {
    erc20_transfer_preds(EIP7708_ETH_LOG_ADDRESS, from, to, min_amount)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    #[test]
    fn bytes_eq_matches_slice_eq_at_every_offset() {
        let buf: Vec<u8> = (0..64u8).collect();
        for oa in 0..4 {
            for ob in 0..4 {
                for n in 0..40 {
                    let (a, b) = (&buf[oa..oa + n], &buf[ob..ob + n]);
                    assert_eq!(super::bytes_eq(a, b), a == b);
                    let mut c = a.to_vec();
                    for i in 0..n {
                        c[i] ^= 1;
                        assert!(!super::bytes_eq(a, &c));
                        c[i] ^= 1;
                    }
                }
            }
        }
    }

    /// A header claiming a payload near usize::MAX must be rejected, not overflow enc_len.
    #[test]
    fn rlp_item_rejects_huge_length() {
        assert!(super::rlp_item(&[0xbb, 0xff, 0xff, 0xff, 0xff, 0x00]).is_none());
        assert!(super::rlp_item(&[0xfb, 0xff, 0xff, 0xff, 0xff, 0x00]).is_none());
        let mut h = [0xffu8; 10];
        h[0] = 0xbf; // string, 8-byte length = u64::MAX
        assert!(super::rlp_item(&h).is_none());
        h[0] = 0xff; // list, 8-byte length
        assert!(super::rlp_item(&h).is_none());
    }
}
