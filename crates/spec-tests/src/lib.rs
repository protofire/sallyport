//! Harness for the official Ethereum vectors (fetch.sh, README.md Quickstart). The SSZ *decoding*
//! and the container composition of roots lc-core never computes are test-side (production ingests
//! Beacon-API JSON / borsh); every hash lc-core computes, branch check, signing root and BLS
//! operation is the production function. Guest runs use the real zkVM (SPEC_SELFTEST_ELF for the
//! bls.rs path, the LEZ executor via program-tests for the ABI path).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use borsh::BorshSerialize;
use lc_core::{
    BeaconBlockHeader, ExecutionPayloadHeader, HeaderExecution, LightClientBootstrap,
    LightClientHeader, LightClientUpdate, PairingInputs, Root, SyncAggregate, SyncCommittee,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub type R<T> = Result<T, String>;

/// `$SPEC_TESTS_DIR` (default `~/spectests`), as laid out by fetch.sh. Panics if absent: a missing
/// corpus must fail, not pass.
pub fn dir() -> PathBuf {
    let d = std::env::var("SPEC_TESTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(std::env::var("HOME").unwrap()).join("spectests"));
    assert!(
        d.join("VERSIONS").exists(),
        "{}: no vectors, run crates/spec-tests/fetch.sh",
        d.display()
    );
    d
}

/// Sorted subdirectories (empty if `p` does not exist).
pub fn subdirs(p: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(p)
        .map(|r| r.filter_map(|e| e.ok().map(|e| e.path())).collect())
        .unwrap_or_default();
    v.retain(|p| p.is_dir());
    v.sort();
    v
}

pub fn snappy(p: &Path) -> Vec<u8> {
    snap::raw::Decoder::new()
        .decompress_vec(&std::fs::read(p).unwrap_or_else(|e| panic!("{}: {e}", p.display())))
        .unwrap()
}

/// YAML -> JSON value with bare integers and 0x-literals quoted (Beacon-API strings; uint256-safe).
pub fn yaml(p: &Path) -> Value {
    let s = std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    let lit = |v: &str| {
        !v.is_empty()
            && (v.bytes().all(|b| b.is_ascii_digit())
                || v.strip_prefix("0x")
                    .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit())))
    };
    let quoted: String = s
        .lines()
        .map(|l| match l.split_once(": ") {
            Some((k, v)) if lit(v.trim()) => format!("{k}: '{}'\n", v.trim()),
            _ => format!("{l}\n"),
        })
        .collect();
    serde_yaml::from_str(&quoted).unwrap()
}

pub fn hx(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap_or_else(|| panic!("hex string, got {v}"));
    hex::decode(s.trim().trim_start_matches("0x")).unwrap()
}

pub fn root32(v: &Value) -> Root {
    hx(v).try_into().unwrap()
}

pub fn num(v: &Value) -> u64 {
    v.as_u64()
        .unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}

// ------------------------------------------------------------------ test-side merkleization

pub fn sha(a: &Root, b: &Root) -> Root {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// Independent SSZ merkleize (zero-padded to `limit`, a power of two).
pub fn merkleize(mut v: Vec<Root>, limit: usize) -> Root {
    assert!(limit.is_power_of_two() && v.len() <= limit);
    v.resize(limit, [0; 32]);
    while v.len() > 1 {
        v = v.chunks(2).map(|p| sha(&p[0], &p[1])).collect();
    }
    v[0]
}

fn pack(b: &[u8]) -> Vec<Root> {
    b.chunks(32)
        .map(|c| {
            let mut r = [0u8; 32];
            r[..c.len()].copy_from_slice(c);
            r
        })
        .collect()
}

fn bytes_root(b: &[u8]) -> Root {
    let p = pack(b);
    let n = p.len().next_power_of_two();
    merkleize(p, n)
}

fn u64_chunk(v: u64) -> Root {
    let mut c = [0u8; 32];
    c[..8].copy_from_slice(&v.to_le_bytes());
    c
}

/// spec `is_valid_merkle_branch` fold, written independently of lc-core.
pub fn fold_branch(leaf: &Root, branch: &[Root], gindex: u64) -> Root {
    let mut node = *leaf;
    for (i, s) in branch.iter().enumerate() {
        node = if (gindex >> i) & 1 == 1 {
            sha(s, &node)
        } else {
            sha(&node, s)
        };
    }
    node
}

// ------------------------------------------------------------------ test-side SSZ decoding

/// Preset/fork shape of the light-client containers.
#[derive(Clone, Copy, Debug)]
pub struct Shape {
    /// SYNC_COMMITTEE_SIZE: 512 mainnet, 32 minimal.
    pub n: usize,
    pub gloas: bool,
}

impl Shape {
    fn header(self) -> Option<usize> {
        self.gloas.then_some(112 + 32 + 11 * 32)
    }
    fn committee(self) -> Option<usize> {
        Some(self.n * 48 + 48)
    }
    fn sc_branch(self) -> Option<usize> {
        Some(32 * if self.gloas { 11 } else { 6 })
    }
    fn fin_branch(self) -> Option<usize> {
        Some(32 * if self.gloas { 9 } else { 7 })
    }
    fn agg(self) -> Option<usize> {
        Some(self.n / 8 + 96)
    }
}

/// Splits an SSZ container; `Some(len)` = fixed field, `None` = variable (4-byte offset).
pub fn split<'a>(b: &'a [u8], sizes: &[Option<usize>]) -> R<Vec<&'a [u8]>> {
    let fixed: usize = sizes.iter().map(|s| s.unwrap_or(4)).sum();
    if b.len() < fixed {
        return Err(format!("{} < fixed part {fixed}", b.len()));
    }
    let (mut pos, mut out, mut offs) = (0, vec![], vec![]);
    for (i, s) in sizes.iter().enumerate() {
        let l = s.unwrap_or(4);
        if s.is_none() {
            offs.push((
                i,
                u32::from_le_bytes(b[pos..pos + 4].try_into().unwrap()) as usize,
            ));
        }
        out.push(&b[pos..pos + l]);
        pos += l;
    }
    match offs.first() {
        None if b.len() != fixed => return Err(format!("{} != fixed {fixed}", b.len())),
        Some(&(_, o)) if o != fixed => return Err(format!("first offset {o} != {fixed}")),
        _ => {}
    }
    for k in 0..offs.len() {
        let (i, o) = offs[k];
        let end = offs.get(k + 1).map_or(b.len(), |x| x.1);
        if o > end || end > b.len() {
            return Err("bad offsets".into());
        }
        out[i] = &b[o..end];
    }
    Ok(out)
}

fn r32(b: &[u8]) -> Root {
    b.try_into().unwrap()
}

fn roots(b: &[u8]) -> Vec<Root> {
    b.chunks(32).map(r32).collect()
}

fn u64le(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().unwrap())
}

pub fn beacon(b: &[u8]) -> BeaconBlockHeader {
    BeaconBlockHeader {
        slot: u64le(&b[0..8]),
        proposer_index: u64le(&b[8..16]),
        parent_root: r32(&b[16..48]),
        state_root: r32(&b[48..80]),
        body_root: r32(&b[80..112]),
    }
}

fn payload(b: &[u8]) -> R<ExecutionPayloadHeader> {
    let s = [32, 20, 32, 32, 256, 32, 8, 8, 8, 8, 0, 32, 32, 32, 32, 8, 8]
        .map(|l| (l != 0).then_some(l));
    let f = split(b, &s)?;
    if f[10].len() > 32 {
        return Err("extra_data > 32".into());
    }
    Ok(ExecutionPayloadHeader {
        parent_hash: r32(f[0]),
        fee_recipient: f[1].try_into().unwrap(),
        state_root: r32(f[2]),
        receipts_root: r32(f[3]),
        logs_bloom: f[4].try_into().unwrap(),
        prev_randao: r32(f[5]),
        block_number: u64le(f[6]),
        gas_limit: u64le(f[7]),
        gas_used: u64le(f[8]),
        timestamp: u64le(f[9]),
        extra_data: f[10].to_vec(),
        base_fee_per_gas: r32(f[11]),
        block_hash: r32(f[12]),
        transactions_root: r32(f[13]),
        withdrawals_root: r32(f[14]),
        blob_gas_used: u64le(f[15]),
        excess_blob_gas: u64le(f[16]),
    })
}

/// LightClientHeader -> (lc-core type, hash_tree_root). Beacon and execution-header roots are
/// lc-core's; the 3-field container fold is test-side.
pub fn header(b: &[u8], gloas: bool) -> R<(LightClientHeader, Root)> {
    let f = if gloas {
        split(b, &[Some(112), Some(32), Some(11 * 32)])?
    } else {
        split(b, &[Some(112), None, Some(4 * 32)])?
    };
    let (execution, exec_root) = if gloas {
        (HeaderExecution::Gloas(r32(f[1])), r32(f[1]))
    } else {
        let p = payload(f[1])?;
        let r = lc_core::hash_tree_root_execution(&p);
        (HeaderExecution::Electra(Box::new(p)), r)
    };
    let h = LightClientHeader {
        beacon: beacon(f[0]),
        execution,
        execution_branch: roots(f[2]),
    };
    let root = merkleize(
        vec![
            lc_core::hash_tree_root_header(&h.beacon),
            exec_root,
            bytes_root(f[2]),
        ],
        4,
    );
    Ok((h, root))
}

pub fn committee(b: &[u8]) -> SyncCommittee {
    let (keys, agg) = b.split_at(b.len() - 48);
    SyncCommittee {
        pubkeys: keys.chunks(48).map(|k| k.try_into().unwrap()).collect(),
        aggregate_pubkey: agg.try_into().unwrap(),
    }
}

fn pk_root(k: &[u8; 48]) -> Root {
    bytes_root(k)
}

/// hash_tree_root(SyncCommittee): lc-core's for 512 keys, test-side otherwise (minimal: 32).
pub fn committee_root(c: &SyncCommittee) -> Root {
    if c.pubkeys.len() == lc_core::SYNC_COMMITTEE_SIZE {
        return lc_core::hash_tree_root_sync_committee(c);
    }
    let leaves = c.pubkeys.iter().map(pk_root).collect::<Vec<_>>();
    let n = leaves.len().next_power_of_two();
    sha(&merkleize(leaves, n), &pk_root(&c.aggregate_pubkey))
}

fn aggregate(b: &[u8], n: usize) -> (SyncAggregate, Root) {
    let (bits, sig) = b.split_at(n / 8);
    let mut padded = [0u8; 64];
    padded[..bits.len()].copy_from_slice(bits);
    let root = merkleize(vec![bytes_root(bits), bytes_root(sig)], 2);
    (
        SyncAggregate {
            sync_committee_bits: padded,
            sync_committee_signature: sig.try_into().unwrap(),
        },
        root,
    )
}

fn present(b: &[u8]) -> bool {
    b.iter().any(|x| *x != 0)
}

pub fn bootstrap(b: &[u8], s: Shape) -> R<(LightClientBootstrap, Root)> {
    let f = split(b, &[s.header(), s.committee(), s.sc_branch()])?;
    let (h, hr) = header(f[0], s.gloas)?;
    let c = committee(f[1]);
    let root = merkleize(vec![hr, committee_root(&c), bytes_root(f[2])], 4);
    Ok((
        LightClientBootstrap {
            header: h,
            current_sync_committee: c,
            current_sync_committee_branch: roots(f[2]),
        },
        root,
    ))
}

/// LightClientUpdate (`finality_only` = LightClientFinalityUpdate). All-zero branches map to None,
/// as lc-core's JSON decoder does (spec `is_sync_committee_update` / `is_finality_update`).
pub fn update(b: &[u8], s: Shape, finality_only: bool) -> R<(LightClientUpdate, Root)> {
    let f = if finality_only {
        let mut f = split(
            b,
            &[s.header(), s.header(), s.fin_branch(), s.agg(), Some(8)],
        )?;
        f.splice(1..1, [&[][..], &[][..]]);
        f
    } else {
        split(
            b,
            &[
                s.header(),
                s.committee(),
                s.sc_branch(),
                s.header(),
                s.fin_branch(),
                s.agg(),
                Some(8),
            ],
        )?
    };
    let (att, att_root) = header(f[0], s.gloas)?;
    let (fin, fin_root) = header(f[3], s.gloas)?;
    let (agg, agg_root) = aggregate(f[5], s.n);
    let slot = u64le(f[6]);
    let root = if finality_only {
        merkleize(
            vec![
                att_root,
                fin_root,
                bytes_root(f[4]),
                agg_root,
                u64_chunk(slot),
            ],
            8,
        )
    } else {
        let c = committee(f[1]);
        merkleize(
            vec![
                att_root,
                committee_root(&c),
                bytes_root(f[2]),
                fin_root,
                bytes_root(f[4]),
                agg_root,
                u64_chunk(slot),
            ],
            8,
        )
    };
    let u = LightClientUpdate {
        attested_header: att,
        next_sync_committee: (!finality_only && present(f[2]))
            .then(|| (committee(f[1]), roots(f[2]))),
        finalized_header: present(f[4]).then(|| (fin, roots(f[4]))),
        sync_aggregate: agg,
        signature_slot: slot,
    };
    Ok((u, root))
}

/// Exact byte length of a Gloas update/bootstrap (all fields fixed size): picks the wire shape
/// without fork-digest arithmetic.
pub fn is_gloas_len(len: usize, n: usize, kind: &str) -> bool {
    let h = 112 + 32 + 11 * 32;
    let c = n * 48 + 48;
    len == match kind {
        "bootstrap" => h + c + 11 * 32,
        _ => h + c + 11 * 32 + h + 9 * 32 + n / 8 + 96 + 8,
    }
}

// ------------------------------------------------------------------ BLS (production bls.rs)

/// `bls::prepare` + `pairing_check` on the host: 0 rejected by prepare, 1 pairing false, 2 valid.
pub fn bls_host(p: &PairingInputs, hints: &[Vec<u8>], w: &[u8]) -> u8 {
    match attest_program::bls::prepare(p, hints) {
        Err(_) => 0,
        Ok((a, h, s)) => 1 + attest_program::bls::pairing_check(&a, &h, &s, w) as u8,
    }
}

/// Relayer-side residue witness; zero (rejected) witness when no valid pairing exists.
pub fn witness(p: &PairingInputs) -> Vec<u8> {
    attest_program::witness::for_pairing(p).unwrap_or_else(|| vec![0; 864])
}

/// (K hints, K+2 hints) as the relayer builds them.
pub fn hint_sets(p: &PairingInputs) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let full = attest_program::bls::uncompress_non_signers(p);
    (full[..p.non_signer_pubkeys.len()].to_vec(), full)
}

/// Same borsh layout as the guest's `Op` (program-methods/attest-guest/src/spec_selftest.rs).
#[derive(BorshSerialize, Clone)]
pub enum Op {
    Bls(PairingInputs, Vec<Vec<u8>>, Vec<u8>),
    HashToG2(Vec<u8>, Vec<u8>),
    Branch(Root, Vec<Root>, u64, Root),
}

impl Op {
    fn out_len(&self) -> usize {
        match self {
            Op::HashToG2(..) => 192,
            _ => 1,
        }
    }
}

/// Executes `ops` in the zkVM (SPEC_SELFTEST_ELF), batched; one result per op.
pub fn guest(ops: &[Op]) -> Vec<Vec<u8>> {
    use risc0_zkvm::{default_executor, ExecutorEnv};
    let mut res = vec![];
    for batch in ops.chunks(16) {
        let enc: Vec<Vec<u8>> = batch.iter().map(|o| borsh::to_vec(o).unwrap()).collect();
        let env = ExecutorEnv::builder()
            .write(&enc)
            .unwrap()
            .session_limit(None)
            .build()
            .unwrap();
        let j = default_executor()
            .execute(env, program_methods::SPEC_SELFTEST_ELF)
            .unwrap()
            .journal
            .bytes;
        let mut at = 0;
        for o in batch {
            res.push(j[at..at + o.out_len()].to_vec());
            at += o.out_len();
        }
        assert_eq!(at, j.len());
    }
    res
}

// ------------------------------------------------------------------ results

#[derive(Default)]
pub struct Tally {
    pub pass: usize,
    pub mismatch: Vec<String>,
    pub unsupported: BTreeMap<String, usize>,
}

impl Tally {
    pub fn pass(&mut self) {
        self.pass += 1;
    }
    pub fn mismatch(&mut self, id: impl Into<String>) {
        self.mismatch.push(id.into());
    }
    pub fn unsupported(&mut self, reason: impl Into<String>) {
        *self.unsupported.entry(reason.into()).or_default() += 1;
    }
    /// `| suite | PASS | MISMATCH | UNSUPPORTED (reason x n; ...) |`
    pub fn row(&self, suite: &str) -> String {
        let u: usize = self.unsupported.values().sum();
        let why = self
            .unsupported
            .iter()
            .map(|(r, n)| format!("{r} x{n}"))
            .collect::<Vec<_>>()
            .join("; ");
        format!(
            "| {suite} | {} | {} | {u}{} |",
            self.pass,
            self.mismatch.len(),
            if why.is_empty() {
                String::new()
            } else {
                format!(" ({why})")
            }
        )
    }
}

/// Prints the table rows and mismatches; panics on any MISMATCH.
pub fn report(title: &str, rows: &[(String, &Tally)]) {
    println!("\n### {title}\n| suite | PASS | MISMATCH | UNSUPPORTED |\n|---|---|---|---|");
    for (n, t) in rows {
        println!("{}", t.row(n));
    }
    let bad: Vec<&String> = rows.iter().flat_map(|(_, t)| &t.mismatch).collect();
    for m in &bad {
        println!("MISMATCH {m}");
    }
    assert!(bad.is_empty(), "{} MISMATCH in {title}", bad.len());
}
