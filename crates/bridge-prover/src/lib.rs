//! Release proof for RFP-022 (docs/ARCHITECTURE.md §3.6): the `burn_member` guest proves that
//! `B = sha256("b022/burn" ‖ rk ‖ recipient)` is leaf `index` of `burnRoot` and commits the 352-byte
//! [`ReleaseJournal`] (with `Nb = sha256("b022/rnf" ‖ rk)`). The succinct receipt is wrapped into
//! Groth16 by risc0's Docker prover (`RISC0_WORK_DIR` must be Docker-mountable). Under
//! `RISC0_DEV_MODE` the receipt is fake and the seal is the mock `0xffffffff ‖ claim digest`.

use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use bridge_core::{burn_nullifier, ReleaseJournal};
use program_methods::{BURN_MEMBER_ELF, BURN_MEMBER_ID};
use risc0_zkvm::sha::{Digest, Digestible};
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, ProverOpts, Receipt};

/// `MEMBERSHIP_IMAGE_ID` as the vault's `bytes32`.
pub fn image_id() -> [u8; 32] {
    Digest::from(BURN_MEMBER_ID).into()
}

pub struct Proof {
    /// `selector ‖ seal`, as `RiscZeroGroth16Verifier.verify` takes it.
    pub seal: Vec<u8>,
    /// ABI-encoded release journal (352 bytes).
    pub journal: Vec<u8>,
    pub cycles: u64,
    pub succinct: Duration,
    pub wrap: Duration,
    pub fake: bool,
}

/// Proves the release of the burn `(rk, j.recipient)` at leaf `index` of `j.burn_root`.
/// `j.nb` is ignored (the guest derives it from `rk`); every other journal field is bound as given.
pub fn prove(rk: &[u8; 32], index: u64, path: &[[u8; 32]], j: &ReleaseJournal) -> Result<Proof> {
    let j = ReleaseJournal {
        nb: burn_nullifier(rk),
        ..j.clone()
    };
    let input = borsh::to_vec(&(&j, rk, index, path))?;
    let env = ExecutorEnv::builder().write(&input)?.build()?;
    let prover = default_prover();

    let t = Instant::now();
    let info = prover
        .prove_with_opts(env, BURN_MEMBER_ELF, &ProverOpts::succinct())
        .context("burn_member: not a member (or prover failure)")?;
    let succinct = t.elapsed();
    let t = Instant::now();
    let receipt = prover.compress(&ProverOpts::groth16(), &info.receipt)?;
    let wrap = t.elapsed();

    receipt.verify(BURN_MEMBER_ID)?;
    ensure!(
        receipt.journal.bytes == j.encode(),
        "journal differs from the request"
    );
    Ok(Proof {
        seal: encode_seal(&receipt)?,
        journal: receipt.journal.bytes.clone(),
        cycles: info.stats.total_cycles,
        succinct,
        wrap,
        fake: matches!(receipt.inner, InnerReceipt::Fake(_)),
    })
}

/// Same encoding as risc0-ethereum's `encode_seal` (no dependency on it for 10 lines).
fn encode_seal(r: &Receipt) -> Result<Vec<u8>> {
    Ok(match &r.inner {
        InnerReceipt::Groth16(g) => [&g.verifier_parameters.as_bytes()[..4], &g.seal[..]].concat(),
        InnerReceipt::Fake(f) => [&[0xff; 4][..], f.claim.digest().as_bytes()].concat(),
        _ => bail!("receipt is not Groth16"),
    })
}

/// Inputs of the golden vector (`fixtures/b22/vectors.json`): release `B_0` from the 2-leaf tree.
pub fn fixture_inputs() -> Result<([u8; 32], u64, Vec<[u8; 32]>, ReleaseJournal, Vec<u8>)> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/b22/vectors.json"
    );
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let s = |p: &str| -> Result<String> {
        let x = v.pointer(p).with_context(|| format!("vectors.json: {p}"))?;
        Ok(x.as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| x.to_string()))
    };
    fn b<const N: usize>(h: String) -> Result<[u8; N]> {
        hex::decode(h)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad length"))
    }
    let tree_path = v["burn_tree"]["path_index0"]
        .as_array()
        .context("path_index0")?
        .iter()
        .map(|x| b(x.as_str().unwrap_or_default().to_owned()))
        .collect::<Result<Vec<[u8; 32]>>>()?;
    let j = ReleaseJournal {
        chain_id: s("/inputs/bridge_config/evm_chain_id")?.parse()?,
        vault: b(s("/inputs/bridge_config/vault")?)?,
        config_id: b(s("/config/config_id")?)?,
        token: b(s("/inputs/token")?)?,
        denom: s("/inputs/denom")?.parse()?,
        burn_root: b(s("/burn_tree/root")?)?,
        nb: b(s("/per_index/0/nb")?)?,
        recipient: b(s("/per_index/0/recipient")?)?,
        relayer: b(s("/inputs/relayer")?)?,
        fee: s("/inputs/fee")?.parse()?,
    };
    let abi = hex::decode(s("/release_journal/abi")?)?;
    Ok((b(s("/per_index/0/rk")?)?, 0, tree_path, j, abi))
}

/// Inverse of [`ReleaseJournal::encode`]: 11 static ABI words, tag `b022/rel/v1`, high bytes zero.
pub fn decode_journal(abi: &[u8]) -> Result<ReleaseJournal> {
    ensure!(
        abi.len() == 352,
        "release journal must be 352 bytes, got {}",
        abi.len()
    );
    let w = |i: usize| -> &[u8] { &abi[32 * i..32 * (i + 1)] };
    let tail = |i: usize, n: usize| -> Result<&[u8]> {
        ensure!(
            w(i)[..32 - n].iter().all(|&x| x == 0),
            "word {i} overflows {n} bytes"
        );
        Ok(&w(i)[32 - n..])
    };
    ensure!(w(0) == bridge_core::TAG_REL, "not a b022/rel/v1 journal");
    let j = ReleaseJournal {
        chain_id: u64::from_be_bytes(tail(1, 8)?.try_into()?),
        vault: tail(2, 20)?.try_into()?,
        config_id: w(3).try_into()?,
        token: tail(4, 20)?.try_into()?,
        denom: u128::from_be_bytes(tail(5, 16)?.try_into()?),
        burn_root: w(6).try_into()?,
        nb: w(7).try_into()?,
        recipient: tail(8, 20)?.try_into()?,
        relayer: tail(9, 20)?.try_into()?,
        fee: u128::from_be_bytes(tail(10, 16)?.try_into()?),
    };
    debug_assert_eq!(j.encode(), abi);
    Ok(j)
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(s.strip_prefix("0x").unwrap_or(s))?)
}

/// L4 handoff: request `{rk, index, path[], journal}` (hex, `0x` optional; journal = ABI hex) →
/// response `{journal, seal}` (`0x` hex; seal = `selector ‖ seal` as the vault passes it to the
/// verifier). The proven journal must equal the requested one byte for byte (incl. `Nb`).
pub fn prove_request(request: &str) -> Result<serde_json::Value> {
    let r: serde_json::Value = serde_json::from_str(request)?;
    let field = |k: &str| {
        r[k].as_str()
            .with_context(|| format!("request.{k} missing"))
    };
    let b32 = |s: &str| -> Result<[u8; 32]> {
        unhex(s)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected 32 bytes"))
    };
    let rk = b32(field("rk")?)?;
    let index = r["index"].as_u64().context("request.index missing")?;
    let path = r["path"]
        .as_array()
        .context("request.path missing")?
        .iter()
        .map(|x| b32(x.as_str().unwrap_or_default()))
        .collect::<Result<Vec<_>>>()?;
    let abi = unhex(field("journal")?)?;
    let p = prove(&rk, index, &path, &decode_journal(&abi)?)?;
    ensure!(
        p.journal == abi,
        "requested journal is not the proven one (wrong Nb?)"
    );
    let h = |b: &[u8]| format!("0x{}", hex::encode(b));
    Ok(serde_json::json!({ "journal": h(&p.journal), "seal": h(&p.seal) }))
}
