//! `bridge-prover prove --fixture`: proves the golden-vector release (fixtures/b22/vectors.json)
//! with a real Groth16 wrap and writes contracts/bridge/test/fixtures/real_seal.json for L1's
//! `RealSeal` fork test. Refuses to write a fake (RISC0_DEV_MODE) seal.
//! `bridge-prover prove --request REQ.json --out OUT.json`: L4's handoff ([`bridge_prover::prove_request`]).
use anyhow::{bail, ensure, Result};
use bridge_prover::{fixture_inputs, image_id, prove};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opt = |k: &str| {
        args.iter()
            .position(|a| a == k)
            .and_then(|i| args.get(i + 1).cloned())
    };
    if args.first().map(String::as_str) == Some("image-id") {
        println!("0x{}", hex::encode(image_id()));
        return Ok(());
    }
    if args.first().map(String::as_str) != Some("prove") {
        bail!("usage: bridge-prover image-id | prove (--fixture [--out PATH] | --request REQ.json --out OUT.json)");
    }
    if let Some(req) = opt("--request") {
        let out = opt("--out").ok_or_else(|| anyhow::anyhow!("--request needs --out"))?;
        let resp = bridge_prover::prove_request(&std::fs::read_to_string(req)?)?;
        std::fs::write(&out, serde_json::to_string_pretty(&resp)? + "\n")?;
        println!("wrote {out}");
        return Ok(());
    }
    ensure!(
        args.iter().any(|a| a == "--fixture"),
        "need --fixture or --request"
    );
    let out = opt("--out").unwrap_or_else(|| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/bridge/test/fixtures/real_seal.json"
        )
        .into()
    });
    let (rk, index, path, j, abi) = fixture_inputs()?;
    let p = prove(&rk, index, &path, &j)?;
    ensure!(p.journal == abi, "journal differs from vectors.json");
    ensure!(
        !p.fake,
        "fake receipt (RISC0_DEV_MODE set?): not writing a real seal fixture"
    );
    let h = |b: &[u8]| format!("0x{}", hex::encode(b));
    let fixture = serde_json::json!({
        "_note": "RFP-022 L3: real Groth16 seal of burn_member for the release_journal of fixtures/b22/vectors.json. Verify with RiscZeroGroth16Verifier v3.1.0 (Sepolia 0x8c915b5071206C6E328BC18529586c513408aB3b): verify(seal, imageId, journalDigest).",
        "imageId": h(&image_id()),
        "journal": h(&p.journal),
        "journalDigest": h(&j.digest()),
        "seal": h(&p.seal),
        "cycles": p.cycles,
        "succinctSeconds": p.succinct.as_secs_f64(),
        "groth16WrapSeconds": p.wrap.as_secs_f64(),
    });
    std::fs::create_dir_all(std::path::Path::new(&out).parent().unwrap())?;
    std::fs::write(&out, serde_json::to_string_pretty(&fixture)? + "\n")?;
    println!(
        "MEMBERSHIP_IMAGE_ID {}\ncycles {}\nsuccinct {:.1}s\ngroth16 wrap {:.1}s\nwrote {out}",
        h(&image_id()),
        p.cycles,
        p.succinct.as_secs_f64(),
        p.wrap.as_secs_f64()
    );
    Ok(())
}
