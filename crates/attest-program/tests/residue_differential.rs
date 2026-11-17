//! Differential test of the residue check (`residue::check`, docs/RESIDUE-SOUNDNESS.md) against
//! blst's ordinary final exponentiation (`bls::final_exp_is_one`) on random BLS instances built
//! through the production `bls::prepare` / `bls::miller` path. Host blst only (not the risc0 fork).
//! Run: `cargo test -p attest-program --features witness --test residue_differential`.
#![cfg(feature = "witness")]

use attest_program::{bls, residue, witness};
use blst::min_pk::{AggregatePublicKey, AggregateSignature, SecretKey, Signature};
use blst::*;
use lc_core::PairingInputs;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const COMMITTEE: usize = 8;
const ROUNDS: u64 = 25; // 25 rounds x 11 cases = 275 cases

/// Deterministic stream: sha256(seed || counter).
struct Rng(u64);
impl Rng {
    fn bytes32(&mut self) -> [u8; 32] {
        self.0 += 1;
        Sha256::new()
            .chain_update(b"residue-differential-v1")
            .chain_update(self.0.to_be_bytes())
            .finalize()
            .into()
    }
    fn below(&mut self, n: usize) -> usize {
        u64::from_be_bytes(self.bytes32()[..8].try_into().unwrap()) as usize % n
    }
}

struct Params {
    p: BigUint,
    h: BigUint,
    m: BigUint,
    d: BigUint,
    lambda: BigUint,
}

fn params() -> Params {
    let one = BigUint::from(1u8);
    let u = BigUint::from(0xd201000000010000u64);
    let r = u.pow(4) - u.pow(2) + &one;
    let p = (&u + &one).pow(2) * &r / 3u8 - &u;
    let h = (p.pow(12) - &one) / &r;
    let d = 27u8 * ((&u + &one) / 3u8);
    let m = &h / &d;
    Params {
        lambda: &p + &u,
        p,
        h,
        m,
        d,
    }
}

fn pow(base: blst_fp12, e: &BigUint) -> blst_fp12 {
    let mut out = blst_fp12::default(); // one
    for byte in e.to_bytes_be() {
        for bit in (0..8).rev() {
            unsafe { blst_fp12_sqr(&mut out, &out) };
            if (byte >> bit) & 1 != 0 {
                out *= base;
            }
        }
    }
    out
}

fn encode(v: &blst_fp12, coefficients: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for fp in v
        .fp6
        .iter()
        .flat_map(|x| x.fp2.iter())
        .flat_map(|x| x.fp.iter())
        .take(coefficients)
    {
        let mut b = [0u8; 48];
        unsafe { blst_bendian_from_fp(b.as_mut_ptr(), fp) };
        out.extend_from_slice(&b);
    }
    out
}

/// The honest builder's algorithm (witness.rs) without its `final_exp_is_one` gate. A sanity
/// check only: for a non-residue `f` this `s` is not in Fp6 and gets truncated; soundness rests
/// on the argument in docs/RESIDUE-SOUNDNESS.md, not on this adversary.
fn forge(f: blst_fp12, k: &Params) -> Vec<u8> {
    let s = pow(f, &(&k.h - &k.m * k.m.modinv(&k.d).unwrap()));
    let c = pow(f * s, &k.lambda.modinv(&k.m).unwrap());
    [encode(&c, 12), encode(&s, 6)].concat()
}

fn random_fp12(rng: &mut Rng) -> blst_fp12 {
    let mut bytes = Vec::new();
    for _ in 0..12 {
        let mut limb = [rng.bytes32(), rng.bytes32()].concat()[..48].to_vec();
        limb[0] &= 0x0f; // < 2^380 < p: canonical
        bytes.extend(limb);
    }
    residue::decode(&bytes, 12).unwrap()
}

/// Replace the 48-byte limb `i` by its value + p (same residue mod p, non-canonical bytes).
fn non_canonical(w: &[u8], i: usize, p: &BigUint) -> Vec<u8> {
    let mut out = w.to_vec();
    let v = BigUint::from_bytes_be(&w[i * 48..(i + 1) * 48]) + p;
    let b = v.to_bytes_be();
    assert!(b.len() <= 48);
    out[i * 48..(i + 1) * 48].fill(0);
    out[(i + 1) * 48 - b.len()..(i + 1) * 48].copy_from_slice(&b);
    out
}

struct Committee {
    sks: Vec<SecretKey>,
    pks: Vec<[u8; 48]>,
    aggregate: [u8; 48],
}

fn committee(rng: &mut Rng) -> Committee {
    let sks: Vec<SecretKey> = (0..COMMITTEE)
        .map(|_| SecretKey::key_gen(&rng.bytes32(), &[]).unwrap())
        .collect();
    let pks: Vec<_> = sks.iter().map(|s| s.sk_to_pk()).collect();
    let refs: Vec<_> = pks.iter().collect();
    let aggregate = AggregatePublicKey::aggregate(&refs, true)
        .unwrap()
        .to_public_key()
        .compress();
    Committee {
        pks: pks.iter().map(|p| p.compress()).collect(),
        sks,
        aggregate,
    }
}

/// Pairing inputs as `lc_core::prepare_update` shapes them: stored aggregate, non-signers by index.
fn inputs(c: &Committee, signers: &[bool], root: [u8; 32], sigs: &[Signature]) -> PairingInputs {
    let refs: Vec<_> = sigs.iter().collect();
    PairingInputs {
        aggregate_pubkey: c.aggregate,
        non_signer_pubkeys: (0..COMMITTEE)
            .filter(|&i| !signers[i])
            .map(|i| c.pks[i])
            .collect(),
        signing_root: root,
        signature: AggregateSignature::aggregate(&refs, true)
            .unwrap()
            .to_signature()
            .compress(),
    }
}

/// Miller value through the production path; also asserts `pairing_check` agrees with `expect`.
fn miller_of(p: &PairingInputs, w: &[u8], expect: bool) -> blst_fp12 {
    let (apk, h, sig) = bls::prepare(p, &bls::uncompress_non_signers(p)).expect("prepare");
    assert_eq!(bls::pairing_check(&apk, &h, &sig, w), expect);
    bls::miller(&apk, &h, &sig).unwrap()
}

/// An invalid Miller value: residue check rejects the forged and a foreign honest witness,
/// the oracle says not one, and the honest builder refuses.
fn assert_rejected(f: blst_fp12, foreign: &[u8], k: &Params, what: &str) {
    assert!(!bls::final_exp_is_one(&f), "{what}: oracle");
    assert!(witness::make(f).is_none(), "{what}: builder");
    assert!(!residue::check(&f, &forge(f, k)), "{what}: forged witness");
    assert!(!residue::check(&f, foreign), "{what}: foreign witness");
}

#[test]
fn residue_check_matches_final_exp() {
    let k = params();
    let mut rng = Rng(0);
    let mut cases = 0;

    // The oracle is a power of f^h with exponent coprime to r (blst: 3h), see the doc.
    let f = random_fp12(&mut rng);
    let mut fe = blst_fp12::default();
    unsafe { blst_final_exp(&mut fe, &f) };
    assert!(
        fe == pow(f, &(&k.h * 3u8)),
        "blst final_exp computes f^(3h)"
    );

    let mut prev_witness: Option<Vec<u8>> = None;
    for round in 0..ROUNDS {
        let c = committee(&mut rng);
        let signers: Vec<bool> = loop {
            let s: Vec<bool> = (0..COMMITTEE).map(|_| rng.below(2) == 1).collect();
            if s.iter().filter(|&&b| b).count() >= 2 {
                break s;
            }
        };
        let root = rng.bytes32();
        let sigs: Vec<Signature> = (0..COMMITTEE)
            .filter(|&i| signers[i])
            .map(|i| c.sks[i].sign(&root, DST, &[]))
            .collect();

        // 1. valid: honest witness exists, passes, agrees with the oracle.
        let valid = inputs(&c, &signers, root, &sigs);
        let f = miller_of(&valid, &[], false);
        assert!(bls::final_exp_is_one(&f), "round {round}: oracle on valid");
        let w = witness::make(f).expect("honest witness");
        assert!(residue::check(&f, &w));
        miller_of(&valid, &w, true);
        cases += 1;
        let foreign = prev_witness
            .replace(w.clone())
            .unwrap_or_else(|| forge(random_fp12(&mut rng), &k));

        // 2-3. tampered c / s (low byte of a random limb: stays canonical, changes the value).
        for (lo, n) in [(0, 12), (12, 6)] {
            let mut t = w.clone();
            t[(lo + rng.below(n)) * 48 + 47] ^= 1;
            assert!(!residue::check(&f, &t), "round {round}: tampered limb");
            cases += 1;
        }
        // 4-5. non-canonical limb of c / s (value + p): same field element, must be rejected.
        for (lo, n) in [(0, 12), (12, 6)] {
            let t = non_canonical(&w, lo + rng.below(n), &k.p);
            assert!(!residue::check(&f, &t), "round {round}: non-canonical limb");
            cases += 1;
        }
        // 6. c = 0 and s = 0 (homogeneous solution), s = 0 alone, wrong length.
        assert!(!residue::check(&f, &[0u8; residue::WITNESS_BYTES]));
        let mut t = w.clone();
        t[576..].fill(0);
        assert!(!residue::check(&f, &t));
        assert!(!residue::check(&f, &w[..w.len() - 1]));
        cases += 1;

        // 7. wrong message: signing root differs from what was signed.
        let mut p = valid.clone();
        p.signing_root = rng.bytes32();
        assert_rejected(miller_of(&p, &w, false), &foreign, &k, "wrong message");
        // 8. wrong key subset: one actual signer claimed as a non-signer.
        let mut fewer = signers.clone();
        fewer[(0..COMMITTEE)
            .filter(|&i| signers[i])
            .nth(rng.below(2))
            .unwrap()] = false;
        let p = inputs(&c, &fewer, root, &sigs);
        assert_rejected(miller_of(&p, &w, false), &foreign, &k, "wrong subset");
        // 9. tampered signature: an outsider's signature added (still a valid G2 point).
        let outsider = SecretKey::key_gen(&rng.bytes32(), &[])
            .unwrap()
            .sign(&root, DST, &[]);
        let p = inputs(&c, &signers, root, &[sigs.clone(), vec![outsider]].concat());
        assert_rejected(miller_of(&p, &w, false), &foreign, &k, "tampered sig");
        // 10. random Fp12 value in place of a Miller output.
        assert_rejected(random_fp12(&mut rng), &foreign, &k, "random f");
        // 11. valid f, witness of another valid instance.
        assert!(
            !residue::check(&f, &foreign),
            "round {round}: foreign witness on valid f"
        );
        cases += 5;
    }
    assert!(cases >= 200, "{cases}");
    println!("residue differential: {cases} cases");
}
