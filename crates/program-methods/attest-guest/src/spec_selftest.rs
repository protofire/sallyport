//! Test-only guest (crates/spec-tests): runs the production BLS path (`attest_program::bls::prepare`
//! + `pairing_check`, residue witness, K / K+2 hints) and the lc-core branch verifier on official
//! test vectors inside the zkVM. Input: borsh-encoded ops; output: one result per op (journal).
use attest_program::bls;
use borsh::BorshDeserialize;
use lc_core::{PairingInputs, Root};
use risc0_zkvm::guest::env;

#[derive(BorshDeserialize)]
enum Op {
    /// -> 0 prepare rejected, 1 prepared but pairing false, 2 valid.
    Bls(PairingInputs, Vec<Vec<u8>>, Vec<u8>),
    /// -> 192-byte serialized affine point.
    HashToG2(Vec<u8>, Vec<u8>),
    /// -> 0/1 `is_valid_normalized_branch(leaf, branch, gindex, root)`.
    Branch(Root, Vec<Root>, u64, Root),
}

fn main() {
    let ops: Vec<Vec<u8>> = env::read();
    let mut out = Vec::new();
    for op in ops {
        match Op::try_from_slice(&op).expect("op") {
            Op::Bls(p, hints, w) => out.push(match bls::prepare(&p, &hints) {
                Err(_) => 0,
                Ok((a, h, s)) => 1 + bls::pairing_check(&a, &h, &s, &w) as u8,
            }),
            Op::HashToG2(msg, dst) => out.extend(hash_to_g2(&msg, &dst)),
            Op::Branch(leaf, branch, g, root) => {
                out.push(lc_core::is_valid_normalized_branch(&leaf, &branch, g, &root) as u8)
            }
        }
    }
    env::commit_slice(&out);
}

/// blst `hash_to_G2` (the call `bls::prepare` makes with the eth2 DST) for an arbitrary DST.
fn hash_to_g2(msg: &[u8], dst: &[u8]) -> [u8; 192] {
    let (mut p, mut a, mut o) = (
        blst::blst_p2::default(),
        blst::blst_p2_affine::default(),
        [0u8; 192],
    );
    // SAFETY: pointers/lengths from live slices; out-params live.
    unsafe {
        blst::blst_hash_to_g2(
            &mut p,
            msg.as_ptr(),
            msg.len(),
            dst.as_ptr(),
            dst.len(),
            core::ptr::null(),
            0,
        );
        blst::blst_p2_to_affine(&mut a, &p);
        blst::blst_p2_affine_serialize(o.as_mut_ptr(), &a);
    }
    o
}
