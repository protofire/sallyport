//! Host-only residue-witness builder for `UpdateVerify` (relayer side). Algorithm copied from
//! the team's own earlier experimental BLS code (2026-11-04, same terms as this repository, not published; docs/DECISIONS.md D-ATT-2). Untrusted: the guest
//! recomputes the Miller loop and checks the witness itself.

use crate::bls::{miller, prepare, uncompress_non_signers};
use crate::residue;
use blst::*;
use lc_core::PairingInputs;
use num_bigint::BigUint;

fn pow(base: blst_fp12, exponent: &BigUint) -> blst_fp12 {
    let mut out = blst_fp12::default();
    for byte in exponent.to_bytes_be() {
        for bit in (0..8).rev() {
            // SAFETY: in-place square of a live value.
            unsafe {
                blst_fp12_sqr(&mut out, &out);
            }
            if (byte >> bit) & 1 != 0 {
                out *= base;
            }
        }
    }
    out
}

fn encode(value: &blst_fp12, coefficients: usize, bytes: &mut Vec<u8>) {
    for fp in value
        .fp6
        .iter()
        .flat_map(|x| x.fp2.iter())
        .flat_map(|x| x.fp.iter())
        .take(coefficients)
    {
        let mut b = [0u8; 48];
        // SAFETY: 48-byte buffer.
        unsafe {
            blst_bendian_from_fp(b.as_mut_ptr(), fp);
        }
        bytes.extend_from_slice(&b);
    }
}

/// Witness `(c, s)` for a Miller-loop value whose final exponentiation is one; None otherwise.
pub fn make(f: blst_fp12) -> Option<Vec<u8>> {
    if !crate::bls::final_exp_is_one(&f) {
        return None;
    }
    let one = BigUint::from(1u8);
    let u = BigUint::from(0xd201000000010000u64); // -x
    let r = u.pow(4) - u.pow(2) + &one;
    let p = (&u + &one).pow(2) * &r / 3u8 - &u;
    let order = p.pow(12) - &one;
    let kernel_order = &order / &r;
    let d = 27u8 * ((&u + &one) / 3u8);
    let m = &kernel_order / &d;
    let lambda = &p + &u;
    let projection = &m * m.modinv(&d)?;
    let s = pow(f, &(&kernel_order - projection));
    assert_eq!(s.fp6[1], blst_fp6::default(), "scaling factor must be Fp6");
    let c = pow(f * s, &lambda.modinv(&m)?);
    let mut bytes = Vec::with_capacity(residue::WITNESS_BYTES);
    encode(&c, 12, &mut bytes);
    encode(&s, 6, &mut bytes);
    residue::check(&f, &bytes).then_some(bytes)
}

/// Witness for the update a relayer is submitting: `PairingInputs` from host-side
/// `lc_core::prepare_update` on the same store. None if the signature does not verify.
pub fn for_pairing(p: &PairingInputs) -> Option<Vec<u8>> {
    let (apk, h, sig) = prepare(p, &uncompress_non_signers(p)).ok()?;
    make(miller(&apk, &h, &sig)?)
}
