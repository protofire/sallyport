// Copied from the team's own earlier experimental one-transaction BLS code (2026-11-04, not
// published; same terms as this repository; original file sha256 fb4d0617...).
// Changed (D-ATT-4): every assert is now a `None`/`false` return, same conditions, so a bad
// witness is a typed 1102 instead of a guest trap.
//! A BLS12-381 final-exponentiation residue check. Proof: docs/RESIDUE-SOUNDNESS.md.
use blst::*;

pub const WITNESS_BYTES: usize = 18 * 48; // c in Fp12 and s in Fp6

fn zero() -> blst_fp12 {
    blst_fp12 {
        fp6: [blst_fp6::default(); 2],
    }
}

pub fn decode(bytes: &[u8], coefficients: usize) -> Option<blst_fp12> {
    if !(coefficients == 6 || coefficients == 12) || bytes.len() != coefficients * 48 {
        return None;
    }
    let mut out = zero();
    for (fp, chunk) in out
        .fp6
        .iter_mut()
        .flat_map(|x| x.fp2.iter_mut())
        .flat_map(|x| x.fp.iter_mut())
        .zip(bytes.chunks_exact(48))
    {
        unsafe {
            blst_fp_from_bendian(fp, chunk.as_ptr());
        }
        // The C conversion reduces modulo p. Reject noncanonical inputs explicitly.
        let mut canonical = [0u8; 48];
        unsafe {
            blst_bendian_from_fp(canonical.as_mut_ptr(), fp);
        }
        if canonical != chunk {
            return None;
        }
    }
    Some(out)
}

/// True iff `witness` is a valid residue witness for `f` (i.e. `f` is a pairing product equal to 1).
pub fn check(f: &blst_fp12, witness: &[u8]) -> bool {
    if witness.len() != WITNESS_BYTES {
        return false;
    }
    // Upper Fp6 of s is zero by construction.
    let (Some(c), Some(s)) = (decode(&witness[..576], 12), decode(&witness[576..], 6)) else {
        return false;
    };
    // Essential: otherwise c=s=0 satisfies the homogeneous equation for any f.
    if c == zero() {
        return false;
    }
    let mut power = c;
    // -x = 0xd201000000010000. Generic Fp12 square, NOT cyclotomic square:
    // the witness is an arbitrary nonzero field element, not a GT element.
    for bit in (0..63).rev() {
        unsafe {
            blst_fp12_sqr(&mut power, &power);
        }
        if (0xd201000000010000u64 >> bit) & 1 != 0 {
            power *= c;
        }
    }
    let mut frob = blst_fp12::default();
    unsafe {
        blst_fp12_frobenius_map(&mut frob, &c, 1);
    }
    frob * power == *f * s
}
