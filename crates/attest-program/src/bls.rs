//! Guest BLS12-381 (risc0/blst v0.3.16-risczero.0, bigint2-accelerated field arithmetic).
//!
//! Split: [`prepare`] (UpdateBegin) = key aggregation, signature decode + subgroup check,
//! hash_to_G2; [`pairing_check`] (UpdateVerify) = shared two-pair Miller loop + witnessed
//! final-exponentiation residue check (src/residue.rs, copied from the team's own earlier experimental
//! one-transaction BLS code, 2026-11-04, same terms as this repository, not published; see docs/DECISIONS.md D-ATT-2). The relayer builds the witness off-chain ([`crate::witness`]).

use blst::*;
use lc_core::{ErrorCode, PairingInputs};

/// eth2 sync-committee DST (proof of possession).
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

fn p1(pk: &[u8; 48]) -> Option<blst_p1> {
    let mut aff = blst_p1_affine::default();
    let mut p = blst_p1::default();
    // SAFETY: 48-byte compressed input; blst writes only to the out-params.
    unsafe {
        if blst_p1_uncompress(&mut aff, pk.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return None;
        }
        blst_p1_from_affine(&mut p, &aff);
    }
    Some(p)
}

/// Non-signer `pk` given as an uncompressed point `u` (relayer hint, avoids ~96k-cycle
/// decompression each): accepted only if on the curve and `compress(u) == pk`, where `pk` is the
/// stored committee key at that index (so the hint is bound to the SSZ-authenticated key).
fn hinted_p1(pk: &[u8; 48], u: &[u8]) -> Option<blst_p1> {
    let mut aff = blst_p1_affine::default();
    let mut p = blst_p1::default();
    let mut c = [0u8; 48];
    // 0x80 = compression flag: `blst_p1_deserialize` would accept compressed bytes + any padding
    if u.len() != 96 || u[0] & 0x80 != 0 {
        return None;
    }
    // SAFETY: lengths checked; out-params live.
    unsafe {
        if blst_p1_deserialize(&mut aff, u.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return None;
        }
        blst_p1_affine_compress(c.as_mut_ptr(), &aff);
        if c != *pk {
            return None;
        }
        blst_p1_from_affine(&mut p, &aff);
    }
    Some(p)
}

/// Signature given uncompressed (192 B hint): accepted only if on the curve and
/// `compress(u) == sig` (the authenticated signature bytes), so `u` is exactly `uncompress(sig)`
/// (compression is injective on curve points) without the Fp2 square root.
fn hinted_p2(sig: &[u8; 96], u: &[u8]) -> Option<blst_p2_affine> {
    let mut aff = blst_p2_affine::default();
    let mut c = [0u8; 96];
    // only the uncompressed encoding: no malleable compressed-prefix + padding form
    if u.len() != 192 || u[0] & 0x80 != 0 {
        return None;
    }
    // SAFETY: lengths checked; out-params live.
    unsafe {
        if blst_p2_deserialize(&mut aff, u.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return None;
        }
        blst_p2_affine_compress(c.as_mut_ptr(), &aff);
    }
    (c == *sig).then_some(aff)
}

/// Hints for [`prepare`] (relayer side): the uncompressed non-signer keys in index order, then the
/// uncompressed aggregate key and signature. The two trailing entries are optional for the guest
/// (without them it decompresses both itself, ~0.26 M cycles more).
pub fn uncompress_non_signers(p: &PairingInputs) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = p
        .non_signer_pubkeys
        .iter()
        .chain([&p.aggregate_pubkey])
        .map(|pk| {
            let mut aff = blst_p1_affine::default();
            let mut out = vec![0u8; 96];
            // SAFETY: fixed-size buffers.
            unsafe {
                blst_p1_uncompress(&mut aff, pk.as_ptr());
                blst_p1_affine_serialize(out.as_mut_ptr(), &aff);
            }
            out
        })
        .collect();
    let mut aff = blst_p2_affine::default();
    let mut sig = vec![0u8; 192];
    // SAFETY: fixed-size buffers; an undecodable signature leaves the default point (rejected in-guest).
    unsafe {
        blst_p2_uncompress(&mut aff, p.signature.as_ptr());
        blst_p2_affine_serialize(sig.as_mut_ptr(), &aff);
    }
    out.push(sig);
    out
}

/// Serialized `(apk, H(m), sig)`. `p` comes from `lc_core::prepare_update`: the aggregate key and
/// the non-signer keys are taken *by index* (sync_committee_bits) from the SSZ-authenticated
/// committee in the Store, never from instruction data; `hints` only carries their uncompressed
/// encodings, one per non-signer, each bound by [`hinted_p1`], optionally followed by the
/// uncompressed aggregate key ([`hinted_p1`] against the stored aggregate) and signature
/// ([`hinted_p2`] against the update's signature bytes). Committee keys are PoP-validated
/// on deposit, so no per-key subgroup check; the aggregate must not be infinity. The signature
/// must be in G2 and not infinity. Any failure is 1102.
pub fn prepare(
    p: &PairingInputs,
    hints: &[Vec<u8>],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), ErrorCode> {
    let k = p.non_signer_pubkeys.len();
    let tail = match hints.len().checked_sub(k) {
        Some(0) => None,
        Some(2) => Some((&hints[k], &hints[k + 1])),
        _ => return Err(ErrorCode::SyncSigInvalid),
    };
    let mut acc = match tail {
        Some((u, _)) => hinted_p1(&p.aggregate_pubkey, u),
        None => p1(&p.aggregate_pubkey),
    }
    .ok_or(ErrorCode::SyncSigInvalid)?;
    for (pk, u) in p.non_signer_pubkeys.iter().zip(hints) {
        let mut q = hinted_p1(pk, u).ok_or(ErrorCode::SyncSigInvalid)?;
        // SAFETY: live, initialized points.
        unsafe {
            blst_p1_cneg(&mut q, true);
            let prev = acc;
            blst_p1_add_or_double(&mut acc, &prev, &q);
        }
    }
    let mut apk = blst_p1_affine::default();
    let mut sig = blst_p2_affine::default();
    let mut h = blst_p2::default();
    let mut h_aff = blst_p2_affine::default();
    let (mut apk_b, mut h_b, mut sig_b) = (vec![0u8; 96], vec![0u8; 192], vec![0u8; 192]);
    // SAFETY: fixed-size buffers of the serialized lengths; pointers to live values.
    unsafe {
        blst_p1_to_affine(&mut apk, &acc);
        if blst_p1_affine_is_inf(&apk) {
            return Err(ErrorCode::SyncSigInvalid);
        }
        match tail {
            Some((_, u)) => sig = hinted_p2(&p.signature, u).ok_or(ErrorCode::SyncSigInvalid)?,
            None => {
                if blst_p2_uncompress(&mut sig, p.signature.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
                    return Err(ErrorCode::SyncSigInvalid);
                }
            }
        }
        if blst_p2_affine_is_inf(&sig) || !blst_p2_affine_in_g2(&sig) {
            return Err(ErrorCode::SyncSigInvalid);
        }
        blst_hash_to_g2(
            &mut h,
            p.signing_root.as_ptr(),
            p.signing_root.len(),
            DST.as_ptr(),
            DST.len(),
            core::ptr::null(),
            0,
        );
        blst_p2_to_affine(&mut h_aff, &h);
        blst_p1_affine_serialize(apk_b.as_mut_ptr(), &apk);
        blst_p2_affine_serialize(h_b.as_mut_ptr(), &h_aff);
        blst_p2_affine_serialize(sig_b.as_mut_ptr(), &sig);
    }
    Ok((apk_b, h_b, sig_b))
}

/// e(apk, H(m)) == e(G1, sig), i.e. FinalExp(Miller(H, apk) * Miller(sig, -G1)) == 1.
/// Inputs come from [`prepare`] via this program's own Job state; deserialization still
/// re-checks curve membership.
pub fn pairing_check(apk: &[u8], h: &[u8], sig: &[u8], witness: &[u8]) -> bool {
    match miller(apk, h, sig) {
        Some(f) => final_check(&f, witness),
        None => false,
    }
}

/// Shared two-pair Miller loop `Miller(H, apk) * Miller(sig, -G1)`; None on bad encodings.
pub fn miller(apk: &[u8], h: &[u8], sig: &[u8]) -> Option<blst_fp12> {
    let mut a = blst_p1_affine::default();
    let mut hq = blst_p2_affine::default();
    let mut s = blst_p2_affine::default();
    if apk.len() != 96 || h.len() != 192 || sig.len() != 192 {
        return None;
    }
    // SAFETY: lengths checked above; out-params are live.
    let f = unsafe {
        if blst_p1_deserialize(&mut a, apk.as_ptr()) != BLST_ERROR::BLST_SUCCESS
            || blst_p2_deserialize(&mut hq, h.as_ptr()) != BLST_ERROR::BLST_SUCCESS
            || blst_p2_deserialize(&mut s, sig.as_ptr()) != BLST_ERROR::BLST_SUCCESS
        {
            return None;
        }
        let mut neg_g = *blst_p1_affine_generator();
        let mut tmp = blst_p1::default();
        blst_p1_from_affine(&mut tmp, &neg_g);
        blst_p1_cneg(&mut tmp, true);
        blst_p1_to_affine(&mut neg_g, &tmp);
        let qs = [hq, s];
        let ps = [a, neg_g];
        let qp: [*const blst_p2_affine; 2] = [qs.as_ptr(), core::ptr::null()];
        let pp: [*const blst_p1_affine; 2] = [ps.as_ptr(), core::ptr::null()];
        let mut f = blst_fp12::default();
        blst_miller_loop_n(&mut f, qp.as_ptr(), pp.as_ptr(), 2);
        f
    };
    Some(f)
}

/// Default (and only on-chain) path: residue witness check, pinned (no mode chosen by the
/// prover). Any bad witness → false → 1102 (no guest trap).
fn final_check(f: &blst_fp12, witness: &[u8]) -> bool {
    crate::residue::check(f, witness)
}

/// Test oracle: ordinary final exponentiation over the same Miller loop (not used on-chain).
pub fn final_exp_is_one(f: &blst_fp12) -> bool {
    // SAFETY: live values.
    unsafe {
        let mut out = blst_fp12::default();
        blst_final_exp(&mut out, f);
        blst_fp12_is_one(&out)
    }
}
