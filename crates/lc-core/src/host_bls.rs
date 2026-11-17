//! Host [`SigVerifier`] on crates.io `blst` (min_pk: G1 pubkeys, G2 signatures).

use crate::{BlsPubkey, BlsSignature, Root, SigVerifier};
use blst::min_pk::{PublicKey, Signature};
use blst::{
    blst_p1, blst_p1_add_or_double, blst_p1_affine, blst_p1_affine_compress, blst_p1_cneg,
    blst_p1_from_affine, blst_p1_to_affine, blst_p1_uncompress, BLST_ERROR,
};

/// eth2 BLS signature DST (proof-of-possession scheme).
pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub struct BlstVerifier;

fn point(pk: &BlsPubkey) -> Option<blst_p1> {
    let mut aff = blst_p1_affine::default();
    let mut p = blst_p1::default();
    // SAFETY: fixed-size input buffer of the compressed G1 length; blst writes only to `aff` / `p`.
    unsafe {
        if blst_p1_uncompress(&mut aff, pk.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return None;
        }
        blst_p1_from_affine(&mut p, &aff);
    }
    Some(p)
}

impl SigVerifier for BlstVerifier {
    fn verify_sync_aggregate(
        &self,
        committee_aggregate_pubkey: &BlsPubkey,
        non_signer_pubkeys: &[BlsPubkey],
        signing_root: &Root,
        signature: &BlsSignature,
    ) -> bool {
        let Some(mut acc) = point(committee_aggregate_pubkey) else {
            return false;
        };
        for pk in non_signer_pubkeys {
            let Some(mut p) = point(pk) else { return false };
            // SAFETY: all pointers are to live, initialized blst points.
            unsafe {
                blst_p1_cneg(&mut p, true);
                let prev = acc;
                blst_p1_add_or_double(&mut acc, &prev, &p);
            }
        }
        let mut aff = blst_p1_affine::default();
        let mut compressed = [0u8; 48];
        // SAFETY: as above; `compressed` is the 48-byte G1 compressed length.
        unsafe {
            blst_p1_to_affine(&mut aff, &acc);
            blst_p1_affine_compress(compressed.as_mut_ptr(), &aff);
        }
        let (Ok(pk), Ok(sig)) = (
            PublicKey::from_bytes(&compressed),
            Signature::from_bytes(signature),
        ) else {
            return false;
        };
        // sig_groupcheck + pk_validate (rejects infinity / non-subgroup aggregate).
        sig.verify(true, signing_root, DST, &[], &pk, true) == BLST_ERROR::BLST_SUCCESS
    }
}
