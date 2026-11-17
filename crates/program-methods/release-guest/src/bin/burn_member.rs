//! `burn_member` (docs/ARCHITECTURE.md §3.6): proves `B = sha256("b022/burn" ‖ rk ‖ recipient)` is leaf
//! `index` of `burnRoot` and commits the ABI release journal with `Nb = sha256("b022/rnf" ‖ rk)`.
//! Private inputs: `rk`, leaf index, path (`recipient` is private input and public output). Input:
//! one borsh blob (risc0 `env::read::<Vec<u8>>`) `(ReleaseJournal, rk, index, path)`; the journal's `nb` is recomputed here.
use bridge_core::{burn_commitment, burn_nullifier, merkle_root, ReleaseJournal};
use risc0_zkvm::guest::env;

fn main() {
    let (mut j, rk, index, path): (ReleaseJournal, [u8; 32], u64, Vec<[u8; 32]>) =
        borsh::from_slice(&env::read::<Vec<u8>>()).expect("malformed input");
    let b = burn_commitment(&rk, &j.recipient);
    assert!(merkle_root(b, index, &path) == Some(j.burn_root), "not a member of burnRoot");
    j.nb = burn_nullifier(&rk);
    env::commit_slice(&j.encode());
}
