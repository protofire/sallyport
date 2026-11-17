//! UpdateVerify cost split (Performance #8): Miller loop vs residue check, in guest user cycles.
use attest_program::{bls, residue};
use risc0_zkvm::guest::env;

fn main() {
    let (apk, h, sig, witness): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = env::read();
    let c0 = env::cycle_count();
    let f = bls::miller(&apk, &h, &sig).expect("encodings");
    let c1 = env::cycle_count();
    assert!(residue::check(&f, &witness), "residue");
    let c2 = env::cycle_count();
    env::commit(&(c1 - c0, c2 - c1));
}
