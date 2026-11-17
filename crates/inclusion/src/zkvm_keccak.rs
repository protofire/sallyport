//! Guest-only `native_keccak256` for alloy-primitives' `native-keccak` feature: Keccak-256 sponge
//! whose keccak-f[1600] permutations run on the risc0 keccak coprocessor
//! (`risc0_zkvm::guest::env::risc0_keccak_update`; batched and proven by the keccak circuit,
//! resolved as an assumption of the program receipt). Every alloy/alloy-trie keccak256 in the
//! guest lands here. Correctness is checked end to end: header hashes and MPT roots in the
//! executor tests only match real Ethereum data if this is bit-exact Keccak-256.
use risc0_zkvm::guest::env::risc0_keccak_update;

const RATE: usize = 136;

// Keep the aligned load boundary: inlining can fold the copy back into byte
// loads from the unaligned RLP input on RV32.
#[inline(never)]
fn absorb(state: &mut [u64; 25], block: &[u64; RATE / 8]) {
    for (lane, word) in state.iter_mut().zip(block) {
        *lane ^= u64::from_le(*word);
    }
    risc0_keccak_update(state);
}

/// # Safety
/// `bytes` points to `len` readable bytes and `output` to 32 writable bytes (alloy's contract).
#[no_mangle]
unsafe extern "C" fn native_keccak256(bytes: *const u8, len: usize, output: *mut u8) {
    let input = core::slice::from_raw_parts(bytes, len);
    let mut state = [0u64; 25];
    let mut blocks = input.chunks_exact(RATE);
    for block in &mut blocks {
        let mut aligned = [0u64; RATE / 8];
        let bytes = core::slice::from_raw_parts_mut(aligned.as_mut_ptr().cast::<u8>(), RATE);
        bytes.copy_from_slice(block);
        absorb(&mut state, &aligned);
    }
    let rem = blocks.remainder();
    let mut aligned = [0u64; RATE / 8];
    let last = core::slice::from_raw_parts_mut(aligned.as_mut_ptr().cast::<u8>(), RATE);
    last[..rem.len()].copy_from_slice(rem);
    last[rem.len()] ^= 0x01; // Keccak (pre-SHA3) padding
    last[RATE - 1] ^= 0x80;
    absorb(&mut state, &aligned);
    let out = core::slice::from_raw_parts_mut(output, 32);
    for (o, lane) in out.chunks_exact_mut(8).zip(state) {
        o.copy_from_slice(&lane.to_le_bytes());
    }
}
