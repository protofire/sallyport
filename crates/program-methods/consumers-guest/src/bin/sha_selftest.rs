//! Test-only guest: hashes each input message with lc-core's `sys_sha_buffer` wrapper (and, for
//! 64-byte messages, the production SSZ pair hash) and commits the digests for a host-side
//! differential check against the `sha2` crate (crates/program-tests/tests/sha_syscall.rs).
use risc0_zkvm::guest::env;

fn main() {
    let msgs: Vec<Vec<u8>> = env::read();
    let mut out = Vec::new();
    for m in &msgs {
        out.extend_from_slice(&lc_core::sha256_syscall(m));
        if m.len() == 64 {
            out.extend_from_slice(&lc_core::sha256_pair(
                m[..32].try_into().unwrap(),
                m[32..].try_into().unwrap(),
            ));
        }
    }
    env::commit_slice(&out);
}
