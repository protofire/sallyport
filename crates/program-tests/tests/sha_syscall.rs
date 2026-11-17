//! Differential test: the guest SHA-256 syscall path (lc-core `sys_sha_buffer` wrapper, D-UPD)
//! executed in the RISC Zero zkVM vs the host `sha2` crate, across padding boundaries.

use program_methods::SHA_SELFTEST_ELF;
use risc0_zkvm::{default_executor, ExecutorEnv};
use sha2::{Digest, Sha256};

#[test]
fn guest_sha_syscall_matches_sha2() {
    // 0, 55/56 (one vs two padded blocks), 63/64/65, 119/120, 128, multi-block
    let lens = [
        0usize, 1, 31, 32, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 200, 1000,
    ];
    let mut msgs: Vec<Vec<u8>> = lens
        .iter()
        .map(|&n| (0..n).map(|i| (i * 131 + n * 7 + 1) as u8).collect())
        .collect();
    msgs.push(vec![0u8; 64]); // zero pair: the SSZ zero-hash ladder input
    msgs.push(vec![0xff; 64]);

    let env = ExecutorEnv::builder()
        .write(&msgs)
        .unwrap()
        .build()
        .unwrap();
    // client-side executor (r0vm); `ExecutorImpl` needs risc0-zkvm/prove, not enabled here
    let session = default_executor().execute(env, SHA_SELFTEST_ELF).unwrap();
    let journal = session.journal.bytes;

    let mut expected = Vec::new();
    for m in &msgs {
        let d: [u8; 32] = Sha256::digest(m).into();
        expected.extend_from_slice(&d);
        if m.len() == 64 {
            expected.extend_from_slice(&d); // sha256_pair(a, b) == sha256(a ‖ b)
        }
    }
    assert_eq!(journal.len(), expected.len());
    for (i, (g, h)) in journal.chunks(32).zip(expected.chunks(32)).enumerate() {
        assert_eq!(hex::encode(g), hex::encode(h), "digest #{i}");
    }
}
