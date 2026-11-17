//! Minimal SSZ merkleization for the handful of fixed containers the light client needs.

use crate::{
    BeaconBlockHeader, ExecutionPayloadHeader, Root, SyncCommittee, DOMAIN_SYNC_COMMITTEE,
};

#[cfg(not(all(target_os = "zkvm", target_arch = "riscv32")))]
pub(crate) fn hash2(a: &Root, b: &Root) -> Root {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// Same SHA-256 as above through the risc0 accelerator in one syscall (the `sha2` Digest path costs
/// ~2.1k cycles per 64-byte hash, this ~0.2k): block 1 = `a ‖ b`, block 2 = the fixed padding of a
/// 64-byte message. State words are kept in big-endian memory order, as the syscall expects, so the
/// output state bytes are the digest. `sys_sha_buffer` is exported by risc0-zkvm-platform (already
/// linked by the guest; the risc0 `sha2` fork declares it the same way).
#[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
pub(crate) fn hash2(a: &Root, b: &Root) -> Root {
    let mut buf = [0u32; 32]; // word-aligned 128-byte buffer
    let mut state = zkvm_sha::IV;
    // SAFETY: `buf` is 128 bytes; the syscall reads 2 blocks from it and writes 8 words to `state`.
    unsafe {
        let bytes = core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 128);
        bytes[..32].copy_from_slice(a);
        bytes[32..64].copy_from_slice(b);
        bytes[64] = 0x80;
        bytes[126] = 0x02; // bit length 512 = 0x0200, big-endian in bytes 120..128
        zkvm_sha::sys_sha_buffer(&mut state, &state, buf.as_ptr() as *const u8, 2);
        core::mem::transmute(state)
    }
}

#[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
mod zkvm_sha {
    extern "C" {
        pub fn sys_sha_buffer(
            out: *mut [u32; 8],
            state: *const [u32; 8],
            buf: *const u8,
            blocks: u32,
        );
    }
    pub const IV: [u32; 8] = [
        0x6a09e667u32.to_be(),
        0xbb67ae85u32.to_be(),
        0x3c6ef372u32.to_be(),
        0xa54ff53au32.to_be(),
        0x510e527fu32.to_be(),
        0x9b05688cu32.to_be(),
        0x1f83d9abu32.to_be(),
        0x5be0cd19u32.to_be(),
    ];
}

/// SHA-256 of any message through the same syscall and IV/state convention as [`hash2`]; exists
/// so a guest differential test can check that convention (padding, endianness, multi-block)
/// against the `sha2` crate on arbitrary lengths. Not used on the verification path.
#[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
pub fn sha256_syscall(msg: &[u8]) -> Root {
    let blocks = (msg.len() + 9).div_ceil(64);
    let mut buf = vec![0u32; blocks * 16];
    let mut state = zkvm_sha::IV;
    // SAFETY: `buf` is `blocks * 64` bytes; the syscall reads that many and writes 8 words.
    unsafe {
        let bytes = core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, blocks * 64);
        bytes[..msg.len()].copy_from_slice(msg);
        bytes[msg.len()] = 0x80;
        bytes[blocks * 64 - 8..].copy_from_slice(&((msg.len() as u64) * 8).to_be_bytes());
        zkvm_sha::sys_sha_buffer(&mut state, &state, buf.as_ptr() as *const u8, blocks as u32);
        core::mem::transmute(state)
    }
}

/// Host twin of the guest [`sha256_syscall`] (plain `sha2`), so the function exists on both sides.
#[cfg(not(all(target_os = "zkvm", target_arch = "riscv32")))]
pub fn sha256_syscall(msg: &[u8]) -> Root {
    use sha2::{Digest, Sha256};
    Sha256::digest(msg).into()
}

/// [`hash2`] exported for the guest differential test (the production SSZ pair hash).
#[doc(hidden)]
pub fn sha256_pair(a: &Root, b: &Root) -> Root {
    hash2(a, b)
}

fn u64_chunk(v: u64) -> Root {
    let mut c = [0u8; 32];
    c[..8].copy_from_slice(&v.to_le_bytes());
    c
}

/// Packs bytes into zero-padded 32-byte chunks.
fn pack(bytes: &[u8]) -> Vec<Root> {
    bytes
        .chunks(32)
        .map(|c| {
            let mut r = [0u8; 32];
            r[..c.len()].copy_from_slice(c);
            r
        })
        .collect()
}

/// Merkleizes `layer` (in place) padded with zero chunks up to `limit` leaves (`limit` a power of two).
fn merkleize(mut layer: Vec<Root>, limit: usize) -> Root {
    debug_assert!(limit.is_power_of_two() && layer.len() <= limit);
    let mut zero = [0u8; 32];
    let mut width = limit;
    while width > 1 {
        if layer.len() % 2 == 1 {
            layer.push(zero);
        }
        for i in 0..layer.len() / 2 {
            layer[i] = hash2(&layer[2 * i], &layer[2 * i + 1]);
        }
        layer.truncate(layer.len() / 2);
        zero = hash2(&zero, &zero);
        width /= 2;
    }
    layer.first().copied().unwrap_or(zero)
}

/// `hash_tree_root(Bytes48)` = sha256(pk[..32] ‖ pk[32..] ‖ 0^16).
fn pubkey_root(pk: &[u8; 48]) -> Root {
    let mut tail = [0u8; 32];
    tail[..16].copy_from_slice(&pk[32..]);
    hash2(pk[..32].try_into().unwrap(), &tail)
}

pub fn hash_tree_root_header(h: &BeaconBlockHeader) -> Root {
    merkleize(
        vec![
            u64_chunk(h.slot),
            u64_chunk(h.proposer_index),
            h.parent_root,
            h.state_root,
            h.body_root,
        ],
        8,
    )
}

/// Caller guarantees `pubkeys.len() == 512`.
pub fn hash_tree_root_sync_committee(c: &SyncCommittee) -> Root {
    let leaves: Vec<Root> = c.pubkeys.iter().map(pubkey_root).collect();
    hash2(
        &merkleize(leaves, crate::SYNC_COMMITTEE_SIZE),
        &pubkey_root(&c.aggregate_pubkey),
    )
}

/// Caller guarantees `extra_data.len() <= 32`.
pub fn hash_tree_root_execution(h: &ExecutionPayloadHeader) -> Root {
    let mut fee_recipient = [0u8; 32];
    fee_recipient[..20].copy_from_slice(&h.fee_recipient);
    // ByteList[32]: one chunk, mixed with its length.
    let extra = hash2(
        &merkleize(pack(&h.extra_data), 1),
        &u64_chunk(h.extra_data.len() as u64),
    );
    let fields = [
        h.parent_hash,
        fee_recipient,
        h.state_root,
        h.receipts_root,
        merkleize(pack(&h.logs_bloom), 8),
        h.prev_randao,
        u64_chunk(h.block_number),
        u64_chunk(h.gas_limit),
        u64_chunk(h.gas_used),
        u64_chunk(h.timestamp),
        extra,
        h.base_fee_per_gas,
        h.block_hash,
        h.transactions_root,
        h.withdrawals_root,
        u64_chunk(h.blob_gas_used),
        u64_chunk(h.excess_blob_gas),
    ];
    merkleize(fields.to_vec(), 32)
}

/// `compute_signing_root(header_root, compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version, gvr))`.
pub fn signing_root(
    object_root: &Root,
    fork_version: [u8; 4],
    genesis_validators_root: &Root,
) -> Root {
    let mut v = [0u8; 32];
    v[..4].copy_from_slice(&fork_version);
    let fork_data_root = hash2(&v, genesis_validators_root);
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&DOMAIN_SYNC_COMMITTEE);
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    hash2(object_root, &domain)
}

/// `is_valid_normalized_merkle_branch`: `branch` may be longer than depth(gindex) only by leading
/// zero nodes (fork-upgraded branches).
pub fn is_valid_normalized_branch(leaf: &Root, branch: &[Root], gindex: u64, root: &Root) -> bool {
    let depth = 63 - gindex.leading_zeros() as usize;
    let Some(extra) = branch.len().checked_sub(depth) else {
        return false;
    };
    if branch[..extra].iter().any(|n| n != &[0u8; 32]) {
        return false;
    }
    let mut node = *leaf;
    for (i, sib) in branch[extra..].iter().enumerate() {
        node = if gindex >> i & 1 == 1 {
            hash2(sib, &node)
        } else {
            hash2(&node, sib)
        };
    }
    &node == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkleize_zero_padding() {
        let z = [0u8; 32];
        assert_eq!(merkleize(vec![], 1), z);
        assert_eq!(merkleize(vec![], 4), hash2(&hash2(&z, &z), &hash2(&z, &z)));
        let a = [1u8; 32];
        assert_eq!(merkleize(vec![a], 2), hash2(&a, &z));
        assert_eq!(
            merkleize(vec![a, a, a], 4),
            hash2(&hash2(&a, &a), &hash2(&a, &z))
        );
        let mut pk = [0u8; 48];
        pk[0] = 0xb0;
        pk[47] = 7;
        assert_eq!(pubkey_root(&pk), merkleize(pack(&pk), 2));
    }

    #[test]
    fn branch_roundtrip_and_normalization() {
        let leaf = [9u8; 32];
        let sibs = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let gindex = 0b1101; // depth 3, index 5
        let mut node = leaf;
        node = hash2(&sibs[0], &node); // bit0 = 1
        node = hash2(&node, &sibs[1]); // bit1 = 0
        node = hash2(&sibs[2], &node); // bit2 = 1
        assert!(is_valid_normalized_branch(&leaf, &sibs, gindex, &node));
        let mut padded = vec![[0u8; 32]; 2];
        padded.extend(sibs);
        assert!(is_valid_normalized_branch(&leaf, &padded, gindex, &node));
        padded[0][0] = 1;
        assert!(!is_valid_normalized_branch(&leaf, &padded, gindex, &node));
        assert!(!is_valid_normalized_branch(
            &leaf,
            &sibs[..2],
            gindex,
            &node
        ));
    }
}
