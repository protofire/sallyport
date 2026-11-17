//! Differential test of `inclusion::verify_mpt` / `mpt_lookup` (zero-copy, D-GAS-1/8) against alloy-trie's
//! `verify_proof` on generated tries: identical verdicts on honest proofs (present and absent keys,
//! hashed 32-byte keys and receipt-style rlp(index) keys, small values that get embedded inline),
//! and never more lenient on tampered proofs.
use alloy_primitives::{keccak256, Bytes, B256};
use alloy_trie::{proof::verify_proof, proof::ProofRetainer, HashBuilder, Nibbles};
use inclusion::{mpt_lookup, verify_mpt};

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn build(leaves: &[(Vec<u8>, Vec<u8>)], target: &[u8]) -> ([u8; 32], Vec<Vec<u8>>) {
    let t = Nibbles::unpack(target);
    let mut l: Vec<(Nibbles, &Vec<u8>)> = leaves
        .iter()
        .map(|(k, v)| (Nibbles::unpack(k), v))
        .collect();
    l.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([t]));
    for (k, v) in &l {
        hb.add_leaf(*k, v);
    }
    let root = hb.root();
    let proof = hb
        .take_proof_nodes()
        .matching_nodes_sorted(&t)
        .into_iter()
        .map(|(_, n)| n.to_vec())
        .enumerate()
        // the retainer also lists nodes embedded in their parent; RPC proofs carry only hashed ones
        .filter(|(i, n)| *i == 0 || n.len() >= 32)
        .map(|(_, n)| n)
        .collect();
    (root.0, proof)
}

fn alloy(root: &[u8; 32], key: &[u8], value: Option<&[u8]>, proof: &[Vec<u8>]) -> bool {
    let nodes: Vec<Bytes> = proof.iter().map(|n| Bytes::copy_from_slice(n)).collect();
    verify_proof(
        B256::from(*root),
        Nibbles::unpack(key),
        value.map(|v| v.to_vec()),
        &nodes,
    )
    .is_ok()
}

fn check(rng: &mut Lcg, leaves: &[(Vec<u8>, Vec<u8>)], key: &[u8], present: Option<&[u8]>) -> bool {
    let (root, proof) = build(leaves, key);
    // honest: same verdict, and the right one
    let ok = alloy(&root, key, present, &proof);
    assert_eq!(
        verify_mpt(&root, key, present, &proof),
        ok,
        "verdicts differ on an honest proof"
    );
    if !ok {
        return false; // root node < 32 bytes: both reject (counted below)
    }
    // the lookup (compact receipt witness, D-GAS-6) returns exactly the honest value / absence
    assert_eq!(mpt_lookup(&root, key, &proof), Some(present));
    // wrong claimed value / wrong presence
    let wrong: Vec<u8> = present.map_or(vec![1], |v| [v, &[0]].concat());
    assert!(!verify_mpt(&root, key, Some(&wrong), &proof));
    if present.is_some() {
        assert!(!verify_mpt(&root, key, None, &proof));
    }
    // tampering: never accept what alloy rejects
    let mut cases: Vec<Vec<Vec<u8>>> = vec![];
    if !proof.is_empty() {
        cases.push(proof[..proof.len() - 1].to_vec());
        cases.push(proof[1..].to_vec());
        let mut p = proof.clone();
        let i = rng.next() as usize % p.len();
        let j = rng.next() as usize % p[i].len();
        p[i][j] ^= 1 << (rng.next() % 8);
        cases.push(p);
        let mut p = proof.clone();
        p.push(proof[proof.len() - 1].clone());
        cases.push(p);
    }
    for p in cases {
        // whatever the lookup returns from a tampered proof, alloy-trie accepts too
        if let Some(found) = mpt_lookup(&root, key, &p) {
            assert!(
                alloy(&root, key, found, &p),
                "lookup more lenient than alloy-trie"
            );
        }
        for v in [present, None, Some(&wrong[..])] {
            if verify_mpt(&root, key, v, &p) {
                assert!(alloy(&root, key, v, &p), "more lenient than alloy-trie");
            }
        }
    }
    true
}

#[test]
fn verify_mpt_matches_alloy_trie() {
    let mut rng = Lcg(7);
    let (mut checked, mut honest) = (0, 0);
    for round in 0..1000 {
        let n = 1 + rng.next() as usize % if round % 3 == 0 { 4 } else { 120 };
        let receipt_keys = round % 2 == 1;
        let key = |i: usize, rng: &mut Lcg| -> Vec<u8> {
            if receipt_keys {
                alloy_rlp::encode(i as u32)
            } else {
                keccak256(rng.bytes(8)).to_vec()
            }
        };
        let leaves: Vec<(Vec<u8>, Vec<u8>)> = (0..n)
            .map(|i| {
                let k = key(i, &mut rng);
                // short values make leaves < 32 bytes, embedded in their parent
                let len = 1 + rng.next() as usize % if rng.next() % 2 == 0 { 3 } else { 120 };
                (k, rng.bytes(len))
            })
            .collect();
        let pick = rng.next() as usize % n;
        checked += 1;
        honest += check(&mut rng, &leaves, &leaves[pick].0, Some(&leaves[pick].1)) as u32;
        let absent = key(n + 1 + rng.next() as usize % 50, &mut rng);
        if leaves.iter().all(|(k, _)| *k != absent) {
            checked += 1;
            honest += check(&mut rng, &leaves, &absent, None) as u32;
        }
    }
    eprintln!("honest {honest}/{checked}");
    assert!(
        honest * 10 >= checked * 9,
        "too few accepted honest proofs: {honest}/{checked}"
    );
    // empty trie
    let root = alloy_trie::EMPTY_ROOT_HASH.0;
    assert!(verify_mpt::<Vec<u8>>(&root, &[1; 32], None, &[]));
    assert!(verify_mpt(&root, &[1; 32], None, &[vec![0x80]]));
    assert!(!verify_mpt::<Vec<u8>>(&root, &[1; 32], Some(&[1]), &[]));
    assert!(!verify_mpt::<Vec<u8>>(&[0; 32], &[1; 32], None, &[]));
}
