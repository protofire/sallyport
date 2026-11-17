//! `--local` only: a **devnet beacon** for anvil, so the unchanged attest program can record anvil
//! blocks. Anvil has no consensus layer; this module plays one: a 512-seat sync committee that is
//! one BLS key repeated (participation 512/512), Electra-shaped light-client headers whose
//! `execution_payload_header.block_hash` is the anvil block hash, and SSZ branches whose siblings are
//! zero (the state/body roots are whatever those branches hash to). The attest guest verifies it
//! exactly as it verifies Sepolia (same Init/Update path, same BLS check); only the trust root differs.
//! Never used on Sepolia (there the real beacon chain and the RFP-021 relayer feed the instance).

use attest_program::InstanceConfig;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, SecretKey};
use lc_core::*;

const FORK: [u8; 4] = [0xb2, 0x22, 0x00, 0x01];

pub struct Devnet {
    pub cfg: InstanceConfig,
    sk: SecretKey,
    committee: SyncCommittee,
}

/// Root of a branch of zero siblings over `leaf` at `gindex`.
fn zero_branch_root(leaf: Root, (gindex, len): (u64, usize)) -> (Root, Vec<Root>) {
    let mut node = leaf;
    for i in 0..len {
        node = if gindex >> i & 1 == 1 {
            sha256_pair(&[0; 32], &node)
        } else {
            sha256_pair(&node, &[0; 32])
        };
    }
    (node, vec![[0; 32]; len])
}

impl Devnet {
    /// `genesis_time` fixes the slot clock (binds `now_slot` to LEZ block time, as for Sepolia).
    pub fn new(chain_id: u64, genesis_time: u64, key_seed: &[u8; 32]) -> Self {
        let sk = SecretKey::key_gen(key_seed, &[]).expect("32-byte ikm");
        let pk = sk.sk_to_pk();
        let pks = vec![&pk; SYNC_COMMITTEE_SIZE];
        let agg = AggregatePublicKey::aggregate(&pks, false)
            .unwrap()
            .to_public_key();
        let committee = SyncCommittee {
            pubkeys: vec![pk.compress(); SYNC_COMMITTEE_SIZE],
            aggregate_pubkey: agg.compress(),
        };
        let mut gvr = [0u8; 32];
        gvr[..16].copy_from_slice(b"b022/devnet-gvr\0");
        let cfg = InstanceConfig {
            chain: ChainConfig {
                chain_id,
                genesis_validators_root: gvr,
                fork_versions: vec![(0, FORK)],
                electra_fork_epoch: 0,
                gloas_fork_epoch: u64::MAX,
                min_participation: 512,
                ws_period_epochs: SEPOLIA_WS_PERIOD_EPOCHS,
            },
            genesis_time,
        };
        Self { cfg, sk, committee }
    }

    pub fn now_slot(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (now - self.cfg.genesis_time) / 12
    }

    fn header(&self, slot: u64, ebh: Root, state_root: Root) -> LightClientHeader {
        let p = ExecutionPayloadHeader {
            parent_hash: [0; 32],
            fee_recipient: [0; 20],
            state_root: [0; 32],
            receipts_root: [0; 32],
            logs_bloom: [0; 256],
            prev_randao: [0; 32],
            block_number: slot,
            gas_limit: 0,
            gas_used: 0,
            timestamp: self.cfg.genesis_time + 12 * slot,
            extra_data: vec![],
            base_fee_per_gas: [0; 32],
            block_hash: ebh,
            transactions_root: [0; 32],
            withdrawals_root: [0; 32],
            blob_gas_used: 0,
            excess_blob_gas: 0,
        };
        let (body_root, execution_branch) =
            zero_branch_root(hash_tree_root_execution(&p), EXECUTION_PAYLOAD);
        LightClientHeader {
            beacon: BeaconBlockHeader {
                slot,
                proposer_index: 0,
                parent_root: [0; 32],
                state_root,
                body_root,
            },
            execution: HeaderExecution::Electra(Box::new(p)),
            execution_branch,
        }
    }

    /// `(trusted_block_root, bootstrap)` at `slot` recording EL block `ebh`.
    pub fn bootstrap(&self, slot: u64, ebh: Root) -> (Root, LightClientBootstrap) {
        let (state_root, branch) = zero_branch_root(
            hash_tree_root_sync_committee(&self.committee),
            CURRENT_SC_ELECTRA,
        );
        let header = self.header(slot, ebh, state_root);
        (
            hash_tree_root_header(&header.beacon),
            LightClientBootstrap {
                header,
                current_sync_committee: self.committee.clone(),
                current_sync_committee_branch: branch,
            },
        )
    }

    /// Finality update after a store finalized at `store_slot`: finalizes EL block `ebh` at
    /// `store_slot + 1`, signed at `store_slot + 2` by all 512 seats.
    pub fn finality(&self, store_slot: u64, ebh: Root) -> LightClientUpdate {
        let fin = self.header(store_slot + 1, ebh, [0; 32]);
        let (att_state, fin_branch) =
            zero_branch_root(hash_tree_root_header(&fin.beacon), FINALIZED_ROOT_ELECTRA);
        let att = self.header(store_slot + 1, ebh, att_state);
        let signature_slot = store_slot + 2;
        let root = signing_root(
            &hash_tree_root_header(&att.beacon),
            self.cfg
                .chain
                .fork_version_at(epoch_at_slot(signature_slot - 1))
                .unwrap(),
            &self.cfg.chain.genesis_validators_root,
        );
        let sig = self.sk.sign(&root, host_bls::DST, &[]);
        let sigs = vec![&sig; SYNC_COMMITTEE_SIZE];
        let agg = AggregateSignature::aggregate(&sigs, false)
            .unwrap()
            .to_signature();
        LightClientUpdate {
            attested_header: att,
            next_sync_committee: None,
            finalized_header: Some((fin, fin_branch)),
            sync_aggregate: SyncAggregate {
                sync_committee_bits: [0xff; 64],
                sync_committee_signature: agg.compress(),
            },
            signature_slot,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The devnet bootstrap and a finality update pass lc-core's own checks and the BLS verifier.
    #[test]
    fn devnet_bootstrap_and_finality_verify() {
        let d = Devnet::new(31337, 1_700_000_000, &[7; 32]);
        let now = 4_000;
        let (root, b) = d.bootstrap(100, [0xAB; 32]);
        let mut store = lc_core::bootstrap(&d.cfg.chain, &root, &b, now).unwrap();
        assert_eq!(store.finalized_header.execution_block_hash, [0xAB; 32]);
        for (i, ebh) in [[0xCD; 32], [0xEF; 32]].into_iter().enumerate() {
            let u = d.finality(store.finalized_header.beacon.slot, ebh);
            let v = verify_update(&d.cfg.chain, &store, &u, now, &host_bls::BlstVerifier).unwrap();
            apply_update(&mut store, &v).unwrap();
            assert_eq!(store.finalized_header.execution_block_hash, ebh);
            assert_eq!(store.finalized_header.beacon.slot, 101 + i as u64);
        }
    }
}
