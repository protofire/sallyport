# Vector index (generated; do not edit)

| id | layer | targets | expected | accept_also | rationale |
|---|---|---|---|---|---|
| `ok_bootstrap` | bootstrap | F1 F9 | 0 | — | Unmutated Sepolia bootstrap at the configured checkpoint root; must initialise. |
| `ok_fab_bootstrap` | bootstrap | F1 F9 F14 | 0 | — | Fabricated-universe positive control: the config trusts the fabricated checkpoint, so the bootstrap is valid. If this fails, the vs1_* rejections above are for the wrong reason. |
| `bootstrap_aggregate_pubkey_wrong` | bootstrap | F1 | 1107 | — | aggregate_pubkey replaced by a member key; the SyncCommittee root changes so the branch fails. (A verifier that ignores aggregate_pubkey entirely would also reject, via 1107, since it is hashed.) |
| `bootstrap_checkpoint_mismatch` | bootstrap | F9 VS2.a | 1107 | — | Checkpoint root is a different real Sepolia block root; hash_tree_root(bootstrap.header.beacon) != checkpoint. |
| `bootstrap_committee_511_pubkeys` | bootstrap | VS2 | 1001 | 1107 | Committee list truncated to 511 entries (Vector[BLSPubkey, 512]). |
| `bootstrap_committee_513_pubkeys` | bootstrap | VS2 | 1001 | 1107 | Committee list with a 513th entry. |
| `bootstrap_committee_branch_10_elements` | bootstrap | VS2 | 1001 | 1107 | current_sync_committee_branch has 10 elements instead of 11. |
| `bootstrap_committee_branch_tampered` | bootstrap | F1 VS2.a | 1107 | — | current_sync_committee_branch[0] bit-flipped: committee no longer proven under the checkpoint state root. |
| `bootstrap_committee_pubkey_swapped` | bootstrap | F1 VS2.a | 1107 | — | pubkeys[0] replaced by pubkeys[7]; aggregate_pubkey and branch untouched, so the committee root mismatches. |
| `bootstrap_execution_hash_vs_branch` | bootstrap | F3 VS2.d | 1201 | 1107 | Gloas: execution_block_hash tampered, execution_branch left intact -> branch fails against body_root. Spec checks is_valid_light_client_header at bootstrap. |
| `bootstrap_pre_gloas_slot` | bootstrap | F14 | 1003 | 1001 1201 1105 | Gloas-shaped bootstrap whose slot is the last Fulu slot; checkpoint root recomputed so only the fork check fails. |
| `bootstrap_pubkey_47_bytes` | bootstrap | VS2 | 1001 | — | pubkeys[3] is 47 bytes: malformed BLSPubkey. |
| `bootstrap_pubkey_infinity_flag` | bootstrap | VS2 | 1001 | 1107 1102 | pubkeys[5] has the compressed-infinity flag set on a non-zero x: invalid encoding. A verifier that hashes before decoding reports 1107 instead. |
| `bootstrap_stale_checkpoint` | bootstrap | F10 VS2 | 1105 | — | current_slot is ws_period_epochs+1 epochs past the checkpoint: instance must be replaced, not initialised. |
| `vs1_fabricated_bootstrap` | bootstrap | VS1 F9 VS2.a | 1107 | — | Fully fabricated bootstrap (fresh committee, consistent branch) submitted against the real checkpoint root. |
| `ok_fab_fork_boundary_signature_slot` | update | F14 VS2.b | 0 | — | attested slot 11505599 (epoch 359549, version 0x90000076), signature_slot 11505600 is the first slot of a new fork (0x90000077). Spec: domain uses the fork version at epoch(signature_slot - 1) = old version. Signed accordingly. |
| `ok_fab_handoff_next_period` | update | F1 | 0 | — | Period-1404 update carrying next committee, then a period-1405 update signed by that committee. |
| `ok_fab_participation_342` | update | VS2.b | 0 | — | Exactly 342/512 valid signers: the threshold boundary (2/3 of 512 rounds up to 342). |
| `ok_update_learn_next_committee` | update | F1 | 0 | — | Real period-1404 LightClientUpdate: attested slot is older than the store's finalised slot but it carries the (unknown) next_sync_committee for period 1405, which the spec accepts (update_has_next_sync_committee). |
| `fab_committee_infinity_pubkey` | update | VS2.b | 1102 | 1001 | Committee member 0 is the point at infinity (consistently hashed into the bootstrap). Bits claim 512/512; the aggregate was made by the other 511. Without KeyValidate the identity key contributes nothing and the signature 'verifies' with a phantom participant. |
| `fab_fork_boundary_wrong_version` | update | F14 VS2.b | 1102 | — | Same headers, but the aggregate was produced under the NEW fork version (epoch of signature_slot instead of signature_slot - 1). A verifier selecting the version by signature_slot's own epoch would wrongly accept. |
| `fab_handoff_skipped_without_next` | update | VS2.a F1 | 1104 | — | Store has no next committee; update signed in period 1405 by the same committee (even though it is the same keys) must be rejected: the handoff was never proven. |
| `fab_participation_341` | update | VS2.b F1 | 1103 | — | 341/512 signers with a genuinely valid aggregate signature: below threshold by one. |
| `fab_participation_341_then_attest` | update | VS2.b VS2.c | 1103 | — | Same, followed by an otherwise-valid inclusion under A1: must never reach the attest layer. |
| `fab_period_gap_plus_2` | update | VS2.a F1 | 1104 | — | After learning the next committee at period 1404, an update signed in period 1406 (signature_slot 11517953). |
| `fab_sig_bit_added_to_valid_400` | update | VS2.b | 1102 | — | 400 valid signers; bit 400 set without its signature. |
| `fab_sig_bit_dropped_from_valid_400` | update | VS2.b | 1102 | — | 400 signed; bit 399 cleared so the aggregate key no longer matches. |
| `ok_update_finality` | update | F1 F2 | 1106 | — | Real, fully valid finality update (510/512) whose finalised header IS the bootstrap header. BY DESIGN the store rejects a store-neutral update as not newer (1106) before any other check; it must not be accepted as progress. The real Sepolia fixtures contain no finality-advancing update, so advancing positive controls are ok_fab_*. |
| `ok_update_optimistic` | update | F1 | 1106 | 1101 | Real optimistic update (no finalized_header). BY DESIGN the on-chain store keeps no optimistic data, so a non-finality update is never accepted; documented as 1106 (1101 also acceptable). |
| `update_attested_slot_tampered` | update | VS2.b F1 | 1102 | — | Signed over attested slot 11505599 (signature_slot 11505602); slot changed to 11505600, still < signature_slot, so only the signature no longer covers the header. |
| `update_bits_63_bytes` | update | VS2 | 1001 | — | sync_committee_bits is 63 bytes. |
| `update_branch_element_31_bytes` | update | VS2 | 1001 | 1101 | FU2 finality_branch[0] is 31 bytes. |
| `update_duplicate` | update | VS2 F1 | 1106 | — | Same finality update submitted twice; second is not newer. |
| `update_duplicate_period_update` | update | VS2 F1 | 1106 | 1104 | Period-1404 update applied twice; second brings nothing new (next committee already known, finality not newer). |
| `update_finality_branch_short` | update | VS2 | 1001 | 1101 | FU2 finality_branch has 8 elements instead of 9. |
| `update_finality_branch_tampered` | update | F2 VS2.c | 1101 | — | FU2 with finality_branch[2] bit-flipped. |
| `update_finalized_execution_hash_tampered` | update | F3 VS2.d | 1201 | 1101 | Gloas: FU2 finalized_header.execution_block_hash tampered, beacon root unchanged, execution_branch stale. |
| `update_finalized_header_tampered` | update | F2 VS2.c | 1101 | — | FU2 with finalized_header.state_root changed; its root is no longer the leaf proven by finality_branch. |
| `update_next_committee_branch_tampered` | update | VS2.a F1 | 1104 | — | next_sync_committee_branch[0] bit-flipped; handoff for period 1405 not proven. |
| `update_next_committee_member_swapped` | update | VS2.a | 1104 | — | A member of the claimed next committee replaced; committee root != proven leaf. |
| `update_nonsigner_hint_duplicates` | update | VS2.b | 1102 | 1001 | 511 signed (member 0 absent), bits claim 512/512, hint lists member 0 twice. |
| `update_nonsigner_hint_foreign_pubkey` | update | VS2.b | 1102 | 1001 | 511 signed, bits claim 512/512, hint names a pubkey that is not in the committee. |
| `update_nonsigner_hint_subtracts_everyone` | update | VS2.b VS6 | 1102 | 1001 | bits=512/512, hint lists every committee member, signature=infinity. A verifier computing aggregate_pubkey - sum(hint) gets the identity and may 'verify' infinity against it. Bits are authoritative. |
| `update_older_period` | update | VS2.a F1 | 1104 | 1106 | Real period-1403 update against a period-1404 store: signature period not in {store, store+1}; also not newer. |
| `update_participation_zero_infinity_sig` | update | VS2.b | 1103 | — | Zero participants + infinity signature: eth_fast_aggregate_verify(empty, msg, inf) is TRUE per spec, so only the participation threshold can reject. |
| `update_replay_mainnet_gvr` | update | F5 F14 VS2.e | 1102 | 1002 | Verifier configured for mainnet identity (chain_id 1, mainnet genesis_validators_root; fork schedule and checkpoint kept so only the binding differs). FU2 was signed under the Sepolia domain, so it fails. |
| `update_replay_wrong_fork_version` | update | F14 | 1102 | — | Config whose Gloas fork version is 0x90000077 instead of 0x90000076: domain differs, FU2's signature fails. |
| `update_sig_bit_added_nonsigner` | update | VS2.b F1 | 1102 | — | 511 valid signers; participation bit 347 set although member 347 did not sign. |
| `update_sig_byte_flipped` | update | VS2.b | 1102 | 1001 | FU2 signature byte 10 bit-flipped (still a well-formed point with high probability). |
| `update_sig_infinity_full_bits` | update | VS2.b | 1102 | — | FU2 with all 512 bits set but signature = point at infinity. |
| `update_sig_not_in_g2_subgroup` | update | VS2.b | 1102 | 1001 | FU2 signature replaced by a valid point on E'(Fp2) outside the prime-order subgroup; must fail subgroup check, not be pairing-tested. |
| `update_signature_slot_in_future` | update | VS2 | 1001 | 1106 | current_slot < signature_slot: the update claims a signature from the future. |
| `update_signature_slot_not_after_attested` | update | VS2 | 1001 | 1102 1106 | signature_slot == attested slot violates signature_slot > attested_slot. |
| `vs1_fabricated_chain_after_real_handoff` | update | VS1 VS2.a | 1102 | — | Real period-1404 update first (store learns the real period-1405 committee), then the fabricated period-1405 update: the signature is checked against the real next committee and fails. |
| `vs1_fabricated_chain_log` | update | VS1 F3 | 1102 | — | Same fabricated chain; the inclusion claim is a fabricated Transfer log to the attacker. |
| `vs1_fabricated_chain_next_period` | update | VS1 VS2.a F1 | 1104 | — | Fabricated update signed in period 1405 (signature_slot 11509761) carrying a fabricated next_sync_committee, while the real store knows no next committee: handoff never verified from the checkpoint. |
| `vs1_fabricated_chain_same_period` | update | VS1 VS2.a VS2.b F1 F3 | 1102 | — | THE central test. Real bootstrap. Then a fully self-consistent fabricated update (attested A2 -> finalised A1, valid finality_branch, valid execution_branch, 512/512 participation, genuinely valid BLS aggregate over A2) signed by 512 freshly generated keys, followed by valid MPT proofs over invented state (WETH balance 1e27) under A1. Only the fact that the signers are not the tracked period-1404 committee can reject it. |
| `ok_attest_account` | attest | F3 F4 F6 | 0 | — | WETH account under the finalised bootstrap header, balance equality predicate. |
| `ok_attest_account_lt` | attest | F4 | 0 | — | Same account, strict less-than over 256-bit balance. |
| `ok_attest_log` | attest | F3 F4 F6 | 0 | — | Receipt log (tx 2, log 0) proven in the receipts trie rebuilt from eth_getBlockReceipts; address equality. |
| `ok_attest_log_multi` | attest | F3 | 0 | — | tx 1 has 6 logs; log 5 with topic0 equality (log position within receipt must be honoured). |
| `ok_attest_storage` | attest | F3 F4 F6 | 0 | — | WETH storage slot 0 ('Wrapped Ether' name) under the finalised header. |
| `ok_fab_attest_log` | attest | F3 | 0 | — | Fabricated-universe log inclusion positive control. |
| `ok_fab_finalise_and_attest` | attest | F1 F2 F3 | 0 | — | Fabricated finality update (attested A2 finalises A1 > F0), then inclusion of the invented WETH account under A1. |
| `attest_account_proof_node_tampered` | attest | F3 VS2.f | 1202 | — | Last account proof node bit-flipped. |
| `attest_account_proof_truncated` | attest | F3 VS2.f | 1202 | 1001 | Account proof missing its leaf node. |
| `attest_account_proof_wrong_address` | attest | F3 VS2.f | 1202 | — | WETH's proof presented for address 0x..01: the key path diverges and the proof does not terminate for that key. |
| `attest_el_receipts_root_tampered` | attest | F3 VS2.d | 1201 | — | EL header RLP with receiptsRoot bit-flipped: keccak mismatch. |
| `attest_el_rlp_extra_field` | attest | VS2 | 1201 | 1001 | Valid header RLP with one extra 32-byte field appended inside the list: keccak differs. |
| `attest_el_rlp_truncated` | attest | VS2 | 1001 | 1201 | EL header RLP cut at 500 bytes. |
| `attest_el_state_root_tampered` | attest | F3 VS2.d | 1201 | — | EL header RLP with stateRoot bit-flipped: keccak(rlp) != execution_block_hash of the finalised header. |
| `attest_fact_block_hash_mismatch` | attest | F6 VS2 | 1204 | — | Expected fact names a different (real, non-finalised) execution block hash. |
| `attest_fact_chain_id_mismatch` | attest | F5 F14 F15 VS2.e | 1002 | 1204 | Expected fact claims chain_id 1 for the same WETH address; verifier is bound to 11155111. |
| `attest_fact_gvr_mismatch` | attest | F5 F15 VS2.e | 1002 | 1204 | Expected fact carries the mainnet genesis_validators_root (same chain_id). |
| `attest_fact_value_mismatch` | attest | F6 | 1204 | — | Expected fact's balance differs from the proven one. |
| `attest_header_execution_hash_rebound` | attest | F3 VS2.d | 1201 | — | Claim header carries execution_block_hash = keccak(tampered RLP) with the original execution_branch: the verifier must re-check the branch against the finalised body_root instead of trusting the supplied header. |
| `attest_log_index_out_of_range` | attest | F3 VS2.f | 1202 | — | tx 2 has exactly one log; log_index 1 does not exist. |
| `attest_log_index_wrong_log` | attest | F3 F4 VS2.f | 1203 | — | tx 1 log 1 is proven but the predicate asserts log 0's emitter address; the fact is valid, the predicate is false. |
| `attest_log_wrong_tx_index` | attest | F3 VS2.f | 1202 | — | Receipt proof for tx 2 presented with locator tx_index 3. |
| `attest_predicate_false` | attest | F4 | 1203 | — | Balance equality against balance+1. |
| `attest_predicate_field_not_in_fact` | attest | F4 VS2.f | 1203 | 1001 | Storage-slot fact with a predicate over 'balance': the proof does not cover that field. |
| `attest_storage_proof_missing` | attest | F3 VS2.f | 1202 | 1001 | Storage locator with an account proof only. |
| `attest_storage_proof_node_tampered` | attest | F3 VS2.f | 1202 | — | Last storage proof node bit-flipped. |
| `attest_storage_slot_not_covered` | attest | F3 VS2.f | 1202 | — | Locator is slot 1 but the storage proof is for slot 0 (predicate over state the proof does not cover). |
| `attest_under_optimistic_header` | attest | F2 VS2.c | 1101 | 1201 | The claim names the real attested (non-finalised) header of the finality update, slot 11505537, which the store never finalised; EL material is the finalised block's (a hash check would also fail -> 1201 accepted). |
| `attest_under_unknown_header` | attest | F2 VS2.c | 1101 | — | Self-consistent header the store has never verified (its execution_branch even proves the real block hash). Finality is a store property, not a header property. |
| `fab_attest_under_optimistic_header` | attest | F2 VS2.c | 1101 | — | FU2 finalises A1; the claim is under A2, the attested (optimistic) header of that same update. Inclusion under A2 is fully valid (E2 keccaks to A2's execution_block_hash, proofs verify) but A2 is not finalised. |
| `vs1_fabricated_el_header_under_real_header` | attest | VS1 F3 VS2.d | 1201 | — | Real finalised header; fabricated EL header (invented stateRoot) whose keccak is not the finalised execution_block_hash. |
| `vs1_fabricated_inclusion_under_real_header` | attest | VS1 F3 VS2.f | 1202 | — | Real finalised header and real EL header; MPT proofs over the invented state (different state root). |
