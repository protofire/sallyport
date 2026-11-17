# Adversarial vectors — RFP-021 light-client attestation verifier

Everything here is derived **from the specs and the real Sepolia Gloas fixtures only** (`fixtures/sepolia/*.json`, the error codes in `crates/lc-core/src/lib.rs`, consensus-specs
altair/electra/gloas light-client, Yellow Paper RLP/MPT), written without reading the implementation.

- Vector table: **[index.md](index.md)** (generated; 89 vectors: 74 adversarial cases and 15 positive controls (`ok_*`; 13 expect acceptance, 2 expect 1106 by design); 15 bootstrap / 42 update / 32 attest).
- Schema: [schema.json](schema.json). Every vector validates against it (checked by the generator).
- Machine index: [index.json](index.json).

## Provenance

The vectors were produced by a deterministic Python generator (fixed seeds) that is not part of this
repository; the checked-in files are the artifact, and `crates/vector-runner` replays them. The generator
self-checked before writing: real header root == beacon-API root, real sync signature verifies
under the computed domain, EL header RLP keccaks to `execution_block_hash`, the receipts trie
rebuilt from `eth_getBlockReceipts` reproduces `receiptsRoot`, and the fabricated universe's
branches / BLS aggregates / MPT proofs all verify (so `vs1_*` can only be rejected for ancestry).

## How a harness consumes a vector

```
config  ->  bootstrap (JSON)  ->  updates[] in order (JSON)  ->  attest
```

Freshness gate. The store rejects any update that neither advances finality nor teaches an unknown
next committee with 1106 *before* branch/BLS/chain checks (`UpdateNotNewer`; confirmed when the vectors were first replayed). Every vector that mutates an update therefore mutates an update that genuinely advances
finality, so only the mutation can cause rejection. The real Sepolia fixtures contain **no** update that
advances finality past the bootstrap header (`finality_update` finalises the bootstrap slot itself; the
period-1404 `updates[1]` finalises an older slot), so all such mutations live in the fabricated universe
(`fcfg`/`fabB`, base update `FU2`: attested A2 finalises A1 > F0). Two real-material vectors document
the gate itself: `ok_update_finality` (store-neutral, 1106 by design) and `ok_update_optimistic`
(no `finalized_header`; the store keeps no optimistic data, 1106/1101 by design).

- `layer` is the step at which a spec-correct verifier rejects; every earlier step must succeed.
  `expected_error` is the `ErrorCode` of `crates/lc-core/src/lib.rs` (0 = everything accepted).
- `accept_also` lists codes that are also correct where the spec's check order is not binding
  (e.g. a stale `execution_branch` on a tampered finalised header: 1201 or 1101). Any other
  code, or acceptance, is a finding.
- `config` is `ChainConfig` of `crates/lc-core/src/lib.rs` plus `checkpoint_root` (trusted block root for
  bootstrap) and `current_slot` (the verifier's notion of "now", for `signature_slot <= now`
  and weak-subjectivity). `ws_period_epochs` is 1024 in all vectors (illustrative).
- `bootstrap` / `updates[]` are beacon-API JSON (`data` object). An update with
  `next_sync_committee` is a `LightClientUpdate`, with only `finalized_header` a
  `FinalityUpdate`, with neither an `OptimisticUpdate`. No SSZ: the program ingests JSON/borsh only, so
  malformed-encoding vectors are JSON-shaped (wrong list lengths, short byte strings, bad flag bits).
- `sync_aggregate.non_signers_hint` (optional, 3 vectors) is an *untrusted* hint a submitter might
  supply so an in-guest verifier can subtract non-signers from `aggregate_pubkey`. Bits are
  authoritative. If the implementation has no such field, ignore the hint and the vectors still
  reject (the bits/signature are inconsistent on their own).
- `attest.header` is the `LightClientHeader` the claim is made under. The verifier must check it is
  the finalised header it tracks (root equality) and re-verify its `execution_branch` against
  `body_root`; two vectors supply headers whose beacon root matches but whose execution hash was
  rebound.
- `attest.proof`: `account_proof` / `storage_proof[{key, proof}]` are `eth_getProof` node lists;
  `receipt_proof` is the node list from the receipts trie keyed by `rlp(tx_index)`, value = typed
  receipt (`type || rlp([status, cumulative_gas, bloom, logs])`).
- `attest.predicate.field`: `nonce|balance|storage_root|code_hash` (account), `slot` (storage),
  `log.address|log.topicN|log.data|log.status` (log). Ordered ops compare 256-bit big-endian.
- `attest.expected_fact` (optional): the `Fact` the harness must produce, with `statement_id =
  sha256("rfp021/fact/v1" || borsh(chain_id, gvr, execution_block_hash, locator))`. Encoding
  assumption: the prefix is 14 raw bytes (not a borsh string), locator is borsh enum
  (`u8` tag 0/1/2 + fields, `u32` LE indices). If the implementation encodes differently, treat the
  id mismatch as a conformance discussion, not a vector failure — the rest of the fact is binding.

## Facts recovered from the fixtures (useful to implementers, all verified by the generator)

| Fact | Value |
|---|---|
| Gloas `FINALIZED_ROOT_GINDEX` | **735** (branch depth 9), vs `attested_header.beacon.state_root` |
| Gloas `CURRENT_SYNC_COMMITTEE_GINDEX` / `NEXT_...` | **2945 / 2946** (depth 11), vs `state_root` |
| Gloas `execution_block_hash` gindex | **2856** (depth 11), vs `beacon.body_root` — *not* `state_root` |
| EL header RLP (Sepolia, Glamsterdam) | Prague 21 fields + `blockAccessListHash` + `slotNumber` (23 fields); keccak == `execution_block_hash` |
| Sync-committee domain | `0x07000000 ‖ fork_data_root(version@epoch(signature_slot−1), gvr)[:28]`; verified against the real 510/512 aggregate |
| Sepolia period-1404 committee | 512 keys, only **440 distinct** (duplicates are normal; subtract per index, never per pubkey) |

## Coverage of RFP "Verification Security"

| RFP item | Vectors |
|---|---|
| VS1 fabricated chain (self-consistent header + proofs over never-finalised state, fresh committee with genuinely valid BLS aggregate) | `vs1_fabricated_chain_same_period` (central), `vs1_fabricated_chain_log`, `vs1_fabricated_chain_next_period`, `vs1_fabricated_chain_after_real_handoff`, `vs1_fabricated_bootstrap`, `vs1_fabricated_inclusion_under_real_header`, `vs1_fabricated_el_header_under_real_header`; controls `ok_fab_*` prove the fabricated universe is internally valid |
| VS2.a committee never handed off from checkpoint | `vs1_fabricated_chain_next_period`, `fab_handoff_skipped_without_next`, `fab_period_gap_plus_2`, `update_next_committee_branch_tampered`, `update_next_committee_member_swapped`, `update_older_period`, `bootstrap_*` |
| VS2.b participation below threshold / signature | `fab_participation_341` (+`_then_attest`), `ok_fab_participation_342`, `update_participation_zero_infinity_sig`, `update_sig_*`, `fab_sig_bit_*`, `fab_committee_infinity_pubkey`, `update_nonsigner_hint_*` |
| VS2.c valid inclusion under non-finalised header | `fab_attest_under_optimistic_header` (clean: claim under A2, the attested header of the update that finalised A1), `attest_under_optimistic_header`, `attest_under_unknown_header`, `update_finality_branch_tampered`, `update_finalized_header_tampered` |
| VS2.d finalised header with tampered state / receipts root (Gloas: `execution_block_hash` vs `execution_branch`, RLP keccak) | `attest_el_state_root_tampered`, `attest_el_receipts_root_tampered`, `attest_header_execution_hash_rebound`, `update_finalized_execution_hash_tampered`, `bootstrap_execution_hash_vs_branch` |
| VS2.e replay against a different chain ID (same contract address) | `update_replay_mainnet_gvr`, `attest_fact_chain_id_mismatch`, `attest_fact_gvr_mismatch`, `update_replay_wrong_fork_version` (F14) |
| VS2.f predicate over state the proof does not cover | `attest_storage_slot_not_covered`, `attest_log_wrong_tx_index`, `attest_log_index_out_of_range`, `attest_account_proof_wrong_address`, `attest_predicate_field_not_in_fact`, `attest_log_index_wrong_log` |
| F9/F10 stale checkpoint | `bootstrap_stale_checkpoint`, `bootstrap_checkpoint_mismatch` |
| Fork edge (signature_slot in a different fork than attested slot) | `ok_fab_fork_boundary_signature_slot` (must accept), `fab_fork_boundary_wrong_version` (must reject), `bootstrap_pre_gloas_slot` |
| Malformed / truncated encodings (JSON-shaped SSZ violations, RLP) | `bootstrap_committee_511_pubkeys`, `bootstrap_committee_513_pubkeys`, `bootstrap_committee_branch_10_elements`, `bootstrap_pubkey_infinity_flag`, `bootstrap_pubkey_47_bytes`, `update_bits_63_bytes`, `update_finality_branch_short`, `update_branch_element_31_bytes`, `attest_el_rlp_truncated`, `attest_el_rlp_extra_field`, `attest_account_proof_truncated` |
| Duplicate / older update | `update_duplicate`, `update_duplicate_period_update`, `update_older_period` |
| F6 statement identity | `attest_fact_block_hash_mismatch`, `attest_fact_value_mismatch`, `ok_attest_*` carry `statement_id` |
| VS3 (verification logic not swappable), VS4/VS5 (docs), VS6 (identity-blind acceptance) | not encodable as static vectors — see below |

The fabricated universe: 512 keys from `sha256("rfp021-redteam"‖i)`, committee `C`; headers
`F0(11505472) ← A1(11505536) ← A2(11505599) ← A3(11509760, period 1405)`; each header's
`state_root` is a sparse Merkle tree with `C` at 2945/2946 and the previous header's root at 735,
`body_root` a sparse tree with the fabricated EL block hash at 2856. EL state: WETH
(`0x7b79…e7f9`) with 1e27 wei, storage slot 0 = real name, slot 1 = `0xde…`, attacker
`0xbad…0bad` with 1e27 wei; one type-2 receipt with a `Transfer` log to the attacker.

## Attacks considered but not encodable as static vectors

| Attack | Why not static | Suggested test |
|---|---|---|
| **VS3 mutable `ProgramId` indirection** | Property of program/account layout, not of an input. | Static scan: no consensus/inclusion call reaches a program id read from account data; migration doc names the new-deploy path. |
| **VS6 submitter identity** | Needs two signers. | Integration test: the same valid update from a never-seen keypair advances state; an invalid one from the deployer is rejected with the same code. |
| **PDA / namespace griefing** | Needs the on-chain runtime. | Fuzz seed derivations: `b"instance"‖x` vs `b"header"‖y` vs `b"job"‖z` never collide for crafted `x,y,z` of varying lengths; adversary pre-creates the PDA an instance init would use. |
| **F15 cross-instance statement** | Instance identity lives in accounts. | Two instances (Sepolia, mainnet-config) under one program; a statement from A presented to a consumer bound to B must fail. |
| **Concurrency / front-running of updates** | Ordering is a runtime property. | Two valid updates for the same period submitted in the same slot in both orders; final store identical; the loser gets 1106, not a panic. |
| **Equivocating / colluding committee (VS4)** | By construction indistinguishable from honest finality. | Document; consumer-side caps/freeze (RFP-022). A vector would just be `ok_*` signed by a hostile but legitimate committee. |
| **Weak-subjectivity drift during operation** | Needs a wall clock advancing past the period mid-run. | Time-mocked test: instance initialised at slot S, clock moved to S + ws + 1 → updates rejected 1105, attest still served or refused per documented policy. |
| **Long-range: real old finality update + real old committee** | Needs a checkpoint older than ws and historical material. | Fetch a bootstrap >ws old; the verifier must refuse it (1105), even though every branch verifies. |
| **Resource exhaustion** | Cycle budget is a zkVM/runtime property. | Update with 512/512 bits vs 342/512: measure cycles; proof lists with 64 deep nodes; receipts with 1000 logs. |
| **Reorged optimistic header** | Needs two conflicting attested headers at the same slot. | `optimistic_update` for slot N, then a finality update whose finalised chain excludes N; store must drop/ignore the optimistic head. |
| **Empty storage trie / absent account proofs** | `eth_getProof` fixture only covers an existing account and slot. | Fetch a proof for a fresh address and for an unused slot of WETH; `FactValue` must distinguish "absent" from zero; a predicate `balance eq 0` on an absent account must not be provable as "account exists". |
| **Statement replay to consumer** | Nullifier is explicitly the consumer's job. | Consumer test: same `statement_id` consumed twice → consumer rejects. |

## Known limits of this catalogue

- Real-committee signature vectors cannot *add* valid signers (no private keys), and no real update advances
  finality past the bootstrap, so signature / finality-branch / chain-binding mutations are exercised in the
  fabricated universe (config trusts the fabricated checkpoint). Real material still covers bootstrap checks,
  next-committee handoff (`updates[1]`), period ordering, duplicates, slot-order and participation-zero checks,
  and all attest-layer vectors.
- The mainnet replay vector keeps Sepolia's fork schedule so that only chain identity differs; a true mainnet
  config would reject earlier with 1003 (slots are pre-Electra on mainnet).
- `bootstrap_pre_gloas_slot` uses Gloas-shaped material at a Fulu slot; a verifier that also implements Fulu
  may report 1001 instead of 1003.
- `bootstrap_stale_checkpoint` requires the verifier to apply the weak-subjectivity check at bootstrap time
  (`config.current_slot`), not only on updates.
