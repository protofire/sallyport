# Official Ethereum test vectors: results

`crates/spec-tests` runs the published Ethereum test vectors against `lc-core` and the BLS code in `crates/attest-program/src/bls.rs`. The vectors are not stored in git. `crates/spec-tests/fetch.sh` downloads the pinned releases, checks their sha256 and extracts only the suites used here:

| Source | Release | Archive sha256 |
|---|---|---|
| ethereum/consensus-specs (spec tests) | `v1.7.0-beta.4` (2026-10-08) | mainnet `67762986…dd19398c`, minimal `26d09aea…3b7b68` |
| ethereum/bls12-381-tests | `v0.1.2` | bls_tests_json `0dc1dfab…b448bc` |

The full hashes are in `fetch.sh`.

Reproduce:

```
crates/spec-tests/fetch.sh <dir>
SPEC_TESTS_DIR=<dir> RISC0_DEV_MODE=1 cargo test --release -p spec-tests -- --nocapture --test-threads 1
```

`spec-tests` is not a default member. Without the vectors it panics; it never passes vacuously. Host runs use lc-core's production functions and `bls.rs` with crates.io `blst`; guest runs use a test-only zkVM binary that does not change the attest ImageID; the LEZ ABI runs go through the attest program in the executor (dev mode).

## Results

MISMATCH = 0 in every suite. UNSUPPORTED is never counted as PASS. Counts are PASS / MISMATCH / UNSUPPORTED. Run on the prover host.

### consensus-specs v1.7.0-beta.4 (Electra, Fulu, Gloas)

| Suite | Preset | Host | Guest |
|---|---|---|---|
| ssz_static (BeaconBlockHeader, SyncCommittee, LightClientHeader, -Bootstrap, -Update, -FinalityUpdate) | mainnet | 90 / 0 / 30 | n/a |
| ssz_static | minimal | 738 / 0 / 2214 | n/a |
| light_client/single_merkle_proof (finality, current/next committee, execution) | mainnet + minimal | 24 / 0 / 0 | 48 / 0 / 0 (valid + tampered leaf) |
| light_client/sync: bootstrap + per-update execution, finality and next-committee branches | minimal | 64 / 0 / 8 | n/a |
| light_client/sync: sync-aggregate signature (production signing root, committee by signature period) | minimal | 57 / 0 / 0 | 114 / 0 / 0 (K, K+2) |
| light_client/sync: store-state checks (finalized/optimistic header after each step) | minimal | 0 / 0 / 67 | 0 / 0 / 67 |
| light_client/update_ranking | minimal | 0 / 0 / 3 | 0 / 0 / 3 |
| light_client/data_collection | minimal | 0 / 0 / 3 | 0 / 0 / 3 |

The release has no mainnet vectors for sync, update_ranking or data_collection. The LEZ ABI cannot run the minimal sync vectors: Init needs a 512-key committee, and lc-core's period and epoch constants are mainnet.

### bls12-381-tests v0.1.2

| Suite | Host | Guest (zkVM bls.rs) | LEZ ABI |
|---|---|---|---|
| verify | 29 / 0 / 0 | 58 / 0 / 0 (K, K+2) | 0 / 0 / 29 |
| fast_aggregate_verify | 11 / 0 / 1 | 22 / 0 / 0 (K, K+2) | 0 / 0 / 12 |
| aggregate_verify | 0 / 0 / 5 | 0 / 0 / 5 | 0 / 0 / 5 |
| deserialization_G1 | 18 / 0 / 6 | 18 / 0 / 4 | 20 / 0 / 4 |
| deserialization_G2 | 24 / 0 / 4 | 24 / 0 / 2 | 24 / 0 / 4 |
| hash_to_G2 (QUUX DST, `blst_hash_to_g2` as called by `bls::prepare`) | 4 / 0 / 0 | 4 / 0 / 0 (risc0 blst fork) | 0 / 0 / 4 |

Host BLS counts one case as PASS only if `BlstVerifier`, `bls.rs` K and `bls.rs` K+2 all agree with the vector. The deserialization rows count each case once per hint shape. They do not include the `sign`, `aggregate` and `batch_verify` suites, which a verifier does not use.

## UNSUPPORTED, by reason

Preset (minimal): lc-core fixes `SYNC_COMMITTEE_SIZE = 512`, 32-slot epochs, 256-epoch periods and `[u8; 64]` sync-committee bits, the mainnet preset, which Sepolia also uses. Minimal-preset `SyncCommittee`, `LightClientBootstrap`, `LightClientUpdate` and `LightClientFinalityUpdate` (ssz_static), and the store transitions in `sync`, cannot be expressed. The parts that do not depend on the preset still run: every branch, execution-header root, beacon-header root, signing root and sync-aggregate signature in the 15 sync cases.

Deliberate on-chain deviations from the light-client spec (`docs/DECISIONS.md` D-LC-2): no optimistic header, no `best_valid_update`, no `force_update`, finality required, at least 342 participants (`LightClientOptimisticUpdate`, `update_ranking`, `force_update`/`upgrade_store` steps, optimistic store checks); a finalized header at `GENESIS_SLOT` (8 sync updates), where the spec proves a zero leaf and lc-core always hashes the header; `data_collection` covers how a full node produces light-client data, not verification.

BLS, not expressible through our interface: `verify` and `hash_to_G2` through the LEZ ABI (the signed message is always the signing root of an attested header, and the DST is the eth2 POP DST; the same `bls.rs` code runs on these vectors in the zkVM guest); `fast_aggregate_verify` (an arbitrary key set is not an input, because the committee comes from an SSZ branch); `aggregate_verify` (a sync aggregate signs one message); wrong-length encodings (borsh `[u8; 48]` / `[u8; 96]` fields cannot carry them, and the relayer's JSON decode rejects them with 1001).

BLS, by design (the result differs from the vector):
- `deserialization_G1/fails_not_in_G1` is accepted as a committee aggregate key. `bls::prepare` does not check that the stored aggregate key is in the G1 subgroup. That key is SSZ-authenticated: it is `eth_aggregate_pubkeys` over deposit keys that passed `KeyValidate`. `BlstVerifier` (relayer pre-check) still checks the subgroup of the final key.
- `deserialization_G1/succeeds_infinity_with_true_b_flag` is rejected on host and guest when there are no non-signers: `prepare` refuses an infinity aggregate. Infinity keys are also refused at committee admission (D-LC-5).
- `deserialization_G2/succeeds_infinity_with_true_b_flag` is rejected: `prepare` refuses an infinity signature. With a non-infinity aggregate key, `FastAggregateVerify` returns false for it anyway.
