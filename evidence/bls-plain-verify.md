# Plain in-guest BLS12-381 verify: 10.45M cycles

Applies to a standalone measurement guest (not one of the shipped ImageIDs), risc0-zkvm 3.0.5, executor only, built on the repository's base before the attestation program (LEZ v0.4.0-rc1, 1806e87, is the target runtime). The experiment code is not included in this repository.

Local paths and host names are normalised in this file (`<repo>`, `prover-host`).

## Result

A plain BLS12-381 aggregate-signature verify inside the risc0 guest does not fit the 10M per-action cycle cap. Executor cycles, measured with `env::cycle_count()` deltas inside the guest, committee size N=512 and K=20 non-signers:

| Operation | Cycles |
|---|---:|
| G1 pubkey decompress (on curve, no subgroup check) | 98,682 |
| G1 pubkey subgroup check | 412,271 |
| G2 signature decompress | 201,425 |
| G2 signature subgroup check | 398,748 |
| hash_to_G2 (DST `…SSWU_RO_POP_`) | 1,323,238 |
| full pairing verify, no group checks (includes hash_to_G2) | 10,445,335 |
| verify with signature group check and pubkey validation | 11,255,837 |
| aggregate 512 uncompressed G1 keys (deserialize + add, no subgroup check) | 4,375,415 |
| subtract 20 non-signers from the aggregate | 200,800 |

The pairing alone (verify minus hash_to_G2) is about 9.12M. With hashing done elsewhere it would fit only barely, leaving under 1M. The whole guest run, with three verifies, input deserialisation and sanity checks, was 51.07M cycles in 52 segments; executor wall time was 1.3 to 2.4 s.

## What was measured and how

- Guest: `blst` 0.3.16 from the risc0 fork (tag `v0.3.16-risczero.0`, resolved commit 7d1fc3e6), which routes field arithmetic to `risc0-bigint2` 1.4.14 on the zkVM target. It exposes the same `min_pk` API Ethereum clients use. Host (test vector only): crates.io `blst =0.3.16`, plain C.
- Toolchain: risc0-zkvm and risc0-build `=3.0.5`; rzup rust 1.97.0, cpp 2024.1.5, r0vm 3.0.5. The C part of `blst` needs `rzup install cpp`; on macOS `AR_riscv32im_risc0_zkvm_elf` must point at the risc0 `riscv32-unknown-elf-ar`, otherwise the build produces an empty `libblst.a`.
- Test vector: 512 deterministic keys, the first 20 are non-signers, the last 492 sign a 32-byte root; the aggregate signature was verified on the host first. The guest asserts that verification succeeds, that a wrong message fails and that the subtract result equals the aggregate of the remaining keys.
- Run: `cargo run --release` with the executor only (risc0-zkvm feature `client`); no proofs were generated.

## Caveats

- Subgroup checks on public keys are skipped in the aggregation row; committee keys would have to be validated once elsewhere.
- Acceleration is inferred from the 10M-scale pairing and the `bigint2` dependency; it was not A/B measured, because the unmodified crates.io `blst` panics at guest startup (its thread pool needs `sys_getenv`), so there is no baseline.
- A publicly reported figure of about 7.85M cycles per accelerated pairing is about 14% below the 9.12M measured here: same order, not reproduced.

## Why it matters

A straightforward verify is over the cap (10,445,335 against 10,000,000), so the light-client update cannot call it directly. This motivates the residue kernel in `crates/attest-program/src/residue.rs`, a BLS12-381 final-exponentiation residue check used in place of a plain pairing verify; the resulting one-transaction update costs are in [onetx.md](onetx.md) and [../docs/BENCHMARKS.md](../docs/BENCHMARKS.md).
