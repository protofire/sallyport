# One-transaction BLS light-client update: cycle results

Applies to the attest guest at development commits `948d70f` (merged as `aa619ca`) and `533ad74`, LEZ v0.4.0-rc1 (1806e87). The measurements predate the Docker-built guests, so no ImageID is recorded for them; the Docker-built ImageIDs of the final guests are in [rfp021-final-run.md](rfp021-final-run.md).

Local paths and host names are normalised in this file (`<repo>`, `prover-host`). This is a historical record of the measurements behind decisions D-UPD-1 and D-UPD-2 in [../docs/DECISIONS.md](../docs/DECISIONS.md); current figures are in [../docs/BENCHMARKS.md](../docs/BENCHMARKS.md).

## Result

A sync-committee update (finality, rotation or committee-learning) is verified and applied in one `Update` instruction, instead of a split `UpdateBegin`/`UpdateVerify` pair, with the header and root writes chained in the same transaction. The per-action cap is 10M cycles. Final figures (commit `533ad74`, one transaction, `charge.cycles` of the LEZ public-transaction executor including chained calls and account I/O):

| Update case | Before (first one-tx version) | After |
|---|---:|---:|
| committee-learning, real Sepolia K=2 | 9,754,318 | 7,134,660 |
| finality, real Sepolia K=2 | 7,630,600 | 6,650,027 |
| finality, real mainnet K=0 | 7,658,455 | 6,632,596 |
| handoff learn / rotate+finality / finality (real, 1403 anchor) | split only | 7,181,113 / 7,404,170 / 6,651,204 |

K is the number of non-signers in the 512-member committee. Split path after the same change: Begin/Verify 2.95M/5.21M (learn), 2.03M/5.06M (finality).

## K sweep and worst case

Synthetic but fully verified updates: distinct deterministic keys and genuinely valid aggregate signatures for each K, real header fixtures, largest accumulator carry, a retained next committee (~49 KB store). This is cost profiling, not a claim that Ethereum produced these committees.

| Update case, one tx | K=64 | K=128 | K=170 |
|---|---:|---:|---:|
| finality, Sepolia shape (after) | 7,387,258 | 8,123,777 | 8,610,246 |
| finality, mainnet shape (after) | 7,389,920 | 8,125,769 | 8,611,793 |
| committee-learning (after) | 7,848,368 | 8,584,857 | 9,071,354 |
| finality, Sepolia shape (first one-tx version) | 8,367,897 | 9,104,262 | 9,590,845 |
| finality, mainnet shape (first one-tx version) | 8,415,630 | 9,151,481 | 9,637,512 |

K=170 is the participation limit. Its worst case is 8.61M for finality (Sepolia 8,610,246, mainnet 8,611,793) and 9.07M for committee-learning (9,071,354), under the 10M cap; in the first one-transaction version the same finality case was 9.59M-9.64M. Committee-learning with K=0 is 7,110,583. The source states every K up to 170 was measured for the first version, so the result does not assume monotonic cost.

## Method

All builds and executions ran on an x86_64 Linux box (WSL2 Ubuntu 24.04, the desktop GPU box of [../docs/BENCHMARKS.md](../docs/BENCHMARKS.md)) with `CARGO_BUILD_JOBS=3` and `RISC0_DEV_MODE=1`. Cycles are executor results, not proving time. Test pointer: `crates/program-tests/tests/onetx.rs` (run with `cargo test --release -p program-tests --test onetx -- --nocapture`). Acceptance at the first commit: full suite 93 passed, 0 failed; each guest-vector mode 84 PASS / 0 MISMATCH / 5 UNSUPPORTED / 0 PANIC. `bls.rs`, `residue.rs` and `lc-core/src/sync.rs` were unchanged by the one-transaction work. The follow-up (`533ad74`) cut cycles with a single `sys_sha_buffer` call for `hash2`, in-place merkleization, bulk Borsh for `SyncCommittee` (identical layout) and optional uncompressed aggregate and signature hints checked by recompression.
