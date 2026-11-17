# BENCHMARKS: cycles, gas and real proving (RFP-021 Performance #1, #2, #4, #8)

Every table below starts with a **label line**: code commit, guest keccak (software or risc0 coprocessor), proof mode
(execute only = no proof; composite / succinct = real RISC0 proof, `RISC0_DEV_MODE` unset), machine, and whether the
machine was **shared** (other builds and tests running, timings vary up to ~2x) or **quiet**. Cycle counts are
deterministic for a given commit and input; times are not. Numbers from different commits are not comparable without
reading their labels. CPU proving on the final code (`8be9338`) is in "Final code, 2026-11-12" at the end of this file.

Raw rows for the M2 Max proving runs: [../evidence/bench/bench-results.log](../evidence/bench/bench-results.log); final code, 2026-11-12: [../evidence/bench/bench-results-m2-cpu-final.log](../evidence/bench/bench-results-m2-cpu-final.log) (CPU) and [../evidence/bench/bench-gpu-rerun-48bc5e9.log](../evidence/bench/bench-gpu-rerun-48bc5e9.log) (GPU). Decisions behind the numbers: [DECISIONS.md](DECISIONS.md)
D-BENCH-1 (bench method), D-ATT-7 (keccak), D-ATT-5 (UpdateBegin cap).

## Reproduce

```
cargo test --release -p program-tests -- --nocapture          # executor cycles (cycle_table, ancestry_cycle_table, onetx_cycles_by_non_signers, onetx_committee_learning_cycles)
crates/bench/build.sh                                        # builds target/release/bench (see Build notes)
cargo build -p bench --release --no-default-features --features cuda   # GPU build (needs the CUDA 12.8 toolkit); cold build about 45 min
target/release/bench <action> [--mode execute|composite|succinct] [--step N] [--po2 N]
/usr/bin/time -l target/release/bench attest-erc20 --mode succinct   # adds peak RSS
RAYON_NUM_THREADS=4 target/release/bench attest-erc20 --mode succinct --po2 18   # constrained profile
crates/bench/run-all.sh evidence/bench/bench-results.log               # every proving row (about 4 h on the M2 Max)
```
Bench actions: `claim` (steps 0..3 = Claim, Attest, AttestReply, Nullify), `claim-inline` (steps ClaimInline,
CheckHeader, Nullify), `attest-slot`, `attest-erc20`, `attest-erc20-compact`, `attest-eth`, `update-finality`,
`update-learn`, `update-k170` (one-tx Update; steps Update, Write1, Write2 where present). The pre-one-tx actions
(`update-begin`, `update-verify`, `breakdown`, `circuit-empty`, `compose`) behind sections 2 to 6 were removed from the
bench; those rows are reproducible at their labelled commits. Inputs are the real Sepolia fixtures from `program-tests`; each step's `ReceiveInput` is captured by a
mini-sequencer that runs the chain on the LEZ executor, so cycles equal what the executor charges.

## How LEZ charges gas (what the cycle numbers mean)

From LEZ v0.4.0-rc1 (1806e87) source:
- Public tx: execution gas = `session.user_cycles` of the guest (`lee/state_machine/src/program/image_cache/mod.rs:169`),
  clamped to the tx `gas_limit`; storage gas = tx data bytes (`lez/programs/fee/core/src/assess.rs:33-37, 84-90`).
  `MAX_GAS_EXEC` = 10M (`market.rs:15`) is the **per-block** execution-gas cap, and so also the most one tx may use;
  `TARGET_GAS_EXEC` = 5M (`market.rs:10`) is the per-block target the base fee is steered to (`next_base_fee`,
  damping 8: a block at 6.6M raises the base fee about 4%, a full block 12.5%). Charged cycles add to the block total
  (`chain_state/src/apply.rs:635`, `validity.rs:87-93`), and the sequencer admits a tx only if the block's used gas plus
  the tx's declared `gas_limit` is ≤ 10M (`sequencer/core/src/lib.rs:144`). So the **declared** limit, not the cycles
  used, decides what can share a block.
- Block share of an Update. One `Update` uses 6.4–8.9M, i.e. 64–89% of a block and over the 5M target by itself.
  The client used to declare 10M for every tx, so no other tx could share a block with it. It now declares
  `lez_client::update_gas_limit(K)` = 7.4M + 11.5k·K (measured + about 5%; 7.42M at K=2, 9.36M at K=170; test
  `onetx_cycles_by_non_signers` runs every sampled K under exactly that limit), leaving 0.6–2.6M for other txs, a
  few claims (section 1: 59k–578k). The 2-tx fallback (K>170, unreachable at the 342 floor) still declares 10M.
- Keccak coprocessor work is not metered. Guest keccak runs through `sys_keccak`; those permutations are proven in a
  separate keccak circuit and do not appear in `user_cycles`. So "cycles after keccak" below is what a public tx pays, not
  the total proving work.
- Private tx: the fee covers a fixed verification gas `PRIVATE_VERIFY_GAS = 409,764` plus the cycles of its public
  effects, plus a fixed storage gas `PRIVATE_GAS_STOR` (`assess.rs:93-103` `private_fee_required`, `market.rs:49`). The
  private transitions' own cycles are not metered; they cost prover time on the user's machine.
- Base fee per gas unit is a fee-market value; no fee-charging LEZ v0.4 network was available, so no fee in tokens is
  reported anywhere in this repo.

## 1. Executor cycles per transaction (final code)

Label: update and attest rows commit `82bb54d`; claim and private-claim rows commit `8be9338` (measured in a checkout at `48bc5e9`, 2026-11-12;
`git diff --stat 48bc5e9 8be9338 -- crates/` shows no guest code change: one doc comment in `attest-program/src/residue.rs`, formatting, a new host-side test file and two test assertions) |
coprocessor keccak | execute only (LEZ executor, dev mode) | machine-independent | n/a.
Sources: update rows from D-UPD-3 (tests `onetx_cycles_by_non_signers`,
`onetx_committee_learning_cycles` in `crates/program-tests/tests/onetx.rs`; method and the K sweep in
[../evidence/onetx.md](../evidence/onetx.md)); attest and claim rows from D-GAS-6, D-GAS-5, "final tree" row (tests `cycle_table`,
`ancestry_cycle_table`, `inline_consumer_claim_binds_header` in `crates/program-tests/tests/executor.rs`,
`private_claim_cycles` in `private.rs`).

| Action (one tx) | Cycles (= public exec gas) | Source |
|---|---:|---|
| Update, finality only, Sepolia K=2 | 6,559,273 | `onetx_cycles_by_non_signers`, D-UPD-3 |
| Update, finality only, mainnet K=0 | 6,539,551 | D-UPD-3 |
| Update, committee-learning K=2 | 6,981,423 | `onetx_committee_learning_cycles`, D-UPD-3 |
| Update, K=170 non-signers: Sepolia / mainnet / committee-learning | 8,472,345 / 8,471,460 / 8,866,373 | `onetx_cycles_by_non_signers`, D-UPD-3 |
| Attest ERC-20 Transfer log, compact / explicit receipt witness | 69,316 / 76,635 | `cycle_table`, D-GAS-6, D-GAS-5 |
| Attest native ETH (EIP-7708) log, compact / explicit | 58,785 / 61,165 | `cycle_table`, D-GAS-6, D-GAS-5 |
| Attest storage slot (WETH slot 0) | 153,495 | `cycle_table`, D-GAS-6, D-GAS-5 |
| per ancestry header | ≈10,870 | `ancestry_cycle_table`, D-GAS-6, D-GAS-5 |
| erc20_receiver Claim (chained Attest) | 155,845 | `cycle_table`, D-GAS-6, D-GAS-5 |
| erc20_inline_receiver Claim (optional inline verify + `CheckHeader`) | 120,855 | `inline_consumer_claim_binds_header`, D-GAS-7 |
| eth_receiver Claim (chained Attest) | 135,145 | `cycle_table`, D-GAS-6, D-GAS-5 |
| Private claim transition (proven by the user, not metered) | ≈96,809 | `private_claim_cycles`, D-GAS-6, D-GAS-5 |

The claim rows were 149,489 (chained ERC-20), 117,041 (inline), 133,526 (ETH) and ≈95,949 (private) at `82bb54d`; the increase is the later
per-vault nullifier fix. The update and attest rows were not re-run on the executor at `8be9338`. The bench meter at `8be9338` reports
Update 6,529,823 (finality), 6,981,360 (committee-learning) and 8,441,543 (K=170), Attest ERC-20 69,237 compact / 76,556 explicit and
Attest ETH 61,086 explicit; it differs from the executor figures above by up to about 31k on Update rows and by 79 on Attest rows
(see the note under "Final measurements"). The bench claim steps sum to 155,845 and the inline steps to 120,855.

Every light-client update, committee rotation included, is one transaction. The client
(`LezClient::submit_update_json`, shared by the relayer and the module) sends one `Update` for every kind whenever
K ≤ `lez_client::ONE_TX_MAX_NON_SIGNERS` = 170, the 2/3 participation limit (342 of 512). The test runs every K up to
170 under the 9.5M budget (`MAX_GAS_EXEC` 10M); K=170 is the maximum and leaves more than 630k headroom on every shape.
`UpdateBegin`/`UpdateVerify` remain as a fallback above K=170, reachable only if the participation rule is relaxed.
Not re-measured at `82bb54d`: Init in the executor and Attest at the 448-header maximum (7,106,902 at `20c6fc3`,
section 7, before the gas round).

### 1a. Live cycles (2026-11-05 run, development commit 82bb54d)

Label: commit `82bb54d` (+ host-only commits) | local LEZ v0.4.0-rc1 sequencer, `RISC0_DEV_MODE=1` | live Sepolia data |
cycles = the block's `gas_used_exec` for a block holding only that tx. Source: [../evidence/rfp021-final-run.md](../evidence/rfp021-final-run.md).

| Action (one tx) | Cycles |
|---|---:|
| Init | 917,321 |
| Update, committee-learning, Period(1405) | 7,026,455 |
| Update, finality (4 txs) | 6,604,214 to 6,606,851 |
| erc20_receiver Claim, chained `Attest`, 28 ancestry headers | 538,948 |
| erc20_inline_receiver Claim, 26 ancestry headers | 391,221 |
| eth_receiver Claim, 30 ancestry headers | 577,512 |
| CheckRoot (known root) | 10,552 |

Final run (2026-11-10, development commit `c380d4b`, same method; [../evidence/rfp021-final-run.md](../evidence/rfp021-final-run.md) section 1):

| Action (one tx) | Cycles |
|---|---:|
| Init | 917,213 |
| Update, committee-learning, Period(1409) | 7,004,016 |
| Update, finality (8 txs) | 6,581,557 to 6,592,817 |
| erc20_receiver Claim, chained `Attest`, direct (0 ancestry headers) | 133,717 |
| erc20_inline_receiver Claim, 30 ancestry headers | 437,101 |
| eth_receiver Claim, 2 ancestry headers | 169,570 |

Each replay of the three claims reverted after ~1,040 cycles fewer than the claim; re-executed with
`program-e2e simulate`, each exits with 1250 `ERR_ALREADY_CLAIMED` ([../evidence/rfp021-final-run.md](../evidence/rfp021-final-run.md)).
Live rotation (period 1405→1406, 2026-11-06): rotation + first period-1406 finality, Finality(11,517,952), 6,411,261 cycles
(one tx, block 4746); Period(1406) committee-learning 6,970,272; Finality(11,517,984) under the new committee 6,548,150
([../evidence/rfp021-final-run.md](../evidence/rfp021-final-run.md)).

### 1b. Superseded: executor cycles at `20c6fc3` / `df278b0` (2-tx updates)

Kept because the proving tables below were measured on that code or earlier. Label: commit `20c6fc3` (keccak table) and `df278b0` (UpdateBegin K sweep) | coprocessor keccak | execute only
(LEZ `V03State`, dev mode) | machine-independent | n/a.

A **transaction** total sums every chained transition it runs (e.g. Claim = Claim + Attest + AttestReply + Nullify). The
proving tables in sections 2-4 are **per transition**; they add up to the tx totals here (see Reconciliation).

| Action (one tx) | Cycles (= public exec gas) | Source |
|---|---:|---|
| Init | 2,957,482 | `cycle_table` |
| UpdateBegin, finality only | ≈3.0M | D-ATT-2 |
| UpdateBegin, learns next committee, K=2 non-signers | 5,842,552 | `cycle_table` |
| UpdateBegin, K=170 (most non-signers at 342-of-512) | 7,784,282 | `begin_cycles_by_non_signers` (asserts every K ≤ 10M) |
| UpdateVerify (Miller + residue + Apply + header/root writes) | 6,174,197 (learn-next fixture); 5.6-6.7M across update kinds | `cycle_table`; D-ATT-2 |
| Attest storage slot (WETH slot 0) | 282,875 | `cycle_table` |
| Attest ERC-20 Transfer log | 121,511 | `cycle_table` |
| Attest native ETH (EIP-7708) log | 92,904 | `cycle_table` |
| Attest log + 448 ancestry headers (max) | 7,106,902 | `ancestry_cycle_table`, `fixtures/ancestry/log448.json` |
| per ancestry header | ≈15,592 | `ancestry_cycle_table` |
| erc20_receiver Claim (chained Attest) | 240,522 | `cycle_table` |
| eth_receiver Claim (chained Attest) | 194,551 | `cycle_table` |
| Private claim transition (proven by the user, not metered) | ≈119,505 | `private_claim_cycles` |

At this code a tracking update was **2 transactions**: UpdateBegin 3.0-7.8M plus UpdateVerify 5.6-6.7M, both under the
10M cap for every participation level the program accepts. Superseded by the one-tx `Update` (section 1, D-UPD-1, D-UPD-2, D-UPD-3);
the split pair remains as the fallback above K=170.

## 2. Real proving, CPU, before keccak acceleration

Label: commit `86f5985` (programs of the first full build: before the header accumulator, the front-run fix, ancestry and keccak) |
software keccak | composite and succinct, real | Apple M2 Max, 12 cores, 32 GB, macOS 27.2, risc0-zkvm 3.0.5 CPU prover |
shared (timings varied up to ~2x between runs of the same row, e.g. Attest ERC-20 composite 85 s alone vs 162 s
inside `compose`; treat times as ±50%).

These are **superseded for cycles** by section 1 (and 1b) and kept because they are the only full per-transition proving sweep.
Proving time scales with padded cycles and segment count, so the post-keccak Attest rows would prove in one smaller
segment (section 3).

cycles = user cycles; "padded" = prover cycles after segment padding. Peak RSS from `/usr/bin/time -l`.

| Transition | Cycles | Segments | Padded cycles | Composite: time / receipt | Succinct: time / receipt | Peak RSS (comp / succ) |
|---|---:|---:|---:|---|---|---|
| Claim (erc20_receiver) | 65,295 | 1 | 262,144 | 19 s / 265 KB | 28 s / 232 KB | 2.5 / 2.6 GB |
| Attest ERC-20 log (chained from Claim) | 827,422 | 1 | 1,048,576 | 85 s / 287 KB | 186 s* / 228 KB | 7.2 / 4.8 GB |
| AttestReply (erc20_receiver) | 37,394 | 1 | 131,072 | 10 s / 245 KB | 20 s / 224 KB | 1.3 / 2.3 GB |
| Nullify (erc20_receiver) | 14,384 | 1 | 65,536 | 5 s / 222 KB | 13 s / 224 KB | 0.7 / 1.7 GB |
| **Claim flow, sum of 4** | 944,495 | 4 | | **119 s** | ~247 s* (sum of rows) | max 7.2 / 4.8 GB |
| Attest storage slot (WETH slot 0) | 2,180,415 | 3 | 2,621,440 | 207 s / 839 KB | 273 s / 231 KB | 8.2 / 8.3 GB |
| Attest ERC-20 log (root call) | 826,118 | 1 | 1,048,576 | 85 s / 286 KB | 99 s / 228 KB | 7.0 / 8.2 GB |
| Attest native-ETH log (EIP-7708) | 604,366 | 1 | 1,048,576 | 85 s / 285 KB | 94 s / 226 KB | 7.4 / 7.7 GB |
| UpdateBegin (K=2, learns next committee) | 5,236,588 | 6 | 6,291,456 | 579 s / 1.76 MB | 657 s / 300 KB | 8.1 / 8.7 GB |
| WriteJob | 592,307 | 1 | 1,048,576 | 85 s / 332 KB | 103 s / 274 KB | 7.5 / 7.0 GB |
| UpdateVerify | 4,878,696 | 6 | 5,373,952 | 441 s / 1.70 MB | 947 s / 274 KB | 8.5 / 7.4 GB |
| Apply | 1,278,059 | 2 | 2,097,152 | 217 s / 662 KB | 273 s / 323 KB | 7.5 / 6.5 GB |

\* ran while the machine was busier; the same program as a root call measured 99 s.
UpdateBegin/UpdateVerify run publicly on the sequencer, so nobody proves them in this design; they are listed as the cost
of a hypothetical private or zk-wrapped update.

**Reconciliation with section 1b (same actions, different numbers):**
- Attest ERC-20: 827,422 (chained from Claim, `ctx` bytes in the request) vs 826,118 (root call), both @86f5985; 827,694 in
  the executor before keccak (D-ATT-7); 121,511 after keccak. Differences below 0.2% are call context and commit.
- UpdateBegin tx = UpdateBegin 5,236,588 + WriteJob 592,307 = 5,828,895 @86f5985; executor tx 5,842,552 @20c6fc3.
- UpdateVerify tx = UpdateVerify 4,878,696 + Apply 1,278,059 = 6,156,755 @86f5985; executor tx 6,174,197 @20c6fc3
  (adds the header-accumulator append and root write, D-PRIV-2).
- Claim flow: 944,495 (sum of 4 transitions @86f5985) vs 946,703 executor pre-keccak vs 240,522 after keccak.

Private-path pipeline (SUPERSEDED). This sweep estimated a private claim at "about 10 to 12 min, about 225 KB" from
a stand-in composition guest (`compose`, 208 s + 403 s) plus the empty LEZ privacy circuit (`circuit-empty`, 163 s / 211 s).
It predates the private claim (D-PRIV-2) and keccak acceleration, and is replaced by the real LEZ privacy-preserving proof in
section 3. Kept here only because [../evidence/bench/bench-results.log](../evidence/bench/bench-results.log) contains those rows.

Proof size: the submitted proof is a succinct receipt, 224 to 232 KB for every action; composite receipts are 220 KB to
1.76 MB.

## 3. Real proving, CPU, after keccak acceleration

Label: commit `20c6fc3` | coprocessor keccak | real (succinct; LEZ privacy circuit) | Apple M2 Max, 12 cores, 32 GB,
CPU prover | **shared** (not controlled).

| Run | Before (@86f5985 code, software keccak) | After (@20c6fc3, coprocessor) |
|---|---|---|
| `bench attest-erc20 --mode succinct`, proof verified against the ImageID | 99.0 s, 1,048,576 padded cycles, 8.2 GB peak | 98.8 s, 262,144 padded cycles, 3.26 GB peak, 228 KB receipt |
| Real LEZ privacy-preserving tx, private claim (`program-tests --features lee/prove`, test `private_claim_cycles`: consumer guest proven, keccak assumptions resolved in the LEZ privacy circuit, accepted by `ValidatedStateDiff::from_privacy_preserving_transaction_metered`) | not run | 423 s for the whole test (includes a public re-run of the same claim), 5.0 GB peak |

The 423 s was the figure at `20c6fc3`. It is one run, on a shared machine, and includes test overhead. On the final code a repeat on a quiet
machine took 245.07 s for the whole test (8.60 GB peak; "Final code, 2026-11-12" below), and that is the current figure for a user's private-claim proof (P4).

## 4. Real proving, GPU, before keccak acceleration

Label: commit `f85401d` | software keccak | composite and succinct, real | NVIDIA RTX 3080 12 GB, CUDA 12.8, WSL2
x86_64 | load not recorded. Same bench actions and fixtures as section 2. Raw rows: [../evidence/bench/bench-results-gpu.log](../evidence/bench/bench-results-gpu.log); one run per row.

| Transition | Composite | Succinct |
|---|---:|---:|
| Attest ERC-20 log | 7.0 s | 7.5 s |
| Attest storage slot | 36.3 s | not run |
| UpdateBegin | 68.2 s | 80.5 s |
| UpdateVerify | 56.1 s | 64.4 s |
| Claim flow, 4 steps | ≈20.9 s | not run |

GPU numbers show what a desktop GPU does to the same work: roughly 6x to 12x faster than the composite M2 Max CPU rows of section 2 (different commits, so indicative only). They
are not a minimum-spec figure.

### 4a. GPU detail from the GPU run (succinct + composite, VRAM, host RSS)

Machine `prover-host`: WSL2 Ubuntu 24.04 x86_64, 12 threads, 40 GB RAM, RTX 3080 12 GB (12,288 MiB), CUDA 12.8, rust 1.98.1,
risc0 `rzup` cargo-risczero/r0vm **3.0.5** (made default; matches the 3.0.5 libs in Cargo.lock; 3.0.6 compatibility not tested,
and the in-process prover does not call `r0vm`). Build: `cargo build -p bench --release --no-default-features --features cuda`
(new `cuda` feature in `crates/bench/Cargo.toml`; the Metal patch is not needed on Linux). 33 min cold build.
Code: **pre-keccak code @ f85401d** (before the keccak acceleration and the later program fixes), so cycle counts differ slightly from the M2 rows
(for example Attest ERC-20 826,902 vs 826,118). `RISC0_DEV_MODE=0`, default po2=20, all actions run once, sequentially.
The GPU sweep ran on an otherwise idle box. No CPU run was made on the same machine. Raw rows: [../evidence/bench/bench-results-gpu.log](../evidence/bench/bench-results-gpu.log).

Prove seconds, one run each (M2 = Apple M2 Max CPU, table above):

| Action | M2 composite | GPU composite | M2 succinct | GPU succinct | GPU speedup (succinct) |
|---|---:|---:|---:|---:|---:|
| Claim | 19 | 1.1 | 28 | 1.6 | 18x |
| Attest ERC-20 (chained from Claim) | 85 | 18.3 (see note) | ~100 | 7.2 | 14x |
| AttestReply | 10 | 0.9 | 20 | 1.3 | 15x |
| Nullify | 5 | 0.7 | 13 | 1.2 | 11x |
| **Claim flow, sum of 4** | 119 | 20.9 (about 10 without the outlier) | ~160 | 11.2 | about 14x |
| Attest storage slot (3 segments) | 207 | 36.3 | 273 | 28.9 | 9x |
| Attest ERC-20 (root) | 85 | 7.0 | 99 | 7.5 | 13x |
| Attest native ETH | 85 | 8.1 | 94 | 8.8 | 11x |
| UpdateBegin (6 segments) | 579 | 68.2 | 657 | 80.5 | 8x |
| WriteJob | 85 | 7.6 | 103 | 8.7 | 12x |
| UpdateVerify (6 segments) | 441 | 56.1 | 947 | 64.4 | 15x |
| Apply (2 segments) | 217 | 18.4 | 273 | 24.1 | 11x |

Note: the first Attest in the sweep (claim step 1, composite) took 18.3 s for the same 1.05 M padded-cycle segment that takes 7.0 s as `attest-erc20`
(CUDA context / kernel warm-up and first-use of the device; it is the first heavy segment after an idle GPU). Treat 7 s as steady state.
Succinct is roughly composite plus lift/join, so on GPU the gap is small (1 to 8 s) and the succinct slot row came out below composite (run-to-run noise).

Memory (GPU peak = `nvidia-smi` memory.used sampled at 1 Hz, includes about 1.6 to 1.8 GB already in use by WSL/desktop before the run; process RSS from `/usr/bin/time -v`):

| Segment size (padded cycles) | GPU peak total | RSS |
|---|---:|---:|
| 65,536 to 262,144 (Claim, AttestReply, Nullify) | 4.0 to 5.1 GiB | 0.28 to 0.36 GB |
| 1,048,576 and up (every Attest, WriteJob, Update*, Apply) | 10.7 to 11.3 GiB (about 9.5 GiB attributable) | 0.57 to 0.76 GB |

No OOM at po2=20 on 12 GB; headroom is about 1 GiB, so a card with less than 12 GB, or a desktop holding more VRAM, needs `RISC0_SEGMENT_PO2=19`
(not run here, no failure to fix). Host RSS drops from 7 to 8.7 GB (M2 CPU prover) to under 0.8 GB because the witness and tables live in VRAM.
Private claim on this box: at this code it was an estimate (about 1 minute end to end; untested). It was measured later on the final code: 18.4 s
for the real privacy-preserving proof ("Final code, 2026-11-12" below).

Single-run numbers; one GPU, one machine.

## 5. Laptop profile and provisional minimum target (Performance #4)

Label: commit `86f5985` | software keccak | succinct (and `compose`), real | Apple M2 Max with `RAYON_NUM_THREADS=4` and
smaller segments (`--po2`) to imitate a smaller machine | shared.

| Run | Threads | po2 | Segments | Time | Peak RSS |
|---|---:|---:|---:|---:|---:|
| Attest ERC-20, succinct | 12 | 20 | 1 | 99 s | 8.2 GB |
| Attest ERC-20, succinct | 4 | 18 | 5 | 356 s | 2.4 GB |
| Attest ERC-20, succinct | 4 | 16 | 32 | 1,296 s | 1.6 GB |
| Attest storage slot, succinct | 4 | 18 | 11 | 809 s | 3.4 GB |
| Full claim `compose` (4 receipts + resolve) | 4 | 18 | 9 + 4 | 1,132 s (about 19 min) | 2.4 GB |

(Attest storage slot at po2 16 was started and killed after about an hour; not measured.)

Provisional minimum target, extrapolated (not measured on such a device): 4 cores and 8 GB RAM, with the client
forcing `segment_limit_po2 = 18`. The rows above, taken on a 12-core machine limited to 4 threads with pre-keccak code,
peak at 2.4 to 3.4 GB and take about 19 min per stand-in claim. Recommended: 8+ cores, 16 GB. 4 GB devices (phones) are not
supported by this evidence. Other CPUs, real 4-core laptops and the post-keccak private claim at po2=18 are untested.

Final code at the default segment size on the 12-core M2 Max (no thread or po2 limit; "Final code, 2026-11-12" below): peak RSS 8.39 to 8.69 GB for
a one-tx `Update`, 4.97 to 5.42 GB for an Attest or inline claim step, and 8.60 GB for the whole private-claim test (245 s). The 4-thread rows above
are pre-keccak and have not been repeated on the final code.

## 6. UpdateVerify: in-program BLS vs a hypothetical precompile (Performance #8)

Label: commit `86f5985` | n/a (no keccak in this path; cycles unchanged by D-ATT-7) | execute only (`breakdown`,
`env::cycle_count()`) | machine-independent. Measured on the old two-transaction path (`UpdateVerify`); the
one-transaction `Update` runs the same Miller loop and residue check, and is re-measured in milestone M2.

| Part of the UpdateVerify transition | Cycles | Share |
|---|---:|---:|
| Two-pair Miller loop | 3,266,596 | 67% |
| Residue (final-exponentiation witness) check | 1,009,293 | 21% |
| Rest (borsh decode of Job, finish_update, message build) | 602,807 | 12% |
| **UpdateVerify transition** | **4,878,696** | 100% |

A pairing precompile replacing Miller loop + final exponentiation would remove **at most** 4.28M cycles (88%) of the
transition. That is an upper bound on the saving: the precompile's own metering is undefined in LEZ, and it would be
reachable only from **public** transactions (a private transition is proven on the user's machine, where a sequencer-side
precompile does not exist). It does not change feasibility: every action already fits 10M. UpdateBegin (5.2M transition)
is dominated by hash-to-G2, the subgroup check and SSZ branches, which a pairing precompile would not touch.

## 7. Keccak acceleration (D-ATT-7)

Label: before = executor at the commit preceding `20c6fc3`, software keccak; after = `20c6fc3`, coprocessor keccak |
execute only | machine-independent.

| Action (one tx) | Before (software keccak) | After (coprocessor) | Ratio |
|---|---:|---:|---:|
| Attest storage slot (WETH slot 0) | 2,181,526 | 282,875 | 7.7x |
| Attest ERC-20 Transfer log | 827,694 | 121,511 | 6.8x |
| Attest native ETH (EIP-7708) log | 605,916 | 92,904 | 6.5x |
| Attest log, ancestry 10 | 2,971,447 | 302,054 | 9.8x |
| Attest log, ancestry 32 | 7,191,246 | 658,680 | 10.9x |
| Attest log, ancestry 128 | 24.78M (raised budget, then 1001) | 2,090,114 | 11.9x |
| Attest log, ancestry 448 (new bound) | ~89M (not runnable) | 7,106,902 | |
| per ancestry header | ≈198,861 | ≈15,592 | 12.8x |
| erc20_receiver Claim (chained Attest) | 946,703 | 240,522 | 3.9x |
| eth_receiver Claim (chained Attest) | 707,561 | 194,551 | 3.6x |
| Private claim transition (total as public − public part) | ≈471,760 | ≈119,505 | 3.9x |
| Init / UpdateBegin K=2 / UpdateVerify | 2,957,482 / 5,842,552 / 6,174,197 | identical | 1.0x (sha256 + BLS; no keccak) |

What the acceleration buys, precisely:
- Metered guest cycles drop 6.5x to 12.8x on keccak-heavy actions. Because LEZ meters only `user_cycles` and the
  keccak coprocessor is unmetered, this is also the public gas drop, but the keccak work is moved, not removed.
- Peak memory for an Attest proof drops (8.2 GB to 3.26 GB, section 3).
- Ancestry headroom: `MAX_ANCESTRY` rises from 32 to 448 headers under the 10M cap.
- Proving time is unchanged for a single Attest (98.8 s vs 99.0 s, section 3): the keccak-circuit proofs and their
  resolution replace the saved rv32im segment work.

## 8. Build notes (macOS Metal blocker)

1. `xcodebuild -downloadComponent MetalToolchain` (no sudo) worked (Metal Toolchain 27B47, 839 MB).
2. With it, `risc0-sys 1.5.0` still fails on this compiler (`poseidon2.metal`: "use of overloaded operator '=' is
   ambiguous", 3 sites). The kernel build is unconditional on macOS (`RISC0_SKIP_BUILD_KERNELS` also drops the CPU circuit
   C++ and breaks linking). Fix: 3-line patch `crates/bench/patches/risc0-sys-poseidon2-metal.patch` (`= 0` becomes
   `= Fp(0u)`), applied by `build.sh` to a copy under `target/` and wired in with `--config patch.crates-io.risc0-sys.path`.
3. In risc0-circuit-rv32im 4.0.5 the Metal segment prover is commented out (`src/prove/mod.rs`), so **segment proving on
   macOS is CPU-only** (12 cores busy, ~10x user/real). Core count and RAM are the levers on a Mac; CUDA is on Linux.

## Final measurements (final code)

Executor and live cycles on the final code: section 1 and 1a. Real proving on the final code:

| Prover | Code | Actions | Time | Peak memory | Status |
|---|---|---|---|---|---|
| GPU, RTX 3080 CUDA | `022bb8b` | 6 actions, table below | 4.8 s to 107.1 s | not recorded | done |
| CPU, Apple M2 Max | `8be9338` | 9 bench actions, private claim | 12.4 s to 868.7 s per transition | 1.7 to 8.7 GB | done, 2026-11-12 |
| GPU, RTX 3080 CUDA | `8be9338` (checkout `48bc5e9`) | 6 actions, private claim, `burn_member` | 4.4 s to 75.7 s | GPU 4.1 GB (private claim) | done, 2026-11-12 |

GPU, final code. Label: commit `022bb8b` (program code identical to `82bb54d`; only `program-e2e` and documentation differ) |
real proofs, succinct | NVIDIA RTX 3080 12 GB, driver 617.14, CUDA 12.8, risc0 3.0.5, WSL2 x86_64 (`prover-host`) | median of
3 runs after one discarded warm-up | `target/release/bench <action> --mode succinct` (`--features cuda`). Raw log:
[../evidence/bench/bench-final-gpu-022bb8b.log](../evidence/bench/bench-final-gpu-022bb8b.log). Time is the sum of the per-transition proofs of the action, proved one after
another. The Cycles column is the executor figure (section 1); the bench meter reports about 29k fewer on the Update rows (for example 6,529,880 for `update-finality`, see the raw log).

| Action (bench action) | Cycles (executor figure) | Segments | Median (min–max) |
|---|---:|---|---|
| One-tx Update, finality (`update-finality`) | 6,559,273 | 7+1+1 | 84.6 s (83.1–86.9) |
| One-tx Update, committee-learning (`update-learn`) | 6,981,423 | 8 | 80.4 s (79.6–81.2) |
| One-tx Update, K=170 (`update-k170`) | 8,472,345 | 9+1+1 | 107.1 s (105.7–110.0) |
| Attest ERC-20 log, compact (`attest-erc20-compact`) | 69,237 | 1 | 4.8 s |
| ERC-20 claim, chained (`claim`) | 149,409 | 1×4 | 7.5 s |
| ERC-20 claim, inline (`claim-inline`) | 116,965 | 1×3 | 6.6 s |

Updates run publicly on the sequencer, so nobody proves them in this design; their rows are the cost of a hypothetical
private or zk-wrapped update. Peak memory (VRAM, host RSS) was not recorded in this run.

The 2026-11-05 `022bb8b` table above is superseded by the GPU re-run below. The proving times in sections 2 to 5 come from older code
(`86f5985`, `20c6fc3`, `f85401d`), as each section's label states.

## Final code, 2026-11-12 (independent clean-checkout run)

Run from a clean checkout; context and the rest of the run (ImageIDs, Sepolia end to end) are in
[../evidence/independent-run-2026-11-12.md](../evidence/independent-run-2026-11-12.md). Raw rows:
[../evidence/bench/bench-results-m2-cpu-final.log](../evidence/bench/bench-results-m2-cpu-final.log),
[../evidence/bench/bench-gpu-rerun-48bc5e9.log](../evidence/bench/bench-gpu-rerun-48bc5e9.log).

### CPU, Apple M2 Max

Label: commit `8be9338` | coprocessor keccak | succinct, real (`RISC0_DEV_MODE` unset) | Apple M2 Max, 12 cores, 32 GB, macOS arm64, CPU prover built
without Metal (`cargo build -p bench --release --no-default-features` with the repo's risc0-sys Metal patch via `--config patch.crates-io.risc0-sys.path`, see
`crates/bench/build.sh`) | **quiet** | one run per row, `/usr/bin/time -l`. Time is the bench `prove_ms` of the transition (wall time is a few seconds higher, for
example 708.8 s for the `update-finality` Update); peak RSS is the process maximum.

| Action (bench action) | Transition | Cycles | Segments | Prove time | Peak RSS |
|---|---|---:|---:|---:|---:|
| `update-finality` | Update | 6,529,823 | 7 | 681.7 s | 8.39 GB |
| | Write1 / Write2 | 15,698 / 13,697 | 1 / 1 | 12.5 s / 12.4 s | |
| `update-learn` | Update | 6,981,360 | 8 | 728.9 s | 8.49 GB |
| `update-k170` | Update | 8,441,543 | 9 | 868.7 s | 8.69 GB |
| | Write1 / Write2 | 15,698 / 13,697 | 1 / 1 | 12.5 s / 12.5 s | |
| `claim` step 0 | Claim | 39,012 | 1 | 17.1 s | 2.28 GB |
| `claim` step 1 | Attest | 70,909 | 1 | 60.0 s | 4.97 GB |
| `claim` step 2 | AttestReply | 30,602 | 1 | 17.3 s | |
| `claim` step 3 | Nullify | 15,322 | 1 | 12.5 s | 1.71 GB |
| **ERC-20 claim flow, 4 steps** | | 155,845 | 4 | **about 107 s** | max 4.97 GB |
| `attest-eth` | Attest (explicit witness) | 61,086 | 1 | 60.0 s | 4.77 GB |
| `attest-erc20` | Attest (explicit witness) | 76,556 | 1 | 69.8 s | 5.41 GB |
| `claim-inline` step 0 | ClaimInline | 90,795 | 1 | 69.3 s | 5.42 GB |
| `claim-inline` step 1 | CheckHeader | 14,964 | 1 | 12.5 s | |
| `claim-inline` step 2 | Nullify | 15,096 | 1 | 12.5 s | |
| **Inline claim flow, 3 steps** | | 120,855 | 3 | **about 94 s** | max 5.42 GB |

Real private claim (LEZ privacy-preserving proof, consumer guest proven, keccak assumptions resolved in the privacy circuit, accepted by settlement):
`cargo test --release -p program-tests --features lee/prove --test private private_claim_cycles -- --nocapture` (on macOS the same
`--config patch.crates-io.risc0-sys.path` is needed). Same label as above. Total as a public call 143,466 cycles, public part 46,657, private transition
≈96,809. The whole test (includes a public re-run of the same claim) took 245.07 s, peak RSS 8.60 GB. This replaces the 423 s of section 3.

Build note: a plain `--no-default-features` build fails on macOS because `risc0-sys 1.5.0` still compiles its Metal kernels (section 8); the patch is required.

### GPU re-run

Label: commit `8be9338`, run in a checkout at `48bc5e9` (no guest code difference, see section 1) | coprocessor keccak | succinct, real | NVIDIA RTX 3080 12 GB,
driver 617.14, CUDA 12.8, risc0 3.0.5, WSL2 x86_64, in a container | **quiet** | median of 3 runs after one discarded warm-up; same method as the `022bb8b` table above.
The "Before" column is the `022bb8b` table (code `82bb54d`-equivalent, 2026-11-05).

| Action (bench action) | Cycles (bench meter) | Segments | Before (`022bb8b`) | Median (min–max) | Time saved |
|---|---:|---|---:|---:|---:|
| One-tx Update, finality (`update-finality`) | 6,529,823 | 7+1+1 | 84.6 s | 61.1 s (58.2–61.2) | 28% |
| One-tx Update, committee-learning (`update-learn`) | 6,981,360 | 8 | 80.4 s | 58.9 s (58.3–61.8) | 27% |
| One-tx Update, K=170 (`update-k170`) | 8,441,543 | 9+1+1 | 107.1 s | 75.7 s (74.0–77.0) | 29% |
| Attest ERC-20 log, compact (`attest-erc20-compact`) | 69,237 | 1 | 4.8 s | 4.4 s (4.34–4.42) | 8% |
| ERC-20 claim, chained (`claim`) | 155,845 | 1×4 | 7.5 s | 6.9 s (6.88–6.99) | 8% |
| ERC-20 claim, inline (`claim-inline`) | 120,855 | 1×3 | 6.6 s | 6.1 s (5.94–6.08) | 8% |

The cause of the shorter times was not isolated. The claim cycle counts are higher than the `022bb8b` rows (149,409 and 116,965) by the nullifier fix noted in section 1, and still prove faster.

### GPU: real private claim, `burn_member` and Groth16

Label: commit `8be9338` (checkout `48bc5e9`) | coprocessor keccak | real proofs | RTX 3080 12 GB, CUDA 12.8, WSL2, container | **quiet**.

| Run | Result |
|---|---|
| Real private claim: `private_claim_cycles` with `--features lee/prove,risc0-zkvm/cuda`, alone | 18.4 s wall including setup; GPU memory 4.1 GB |
| All 11 tests of `crates/program-tests/tests/private.rs` with real proofs, `--test-threads=1` | all pass, 156.6 s |
| `burn_member` release proof, CPU build of `bridge-prover` on the same box (`bridge-prover prove --fixture`) | 262,144 cycles; succinct 36.7 s; Groth16 wrap 56.1 s; total 92.8 s; peak RSS 2.4 GB; ImageID `b75588bc…5821` |
| `b22 e2e --sepolia`, membership proof + wrap, two releases | 103.8 s and 103.1 s (end to end inside the run, see [../evidence/independent-run-2026-11-12.md](../evidence/independent-run-2026-11-12.md)) |

Known issue: the CUDA build of `bridge-prover` aborts about 6 s into proving with
`sppark_error ... cudaStreamSynchronize ... illegal memory access` (2 of 2 runs; cause not found). The Groth16 wrap therefore runs on the CPU build. The
bench and `program-tests` CUDA builds (rows above) are not affected.

Cycle counts were identical between the Docker-built and the local guests in this run. Measurements here come from one box and one run per row except where a median is given.
