# Independent clean-checkout run (2026-11-12)

Purpose: check, from clean checkouts and with keys that were not used in the earlier runs, that the documented build, ImageIDs, benchmarks and the
Sepolia end-to-end flow reproduce. Code: commit `8be9338` (the tree in this repository). The GPU container held a checkout at `48bc5e9`, which
differs from `8be9338` only in documentation, formatting and tests: `git diff --stat 48bc5e9 8be9338 -- crates/` lists a doc comment in
`attest-program/src/residue.rs`, a formatting change in `bridge-cli`, one new host-side test file (`residue_differential.rs`) and assertion changes in
three other test files; no guest code. Commit hashes refer to the development history (see the README).

Related: [../docs/BENCHMARKS.md](../docs/BENCHMARKS.md) "Final code, 2026-11-12", [rfp022-sepolia.md](rfp022-sepolia.md), [rfp021-final-run.md](rfp021-final-run.md).

## Machines

| Name | Hardware | Used for |
|---|---|---|
| Mac | Apple M2 Max, 12 cores, 32 GB, macOS arm64; quiet | ImageIDs, CPU proving, real private claim |
| GPU box | WSL2 x86_64, RTX 3080 12 GB, driver 617.14, CUDA 12.8; container; quiet | GPU proving, real private claim, `burn_member` proof, Sepolia end to end |

## 1. ImageIDs

`scripts/image-ids.sh` from a clean clone reproduces all eight ImageIDs in the README table, on aarch64 macOS and, earlier the same day, on x86_64 Linux.
Docker builder pinned by digest `sha256:6f6c300e4af57ea3efe62b7f04a17629efe0f0caa6ad3699d6766bf19e0e62fb`. Output (Mac):

| guest | ImageID |
|---|---|
| attest | `dbdf349c065395c8fba0857cddc096ba4e5a7a458adc2d117f101fc3cea2fd80` |
| erc20_receiver | `f132dd78b21cd013671482e77102ffe0dc6ee98337bdb71cb2ee52c025447a25` |
| eth_receiver | `309ad796177939a8a857b9b4de81ec96068897adef7d82cb0d75371ee28d4f08` |
| erc20_inline_receiver | `1b62b2f919fb9d79a2e6054632fa567ba54a1ce0df307caa7460d75247218655` |
| bridge | `030e554bab245def77adb144a04ada0bd57a9593109d74b034f6fcbded18878c` |
| burn_member | `b75588bcf980443c07957f005de58e9b811dd6f1b7d3795a26899785d78b5821` |
| spec_selftest (test only) | `ea8a7d689a298a109689675cd2ca8a2a1e4e5bdc0ccb2adffb6a3705211a520a` |
| sha_selftest (test only) | `37b9e1663c11ac238795e4e4c14f21f3488d6012748a74c59559674fc9d40b70` |

Guests built without Docker have different ImageIDs. The Sepolia run below used a vault with `MEMBERSHIP_IMAGE_ID = 0xb75588bc…5821`, the Docker-built `burn_member`.

## 2. Proving benchmarks (summary)

Full tables with labels are in [../docs/BENCHMARKS.md](../docs/BENCHMARKS.md); raw rows in [bench/bench-results-m2-cpu-final.log](bench/bench-results-m2-cpu-final.log)
and [bench/bench-gpu-rerun-48bc5e9.log](bench/bench-gpu-rerun-48bc5e9.log). All real proofs, `RISC0_DEV_MODE` unset, succinct.

- Mac, CPU prover, `8be9338`: one-tx Update 681.7 s (finality), 728.9 s (committee-learning), 868.7 s (K=170), peak RSS 8.39 to 8.69 GB; ERC-20 claim flow about 107 s; inline claim flow about 94 s.
  Real private claim (LEZ privacy-preserving proof): 143,466 cycles as a public call, public part 46,657, private transition ≈96,809; whole test 245.07 s, 8.60 GB.
- GPU box, GPU prover, `48bc5e9`: Update rows 27 to 29% shorter than the 2026-11-05 `022bb8b` table (finality 61.1 s, learn 58.9 s, K=170 75.7 s); attest and claim rows about 8% shorter.
  Real private claim 18.4 s with 4.1 GB GPU memory; all 11 tests of `tests/private.rs` pass with real proofs in 156.6 s.
- `burn_member` release proof (CPU build of `bridge-prover`): 262,144 cycles, succinct 36.7 s, Groth16 wrap 56.1 s, total 92.8 s, peak RSS 2.4 GB.
- Executor claim cycles on the final code are higher than in the earlier tables, because of the later per-vault nullifier fix: ERC-20 chained 155,845 (was 149,489), ETH 135,145 (133,526), inline 120,855 (117,041), private ≈96,809 (≈95,949). Docker-built and local guests gave identical cycle counts.
- Known issue: the CUDA build of `bridge-prover` aborts about 6 s into proving with `sppark_error ... cudaStreamSynchronize ... illegal memory access` (2 of 2 runs, cause not found). The Groth16 wrap runs on the CPU build.

## 3. Sepolia end to end with fresh keys

`b22 e2e --sepolia`: PASS in 2,500 s, one run. New deployer and new signer, freezer, user and relayer keys, so none of the earlier addresses are reused. Own LEZ v0.4.0-rc1
sequencer (`1806e87`) in the container; LEZ transactions in dev mode, as in the recorded runs. Both root signers and the prover ran in the same container, so this is not a
test with the second signer on a separate host. Real Groth16 seals on Ethereum. RPC `https://sepolia.gateway.tenderly.co`. Latencies of the run: Ethereum finality plus attest relay 1,149 s,
release delay D 506.4 s, membership proof plus wrap 103.8 s and 103.1 s.

### Contracts

| Item | Address |
|---|---|
| `BridgeVault` | `0x06E4B9f3fE5b745E0DF99F4501a5Cf4c380e3af0` |
| `EcdsaRootVerifier` | `0x79b105223fF0d52838fc176fffb0D1Fa9A30dfF2` |
| USDT mock | `0x227612D745EEe65000F0d7762F59b6Ef918Ec48d` |
| RFP-021 `DepositVault` | `0xa448c3c6049ee5ad2c7a76827f828ca0f406099f` |

### Ethereum transactions

| Step | Transaction |
|---|---|
| deploy vault | `0x7846bd36a018e30ad69606a3135264e95e23c105b1fa2e6d138c89718df30221` |
| deposit USDT | `0x27eabbfacd87698581e65cb327fea2905d6a4856484b507e45da4538570c884b` |
| deposit USDT | `0x7a6c746ed02996349f0a9375bdafc3929437fc96741a95e0500855386464a3ae` |
| deposit ETH | `0xe3f7166e299a07f8c3a0fb2650a95bebb26aec72a15fc52f9fd070ac26370998` |
| deposit ETH | `0x5b0cd709e24f0866ae647849222d4777e60e34bb88f97782adbfbafbd3e7d071` |
| `acceptBurnRoot` USDT | `0xcc189826fba1aeecbbb6987ffb84f19f4a2d80860c7d1a6404c34588f6a1ffac` |
| `revokeRoot` | `0xc955f1b17e365fb2ebf4489d81d76dcc492f4b5306d1cb2db4660a8fac7f0883` |
| `acceptBurnRoot` ETH | `0xd3c14ba06135bf6981f2f70d905ee51032980adf0e3d264fe474e7d92bf2cd85` |
| `acceptBurnRoot` USDT (second) | `0x4197639d459c708cf3726a69fff42673b1664b59136e7eb6736c4159e10b3a25` |
| release USDT, real Groth16, 743,213 gas | `0xbdaebe13ada0c2d87a8fc2a726a8c5ffa44f1fa6082ee4fea1e33e8a1d0e7321` |
| release ETH, real Groth16, 691,836 gas | `0xba347dc97424954740fd62babd7ba0588f05ec4521d8cd05fecf33d5686a67a7` |

### LEZ transactions

| Step | Transaction |
|---|---|
| claim USDT i=0 | `55246161cb08faa90423e72d78f5b049bcb77d8ece0c640b38b9c95aff329353` |
| burn B USDT | `08354cc2c28dc7d913e4719409a5ef2d1a3be9244c2aea7259f0e8d66fb8d87c` |
| burn A ETH | `41a70e0bf977c55d3cc4bcf9700f28e372046cbce733882d22a9140ff829c9a9` |

### Probes

All behaved as expected: release before the delay reverts `ReleaseTooEarly`; replayed release `NullifierSpent`; release under the revoked root `RootRevoked`; deposit and release while frozen
`Frozen`; claim and burn while LEZ mint or burn is paused are refused with LEZ code 1304; a replayed claim with mint unpaused is refused with 1250.

## 4. RFP-021 consumers on fresh deposits

Same Sepolia run, a second `DepositVault` and two fresh deposits; the LEZ side ran in dev mode.

| Step | Transaction |
|---|---|
| `DepositVault` deploy | `0x23bb01a05cc5cd077dbe7f1377c2ccc717203ef5dc319ffda0f3041ad104a211` |
| deposit | `0x1e0cf51e290b29e9260b257bc739ae92ed94a8bd47989fd64140de766527a73e` |
| deposit | `0xcb8b4757265016f75d0de7a9b271babd21bf618e50fbf7d1f3b634594de86a28` |
| LEZ `erc20_receiver` Claim (replay reverted) | `ba7eb8b93d0d9589989a0ff7563cebb335f5e37f1f07baebfa82dd97539ff1e8` |
| LEZ `eth_receiver` Claim, EIP-7708 log (replay reverted) | `0f379125cc6d03da3c4da4e8deba7fc6749b18f93859aac998142847a288fc9a` |
| LEZ `PrivateClaim` | `3de353d4c25dd3ca1c9bf79afcb6beee45487dda220bca364e2386110b9a5111` |

For the private claim, a second claimant with the same nullifier key was reverted, and a replay and a claim through a second vault were refused with 1250. The footprint scan was clean. Two overlapping harness runs overwrote the eth and private claim logs, so these ids were confirmed afterwards by restarting the run's own LEZ sequencer from its saved state and reading the blocks back, no new transactions: eth InitVault block 1573 and Claim block 1583 applied (311,228 cycles), its replay block 1593 reverted; PrivateClaim block 1616 applied (nullifier PDA spent), the same-key second claimant in block 1616 reverted; a later duplicate eth claim from the second harness run (block 1624) reverted because the deposit was already claimed. Readback: [independent/r21-claims-readback.txt](independent/r21-claims-readback.txt).
Sepolia gas spent by the run: about 0.0017 ETH.

## 5. Not covered

- The inline-consumer claim (`erc20_inline_receiver`) was skipped in the Sepolia run; it is covered by the executor tests and the proving rows above.
- LEZ transactions were in dev mode, so LEZ execution validity was not checked on this run (the one real LEZ `Burn` proof is [rfp022/real-burn-proof.log](rfp022/real-burn-proof.log)).
- Signer 2 and the prover were in the same container; a separate-host signer was not tested.
- The CUDA Groth16 wrap does not work (section 2); the wraps used the CPU build.
- One run per row on one Mac and one GPU box; no repeat of the Mac rows.
- The Mac checkout ran `cargo` without `--locked`; cargo removed two lines from `Cargo.lock` in that checkout.

## 6. Documentation gaps found and fixed

| Gap | Fix |
|---|---|
| `b22 setup --sepolia` used a hard-coded deployer address | now `SEPOLIA_DEPLOYER` (an address) or the address of `SEPOLIA_KEY`; README "Keys" and the operator guide |
| `b22 --help`, `-h` or no arguments ran a command (`b22 setup --help` ran setup and cleared `target/b22-local`) | now prints usage (code change in `bridge-cli`) |
| The Sepolia flow needs ssh hosts for signer 2 and the prover, and `remote_groth16` uses `RISC0_WORK_DIR=$HOME/r0work` there | documented in the operator guide, "RFP-022 client" |
| `deploy_sepolia.py` needs `eth-abi`, `eth-account`, `eth-utils`, `rlp` | added to the prerequisites in the README and the operator guide |
| The Groth16 wrap needs `rzup install risc0-groth16 0.1.0` (the `rzup` default 0.2.0 is rejected by risc0 3.0.5) | added to the prerequisites |
| Guests built without Docker have other ImageIDs, so the vault's `MEMBERSHIP_IMAGE_ID` matches only the same build | sentence added to the operator guide; use `RISC0_USE_DOCKER=1` for the README IDs |
| "Fund claimants with `auth-transfer send`" fails for a private recipient because fees are non-zero | [rfp021-final-run.md](rfp021-final-run.md) "Reproduce" step 3: fund through an intermediate public account |
| `program-e2e deploy` re-sends the `attest` deploy for an existing account and prints "deployed"; the sequencer's loader panics (`header target already deployed`) in a caught task and keeps running | noted as known behaviour in the operator guide and in the "Reproduce" step 4 |
| Header of `crates/program-tests/tests/private.rs` said "dev-mode proofs" | now states dev-mode proofs by default and real proofs with `--features lee/prove` |
