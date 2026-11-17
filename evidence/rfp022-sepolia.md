# RFP-022 private wrapped ERC-20/ETH bridge: Sepolia end-to-end run (2026-11-10)

Applies to guest ImageIDs bridge `030e554bab245def77adb144a04ada0bd57a9593109d74b034f6fcbded18878c` (LEZ program) and burn_member `0xb75588bcf980443c07957f005de58e9b811dd6f1b7d3795a26899785d78b5821` (`MEMBERSHIP_IMAGE_ID`); LEZ v0.4.0-rc1 (1806e87). The attest guest of RFP-021 (`dbdf349c…2fd80`, see [rfp021-final-run.md](rfp021-final-run.md)) is unchanged.

Local paths and host names are normalised in this file (`<repo>`, `prover-host`). Related: [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md), [../docs/BENCHMARKS.md](../docs/BENCHMARKS.md), [../docs/DECISIONS.md](../docs/DECISIONS.md), [../docs/TRUST-ASSUMPTIONS.md](../docs/TRUST-ASSUMPTIONS.md), [../proposal/COVERAGE.md](../proposal/COVERAGE.md), [README.md](README.md) (evidence index).

## Scope and trust notes

This is the recorded Sepolia run of the prototype bridge: private deposits on Ethereum, private claims, a private transfer, burns and releases, with wallet recovery and the pause/freeze controls exercised along the way.

- The root path is interim and custodial. Burn roots are accepted on Ethereum by `EcdsaRootVerifier`, a 2-of-2 secp256k1 signer set. The two signers can jointly accept a forged root. The release delay `D = 600 s`, demo-sized caps and permanent root revocation bound and undo that. The vault reports `TRUSTLESS() == false`. The zk root path is a milestone, not part of this run.
- Every LEZ transaction in the run used `RISC0_DEV_MODE=1`, which removes LEZ execution validity, not only liveness. The one real LEZ proof is a single `Burn` produced separately (Section 5).
- On Ethereum, the two `release` transactions carry real proofs: succinct `burn_member` receipts wrapped to Groth16 on the prover host and verified by the pinned `RiscZeroGroth16Verifier` v3.0.0.

## 1. Final Sepolia run

`b22 e2e --sepolia --groth16-host prover-host`: PASS in 2,477 s, one uninterrupted run (attempt 2; attempt 1 failed, see Section 3). Code: development commit `c380d4b` plus the freezer commit `4b680f8` (freezer cancel of a queued token change, `MIN_TIMELOCK`, freezer different from admin, `b22 freezer` commands) plus the RFP-021 final-run commits. All guests were built with risc0's reproducible Docker builder: bridge `030e554b…878c`, burn_member `b75588bc…5821`, identical on an aarch64 macOS host and an x86_64 Linux host. LEZ: local v0.4.0-rc1 sequencer on `:3063` (`B22_LEZ_PORT`; the previous run's `:3053` was still up), dev mode, fees 0. Ethereum: Sepolia, real `D = 600 s` release delay. Wrap time on the prover host: 88.3 s and 88.0 s.

Transcript: [rfp022/e2e-sepolia-final-transcript.txt](rfp022/e2e-sepolia-final-transcript.txt) (filtered of wallet progress lines; includes the post-e2e freezer evidence). Contract record: `contracts/bridge/deployments/sepolia.json` (Section 6).

### Addresses

| Item | Value |
|---|---|
| `BridgeVault` | `0x4A9695DBDAbed69F796dE39945A8EF7A35825472` (deployer nonce 46, predicted by `b22 setup` from nonce 44) |
| `EcdsaRootVerifier` 2-of-2 (`ROOT_VERIFIER()` readback equal) | `0x20F702cC8b15897EbbfE008d110C55c82dAA2876` (nonce 45) |
| `TetherToken` mock (USDT, 6 dec) | `0xBB2bb9aA927b3925dBf1AA92587aA448c8DB4f0e` (nonce 44) |
| Groth16 verifier (risc0-ethereum v3.0.0) | `0x2a098988600d87650Fb061FfAff08B97149Fa84D` |
| `CONFIG_ID` | `0xd998032a2613a668e0fe647ca4013f9ce74c6eda1843bbac3415474103d07a8e` |
| `MEMBERSHIP_IMAGE_ID` | `0xb75588bcf980443c07957f005de58e9b811dd6f1b7d3795a26899785d78b5821` (Docker build) |
| `MIN_TIMELOCK`, `MAX_FEE_BPS`, `D`, `minLezDepth` | 21,600 s, 500, 600 s, 10 |
| Root signer 1 (key from `B22_ROOT_SIGNER_1_KEY`, new) | `0x26497fe42fcfda16de4f6e225fa0340c430760c1` |
| Root signer 2 (`b22 gen-signer` on the prover host; the key exists only there) | `0x0dd666e319d673813c440f835bf9708cee9d95d1` |
| Freezer (`B22_FREEZER_KEY`), different from admin/deployer (`0x6378…4Aab`) | `0x413c7f9f0bdc9f73b1d5405e2e23e0d6a2d05e97` |
| LEZ bridge program / attest instance (RFP-021 instance on Sepolia, fresh checkpoint) | `0x7232c549…41cb` / `0xa7b7292c…dc31` |

The 2026-11-09 vault and its signer keys were left as they were; that older vault may still hold escrow.

### Deploy (`contracts/bridge/script/deploy_sepolia.py`, gas limits from the node)

Same order and parameters as `Deploy.s.sol`, but every transaction is estimated with the Sepolia node's `eth_estimateGas` and sent with limit = estimate x 1.2 at an explicit nonce. The local simulation underestimated contract creations about 7x in the 2026-11-09 deploy: for the vault creation a local revm fork estimated 2.30M gas, the Sepolia node 16.31M, and 16.18M was used. Sepolia charges far more than the mainnet schedule for state creation (probed with `eth_estimateGas` on 2026-11-09: empty contract 210,421; 1,000 runtime bytes 1,752,943; 2,000 runtime bytes 3,295,372; empty contract plus one fresh storage slot 321,389). The EIP behind this was not identified.

| tx | nonce | hash | block | node estimate | gas used |
|---|---:|---|---:|---:|---:|
| TetherToken mock | 44 | `0x4006ab565e5295d7e176aeb37324effbab50f6de37522a3886b4e1278e1dc4d0` | 12,102,057 | 9,772,199 | 9,694,094 |
| EcdsaRootVerifier | 45 | `0xfc99a8eb2caaade05fd15fbde5f473e5372810492dc939963a26be7e5000368b` | 12,102,058 | 4,065,517 | 4,032,347 |
| BridgeVault | 46 | `0xed2c7d65897a0789e12910dc2e04f2c7afcd806f3241ebb4d99ff7433827137b` | 12,102,059 | 16,310,416 | 16,180,829 |
| setToken ETH / setDenom ETH | 47 / 48 | `0x7823fc9d…0ef1` / `0x0fdb7b86…5aee` | 12,102,060–61 | | 244,209 / 129,123 |
| setToken USDT / setDenom USDT | 49 / 50 | `0xc9745b8f…2737` / `0xc67ee0c3…a017` | 12,102,062–63 | | 244,401 / 129,315 |
| setMinLezDepth(10) | 51 | `0x985a86e3b6c530ca98f91e160d0aebdddec18b2e8e487800f152f1d6f5652089` | 12,102,064 | | 130,653 |
| `fund-sepolia`: 200 USDT mock to the user | – | `0x9e1bd154c0ec3dabf7acddedf4c53f412790865ef4a4a268393aeadcd55b22ca` | 12,102,065 | | |

LEZ setup: Init `049e3450…f567` (block 172), InitConfig `700b0d3c…1e87` (182), RegisterToken USDT `d3c413bd…0ede` (192), ETH `fe671aa9…4524` (202).

### Transactions (from the transcript)

| step | chain | tx | block | gas |
|---|---|---|---:|---:|
| deposit A USDT i=0 / i=1 | eth | `0x652b6361…4cbc` / `0x5275c902…0047` | 12,102,067 / 69 | |
| deposit A ETH i=0 / i=1 | eth | `0x2bfd755f…d599` / `0xf4ee3994…58ce` | 12,102,070 / 71 | |
| claim A USDT i=0, ETH i=0, ETH i=1 (private; anchor leaf 5, 25/22/21 ancestry) | lez | `320ddb1b…4522`, `417fa403…4805`, `aca4f2d5…c979` | 644, 657, 669 | |
| transfer A to B 100 USDT (send, receive) | lez | `e40a74c8…16e3` + receive | 679 | |
| burn B USDT j=0 | lez | `1ba0beb8…390b` | 702 | |
| acceptBurnRoot USDT (count 1, lezHeight 712) | eth | `0xeb34f67ed1eea91282cf51270ea2651310e726ac1248b49edd48bc88dd967a19` | 12,102,179 | 151,877 |
| revokeRoot USDT (freezer) | eth | `0xc048b34e8ffc1b8f30d975480b7431cd7515d31f853ab85634eb41811f02a58f` | 12,102,180 | |
| burn A ETH j=0; acceptBurnRoot ETH (count 1, lezHeight 731) | lez / eth | `40b52ac0…374c` (721) / `0xcea2511b6982fb170345fbfc10e44bf061f2a4b032746f2fb4435d126fd1abac` | 12,102,184 | 151,661 |
| wipe A's notes and LEZ wallet; restore from mnemonic; recovery scan (8.2 s) | – | same holder account `5BCCVTd1…Fu9Q`; found unclaimed USDT i=1 and the unreleased ETH burn | | |
| claim A USDT i=1 (restored wallet); burn A USDT j=1 | lez | `ee9ad732…81e1` / `a2b52f5b…5669` | 742 / 752 | |
| acceptBurnRoot USDT (count 2, lezHeight 762) | eth | `0x8f50367e58b3af81da4d4511615630d1e823dfc3e82fc121435bed06b0082687` | 12,102,192 | 151,877 |
| release USDT (real Groth16), B's `recipient_0` `0xccdc…8992` +99,000,000, fee 1,000,000 | eth | `0x13fd50c7448dfd063e06e0ca4110a4167c8eeb1dbced0ef966e0beeedb9cd2a8` | 12,102,243 | 743,249 |
| release ETH (real Groth16), A's recovered `recipient_0` `0xbff3…c82f` 0 to 0.0099 ETH | eth | `0xc2d6baf1377dc63072f62b4a34b339556061e0161684c0abf6f946aae54faa0f` | 12,102,258 | 691,848 |

### Probes (asserted by the run; selector or LEZ code)

Release before the delay `ReleaseTooEarly()` `0xe1353c3d`; replayed release `NullifierSpent()` `0x63734faa`; release under the revoked root `RootRevoked()` `0x52053cdb`; deposit while deposits frozen and release while releases frozen `Frozen()` `0xa8cab3d1` (setFrozen txs `0xb80ed8c8…1e5e`, `0xc3038b86…995c`, `0x107ab10e…7f1`, `0x988c5eab…1092`); LEZ claim while mint paused 1304, the same replayed claim unpaused 1250, burn while burn paused 1304 (LEZ Freeze txs in blocks 1038–1074).

### Leak scans (all clean)

Deposit calldata x4 (100 B; absent `nk`, holder LEZ account); LEZ claims x4 (32,074 B; absent deposit block hash, header PDA, C, `nk`, holder, receipt, vault address); transfer send (34,193 B) and receive (30,913 B); burns x3 (31,898 B; absent `rk`, `recipient_j`, `Nb`, holder); releases B USDT and A ETH (1,849 B each; absent burn commitment, `rk`, LEZ account, `sk`).

### Latency (seconds; LEZ rows dev mode, no proving)

| step | s | step | s |
|---|---:|---|---:|
| deposit inclusion (4) | 16.1 / 27.3 / 9.9 / 21.7 | Ethereum finality + attest relay (RFP-021 relayer) | 1,065.8 |
| LEZ claim (3) | 37.2 / 30.7 / 30.7 | transfer send / receive | 30.4 / 30.4 |
| burn (3) | 30.7 / 31.0 / 30.6 | root signing, both signers (3) | 2.1 / 2.2 / 1.4 |
| acceptBurnRoot inclusion (3) | 13.5 / 14.5 / 15.2 | recovery (restore + scan) | 8.2 |
| membership proof + Groth16 wrap (prover host) | 88.3 / 88.0 | remaining release delay after proving | 520.4 |
| release inclusion USDT / ETH | 17.0 / 13.4 | whole run | 2,477 |

### Post-e2e freezer evidence (same deployment)

| step | tx | block | readout |
|---|---|---:|---|
| admin `setToken(USDT)` loosening (deposit cap 4d to 8d) | `0xa6fe9dc5da2d0a5287e729fe40dbeb3293680475b04321ecebc20b7cdc93fcf6` | 12,102,271 | `TokenChangeQueued`; `b22 freezer watch`: PENDING, matures in 21,600 s, cap 400,000,000 to 800,000,000 |
| freezer `b22 freezer cancel usdt` | `0x0e6a567f4568f058146b440e311477f2f5656b75c68ddbd07904ff36c3958122` | 12,102,273 | `pendingTokenAt now 0`; watch again: "matured, cancelled or replaced" |
| `b22 freeze eth both on` | `0x0e6297b29af4990d58cb4912afdac0aa52e4f02efc66b97f1d5f2043bfc72913` | 12,102,274 | deposits frozen true, releases frozen true |
| `b22 freeze eth both off` | `0x25ebef266181080739592c70b689eb829587fec5e5d6a4b8cee9cb81ed4fc2a1` | 12,102,275 | deposits frozen false, releases frozen false |

### Real Groth16 seal fixture

`contracts/bridge/test/fixtures/real_seal.json` was regenerated from this run: it is the seal from the USDT release calldata and `vault.releaseJournal(...)` at that block. `RealSeal.t.sol` now asserts `imageId ==` burn_member `b75588bc…5821` and verifies on the Sepolia Groth16 verifier (226,627 gas; a flipped seal reverts). `forge test` with `SEPOLIA_RPC` set: 71/71.

## 2. Local end-to-end flow (summary)

`b22 e2e --local` runs the same flow on anvil with a devnet beacon and a fresh LEZ sequencer (`:3052`, `RISC0_DEV_MODE=1`), with a mock risc0 verifier and two local dev root-signer keys on one machine. It exercises: four deposits (USDT i=0 and i=1, ETH i=0 and i=1, one left unclaimed on purpose); three private claims; a private transfer A to B with receive; burns and `acceptBurnRoot` for USDT and ETH; wallet restore and recovery scan for A; the recovered claim and a second USDT burn; the release delay `D` (600 s); and two releases with the mock seal. Setup took 637 s; the result is `b22 e2e --local: PASS in 1162 s (one run, no resume)`. It proves flow and contract logic, not proof validity: LEZ proofs are not generated or verified, and the seal is a mock. Transcript: [rfp022/e2e-local-transcript.txt](rfp022/e2e-local-transcript.txt) (filtered of wallet progress lines only; its header states what was removed).

## 3. Reruns (as they happened)

1. Attempt 1 (02:51–03:24 UTC) FAILED in step 10: deployment `0x7F3707E8…ae8E` (CONFIG_ID `0x5e69f5c6…d212`; its deploy txs are under "superseded" in `deployments/sepolia.json`). Steps 1–9 passed, both real-Groth16 releases included. Then the probe "deposit while deposits frozen" got `eth_estimateGas: OutOfFunds` instead of `Frozen()`: the user key held less than the 0.01 ETH the probe deposit carries. Cause: funding. The user key had 0.025 ETH; the run needs at least 0.03 ETH plus gas (two 0.01 ETH deposits, then the probe), and `fund-sepolia` skips any key whose balance is non-zero. Fix (no code change): moved 0.013 / 0.0035 / 0.0095 ETH from the relayer / freezer / deployer keys to the user (`0x4c3487f4…897c`, `0x5397ef61…ccaba`, `0xb36326d8…510b`). Attempt 1's two ETH deposits (0.02 ETH) stay escrowed in its vault: i=0 was burned on LEZ but its release comes after the failed probe; i=1 was claimed on LEZ. Transcript: [rfp022/e2e-sepolia-final-run1-FAILED-transcript.txt](rfp022/e2e-sepolia-final-run1-FAILED-transcript.txt).
2. Setup of attempt 2, first try, FAILED before any Ethereum transaction: attempt 1's LEZ sequencer still held `:3063`, so the new one could not bind and the first wallet transfer timed out. `setup_sepolia` deletes the run home (with `sequencer.pid`) before `setup_lez` tries to kill the old sequencer by that pid file. The old sequencer was killed by hand and setup run again. Not fixed in code (the fix is reordering two calls; not done, to keep the deployed build unchanged).
3. Attempt 2: PASS (Section 1), fresh setup, fresh deploy, one run.

## 4. Real Groth16 releases

Both releases in Section 1 were accepted by the vault with real seals: USDT release `0x13fd50c7…d2a8` (block 12,102,243, 743,249 gas, B's `recipient_0` `0xccdc…8992` +99,000,000 with fee 1,000,000) and ETH release `0xc2d6baf1…aa0f` (block 12,102,258, 691,848 gas, A's recovered `recipient_0` `0xbff3…c82f` 0 to 0.0099 ETH). Each seal is a succinct `burn_member` receipt wrapped to Groth16 on the prover host (88.3 s and 88.0 s) and verified on chain by the Groth16 verifier above (226,627 gas for the verification alone in `RealSeal.t.sol`). The release was attempted only after the 600 s delay; an early release reverts with `ReleaseTooEarly()`.

## 5. Real LEZ `Burn` proof and bridge executor cycles

Real proof, measured once on the prover host with `cargo test --release -p program-tests --test bridge real_burn_proof -- --ignored --nocapture` (setup claims in dev mode, then the `Burn` privacy-preserving transaction proven with `RISC0_DEV_MODE=0` and settled with proof checking on). Log: [rfp022/real-burn-proof.log](rfp022/real-burn-proof.log).

| Metric | Value |
|---|---|
| Prove (wall) | 285.3 s |
| verify + settle | 0.16 s |
| Tx size | 227,120 bytes |
| Peak RSS (`/usr/bin/time -v`) | 9,606,580 KB (9.6 GB) |
| Machine | WSL2 x86, 12 threads, CPU only (CUDA off), 1089% CPU |

No other real LEZ proof was produced; all other LEZ evidence is dev mode. The proof was not submitted to the live sequencer. (The log was captured from a dev-mode compile of the setup claims, so it also contains dev-mode warnings before the real-proof line.)

Bridge executor cycles, final guest: `RISC0_DEV_MODE=1 cargo test --release --locked -p program-tests --test bridge bridge_cycles -- --nocapture` on the prover host, 2026-11-10, `1 passed`.

| Step | Total (as public) | Public part | Private transition |
|---|---:|---:|---:|
| Claim | 176,776 | 74,270 (MintCheck: config hop + token PDA + CheckRoot + Spend) | ~102,506 |
| Burn | 145,062 | 123,012 (RecordBurn: config hop + token PDA + WriteLeaf) | ~22,050 |

The private transitions are measured as signed public root calls of the same guest code; the private part is proven by the user and is not metered by LEZ. The raw log of this cycle run is not in the repository.

## 6. Deployment record: `contracts/bridge/deployments/sepolia.json`

The file records, for the final deployment: chain id 11155111, deployer, `config_id`; for `BridgeVault`, `EcdsaRootVerifier` and the `TetherToken` mock the address, nonce, deployment tx, block, node gas estimate, gas limit and gas used, plus the constructor arguments (admin, freezer, root verifier, Groth16 verifier, `membership_image_id`, `config_id`, `max_fee_bps` 500, `min_timelock` 21600; verifier signers and threshold 2); the `registration` of ETH and USDT (denomination, standard fee, release delay 600, window 86400, deposit and release caps, `min_lez_depth` 10) with the five registration tx hashes; the LEZ side (`bridge_program_id` `0x7232c549…41cb`, `bridge_image` `0x030e554b…878c`, `attest_instance` `0xa7b7292c…dc31`); the four post-e2e freezer tx hashes of Section 1; and a `superseded` block with the attempt-1 deployment of this day and the 2026-11-09 deployment. No private key is stored in it.
