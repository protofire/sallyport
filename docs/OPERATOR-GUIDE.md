# Operator guide

An operator advances an instance's tracked Ethereum state by fetching public light-client data and submitting it. **No party is obliged to operate.** Liveness rests on interested parties choosing to spend the gas; nothing in this design pays or forces anyone to.

Status, stated plainly: the relayer (`rfp021 run-relayer`, built with feature `lez`) and the Logos module's `submit_update` both advance a live instance on a **local LEZ v0.4.0-rc1 standalone sequencer**, tracking live Sepolia, with RISC0 dev mode (no proofs; updates run publicly, so nobody proves them anyway). The final run (commit `c380d4b`) had two relayers and the module advance one instance, each update in one tx ([../evidence/rfp021-final-run.md](../evidence/rfp021-final-run.md)). Not deployed on a public network: the public LEZ testnet runs v0.3.x. Tested on one machine (M2 Max); other platforms untested.

## What it requires

- A consensus (beacon) API endpoint that serves light-client bootstrap/updates/finality updates, read through `beacon_api_module`. Tested with lodestar and publicnode.
- An execution RPC, only needed to build user attestations, not to advance the instance. Read through `eth_rpc_module` (it sends no User-Agent, which rules out 0xrpc.io). Default `https://sepolia.gateway.tenderly.co`: serves `eth_getProof` at a finalised block hash, `eth_getBlockReceipts`, and header lookups, checked 2026-11-04 (1rpc.io refuses `eth_getBlockReceipts`; publicnode's proof window is too short; D-MOD-2). The EL provider is not trusted for safety: every header and proof is checked.
- A funded LEZ account for gas, **one per operator process** (two signers on one payer race on the nonce; D-CLI-1). **No standing on Ethereum** is required: no validator, stake or registration.
- Permission: none. `Update`, the fallback `UpdateBegin`/`UpdateVerify`, and `Init` have no role or allowlist check. Both live runs (2026-11-05, and the final run of 2026-11-10) had updates from three accounts, op1, op2 and the module's fresh random key, all run by Protofire ([../evidence/rfp021-final-run.md](../evidence/rfp021-final-run.md)).

## Install

```
git clone <repo> && cd <repo>
cargo +1.98.1 build --release -p relayer --features relayer/lez   # binary: target/release/rfp021
```
The relayer pulls `beacon_api_module` (rev f19ec82) and `eth_rpc_module` (rev b39bebf, all execution-layer reads) as git dependencies, without the Nix-only parts (`crates/relayer/Cargo.toml`). Feature `lez` adds the LEZ submitter (`lez-client`, rustc 1.98.1). Building the guest programs and `program-e2e` needs the RISC0 toolchain (rzup, r0vm 3.0.5) and, on macOS only, `AR_riscv32im_risc0_zkvm_elf` pointing at the RISC0 cross archiver (not needed on Linux). The Logos module alternative: docs/MODULE.md.

### Upgrade host and attest guest together

The host side (relayer, `eth_attest_module`, `lez-client`) and the attest program image are one release: deploy the matching attest image before (or with) the new host. A host from this version sends `Update` with K+2 decompression hints (the uncompressed aggregate key and signature after the K non-signer keys, D-UPD-2); an older attest guest accepts only K hints and rejects the update with 1102. Consumers built from this version also need the matching attest image: they send `Proof::LogCompact` (Borsh tag 3) and inline consumers send `Msg::CheckHeader` (tag 10), which older attest images do not decode. Check the attest ImageID against [evidence/rfp021-final-run.md](../evidence/rfp021-final-run.md) before switching.

## Configure

TOML, fields from `crates/relayer/src/config.rs`:

```toml
beacon_endpoints = ["https://lodestar-sepolia.chainsafe.io", "https://ethereum-sepolia-beacon-api.publicnode.com"]  # at least one
chain_id         = 11155111                                    # default Sepolia
state_file       = "/var/lib/rfp021/state.json"                # required; makes restarts resume
operator_key     = "operator-1"                                # required, distinct per operator; seeds jitter
max_defer_secs   = 300                                         # default 600; >= 300 recommended for 2 operators
poll_secs        = 12                                          # default

[lez]
payer          = "<base58 LEZ account, one per process>"
attest_program = "<base58 attest program account>"
instance_id    = "0x..."    # printed by `program-e2e init`; = attest_program::instance_id(cfg, checkpoint root)
max_fee_cap    = 20684800000 # optional; ceiling on any tx's max_fee (default lez_client::DEFAULT_MAX_FEE_CAP)
```
The LEZ signer comes from the LEZ wallet (`LEE_WALLET_HOME_DIR`). Logs are JSON on stderr (`tracing`). Ctrl-C / SIGTERM sets a stop flag and the loop exits after the current tick.

## Run

```
rfp021 dry-run --config relayer.toml        # prints the next job it would submit, submits nothing
rfp021 run-relayer --config relayer.toml    # operator loop against the LEZ instance in [lez]
rfp021 fetch-update --period <n> [--bootstrap-root finalized|0x..]   # LC material (and a bootstrap for Init)
rfp021 fetch-attest --block-hash 0x.. --address 0x.. [--slot 0x..] [--tx-index N --log-index N] [--anchor 0x..] [--exec-verified http://127.0.0.1:8545]
```
Starting a new instance: first fetch the bootstrap material for the current period, then init.

```
rfp021 fetch-update --period <n> --bootstrap-root finalized --beacon <url> --out init-material.json
program-e2e init <payer> init-material.json
```
`n` = finalized slot / 8192 (integer division; 8192 slots per sync-committee period). Get the finalized slot from `<beacon>/eth/v1/beacon/states/head/finality_checkpoints` (the epoch under `finalized`, times 32) or `<beacon>/eth/v1/beacon/headers/finalized` (`header.message.slot`).

`program-e2e init <payer> <material>` computes and prints the instance id from the config and checkpoint (`Init` rejects any other id, and any config below the floor). The full sequence, including deployment, is in [../evidence/rfp021-final-run.md](../evidence/rfp021-final-run.md) "Reproduce".

## Cadence

Hard requirement: tracking moves one sync-committee period (256 epochs, about 27.3 h) at a time. The instance must learn each `next_sync_committee` before the period ends; an update that skips a period is refused (1104). Miss longer than `ws_period_epochs` (Sepolia 279 epochs × 384 s = about 29.8 h; mainnet 3,537 epochs, about 15.7 days; D-LC-6) and the instance can no longer be advanced (1105): replace it.

Weak-subjectivity window, what an operator must do. The clock runs from the instance's last recorded finalized slot (`check_not_stale`), not from the last tx. On Sepolia the window (~29.8 h) is only ~2.5 h longer than one sync-committee period (~27.3 h), so a single missed day can end the instance; it cannot be refreshed in place (F13).
- Keep at least one finality-advancing `Update` landing every few hours, and the next committee learned early in each period (the relayer's job order already puts handoffs first).
- Alert when the finalized slot is older than half the window (~15 h on Sepolia), and again at ~24 h; at that point submit by hand from a second machine or key if the relayer is stuck.
- Run at least two operators with independent hosts, keys and beacon/EL providers; any party may submit (R7).
- If the window is missed (every update returns 1105): `Init` a new instance from a fresh, independently checked checkpoint (TRUST-ASSUMPTIONS.md section 3) and tell consumers to migrate (CONSUMER-GUIDE.md, "Migrating"). Facts already attested stay valid. This migration is untested end to end.

Soft requirement: consumers attest to recorded execution blocks, or to any block up to 448 headers below one (ancestry). A header is recorded when a finality update advances `finalized_header`. Recording every epoch's checkpoint keeps every finalised block within 31 headers of a recorded one. The relayer's `next_job` order is: outstanding period handoffs first, then a finality advance if head moved (`operator.rs`).

## Costs

LEZ charges a public tx its metered guest cycles (`user_cycles`, capped at the tx gas limit) plus its data bytes; the 10M action cap is `MAX_GAS_EXEC` (docs/BENCHMARKS.md "How LEZ charges gas"). Executor cycles, current guest code (docs/BENCHMARKS.md section 1):

| Action (one tx) | Cycles = execution gas units |
|---|---|
| Init | 2,957,482 (executor at `20c6fc3`); 917,321 live at `82bb54d` |
| Update (atomic, the client default for K <= 170, D-UPD-3): finality K=2 / committee-learning K=2 / any kind K=170 | 6,559,273 / 6,981,423 / 8.47-8.87M |
| Fallback only (K > 170), at `20c6fc3`: UpdateBegin, finality only (no new committee) | ≈3.0M |
| Fallback only: UpdateBegin, learning next committee, K=2 non-signers | 5,842,552 |
| Fallback only: UpdateBegin, K=170 non-signers | 7,784,282 |
| Fallback only: UpdateVerify | 6,174,197 (learn-next fixture); 5.6-6.7M across update kinds |
| One update (Begin + Verify), 2 txs (fallback only) | about 8.6-14.5M (sum of the ranges) |

Amortised, in gas units: one committee-learning `Update` per period (about 7.0M; 7,026,455 live) plus one finality `Update` per recorded epoch (about 6.6M; 6,604,214-6,606,851 live). At one recorded checkpoint per epoch that is 256 finality updates per 27.3 h period, about 1.7 billion gas units per period (derived, not measured); recording less often lowers it and pushes more users onto ancestry. Fee in tokens depends on the LEZ base fee, which no available v0.4 network sets, so it is not reported. The client sets each tx's `max_fee` from the sequencer's `getFeeState` (next-block base-fee ceilings, doubled), not from a fixed price, so a congested base fee raises the cap instead of locking the operator out; it is clamped to `max_fee_cap` (default: a full 10M-gas tx at base fee 1024, doubled), so a hostile sequencer quote cannot make the payer authorize more, and above it txs are refused rather than overpaid; the fee charged is still the actual base fee for the cycles used. A collided update still pays its gas (one wasted Begin+Verify was seen live in an earlier run, before one-tx updates; none collided in the final run).

Off-chain: the residue witness is built on the host (`crates/attest-program/src/witness.rs`, feature `witness`); relayer CPU/RAM/time are **not measured** (P6).

## Concurrent operators

Several operators can run against one instance. Before submitting, the relayer re-checks that the job is still needed (once after fetching, and again right before submit), and marks a submitted job as suppressed for 5 minutes in the state file (tests `skips_when_chain_advanced_before_submit`, `restart_resumes_without_resubmitting`). A duplicate that still lands is rejected by the program with 1106 and does not double-apply. Each submit uses a random u64 job id, so two operators do not collide on the job PDA by accident. An adversary can still squat it on the split path: `UpdateBegin` writes the job PDA before the BLS pairing is checked, so a front-runner who copies the pending `job_id` with a bogus signature makes our `UpdateBegin` fail (liveness only; nothing is applied, the relayer retries with a new id). This path is the K > 170 fallback, unreachable at the 342 participation floor; the default atomic `Update` has no job PDA and is unaffected.

Deferral. Each job is delayed by a random interval in [0, `max_defer_secs`] seeded by `operator_key` and the job (`defer_ms`), so over many updates different operators win (`deferral_spreads_cost`). Measured live with two operators and `max_defer_secs = 300`: seen → verified took 33-60 s when an early deadline fell soon, and 3 m 03 s when it fell late; one collision in five advances, harmless ([../evidence/rfp021-final-run.md](../evidence/rfp021-final-run.md)). The needed-check cannot see a rival's in-flight tx, which takes about 30 s (two 15 s LEZ blocks); more operators need a wider window or a leader rule.

## Detecting a stalled instance

- Read the instance (module `read_instance`, or `lez_client::read_instance`) and compare `finalizedSlot` with Ethereum's current finalized slot (`/eth/v1/beacon/states/head/finality_checkpoints`). A lag of more than one period means it will refuse new updates soon.
- `rfp021 dry-run` prints a job when the tracked state is behind.
- Consumer symptom: `Attest` returns 1101 for recent blocks.
- Hard stall: 1105 on any update attempt. The instance must be replaced (CONSUMER-GUIDE.md). Recorded headers keep verifying.
A stalled instance resumes if any party submits the outstanding updates in order (R7), as long as the ws period has not passed.

## Restart and failure behaviour

The state file records the jobs this operator submitted (job, tx, time; the last 256), and a job submitted less than 5 minutes ago is not resubmitted after a restart (`restart_resumes_without_resubmitting`, against a mock chain). The deferred, not yet submitted job is kept in memory only: after a restart the loop derives it again from the chain and draws a new deferral. Failed ticks back off exponentially up to a cap (`backoff_grows_and_caps`). If the beacon endpoint is down the loop keeps retrying; nothing is lost. A one-tx `Update` that is included but whose result is not on chain while the update is still applicable (most likely out of gas at the measured limit) is resent once at `MAX_GAS_EXEC` (10M); any other unconfirmed result is reported with the re-check reason and not retried. A failed submit is recorded in the state file like a submission, so the loop does not resend it (paying again) on each backoff tick or after a restart until the 5-minute grace period ends (`failed_submit_is_not_resent_within_grace`). A bad witness or signature fails `UpdateVerify` with 1102 (no trap; D-ATT-4) and still costs its gas. LEZ has no revert reasons, so the relayer classifies a revert by re-running its local pre-check on the post-state (D-REL-1).

## Known liveness limits (no fund risk)

- Header accumulator capacity. The instance's header accumulator (a Frontier of depth 20) holds 2^20 − 1 headers. When it is full every finality-advancing `Update` fails with 1001 for good and the client refuses with "header accumulator full"; at one recorded header per epoch (6.4 min) that is about 12.7 years. Replace the instance before then (CONSUMER-GUIDE.md, migration).
- Gloas header records. A header record PDA is keyed by `(instance_id, execution_block_hash)` and is write-once. After the Gloas fork the execution hash taken from a beacon block is its payload bid's `parent_block_hash`, which is not unique per beacon block: if payloads are withheld for a full epoch, two finalized checkpoint blocks can carry the same value, and the second `WriteHeader`/`Update` for different header bytes fails 1001. Finality then cannot advance through that checkpoint until a later one with a fresh value. Not exercised; Gloas is active on Sepolia (epoch 353,024) and its weak-subjectivity margin is short, so watch for repeated 1001 on finality updates.
- Split-path job squat. See "Concurrent operators" (K > 170 fallback only).

## Local live run (RFP-021)

`program-e2e` drives a live flow against a LEZ v0.4.0-rc1 standalone sequencer (`vendor/lez`, `sequencer_service` built with `--features standalone`, started with `RISC0_DEV_MODE=1`, a fresh home and the debug wallet config). Local setup, once per fresh chain (the funding key below is the public key of the LEZ standalone genesis account):

```
sequencer_service setup <home> --config lez/sequencer/service/networks/local.json --funding-public-key 2e03b2eff5a45478e7e79668d2a146cf2c5c7925bce927f2b1c67f2ab4fc0d26 --create-channel
RISC0_DEV_MODE=1 sequencer_service start <home> --rpc-listen-address 127.0.0.1:3060
```
Take the wallet config from `lez/wallet/configs/debug/wallet_config.json` and change the port to the sequencer's. Import the payer key with `wallet account import public --private-key <key>`; the keys are the constants `LEZ_PAYER_KEY` and `ATTEST_DEPLOY_KEY` in `crates/bridge-cli/src/main.rs`, public dev keys of the LEZ standalone genesis. With the default 15 s local blocks, deploy takes about 10 minutes.

Build `program-e2e` with `cargo +1.98.1 build --release -p program-e2e`; its subcommands include `deploy` (it re-deploys `attest` without checking: against an account that already exists it still prints "deployed" and the sequencer logs a caught loader panic, `header target already deployed`; run it once per fresh chain), `init`, `header`, `root`, `claim`, `private-claim`, `simulate`, `gas` and `image-ids`. `rfp021 run-relayer` advances the instance; the recorded flow with every transaction is in [../evidence/rfp021-final-run.md](../evidence/rfp021-final-run.md). `e2e.yml` is manual only because the Sepolia fixture checkpoint ages out of the weak-subjectivity period (279 epochs): `Init` returns 1105 until the fixture is refreshed.

The adversarial vector tests write `crates/vector-runner/RESULTS.md` and `crates/program-tests/GUEST-VECTORS.md` when run; both are untracked. The official Ethereum vectors are downloaded by `crates/spec-tests/fetch.sh` (pinned releases, sha256 checked, about 1.4 GB) and run with `SPEC_TESTS_DIR=<dir> RISC0_DEV_MODE=1 cargo test --release -p spec-tests -- --nocapture --test-threads 1`; the crate panics without the vectors and never passes vacuously.

## RFP-022 client (`b22`)

Prerequisites: Ubuntu 24.04 packages `build-essential curl pkg-config libssl-dev python3 clang cmake jq libpcsclite-dev rsync docker-buildx` (`rsync` for `b22 e2e --local`, `docker-buildx` for `scripts/image-ids.sh`, `libpcsclite-dev` for the LEZ wallet; the GPU bench also needs `protobuf-compiler` and the CUDA 12.8 toolkit), Rust 1.98.1, the RISC0 toolchain (rzup: rust 1.97.0, cpp 2024.1.5, cargo-risczero and r0vm 3.0.5), Foundry 1.5.1 with `git submodule update --init --recursive contracts/bridge/lib`, the Python packages `eth-abi`, `eth-account`, `eth-utils` and `rlp` for `contracts/bridge/script/deploy_sepolia.py` (`pip install eth-abi eth-account eth-utils rlp`), `rzup install risc0-groth16 0.1.0` for the Groth16 wrap (the `rzup` default 0.2.0 is rejected by risc0 3.0.5), and a LEZ checkout at `1806e87` with `sequencer_service` and `wallet` built. Build the client with `cargo build --release -p bridge-cli` (binary `b22`).

Local run (anvil, devnet beacon and a fresh LEZ sequencer on 127.0.0.1, mock seal; about 20 minutes):

```
RISC0_DEV_MODE=1 B22_LEZ_VENDOR=<lez checkout> B22_HOME=<a directory for run state; setup clears its own subdirectories> ./target/release/b22 e2e --local
```

Sepolia run (Sepolia ETH on the user, freezer and relayer accounts; signer host 2 reachable over ssh):

1. On signer host 2: `b22 gen-signer` writes `~/.b22/root-signer-2.key` and prints the address only.
2. On the main host: `b22 setup --sepolia --signer-2 <address>` prints the deploy inputs. Then deploy with `python3 -I contracts/bridge/script/deploy_sepolia.py` (or `forge script script/Deploy.s.sol`) using `CONFIG_ID`, `SIGNER_1`, `SIGNER_2`, `MEMBERSHIP_IMAGE_ID`, `EXPECTED_VAULT`, `FREEZER` (must differ from the deployer) and `SEPOLIA_KEY`. The user key needs at least 0.031 ETH before the run.
3. Copy `deployment.json` (public facts only) to signer host 2's `b22` home, then `b22 e2e --sepolia --groth16-host prover-host`.

The Sepolia flow assumes two ssh hosts: signer host 2 (`B22_SIGNER2_HOST`, runs `b22 sign-root` for the second signer) and the prover host (`--groth16-host`; the same machine in the recorded runs). `remote_groth16` runs `bridge-prover` on the prover host with `RISC0_WORK_DIR=$HOME/r0work` and `RISC0_DEV_MODE` unset (work directory `$HOME/r0work` on that host); the prover host also needs `rzup install risc0-groth16 0.1.0` and Docker for the wrap. Run the wrap with the CPU build of `bridge-prover`: the CUDA build aborted 2 of 2 times about 6 s into proving with `illegal memory access` in `cudaStreamSynchronize` (cause not found, [BENCHMARKS.md](BENCHMARKS.md) "Final code, 2026-11-12").

The ImageIDs in the README are those of the Docker-built guests. A guest built without `RISC0_USE_DOCKER=1` has a different ImageID, and the vault's `MEMBERSHIP_IMAGE_ID` then matches only a `burn_member` built the same way: build `bridge-prover`, `b22` and the deploy inputs with `RISC0_USE_DOCKER=1` if the deployment should carry the README IDs. A run by someone other than the original deployer sets its own `SEPOLIA_KEY` (and `SEPOLIA_DEPLOYER` for `b22 setup` on a host that does not hold the key); an independent run of this flow with fresh keys is in [../evidence/independent-run-2026-11-12.md](../evidence/independent-run-2026-11-12.md).

Freezer duty (key `B22_FREEZER_KEY`): `b22 freezer watch --loop` reports every `TokenChangeQueued` and `MinLezDepthChangeQueued` with the values it would apply; `b22 freezer cancel <eth|usdt|0x...>` cancels a pending token change; `b22 freeze eth|lez mint|burn|both on|off` pauses and prints the resulting flags.

| Variable | Used by | Default / meaning |
|---|---|---|
| `B22_HOME` | every command | `target/b22-<network>`: run home (deployment, cache, wallets, notes) |
| `B22_LEZ_VENDOR` | `setup`, `e2e`, wallets | LEZ `1806e87` checkout with `sequencer_service` and `wallet` built (default: `vendor/lez`) |
| `B22_LEZ_PORT` | `setup --sepolia` | 3053: LEZ sequencer RPC port (local runs use 3052) |
| `B22_REUSE_LEZ` | `e2e --local` | `1` keeps the previous run's sequencer, wallet and deploys |
| `RISC0_DEV_MODE` | all LEZ transactions | `1` for the recorded runs; unset only on the prover host |
| `SEPOLIA_RPC` | `setup --sepolia`, Sepolia commands, forge `RealSeal` | `https://sepolia.gateway.tenderly.co` for `b22`; `RealSeal` is skipped when unset |
| `SEPOLIA_DEPLOYER` | `setup --sepolia` | address that sends the deploy transactions (nonce source for the predicted addresses); default: the address of `SEPOLIA_KEY` |
| `SEPOLIA_BEACON` | `setup --sepolia` | `https://lodestar-sepolia.chainsafe.io` |
| `B22_SIGNER2_HOST` | `sign-root` (signer 2), Groth16 wrap | `signer2` (an ssh host alias for signer host 2, which was also the prover host in the recorded run) |
| `B22_SIGNER2_CLIENT` | signer 2 over ssh | `~/b22-client`: checkout on signer host 2 with `target/release/b22` built |
| `B22_SIGNER2_REPO` | Groth16 wrap over ssh | `~/b22-prover`: checkout on the prover host with `target/release/bridge-prover` built (Docker for the wrap) |
| `B22_LOGS_CHUNK` | recovery, `claim` (`eth_getLogs`) | 10000 blocks per request (lower it for range-limited RPCs) |
| `MIN_TIMELOCK` | `Deploy.s.sol` | 21600 s (allowed 600..2592000): floor on the queue time of a loosening `setToken` and of a `minLezDepth` decrease |

Keys read from the environment: `B22_USER_KEY`, `B22_FREEZER_KEY`, `B22_RELAYER_KEY`, `B22_ROOT_SIGNER_1_KEY` (hex, 32 bytes) and the deployer's `SEPOLIA_KEY` (or only `SEPOLIA_DEPLOYER`, an address, for `b22 setup`). No key is printed.
