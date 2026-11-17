# Sallyport

Sallyport is a prototype for two Logos grant requests, built in one repository because the second consumes the first. RFP-021 is a LEZ program that follows Ethereum's finalised chain through the sync-committee light client and lets other LEZ programs verify, inside their own transaction, that an account, storage slot or receipt log exists under a finalised header and satisfies a predicate. RFP-022 is a private wrapped ERC-20 / ETH bridge between Ethereum and LEZ that uses that attestation for deposits. Target chain for the prototype: Sepolia (Gloas); mainnet (Fulu) is covered by fixtures.

The built design is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## RFP-021: Ethereum state attestation

- `crates/lc-core`: light client (bootstrap, update, handoff).
- `crates/inclusion`: RLP/MPT verification, ancestry, predicates, StatementId.
- `crates/attest-program`: LEZ guest program and BLS residue kernel.
- `crates/consumers`: ERC-20 and native-ETH reference consumers, private claim.
- `crates/relayer`: operator loop and the `rfp021` CLI.
- `crates/lez-client`: LEZ read/submit without the wallet stack.
- `crates/program-methods`: guest builds and ImageIDs.
- `crates/program-tests`: executor, private-claim and guest-vector tests.
- `crates/program-e2e`: live client against a LEZ sequencer (not a default workspace member).
- `crates/vector-runner`, `fixtures/adversarial/`: 89 vectors (74 adversarial cases and 15 positive controls) replayed through the host libraries.
- `crates/spec-tests`: official Ethereum test vectors against `lc-core` and the BLS code (not a default member).
- `crates/bench`: real proving benchmarks (not a default workspace member).
- `modules/`: Logos core modules (`eth_attest_module`, the `headless` run scripts and the `catalog` release workflows).
- `idl/`: SPEL-format IDL; `contracts/DepositVault.sol`: reference deposit contract for private claims.

## RFP-022: bridge

- `crates/bridge`: the LEZ bridge program (private wrapped balances, burn accumulator).
- `crates/bridge-core`: shared formats and golden vectors.
- `crates/bridge-cli`: the `b22` client, root signer and end-to-end driver.
- `crates/bridge-prover`: burn-membership guest and Groth16 wrap (not a default workspace member).
- `contracts/bridge/`: Ethereum vault, root verifier and Foundry tests ([contracts/bridge/README.md](contracts/bridge/README.md)).
- `modules/bridge_module`: Logos core module for the bridge.

## Status

- Everything runs on a local LEZ v0.4.0-rc1 standalone sequencer against live Sepolia, in RISC0 dev mode (guests executed, no on-chain proofs). The public LEZ testnet runs v0.3.x, so nothing is deployed there. Not audited.
- Requirement status in [proposal/COVERAGE.md](proposal/COVERAGE.md): RFP-021, 64 requirements: 28 Done, 28 Partial, 5 Not yet, 3 Milestone. RFP-022, 56 hard requirements: 13 Done, 33 Partial, 10 Milestone.
- Every light-client update, committee rotation included, is one LEZ transaction: 6.4-7.0M cycles typical, 8.5-8.9M at the worst case of K=170 non-signers, all under the 10M per-action limit ([docs/BENCHMARKS.md](docs/BENCHMARKS.md) section 1, D-UPD-3 in [docs/DECISIONS.md](docs/DECISIONS.md); earlier sweep in [evidence/onetx.md](evidence/onetx.md)). A live committee rotation (period 1405 to 1406) was one `Update`, 6,411,261 cycles.
- Final live run (2026-11-10, Docker-built guests): two relayers and the Logos module advance one instance; ERC-20 and native-ETH claims of fresh Sepolia deposits cost 134k (chained ERC-20) / 437k (inline ERC-20) / 170k (ETH) cycles; a private claim is refused when replayed through a clone vault ([evidence/rfp021-final-run.md](evidence/rfp021-final-run.md)). An earlier run held a 19.5 h unattended relayer.
- RFP-022 on Sepolia: deposits, private claims, a private transfer, burns, and two releases with real Groth16 seals (88 s wrap each), 2,477 s for the whole run ([evidence/rfp022-sepolia.md](evidence/rfp022-sepolia.md)). The release path is interim and custodial: a 2-of-2 root signer set attests burn roots; its verifier contract `EcdsaRootVerifier` reports `TRUSTLESS() == false` ([docs/TRUST-ASSUMPTIONS.md](docs/TRUST-ASSUMPTIONS.md)).
- Executor cycles: Attest ERC-20 log 69,316, ETH log 58,785, storage slot 153,495, about 10,870 per ancestry header ([docs/BENCHMARKS.md](docs/BENCHMARKS.md) section 1).
- Real proving is measured on one CPU machine and one GPU box, each table labelled with its commit; the final program code (`8be9338`) was re-measured on both on 2026-11-12, and the older tables keep their own labels ([docs/BENCHMARKS.md](docs/BENCHMARKS.md), [evidence/independent-run-2026-11-12.md](evidence/independent-run-2026-11-12.md)).
- A plain in-guest BLS verify costs 10.45M cycles, over the cap; that is why the residue kernel exists ([evidence/bls-plain-verify.md](evidence/bls-plain-verify.md)).

## Quickstart

Prerequisites (Ubuntu 24.04 packages: `build-essential curl pkg-config libssl-dev python3 clang cmake jq libpcsclite-dev rsync docker-buildx`; `rsync` is needed by `b22 e2e --local`, `docker-buildx` by `scripts/image-ids.sh`, `libpcsclite-dev` by the LEZ wallet; the GPU bench also needs `protobuf-compiler` and the CUDA 12.8 toolkit): the Rust toolchain in `rust-toolchain.toml` (1.98.1), the RISC0 toolchain (`rzup install rust 1.97.0`, `cpp 2024.1.5`, `cargo-risczero 3.0.5`, `r0vm 3.0.5`) and, for RFP-022, Foundry 1.5.1 plus `git submodule update --init --recursive contracts/bridge/lib`, the Python packages `eth-abi`, `eth-account`, `eth-utils` and `rlp` for `contracts/bridge/script/deploy_sepolia.py` (`pip install eth-abi eth-account eth-utils rlp`), `rzup install risc0-groth16 0.1.0` for the Groth16 wrap (the `rzup` default 0.2.0 is rejected by risc0 3.0.5). On macOS only (not needed on Linux), the cc crate needs the RISC0 cross archiver:

```
export AR_riscv32im_risc0_zkvm_elf=$HOME/.risc0/toolchains/v2024.1.5-cpp-aarch64-apple-darwin/riscv32im-osx-arm64/bin/riscv32-unknown-elf-ar
```

LEZ (needed for the live flows and `b22 e2e --local`; the cargo tests do not need it): a LEZ v0.4.0-rc1 checkout at `vendor/lez` (ignored by git), with the standalone sequencer and the wallet built.

```
git init vendor/lez
git -C vendor/lez fetch --depth 1 https://github.com/logos-blockchain/logos-execution-zone 1806e873ea2ac0e1b608aa7cf2f9b6e1fb12db21   # v0.4.0-rc1 (1806e87)
git -C vendor/lez checkout --detach FETCH_HEAD
(cd vendor/lez && cargo build --release --features standalone -p sequencer_service && cargo build --release -p wallet)
```

RFP-021:

```
cargo test -p lc-core -p inclusion -p relayer                 # host-only tests, fixtures included
cargo test -p vector-runner                                   # 89 vectors (74 adversarial + 15 positive controls) through the host libraries (89/89)
RISC0_DEV_MODE=1 cargo test -p program-tests --release --no-fail-fast -- --nocapture   # executor, private-claim and guest-vector tests (dev mode); prints cycle tables
python3 idl/gen_idl.py --check                                # IDL matches the Rust message types
crates/spec-tests/fetch.sh <dir>                              # official vectors (about 1.4 GB), then:
SPEC_TESTS_DIR=<dir> RISC0_DEV_MODE=1 cargo test --release -p spec-tests -- --nocapture --test-threads 1
```

Without `RISC0_DEV_MODE`, the bridge and private tests run real CPU proving (about 6 GB each) and the default test parallelism can exhaust memory; use `--test-threads=1` for real proving.

The guest-vector run gives 84 PASS / 0 MISMATCH / 5 UNSUPPORTED / 0 PANIC; it writes `crates/program-tests/GUEST-VECTORS.md` and `crates/vector-runner/RESULTS.md` (untracked). Running a relayer or a live instance: [docs/OPERATOR-GUIDE.md](docs/OPERATOR-GUIDE.md).

RFP-022:

```
cargo test -p bridge-core -p bridge                           # formats, golden vectors, handler
RISC0_DEV_MODE=1 cargo test -p program-tests --release --no-fail-fast --test bridge -- --nocapture   # bridge program on the LEZ executor (dev mode)
(cd contracts/bridge && forge test -vv)                       # vault, root verifier
cargo build --release -p bridge-cli                           # binary b22
RISC0_DEV_MODE=1 B22_LEZ_VENDOR=<lez 1806e87 checkout> ./target/release/b22 e2e --local
```

`b22 e2e --local` runs anvil, a devnet beacon and a fresh LEZ sequencer end to end with a mock seal. The Sepolia run and the `b22` environment variables are in [docs/OPERATOR-GUIDE.md](docs/OPERATOR-GUIDE.md), "RFP-022 client".

## Reproducible guest builds (ImageIDs)

Every guest is built with risc0's reproducible Docker builder (`risczero/risc0-guest-builder:r0.1.97.0`, pinned by its linux/amd64 digest in `crates/program-methods/build.rs`; Docker context = repo root, mounted at `/src`). To check the ImageIDs, from a clean checkout with Docker running:

```
scripts/image-ids.sh        # = RISC0_USE_DOCKER=1 cargo run -q --release --locked -p program-methods --example image_ids
```

Without `RISC0_USE_DOCKER=1`, builds use the local rzup toolchain and the IDs depend on the host and checkout path (that is what the tests use). The final runs in `evidence/` use the Docker-built ELFs. The output is the same on an aarch64 Mac and on an x86_64 Linux machine; the eight ELF files are byte-identical.

| guest | ImageID |
|---|---|
| attest | `dbdf349c065395c8fba0857cddc096ba4e5a7a458adc2d117f101fc3cea2fd80` |
| erc20_receiver | `f132dd78b21cd013671482e77102ffe0dc6ee98337bdb71cb2ee52c025447a25` |
| eth_receiver | `309ad796177939a8a857b9b4de81ec96068897adef7d82cb0d75371ee28d4f08` |
| erc20_inline_receiver | `1b62b2f919fb9d79a2e6054632fa567ba54a1ce0df307caa7460d75247218655` |
| bridge (RFP-022 LEZ program) | `030e554bab245def77adb144a04ada0bd57a9593109d74b034f6fcbded18878c` |
| burn_member (RFP-022 release proof, vault `MEMBERSHIP_IMAGE_ID`) | `b75588bcf980443c07957f005de58e9b811dd6f1b7d3795a26899785d78b5821` |
| spec_selftest (test only) | `ea8a7d689a298a109689675cd2ca8a2a1e4e5bdc0ccb2adffb6a3705211a520a` |
| sha_selftest (test only) | `37b9e1663c11ac238795e4e4c14f21f3488d6012748a74c59559674fc9d40b70` |

## Keys

No key is stored in the repository or read from an OS secret store. Commands that sign read hex keys from the environment and never print them:

- `SEPOLIA_KEY`: Sepolia deployer (`contracts/sepolia.py`, `contracts/bridge/script/deploy_sepolia.py`, `forge script`), with `SEPOLIA_RPC`. `b22 setup --sepolia` predicts the contract addresses from the deployer's nonce; it takes the deployer address from `SEPOLIA_DEPLOYER` (an address, no key needed) or, if that is unset, from the address of `SEPOLIA_KEY`.
- `B22_USER_KEY`, `B22_FREEZER_KEY`, `B22_RELAYER_KEY`: Sepolia user, freezer and relayer accounts of `b22`.
- `B22_ROOT_SIGNER_1_KEY`: root signer 1 of the interim 2-of-2 root verifier; signer 2 lives on a second machine (`b22 gen-signer`, `b22 sign-root --key-file`).
- `b22 sign-root --key-env <VAR>` and `b22 addr <VAR>` take the name of the environment variable to read.

`--local` runs use well-known dev keys (anvil accounts, LEZ standalone genesis keys), which are public test constants.

The `b22` client expects a LEZ v0.4.0-rc1 checkout (`1806e87`) with `sequencer_service` and `wallet` built at `vendor/lez`, or at the path in `B22_LEZ_VENDOR`.

## Documents

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | built design of both programs: accounts, instructions, formats, flows, custody |
| [docs/DECISIONS.md](docs/DECISIONS.md) | design decisions in force; IDs such as `D-UPD-3` are cited across the documents |
| [docs/BENCHMARKS.md](docs/BENCHMARKS.md) | cycles, gas model, real proving; every table labelled with commit and conditions |
| [docs/TRUST-ASSUMPTIONS.md](docs/TRUST-ASSUMPTIONS.md) | what you must trust, attack cost, degradation |
| [docs/RESIDUE-SOUNDNESS.md](docs/RESIDUE-SOUNDNESS.md) | soundness and completeness of the BLS final-exponentiation residue check (`D-ATT-2`) |
| [docs/PRIVACY.md](docs/PRIVACY.md) | private consumption path and its leak table |
| [docs/CONSUMER-GUIDE.md](docs/CONSUMER-GUIDE.md) | recommended consumer pattern, ancestry, error codes, migration |
| [docs/OPERATOR-GUIDE.md](docs/OPERATOR-GUIDE.md) | running a relayer, costs, cadence, the `b22` client |
| [docs/MODULE.md](docs/MODULE.md) | Logos core module: API, build, catalog release |
| [evidence/README.md](evidence/README.md) | index of transcripts, logs and measurements |
| [proposal/COVERAGE.md](proposal/COVERAGE.md) | requirement-by-requirement status, trust model and disclosures |
| [proposal/MILESTONES.md](proposal/MILESTONES.md) | milestones with acceptance criteria |
| [fixtures/adversarial/README.md](fixtures/adversarial/README.md) | the 89 vectors: 74 adversarial cases and 15 positive controls |

## Source history

This repository is a single squashed commit. Commit hashes cited in the documents and evidence (for example `c380d4b`, `82bb54d`, `022bb8b`) refer to the development history, which is not included. The tree corresponds to development commit `151205b`, which contains `c380d4b` (the final RFP-021 live run) and the final RFP-022 Sepolia redeploy (`a8b8157`). The generator of the adversarial vectors is not included; the vectors are.

## Licence

Copyright 2026 Protofire, all rights reserved; shared for the evaluation of our Logos RFP-021/022 proposal ([LICENSE](LICENSE)). On a Grant award the code is released under MIT and Apache-2.0, as the Logos RFP Program requires.

The Sepolia contracts were deployed from these sources when their SPDX headers still read MIT / Apache-2.0; only the header changed since, so a rebuild differs from the deployed bytecode in the Solidity metadata hash alone. The NatSpec comment in `IBurnRootVerifier.sol` was reworded after deployment, which changes that hash as well.
