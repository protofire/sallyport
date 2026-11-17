# Evidence index

Transcript banner lines that pointed at the run document were updated to its current path, `evidence/rfp022-sepolia.md` §5; nothing else in the transcripts was changed.

Guest ImageIDs are the Docker-built ones listed in the repository README unless the row says otherwise: attest `dbdf349c…fd80`, bridge `030e554b…878c`, burn_member `b75588bc…5821`. Runs are on a local LEZ v0.4.0-rc1 sequencer (`1806e87`) against live Sepolia. Commit hashes cited in the files refer to the development history. Local paths and host names are normalised (`<repo>`, `prover-host`, signer host 2).

| File | Shows | Produced by | Proofs |
|---|---|---|---|
| rfp021-final-run.md | RFP-021 final live run (2026-11-10): init, one-transaction updates, module submit, ERC-20 / ETH / private claims, clone-vault protection; summaries of the 19.5 h unattended run, the 1405 to 1406 rotation and the release-candidate run (update collision, end-to-end latency) | `program-e2e`, `rfp021 run-relayer`, `modules/eth_attest_module/lez-headless.sh` | dev mode |
| rfp022-sepolia.md | RFP-022 Sepolia deployment and end-to-end run (2026-11-10): addresses, transactions, probes, leak scans, latency, freezer evidence, real Groth16 releases, local flow summary | `b22 e2e --sepolia`, `contracts/bridge/script/deploy_sepolia.py` | dev mode on LEZ, real Groth16 on Ethereum |
| onetx.md | one-transaction light-client update cycles, K sweep, K=170 worst case (earlier measurements) | `crates/program-tests/tests/onetx.rs` | executor only |
| spec-tests.md | official Ethereum consensus-spec and BLS test-vector results: host, zkVM guest and LEZ ABI, 0 MISMATCH, UNSUPPORTED cases with reasons | `crates/spec-tests` (`fetch.sh`, then `cargo test --release -p spec-tests`) | host, guest in dev mode |
| bls-plain-verify.md | plain in-guest BLS12-381 verify, 10.45M cycles (over the 10M cap), method | pre-project feasibility experiment (not included) | executor only |
| bench/bench-results.log | M2 Max CPU proving rows (composite and succinct) behind BENCHMARKS sections 2 to 5 | `crates/bench/run-all.sh` | real |
| bench/bench-results-gpu.log | RTX 3080 CUDA sweep of the same actions (older code) | `crates/bench/run-all.sh` | real |
| bench/bench-final-gpu-022bb8b.log | RTX 3080 CUDA, final program code, median of 3: Update, Attest, claims | `target/release/bench <action> --mode succinct` | real |
| independent-run-2026-11-12.md | clean-checkout verification on `8be9338`: ImageIDs on macOS arm64 and Linux x86_64, final-code CPU and GPU proving, Sepolia end to end with fresh keys (transactions, probes), RFP-021 consumers on fresh deposits, documentation gaps found | `scripts/image-ids.sh`, `crates/bench`, `b22 e2e --sepolia`, `program-e2e` | real (proving, Groth16); dev mode on LEZ |
| bench/bench-results-m2-cpu-final.log | M2 Max CPU proving rows on the final code (`8be9338`, quiet): Update, claims, Attest, real private claim | `target/release/bench <action> --mode succinct`, `private_claim_cycles` with `--features lee/prove` | real |
| bench/bench-gpu-rerun-48bc5e9.log | RTX 3080 CUDA re-run on the final code, median of 3 (supersedes `bench-final-gpu-022bb8b.log` for timings) | `target/release/bench <action> --mode succinct` | real |
| rfp022/e2e-sepolia-final-transcript.txt | Sepolia end to end, one uninterrupted run, two real Groth16 releases | `b22 e2e --sepolia --groth16-host prover-host` | dev mode on LEZ, real Groth16 on Ethereum |
| rfp022/e2e-sepolia-final-run1-FAILED-transcript.txt | the first attempt of the same day, failed at the step recorded in rfp022-sepolia.md | `b22 e2e --sepolia` | dev mode |
| rfp022/e2e-local-transcript.txt | local end to end on anvil, devnet beacon and a fresh LEZ sequencer (filtered of wallet progress lines) | `b22 e2e --local` | dev mode, mock seal |
| rfp022/real-burn-proof.log | one real LEZ `Burn` proof accepted by settlement with proof checking on | `REAL_BURN_PROOF=1`, test `real_burn_proof` in `crates/program-tests/tests/bridge.rs` | real |
| module/headless-transcript.txt | `eth_attest_module` under `logosctl`: produce, verify, rejection cases | `modules/headless/run.sh` | host only |
| module/vproxy-transcript.txt, module/vproxy-relayer-transcript.txt | execution-layer headers and receipts through `verified_proxy_module`; relayer `fetch-attest` through it | `modules/headless/run.sh` | host only |
| module/lez-transcript.txt | module `submit_update` and `read_instance` against a live LEZ sequencer (earlier run) | `modules/eth_attest_module/lez-headless.sh` | dev mode |
