# RFP-021 final live run: Ethereum state attestation on LEZ (Sepolia, 2026-11-10)

Applies to guest ImageIDs attest `dbdf349c065395c8fba0857cddc096ba4e5a7a458adc2d117f101fc3cea2fd80`, erc20_receiver `f132dd78b21cd013671482e77102ffe0dc6ee98337bdb71cb2ee52c025447a25`, eth_receiver `309ad796177939a8a857b9b4de81ec96068897adef7d82cb0d75371ee28d4f08`, erc20_inline_receiver `1b62b2f919fb9d79a2e6054632fa567ba54a1ce0df307caa7460d75247218655`; LEZ v0.4.0-rc1 (1806e87).

Local paths and host names are normalised in this file (`<repo>`, `prover-host`). Related: [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md), [../docs/BENCHMARKS.md](../docs/BENCHMARKS.md), [../docs/DECISIONS.md](../docs/DECISIONS.md), [../docs/TRUST-ASSUMPTIONS.md](../docs/TRUST-ASSUMPTIONS.md), [../proposal/COVERAGE.md](../proposal/COVERAGE.md), [README.md](README.md) (evidence index).

## What this is

Two live runs of the attestation program against Ethereum Sepolia, with a LEZ standalone sequencer running locally. The 2026-11-10 run ("final run") is the authoritative one: it uses the guests built by the risc0 reproducible Docker builder, so its ImageIDs can be rebuilt by anyone (`scripts/image-ids.sh`). The earlier 2026-11-05 run (Section 2) used non-Docker builds with different ImageIDs. It is kept for its two long-duration results: a 19.5 h unattended relayer run and a live sync-committee period rotation.

Both runs use `RISC0_DEV_MODE=1` on the LEZ side: execution is real and cycle counts are exact, but no proofs were generated and LEZ execution validity was not enforced. Real proving cost is in [../docs/BENCHMARKS.md](../docs/BENCHMARKS.md). Cycles are read from the block fee summary (`program-e2e gas <block>`): LEZ has no receipts, and each block's forced fee transaction carries `BlockFeeSummary { gas_used_exec, gas_used_stor }`, where `gas_used_exec` is the sum of charged cycles of the block's user transactions. Each row below sits in a block that holds only that transaction unless noted.

## 1. Final run (development commit c380d4b, 2026-11-10)

Short live run of the development commit `c380d4b`, which includes the consumer protections (type-tagged consumer state, per-vault nullifier seed, clone-vault protection) and the per-instruction Update gas limit. Two small deviations from `c380d4b` were used, both in tooling, none in guest code: `program-e2e` reads the type-tagged private-vault state and prints each transaction's declared `gas_limit`; `lez-headless.sh` installs and loads `verified_proxy_module` (the module declares it as a dependency and did not load without it). No guest code differs from `c380d4b`.

Environment: local LEZ v0.4.0-rc1 standalone sequencer (1806e87, `RISC0_DEV_MODE=1`, fresh home, RPC `0.0.0.0:3060`). Beacon: `lodestar-sepolia.chainsafe.io` and publicnode; execution layer: `https://sepolia.gateway.tenderly.co`. Times are UTC. Runtime files were in `target/live-run/` and are not committed.

### Program images (Docker build, pinned)

`scripts/image-ids.sh` (also printed by `program-e2e deploy`); identical on an aarch64 macOS host and an x86_64 Linux host.

| program | LEZ account | ImageID |
|---|---|---|
| attest | `4ZyXXGxaw83mTWZc8fRRTnSDSR6Qhq9d8taM8QWhR9wd` (6 segments) | `dbdf349c065395c8fba0857cddc096ba4e5a7a458adc2d117f101fc3cea2fd80` |
| erc20_receiver (chained + private) | `DqrDo5FhWDweiqqBy2A35QhLTM9e2Q4r6mTKj1Q7mnHu` (4 segments) | `f132dd78b21cd013671482e77102ffe0dc6ee98337bdb71cb2ee52c025447a25` |
| eth_receiver | `C33a4jshw6QiBQGv7XhcpoLgZNMCsYFmAFvph5pJB4X8` (4 segments) | `309ad796177939a8a857b9b4de81ec96068897adef7d82cb0d75371ee28d4f08` |
| erc20_inline_receiver | `21ZX4ZtksE53icamGjwZtpW2uwyqJbCevzA7MHqUy65r` (4 segments) | `1b62b2f919fb9d79a2e6054632fa567ba54a1ce0df307caa7460d75247218655` |

Accounts: op1 payer `6iArKUXx…2VQV` (dev genesis key A; Init, funding), op2 payer `7wHg9sbJ…3YQo` (key B), claims payer C `8Yh7oAgr…YUpw`, module operator key `54Fx8wa5…56NP1` (fresh random, mode 0600), private claimants `D7LucMHg…Jgut` and `BFZnAJrZ…yafm`.

### Init (fresh finalized checkpoint)

`rfp021 fetch-update --period 1409 --bootstrap-root finalized` at 00:57:08: root `0x905a4e3a4abbbb25e6c422be1056133fa41a798467af9bf26eb85133496a6352`, slot 11,544,800. Instance id `0x06a370829dc4dfe9b63671ce8759ac7e1deade9b8a2f6a2419b779e87e4cad87` (derived), instance account `4WpthVCCNawrVyiT2xgeVM6BfU3NeYWjZjqawwAupdKd`. Init tx `4d8d6db384b0f19b7652ddb41c3124bfb65c17afbff55e99c11715c5a0e5fbc9`, block 56, ok, 917,213 cycles (declared gas_limit 5,000,000).

### Updates: one `Update` transaction each

Two relayers (op1, op2; `rfp021 run-relayer`, `max_defer_secs = 300`, `poll_secs = 12`). The declared `gas_limit` is `7,400,000 + 11,500·k` (k = non-signers), not the 10M block cap, so claims can share a block (block 278 below).

| job | by | tx (`Update`) | block | cycles | declared gas_limit | gas_stor |
|---|---|---|---:|---:|---:|---:|
| Period(1409) committee-learning | op2 | `d086e7160257a832a13177ed5afb77f5fd9482375c15a4e3154c7455abc32617` | 67 | 7,004,016 | 7,446,000 | 28,455 |
| Finality(11,544,832) | op1 | `8b5d19dd8e946e5d117daa4a142580f3f940a1134042cdca5e4a28fadf0260ed` | 72 | 6,583,138 | 7,446,000 | 3,729 |
| Finality(11,544,864) | op1 | `f02c5023032cebffbaa384846c4c0ec7b67f87de5794c7455e13cec9befb5bbc` | 92 | 6,581,908 | 7,446,000 | 3,729 |
| Finality(11,544,896) | op2 | `a7f51f5999240c66477aa9ce81b284fbd1f8574c87f839d08428a71fe0b9be35` | 126 | 6,584,545 | 7,446,000 | 3,729 |
| Finality(11,544,928) | op2 | `befcd8ccda06c498cca0e1d84cf84cb05e2c8183adfee7cc9f2a9ce57c8b323f` | 147 | 6,581,732 | 7,446,000 | 3,729 |
| Finality(11,544,960) | op1 | `8cbcb89ccd9af9681b0bf21a5f9ea5d4921f1394bd6368366a1c9e1e9a44c911` | 174 | 6,583,139 | 7,446,000 | 3,729 |
| Finality(11,544,992) | op2 | `55f3f0dc4dd85383d5a7a8dc045c1595aa6272e0e4c495d4dec0f00ef242ffe9` | 196 | 6,581,557 | 7,446,000 | 3,729 |
| Finality(11,545,024) | op1 | `fe89ca96c718cae0bd9d66b624dc6421da9deaa55a3529a6b894339961797f79` | 219 | 6,585,952 | 7,446,000 | 3,729 |
| Finality(11,545,056) | op1 | `d99821168e9bf7e4818ebe7efca3238f21e5d04d8bb68b1e9b0b1e7d413fb34b` | 245 | 6,592,817 | 7,457,500 | 3,829 |
| Finality(11,545,088) | op1 | `3c2a0503fba62e2064acec23e1b19b41da96bf460c656d8518c5d81a580addc9` | 278 (with the two private claims) | (block 7,495,096) | 7,446,000 | – |

Three more relayer updates followed (Finality 11,545,120 / 11,545,152 / 11,545,184, op2/op2/op1, by 02:11). No job was sent by both relayers in this run (13 relayer sends, 13 distinct jobs).

### Logos module submit path (`submit_update`)

`modules/nix-docker.sh build`, then `lez-headless.sh` with `LEZ_RPC=http://host.docker.internal:3060` and the module's own 0600 operator key; transcript `target/live-run/module-headless.txt` (not committed; the module's earlier recorded transcripts are in [module/](module/)). Results:

- `read_instance` before config gives a `lez_config` error; after `set_chain_config` it returns the instance state (finalized slot 11,545,184); an unknown instance gives `lez_read`; a 0644 key copy is refused (nothing sent).
- Tries 1–7 were refused by the module's own pre-check (1106 UpdateNotNewer, nothing sent).
- Try 8 (02:16:33) applied Finality(11,545,216): tx `fce07006f39c62b87b968edf4d63dbf747fec65ad1d4efe4d053636d387ea93f`, LEZ block 373, 6,582,964 cycles, declared gas_limit 7,446,000. Both relayers then logged "no longer needed, dropping" for that job.
- A first attempt of this transcript failed at `module load eth_attest_module` (MODULE_LOAD_FAILED) because the script did not install `verified_proxy_module`. That was fixed in `lez-headless.sh`; the failed transcript was kept as `module-headless-try1-noload.txt` and is not copied here.

Recorded execution-layer hashes used below (parent of the execution block at each checkpoint slot, Gloas): 11,544,896 gives `0xe29c8e5a…4f28` (the E1 deposit block itself), 11,544,928 gives `0x85053cc2…1d12`.

### Sepolia deposits (deployer `0x6378…4Aab`, DepositVault `0x179360c68dd8099fb3b862d8271ed37398f4ef43`, 00:58–00:59)

| deposit | tx | block (time) | tx idx / log | used by |
|---|---|---|---|---|
| D1 vault deposit 1e12 wei, C `0xfd35fead…9b27` | `0x518575cdbfb1dd315b5394ce985f566104d735056994ab70bfd24b8e11a0a86d` | 12,101,233 (00:58:12) | 26 / 1 `Deposit` | private claim, 3 ancestry headers |
| D2 vault deposit 1e12 wei | `0x51ef768fd5a914e59fa24e0401d64091f7a3b032683e8405255336b8c8a2b218` | 12,101,234 (00:58:24) | 83 / 0 EIP-7708 | ETH claim, 2 ancestry headers |
| E1 WETH9 `transfer(DepositVault, 1e14)` | `0x6656ef9ccaad4e7c64c6437d2ca4e3bf1d2c1a0cd133812cc954922e6cad5934` | 12,101,236 (00:59:00) | 2 / 0 | clone + real chained ERC-20 claims, direct (0 ancestry) |
| E2 WETH9 `transfer(0x…dEaD, 1e14)` | `0x5cd227b6640cade7d9aa6360126c9022dc1083626e7485feadede9f090f4a5c6` | 12,101,238 (00:59:24) | 2 / 0 | inline ERC-20 claim, 30 ancestry headers |

E1 was in Finality(11,544,896), applied at 01:14:48, 15 min 48 s after its block (finality plus relayer deferral).

### Claims (payer C) and the clone-vault protection

| step | tx | block | result | cycles |
|---|---|---:|---|---:|
| InitVault erc20_receiver, clone vault `0xc0…c0` (same config as the real one) | `a0d1fbbbf360ae21abaf79bd220eaac848f70d41be43dd98303a564422460328` | 142 | ok | 13,087 |
| Clone front-runs E1 (Claim into `0xc0…c0`) | `9db394415b30752ec612029bba4e0d8190c7d83915b33898a8bc468ecbef4c4b` | 144 | ok | 133,717 |
| clone replay | `bc797d645e44e614fb782dc722c4b229e0d540ed45577fdeeff14e9795e5b38a` | 146 | reverted 1250 | 132,082 |
| InitVault erc20_receiver, real vault `0xe2…e2` | `8a9ce6b4f9e68583388552b40378d48d4f7e97e2516ffac1e4a849167c7ccde5` | 148 | ok | 13,087 |
| Real vault claims E1 after the clone | `f9c97305247abc0955837edec9a7e11cba49281ebccf2972e18216b517c77724` | 150 | ok | 133,717 |
| real replay | `25d9065afe045a450a86e7ad6c1a7c9c7eaf16f8f73f734d3fb91901e7574d6a` | 152 | reverted 1250 | 132,082 |
| InitVault eth_receiver `0xe7…e7` | `14ff5affcee2628f6f124f4d00fe2d5940c87d421497ee57f0343b012cf3c93a` | 154 | ok | 13,367 |
| Claim ETH (EIP-7708), D2 via 2 ancestry headers | `3aa7987ddc09290035941802e313d366a5d1ed0a7caa61aac23e4b91be44871e` | 156 | ok | 169,570 |
| ETH replay | `1f7d253d18c3673a37fd63c36b586fcf79492bc7392955f71b38bb56fcd707eb` | 158 | reverted 1250 | 167,935 |
| InitVault erc20_inline_receiver `0xe3…e3` (WETH to `0x…dEaD`) | `048cc723dbfe7e70f8cab21d6364c408a869294fa6f31553f6fb65f4b6643af8` | 162 | ok | 12,864 |
| Claim ERC-20 inline, E2 via 30 ancestry headers | `b67195318a9bd3a6608aeb183b5bf668d3ea6ea57f90a4bdfd0751de9e458310` | 164 | ok | 437,101 |
| inline replay | `af936997fe9641fcf910e2320fe4002a61684dda781b534ca40459a8c58b5285` | 166 | reverted 1250 | 435,469 |

Readbacks: clone and real vault each `claims=1 credited_total=1e14`, statement `0x82df6210…ec16`, credit `eth_sender=0x6378…4aab`, but different nullifier PDAs (`6mjsLqfR…zJLv` clone, `6yWuXA5G…JKAP` real). The nullifier seed is `sha256("rfp021/nullifier/v2" ‖ vault_id ‖ statement_id)`, so a clone that claims first cannot make the real vault's claim fail (under the previous seed it would have failed 1250 for good). By design a public-path clone can record the same deposit in its own ledger; consumers pin their `vault_id`. For the private path, where the credit is the claimant's own balance, a clone vault cannot claim a deposit already claimed in the real vault (below).

Replay codes: `program-e2e simulate` re-executed the four replays. Each exits 250, which is 1250 `ERR_ALREADY_CLAIMED`, with simulated cycles equal to the charged ones (132,082 / 132,082 / 167,935 / 435,469). File `simulate-replays.txt` (not committed).

### Private claim (D1 via 3 ancestry headers to the recorded leaf 3 of 9)

| step | tx | block | result |
|---|---|---:|---|
| InitPrivateVault `0xee…ee` (DepositVault, denomination 1e12) | `b48b9e353ed4edf5a0bbb26948fe8530402786ba53216d0ac2b2282776072125` | 168 | ok (13,624 cycles) |
| PrivateClaim D1, claimant `BFZnAJrZ…yafm` | `61cd2077f9356191161f0e3b14447e079b766d9a06875c8cd6169cfd79b0f3ab` | 278 | ok |
| same `nk`, claimant `D7LucMHg…Jgut`, proven concurrently | `e34719ab41e4d341831242b1e71f4a7c2c6851da1197771a413b0a904d6b31ff` | 278 | reverted |
| same `nk` after inclusion | not submitted | – | wallet simulation refused: exit 250 = 1250 |
| InitPrivateVault, clone vault `0xee…ef` (same config) | `8828167194b908ccc4e18bee47875bdce3b08c50840b2a67ceb1bf81da248ced` | 280 | ok |
| same deposit via the clone vault | not submitted | – | refused: exit 250 = 1250 (global `pnf(nk)` spent) |

Root `0x8c9a87e1…04db` (9 leaves). Block 278 also holds Finality(11,545,088): together 7,495,096 exec gas, 451,855 storage gas. Footprint of `61cd2077…3ab` (31,905 B): public actors are the vault PDA, fee inbox, N PDA and root PDA; `public_root` none; boundary `RedeemCheck{vault_id, cfg_hash, root, N}` plus a 17-byte fee message from blinded senders; state diff N PDA empty to `a4` (the spent tag). A byte scan of the transaction found none of: block hash, header PDA, anchor hash/PDA/leaf, `statement_id`, `H(statement_id)`, both claimants, C, `nk`, receipt, deposit contract.

Tooling breakage found and fixed (one line): the first `private-claim` attempt panicked after InitPrivateVault because `program-e2e` compared the vault state with untagged `borsh(cfg)`, while every consumer state now carries a type tag (`0xA2`). It was changed to `consumers::tagged(TAG_PRIVATE_VAULT, &cfg)`; the rerun above reused the vault created by that first attempt (block 168). Nothing else in the run was repeated.

Sepolia spend (deployer): 4 deposit transactions, 2 x 1e12 wei and 2 x 1e14 WETH locked; plus a separate 0.01 ETH top-up of the RFP-022 user key in the same window. Balance 0.021470 to 0.010464 ETH.

### Shutdown of the 2026-11-05 run (recorded 2026-11-10 04:31 UTC)

The earlier run's sequencer `:3040` (up 4 d 16 h 52 m) and relayers (up 4 d 16 h 37 m) were stopped after this run was recorded. Its instance had stopped tracking Sepolia long before: the last applied updates were Finality(11,519,232) op1 and Finality(11,519,264) op2 at 2026-11-06 11:41–11:48. From 11:52 every tick failed on beacon-provider timeouts (2,545 failed ticks per relayer). When the providers answered again (2026-11-09 14:07), the stored checkpoint was older than Sepolia's ~29.8 h weak-subjectivity period, and every update since was refused `1105 CheckpointStale` (690 ticks). The relayers sent nothing invalid, but the instance cannot recover without a new `Init`. This is an operational limit, not a code bug: a provider outage longer than the weak-subjectivity period ends an instance, so deployments need alerting on "no applied update for N hours" and a third, independent beacon provider.

### Reproduce (condensed)

1. `RISC0_USE_DOCKER=1 cargo build --locked --release -p program-e2e -p relayer --features relayer/lez`; compare `sh scripts/image-ids.sh` with the table above.
2. Fresh LEZ home: `sequencer_service setup <home> --config <lez>/sequencer/service/networks/local.json --funding-public-key <key> --create-channel`, then `RISC0_DEV_MODE=1 sequencer_service start <home> --rpc-listen-address 127.0.0.1:3060`. The funding key is the public key `2e03b2eff5a45478e7e79668d2a146cf2c5c7925bce927f2b1c67f2ab4fc0d26` (LEZ standalone genesis), e.g. `sequencer_service setup <home> --config lez/sequencer/service/networks/local.json --funding-public-key 2e03b2eff5a45478e7e79668d2a146cf2c5c7925bce927f2b1c67f2ab4fc0d26 --create-channel`. Deploy takes about 10 minutes with the default 15 s local blocks.
3. Wallet (config from `lez/wallet/configs/debug/wallet_config.json`, `sequencer_addr` `127.0.0.1:3060`): import the payer keys with `wallet account import public --private-key <key>` (`LEZ_PAYER_KEY` and `ATTEST_DEPLOY_KEY` in `crates/bridge-cli/src/main.rs`, public dev keys of the LEZ standalone genesis), the op1/op2 payer keys, create a claims payer and two private claimants, and fund them. Fees on this sequencer are non-zero, so `auth-transfer send` straight to a private recipient fails (the new private account has no balance to reserve the fee from): send to an intermediate public account first and move the funds on from there.
4. `program-e2e deploy <op1>` (it re-sends the `attest` deploy and prints "deployed" even if the account exists, which makes the sequencer log a caught loader panic; run it once per fresh chain); `rfp021 fetch-update --period <n> --bootstrap-root finalized --beacon https://lodestar-sepolia.chainsafe.io --out init-material.json`; `program-e2e init <op1> init-material.json` (prints the instance id).
5. Two relayers: `rfp021 run-relayer --config op{1,2}.toml` (two beacon endpoints, `max_defer_secs = 300`, `poll_secs = 12`, own payer, the instance id).
6. Deposit with `SEPOLIA_KEY=… python3.11 -I contracts/sepolia.py deposit|erc20 <to> <wei>`; claim with `rfp021 fetch-attest … --out a.json` then `program-e2e claim <C> <consumer> <id> <vault_id> a.json`.
7. Private claim: `program-e2e private-claim …` given every recorded execution-layer hash in acceptance order, read from the beacon block's `signed_execution_payload_bid.parent_block_hash` at each applied checkpoint slot.
8. Cycles: `program-e2e gas <block>...`; replay codes: `program-e2e simulate <tx>`; module path: `modules/nix-docker.sh build`, then `lez-headless.sh` with `LEZ_RPC=http://host.docker.internal:3060`.

## 2. Earlier run: 2026-11-05 (summary)

Code: development commit `82bb54d` (one-transaction updates for every kind up to K=170, gas round, optional inline consumer) plus a lockfile refresh `52a396e` and a tooling commit `3480ec1` (`program-e2e`: deploys the inline consumer, prints its ImageID, `gas` readout; `sepolia.py erc20`) and the `simulate` readout. No guest code changed after `82bb54d`. Non-Docker build (aarch64-apple-darwin, risc0 toolchain v2024.1.5), so the ImageIDs below differ from the final run. Local sequencer RPC `0.0.0.0:3040`; runtime files in `target/live-run-final/` (not committed). The 9.5M budget in the text below is the target block size; LEZ `MAX_GAS_EXEC` is 10M.

| program | LEZ account (this run) | ImageID @ `82bb54d` |
|---|---|---|
| attest | `4ZyXXGxaw83mTWZc8fRRTnSDSR6Qhq9d8taM8QWhR9wd` (6 segments) | `6f2ab0cb754eaa508ad9462eb5adc62a8167dd00cc5fa21a4ba8d3adba765d50` |
| erc20_receiver | `FyEfNNhwK2wcF54feN1m9aMdc2uBWA69BLc1DRvmDNV3` (4 segments) | `877b6ac100468bcfd31b735f8de29f767b0c7a664f554aef586a8a3722d00c61` |
| eth_receiver | `ChLSsgsixDvWhtd2kJ4nrBkPiPvwCC8JGjGodARBhxEd` (4 segments) | `e69d9478ea10579227d4297395ca3fe36eaf8d89e242ce4643f3d07bb5f9376f` |
| erc20_inline_receiver | `5SnFM5oJmiYSQk6TZiKadZzN8oJhy5Y2XWgXhg6G8JVE` (4 segments) | `f11d8a14976700ffc81898d7ca31cfd2f4be52c2bb8cff641f79f2f1c6e3b173` |

Init: checkpoint fetched 11:53:06 (period 1405, slot 11,512,096, root `0xd1e6410e0ff2b33c84d4a3d7a302060c0159ed85325dc300801eabde4e971699`). Instance id `0x5a6e9b8681f9a99148cedbab79b57146e34ac745c6907fe334758b0d137806d9`, instance account `VtBHr6rGpMNPm87X8BTh1LEk7YYy3jxeffDdByBM7Ar`. Init tx `864e64a14e257cb9079b82404fd27d33fe42767683b36f17c4ff7acbf9ba2828`, block 57, ok, 917,321 cycles.

### 2.1 First updates: every update is one `Update` transaction

No `UpdateBegin`/`UpdateVerify` pair was sent in this run.

| job | applied by | tx (`Update`) | LEZ block | cycles (gas_exec) | gas_stor |
|---|---|---|---:|---:|---:|
| Period(1405) committee-learning | op2 | `a7f7392d6790347757d6ecbe3c0c3642e38e309a048c3cc4433426f40c38395d` | 64 | 7,026,455 | 28,655 |
| Finality(11,512,128) | op2 | `a2a98143f07208a40bdfaa12fd03a687d6bd8469e891ce398d4aac6c224ccf87` | 86 | 6,605,796 | 3,929 |
| Finality(11,512,160) | module `submit_update` (try 6, 12:05:16) | `7714963e797c185ff316f2d9a0ef5e72c0f5cac187d4763244af488b90ad5794` | 105 | 6,604,390 | 3,929 |
| Finality(11,512,192) | op2 | `deb506f380c400cc449eaab0b31e0686801a160e7990ad54f72d706077d06cb8` | 135 | 6,606,851 | 3,929 |
| Finality(11,512,224) | op2 | `271ef58362963915c2ed5de843368a6c9cb136404f332d12faca21e39d23a109` | 164 | 6,604,214 | 3,929 |
| Finality(11,512,320) | op1 (12:37:46) | `e7e45f08d8faa1195daa18175feb251b1b7b0b29a3460f03918b44ae18ffb05e` | 235 | 6,608,434 | 3,929 |

Before 12:37 op1 ran without errors but did not send: its deferral deadline fell after op2's on four jobs, and on Finality(11,512,160) the module landed first. Offline comparison: finality 7.63M before the gas round, committee-learning 7.13M. Accumulator after five headers: `leaves=5 on-chain leaves=5 matches_frontier=true state_matches=true`, membership paths ok for all 5. CheckRoot(known root) block 172 ok (10,552 cycles); CheckRoot(unknown `0xbd…bd`) block 174 reverted.

### 2.2 Claims in brief

Chained ERC-20 claim (E1 via 28 ancestry headers) `02b253e250e3b9ea66ae4f2c05267cde092d2dc07959dd9cdb3f8e884390c0bd`, block 130, 538,948 cycles; inline ERC-20 claim (E2 via 26 ancestry headers) `b96930f9a55ddddd749956a9e6de447e3296770e897ae459d59e7abf9c92b897`, block 136, 391,221 cycles; ETH claim (EIP-7708, D2 via 30 ancestry headers) `63a7daae435671d4e520f2c536ae428f0513dbf828d4731fbf40bfa35dc975cf`, block 142, 577,512 cycles. Each replay reverted (blocks 132, 138, 144; 537,909 / 390,187 / 576,473 cycles) and simulates to exit 250 = 1250 `ERR_ALREADY_CLAIMED` with cycles equal to the charged ones. Private claim (D1 directly under recorded header leaf 1 of 2): PrivateClaim `51044ae660623651b9b734afb15d8e816b21c96de34ea3494e3697172c0d3e6e`, block 91, ok; the same `nk` with a second claimant, proven concurrently, `4e77f09c9dde5dec2061c3c9ef979bbad62ebcb4be328acfeeaa8d6e9bfc5950`, block 91, reverted. Block 91 holds both: `gas_used_exec` 910,911, `gas_used_stor` 448,126, for the two together. The full claim and private-claim tables of the final run (Section 1) have the same shape.

### 2.3 Live period rotation, 1405 to 1406

op1 and op2 ran unattended (`nohup`) from 2026-11-05 11:53 through the period boundary (first slot of period 1406 = 11,517,952, slot time 2026-11-06 07:10:24 UTC). No manual action was taken at any point. The rotation happened live, in one transaction.

| step | sent by | tx (`Update`) | LEZ block | cycles (gas_exec) | gas_stor | result |
|---|---|---|---:|---:|---:|---|
| last finality in period 1405: Finality(11,517,856) | op1, 07:06:16 | `f62e4a4bd676c201363f270c2068c91e24c197667ae176fc7983e1155bf23b92` | 4669 | 6,604,217 | 3,929 | ok |
| rotation + first finality in period 1406: Finality(11,517,952) | op1, 07:25:31 | `6bd96ee81b53e82ddef44146c9d81167f5913185d3390f494f141c3127c578aa` | 4746 | 6,411,261 | 3,429 | ok |
| same job, duplicate | op2, 07:25:46 | `1694953211a261023e2535ec8d879d3c43066b56f9176d482bcd067ee7c389eb` | 4747 | 153,285 | 3,429 | reverted, 1106 UpdateNotNewer |
| committee-learning Period(1406) (learns the period-1407 committee) | op2, 07:27:16 | `ad167504e1d89b38a502f85226d7af3f78ec37dc6bfef8c213218f4ded8a40d4` | 4753 | 6,970,272 | 28,155 | ok |
| first finality verified under the rotated committee: Finality(11,517,984) | op1, 07:33:31 | `a4648cfbedfe46613bfb3a6a3d37a7de2cb0296546ac982192fe51717c1733e1` | 4778 | 6,548,150 | 3,429 | ok |
| same job, duplicate | op2, 07:33:46 | `36d294468390d2cf0a22b4648a9e33726e10421e63a066b41d2be99024206b4c` | 4779 | 258,490 | 3,429 | reverted, 1106 UpdateNotNewer |

Finality(11,517,952) is the rotation: the instance's store was in period 1405 with the period-1406 committee as `next` (learned by Period(1405) at block 64 on day 1). That update is signed by the period-1406 committee, and applying it moved `next` to `current`. The revert codes come from `program-e2e simulate` (read-only). For 4779 the simulated cycles equal the charged ones. For 4747 they do not (258,490 simulated vs 153,285 charged), because state had advanced since; the code is 1106 either way.

Stored committee after the boundary: the raw instance state (`getAccountView`, 50,223 bytes) was matched against `/eth/v1/beacon/light_client/updates`. `current_sync_committee` (offset 318) has aggregate `0x9712c163…10c1d6`, the period-1406 committee; `next_sync_committee` (offset 24,947) has aggregate `0x883d710f…dc33f`, the period-1407 committee. The period-1405 aggregate `0x8f67e656…107c` no longer occurs in the state.

Beacon-provider stale episode (recovered without intervention): lodestar's head stopped at slot 11,517,921 (slot time 07:04:12) and publicnode answered HTTP 404 (once 503). From 07:17:17 to 07:23:24 the relayers logged 23 `tick failed` warnings and backed off, submitting nothing built on stale data. The rotation landed at 07:25:31. Checkpoints 11,517,888 and 11,517,920 were never applied; the next update jumped to 11,517,952, which the light client allows. The instance went without an update from 07:06:16 to 07:25:31 (19 min 15 s). Elsewhere in the ~19.5 h run there were 7 isolated `tick failed` ticks (for example op2 07:03:17, HTTP 429), each retried on the next tick.

Collisions over the whole run: 183 distinct jobs were applied from 11:53 (day 1) to 07:33 (day 2). Both relayers sent the same job 9 times (Finality 11,513,664 / 11,514,368 / 11,514,880 / 11,515,072 / 11,515,872 / 11,515,936 / 11,516,896 / 11,517,952 / 11,517,984), about 5%. In each case the second transaction reverted with 1106, cost only gas, and left state correct. The one-transaction path in `lez-client` confirms success by reading back the expected state, and a rival's identical update produces that same state, so a losing relayer logged "Update included; expected state confirmed" although its transaction reverted. `getTransaction` returns no revert flag, so the client cannot tell its own success from a lost race; the log wording was changed to "expected state reached (by us or another operator)". The first window (to 12:37) saw no collision.

## 3. Earlier run: release candidate, 2026-11-04 (two-transaction updates, summary)

Superseded by sections 1 and 2; kept for the first end-to-end latency measurement and the first update collision. Code: development commit `cf7f084` (clients on the fixed ABI, public `Claim` through ancestry), local LEZ v0.4.0-rc1 standalone sequencer, `RISC0_DEV_MODE=1`. Beacon: lodestar-sepolia.chainsafe.io and publicnode; execution layer through `eth_rpc_module` (relayer in-process, module over Logos IPC). Updates were still `UpdateBegin` plus `UpdateVerify`. Three payer accounts applied updates (relayer 1, relayer 2 and the module's fresh random key).

### 3.1 Live updates (relayers with `max_defer_secs = 300`, `poll_secs = 12`, and the module)

| job | applied by | UpdateBegin (block) | UpdateVerify (block) |
|---|---|---|---|
| Period(1404) learn next committee | relayer 2 | `90ecd400fc5a710370410b9972faf6e3bc14f62286811925ceefc4ef7c29269a` (68) | `15b14a77090a513b718f923a2e25998c304bb5d35e2d33a11a5040cdc1e6baac` (69) |
| Finality(11,507,712) | relayer 1 | `964b00629ad510a4b67323f1b0945ab063ad2ef97d5f6e8a1a697f4fe964d4ff` (87) | `616aa08fa7247ad0e14af342cf3da9eb429e0c54b92a0eefe205f38939663222` (88) |
| Finality(11,507,744) | relayer 2 | `7fa5dddefd898f5948130a477fce4dcb1d767f06038c7117bbd4ca95ff109690` (90) | `90b87d03eae9609fee63890e2389f48512a8dcdd8533d69b823abe0aaf7d2b65` (91) |
| Finality(11,507,776) | relayer 2 | `6403204d270530042be614f9c75e876ac4ac5777484e66f70fb5cbd0925f6b1f` (117) | `c9c4068c96d43f49230fb4eedb882f8258ce786b90d7bbafe2a15748ccba5586` (118) |
| Finality(11,507,808) | module `submit_update` | `fec2e4ce2f1ac4e52d668d7a289d8d8f131e641117c12d5586a68778266fb9a6` | `78ba0f3e729252d5447bdd108483227a948c1da39092d682e602ab1003db9635` |
| Finality(11,507,840) | relayer 1 | `4c7f5b20ee5cd35dcc628183eb0e1d1863a3c82ab8674270199bf0bc2f0c7430` (175) | `231f3e6b7245a4c2ace4e43cda1393bce91c8e6f2090e50083b9b99b83b797d3` (177) |

No update was applied twice. Relayer 2's `UpdateBegin` for 11,507,808 (`d782fccd…55a9`, block 142) reverted with 1106 UpdateNotNewer because the module had applied it first, and relayer 2 dropped the job. For 11,507,840 the two jitter deadlines fell 3 s apart, so both `UpdateBegin` landed (blocks 175 and 176); relayer 2's `UpdateVerify` `1b1b7a5e…1f73` (block 178) reverted with 1106 after relayer 1's, and relayer 2 dropped the job. That is one wasted Begin plus Verify and a correct final state; more operators need a wider window or a leader rule. The accumulator held 6 leaves and its root matched the frontier (`program-e2e root`); `CheckRoot` on the known root succeeded (`c86d90e5…8bb24`, block 183) and on an unknown root reverted (`eacda8b6…d005e`, block 185). No period boundary was crossed in this run.

### 3.2 Latency: event in an Ethereum block to statement consumed on LEZ

| | D2 to public ETH claim | D1 to private claim |
|---|---|---|
| event (block timestamp) | 21:16:12 (#12,065,035) | 21:16:00 (#12,065,034) |
| wait for the next checkpoint block (slot 11,507,808 at 21:21:36) | 5 m 24 s | 5 m 36 s |
| checkpoint finalized and first seen by the operators (21:34:37) | 13 m 01 s | 13 m 01 s |
| finality wait, total | 18 m 25 s | 18 m 37 s |
| update availability (seen to UpdateBegin+Verify on LEZ; module, at most 21:35:14) | at most 37 s | at most 37 s |
| manual step (fetch-attest, InitVault, wallet sync; not inherent) | 3 m 25 s | 5 m 15 s |
| on-chain verification (claim sent to included and read back; dev-mode proof for the private tx) | 30 s (21:38:39 to 21:39:09) | 30 s (21:40:29 to 21:40:59) |
| end to end as run | 22 m 57 s | 24 m 59 s |
| end to end without the manual step | about 19 m 32 s | about 19 m 44 s |

Real proving adds the private-claim proof time ([../docs/BENCHMARKS.md](../docs/BENCHMARKS.md) section 3) to the private on-chain step. The public claim needs no client proof.

| finalized slot | slot time | first seen | finality wait | on LEZ (verify) | seen to verified |
|---:|---|---|---:|---|---:|
| 11,507,712 | 21:02:24 | 21:17:16 (a) | - | 21:21:49 relayer 1 | 4 m 33 s (a) |
| 11,507,744 | 21:08:48 | 21:22:01 | 13 m 13 s | 21:22:34 relayer 2 | 33 s |
| 11,507,776 | 21:15:12 | 21:28:19 | 13 m 07 s | 21:29:19 relayer 2 | 60 s |
| 11,507,808 | 21:21:36 | 21:34:37 | 13 m 01 s | at most 21:35:14 module | at most 37 s |
| 11,507,840 | 21:28:00 | 21:41:01 | 13 m 01 s | 21:44:04 relayer 1 | 3 m 03 s (b) |

(a) The instance existed from 21:15 and the Period(1404) job ran first; this row is not a steady-state sample. (b) The earliest deferral deadline was 21:43:23 (`max_defer_secs = 300`), then 2 LEZ blocks. Steady state: about 13 min of Ethereum finality (about 2 epochs), plus 0 to `max_defer_secs` of operator jitter, plus about 30 s (2 LEZ blocks of 15 s).

### 3.3 Not covered, and the public testnet

Real proofs were not generated in these runs, and the 1404 to 1405 period boundary fell outside the run window (rotation was first observed live in section 2.3). The public LEZ testnet (`testnet.lez.logos.co`, probed 2026-11-04) runs v0.3.x (a `shards` account field and a privacy-circuit ID that does not match the v0.4.0-rc1 wallet), so the v0.4 programs cannot be deployed there.
