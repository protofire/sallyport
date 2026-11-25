# Design decisions

Decision IDs are stable identifiers referenced from other documents.

## Light client

### D-LC-1: Port the helios algorithm, do not depend on the crate
helios `consensus-core` hard-wires BLS (no prepare/finish split for an on-chain pairing). We port its validate/apply rules and gindex table and hand-write SSZ merkleization over `sha256`, pinned by real Sepolia Gloas and mainnet Fulu vectors. Code: `crates/lc-core/src/sync.rs`, `ssz.rs`.

### D-LC-2: lc-core API and on-chain rules
`bootstrap` (takes `current_slot_hint`, 1105 if stale) / `prepare_update` / `finish_update` / `apply_update`, all borsh. A `VerifiedUpdate` is bound to the store it was checked against (1106 if it moved). Deliberate spec deviations: finality required, no optimistic header or force update, every update must advance finality or supply the unknown next committee. Code: `crates/lc-core/src/lib.rs`.

### D-LC-3: lc-core fixtures
Real Sepolia (Gloas) and mainnet (Fulu) data; the 1403 to 1404 handoff test seeds the committee from update(1402). Code: `fixtures/lc-core/`.

### D-LC-4: Native ETH through EIP-7708 logs
Every EIP-7708 transfer emits `Transfer(from, to, amount)` from `0xff…fe`, internal transfers included, so native ETH reuses the receipt-log path in `crates/inclusion`. Transaction inclusion plus signature recovery was rejected. Blocks before the EIP-7708 activation have no such logs.

### D-LC-5: Reject infinity pubkeys at committee admission
Any committee member or aggregate equal to the G1 infinity encoding is 1001. This covers only the infinity part of KeyValidate. G1 subgroup membership of the keys is assumed from deposit-time proof-of-possession and the SSZ authentication of the committee (docs/RESIDUE-SOUNDNESS.md, R-2). Code: `check_committee_len` in `crates/lc-core/src/sync.rs`.

### D-LC-6: Weak-subjectivity period from the Electra spec
`compute_ws_period_epochs` implements the Electra `compute_weak_subjectivity_period`. Measured inputs give `SEPOLIA_WS_PERIOD_EPOCHS = 279` (~29.8 h) and `MAINNET_WS_PERIOD_EPOCHS = 3537` (~15.7 d). Code: `crates/lc-core/src/lib.rs`.

## Program layout

### D-ATT-1: LEZ program layout
LEZ v0.4 actors see only their own state, so every cross-account effect is a chained message to a program PDA, accepted only from the expected sender. Accounts: Instance (config + store), write-once Header records, Job. `now_slot` is bound to LEZ block time by a ±120 s validity window. Code: `crates/attest-program/src/program.rs`.

### D-ATT-2: Update split and BLS kernel
Non-signers are derived in-program from `sync_committee_bits` against the stored committee; the relayer supplies only uncompressed hints, each checked on-curve and recompressed against the stored key. The final-exponentiation residue witness (ePrint 2024/640) is the only on-chain path. `UpdateBegin`/`UpdateVerify` remain as a two-transaction fallback. Code: `crates/attest-program/src/bls.rs`, `residue.rs`.

### D-ATT-3: Instance id bound to config and checkpoint; config floor
`Init` requires `instance_id = sha256("rfp021/instance-id" ‖ borsh(InstanceConfig) ‖ trusted_block_root)`, so an id cannot be squatted with a weak config, and enforces `342 <= min_participation <= 512` and `ws_period_epochs <= 3558`. Code: `MIN_PARTICIPATION_FLOOR`, `MAX_WS_PERIOD_EPOCHS` in `crates/attest-program/src/lib.rs`.

### D-ATT-4: Bad signature is typed 1102, not a guest trap
Residue check asserts became `false` returns with identical conditions; a wrong signature exits 1102 and is charged only the cycles used. Code: `crates/attest-program/src/residue.rs` (`check`).

### D-ATT-5: Cross-network test; UpdateBegin cap asserted
Sepolia and mainnet instances on one LEZ state give distinct statement ids for the same contract locator. `UpdateBegin` is asserted under 10M for every K up to 170. Code: `crates/program-tests/tests/executor.rs`.

### D-ATT-6: Attest any finalised block via header ancestry
`AttestRequest.ancestry` carries headers from the target back to a recorded anchor, linked by `parentHash`; the fact names the target, so `statement_id` is independent of the anchor. Length above `MAX_ANCESTRY` is 1001 before hashing. Code: `verify_ancestry` in `crates/inclusion/src/lib.rs`.

### D-ATT-7: Guest keccak on the risc0 coprocessor; MAX_ANCESTRY 448
Guests route alloy `keccak256` to `risc0_keccak_update`; LEZ v0.4 executes and proves it. Per-header cost ~199k to ~15.6k cycles. `MAX_ANCESTRY = 448`: a measured 448-header log attest is 7,106,902 cycles, ≥ 0.7M headroom under 8M. Code: `crates/inclusion/src/zkvm_keccak.rs`, `crates/inclusion/src/lib.rs`.

## Consumers and privacy

### D-CON-1: Consumer credit bound to the proven sender
`Claim` has no caller-chosen beneficiary: the credit lands on the `from` topic of the attested Transfer, so front-running a claim cannot redirect funds. Code: `crates/consumers/src/lib.rs`.

### D-ATT-8: Header accumulator in the attest program
Private consumers prove header membership against a shared root instead of calling `Attest`, which would publish the block. Instance state holds a depth-20 incremental sha256 `Frontier`; each root gets a write-once PDA checked by `CheckRoot`. See [PRIVACY.md](PRIVACY.md).

### D-PRIV-1: Private consumer claims Deposit(commitment) events
The reference private consumer claims `Deposit(bytes32 commitment, uint256 amount)` with `C = H(nk)`, not raw ERC-20 Transfers, so the claimant is not linked to the deposit. Code: `contracts/DepositVault.sol`.

### D-PRIV-2: Private claim implementation
D-ATT-8 and D-PRIV-1 as built: one `verify` core shared by `Msg::Attest` and the private path; finality-advancing updates append to the accumulator. Code: `crates/attest-program/src/lib.rs`, `crates/consumers/src/lib.rs`.

### D-PRIV-3: Private nullifier is global, not per vault
`pnf(nk) = sha256("rfp021/pnf/v2" ‖ nk)`, so a deposit is spent once across all private vaults; found while testing that a second matching vault could credit the same deposit. Code: `crates/consumers/src/lib.rs`.

### D-CON-2: Clients never choose an instance id; public claim via ancestry
Clients compute `instance_id(cfg, root)`. `Claim.block_hash` names the recorded anchor and `on_reply` checks the reply sender against the anchor PDA, so a public claim can target any ancestor block. Code: `crates/consumers/src/lib.rs`.

### D-CON-3: Consumer state hardening and per-instruction gas
`PrivateClaim` requires `is_authorized`; every consumer state is type-tagged (0xA1 to 0xA5) so one kind cannot squat another. Public nullifier is `sha256("rfp021/nullifier/v2" ‖ vault_id ‖ statement_id)` so a clone vault cannot front-run. `Update` declares `update_gas_limit(K) = 7.4M + 11.5k·K`, not 10M. Code: `crates/consumers/src/lib.rs`, `crates/lez-client/src/lib.rs`.

## Gas and one-transaction update

### D-UPD: One-transaction update
Every light-client update lands in one atomic transaction; the split path is a fallback. Evidence: [../evidence/onetx.md](../evidence/onetx.md).

### D-UPD-1: Atomic `Msg::Update` with the existing verifier
`Msg::Update` (borsh tag 9) runs prepare, BLS and apply in one transaction with no change to any acceptance condition or stored layout. Client policy and cycle figures: D-UPD-2/3. Code: `crates/attest-program/src/program.rs`.

### D-UPD-2: Committee-learning updates fit one transaction
SSZ hashing and store I/O, not BLS, were the measured excess. Fixes: `hash2` via one `sys_sha_buffer` call, flat borsh for `SyncCommittee`, uncompressed aggregate and signature hints. Committee-learning K=2: 9,754,318 to 7,134,660 cycles. Code: `crates/lc-core/src/ssz.rs`, `crates/attest-program/src/bls.rs`.

### D-UPD-3: Client sends every update kind in one transaction up to K=170
`ONE_TX_MAX_NON_SIGNERS = 170`, also the 2/3 participation limit. Worst measured: 8,866,373 cycles (committee-learning K=170) of a 9.5M budget. After inclusion the client confirms the exact HeaderRecord or stored next committee. Code: `crates/lez-client/src/lib.rs`.

### D-GAS: Gas of the attestation and consumer paths
Executor cycles (= LEZ gas), each step measured on top of the previous. Attest ERC-20 log 121,487 to 69,316; ERC-20 claim 241,997 to 149,489; private claim ~120k to 95,949 (at `82bb54d`; final code 155,845 and ≈96,809 after the per-vault nullifier fix). Tables: [BENCHMARKS.md](BENCHMARKS.md).

### D-GAS-1: Zero-copy MPT verifier
`verify_mpt`/`mpt_lookup` walk the proof in place instead of alloy-trie `verify_proof`; a differential test on 2,000 tries never accepts what alloy rejects. Code: `crates/inclusion/src/lib.rs`, `crates/inclusion/tests/mpt_diff.rs`.

### D-GAS-2: Zero-copy guest entry point
`entry::run` replaces `actor_entrypoint!`, commits the received frame bytes instead of re-encoding. Code: `crates/attest-program/src/entry.rs`.

### D-GAS-3: Borrowed Attest decode
`Msg::Attest` decodes as `AttestRequestRef`; `verify_ref` is the core. Code: `crates/attest-program/src/view.rs`.

### D-GAS-4: Spliced Claim message
`Claim` builds the `Attest` message by copying byte spans once; `on_reply` evaluates its predicates directly. Code: `claim_attest_msg` in `crates/consumers/src/lib.rs`.

### D-GAS-5: Borrowed AttestReply in consumers
Consumers decode `AttestReplyRef` without materialising echoed predicates. Code: `crates/consumers/src/lib.rs`.

### D-GAS-6: Compact receipt witness
`Proof::LogCompact` (tag 3) takes the receipt from the proven leaf, so it is carried once; consumers reject a claim receipt that differs from the final leaf (1202). Code: `receipt_is_last_leaf` in `crates/inclusion/src/lib.rs`.

### D-GAS-7: Optional inline consumer
`erc20_inline_receiver` verifies with `verify_at` and chains `Msg::CheckHeader` (tag 10) to the anchor PDA: 117,043 vs 149,489 cycles chained (at `82bb54d`; final code 120,855 vs 155,845, [BENCHMARKS.md](BENCHMARKS.md) §1). Reference consumers stay on chained `Attest`; trade-offs in [CONSUMER-GUIDE.md](CONSUMER-GUIDE.md). Code: `handle_inline` in `crates/consumers/src/lib.rs`.

## Module, relayer and clients

### D-REL-1: Relayer LEZ submitter
Feature `lez` adds the real submitter. Jobs: `Period(p)` (learn or rotate committee) else `Finality(head)`; operators defer with per-job jitter. Code: `crates/relayer/src/operator.rs`, `lez.rs`.

### D-CLI-1: Shared LEZ client crate
`crates/lez-client` holds read and submit code once for the relayer and the Logos module. One payer key per operator process (signers sharing a payer race on the nonce).

### D-MOD-1: Module submits without the LEZ wallet
Feature `submit` encodes, BIP-340-signs (k256) and sends the public transaction on `lee_core` alone; `public_tx_matches_lee` catches layout drift. The module reads the operator key from `operatorKeyFile`, refused unless `mode & 077 == 0`. Code: `crates/lez-client/src/lib.rs`. See [MODULE.md](MODULE.md).

### D-MOD-2: EL access through the Logos Ethereum core modules
Relayer and module reach the execution layer only through `eth_rpc_module`. The transport is untrusted: header hash, ancestry and MPT roots are checked against the BLS-verified header, so a lying provider yields a rejection, not a false fact. Code: `crates/relayer/src/el.rs`.

### D-MOD-3: Headers and receipts through `verified_proxy_module`
`eth_getBlockByHash`, `eth_getBlockByNumber`, `eth_getBlockReceipts` go through the verified proxy; `eth_getProof` stays raw until the proxy exposes it (soundness never depended on it, D-MOD-2). Code: `el_route` in `crates/inclusion/src/host.rs`.

### D-MOD-4: SPEL IDL
SPEL's generator cannot parse LEZ v0.4 actor programs, so `idl/gen_idl.py` derives SPEL-format IDLs from the Rust source; `--check` fails on any drift. Code: `idl/`.

### D-CI-1: CI
`.github/workflows/{ci,e2e,module}.yml`: fmt and tests blocking, clippy reported; e2e is manual (needs a sequencer and a fresh checkpoint).

### D-BENCH-1: Real-proving benchmarks
`crates/bench` measures real (non-dev) proving; on macOS risc0 3.0.5 proves on CPU, so cores and RAM set client cost. See [BENCHMARKS.md](BENCHMARKS.md).

## RFP-022 bridge

Live run: [../evidence/rfp022-sepolia.md](../evidence/rfp022-sepolia.md).

- B22-1: Wrapped balances are bridge-program state on the holder's private account (no LEZ token program on v0.4); private-only prototype.
- B22-2: Inbound is the RFP-021 private claim (`verify_ref`, `CheckRoot`, global `pnf(nk)`); `statement_id` uniqueness is not used on the private path.
- B22-3: Own burn accumulator per (cfg, token, denomination): the RFP-021 `Frontier` (sha256, depth 20) with write-once leaf PDAs; capacity `2^20 − 1` leaves, then 1307.
- B22-4: Ethereum accepts burn roots through `EcdsaRootVerifier`, 2-of-2, once per root, permanently revocable, behind `IBurnRootVerifier`. Interim, custodial, not trustless (`TRUSTLESS() == false`).
- B22-5: Release is a user-side `burn_member` RISC0 proof, Groth16-wrapped, verified by the pinned v3.1.0 verifier (v3.0.0 until 2026-11-25; moved for GHSA-g6qg-9j8p-7j87).
- B22-6: One `BridgeVault` per config, `SafeERC20`, exact-amount pull, fixed denominations, ETH as `address(0)`, verification parameters immutable.
- B22-7: Minimal admin/freezer role on LEZ; `Ownable2Step` plus `freezer` on Ethereum.
- B22-8: All secrets derive from one seed; recovery is a gap-limit scan.
- B22-9: LEZ-side fees are zero; the relayer fee is charged at release on Ethereum, bound in the proof and capped by `MAX_FEE_BPS = 500`.
- B22-10: No mini-app UI in the prototype: the `bridge_module` core module and the `b22` CLI are the interfaces.

Code: `crates/bridge`, `crates/bridge-core`, `contracts/bridge/src/`, `modules/bridge_module`.
