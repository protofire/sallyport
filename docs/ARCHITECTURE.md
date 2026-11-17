# Architecture: Ethereum state attestation (RFP-021) and a private ERC-20 / ETH bridge (RFP-022) on LEZ

This document describes what is built in this repository for both grant requests. Code wins over this text; claims cite source files, tests or evidence. A designed item that is not implemented is marked NOT BUILT once; [../proposal/COVERAGE.md](../proposal/COVERAGE.md) maps each RFP requirement to its status and milestone.

Prototype limits. Everything runs on a local LEZ v0.4.0-rc1 standalone sequencer in RISC0 dev mode: guests are executed, no private proof is verified. The public LEZ testnet runs v0.3.x, so nothing is deployed there. Ethereum is live Sepolia. Real proving is measured separately ([BENCHMARKS.md](BENCHMARKS.md)). The code is not audited and is not for real funds.

| Pin | Value | Source |
|---|---|---|
| LEZ | v0.4.0-rc1, commit `1806e87` | git dependencies, e.g. `crates/program-methods/attest-guest/Cargo.toml` |
| zkVM | risc0-zkvm 3.0.5, guests built in Docker | `crates/program-methods` |
| Header and burn trees | sha256 incremental tree, depth 20, capacity 2^20 − 1 leaves | `Frontier`, `crates/attest-program/src/lib.rs` |
| Ancestry bound | `MAX_ANCESTRY = 448` EL headers | `crates/inclusion/src/lib.rs:101` |
| One-transaction update | `ONE_TX_MAX_NON_SIGNERS = 170` | `crates/lez-client/src/lib.rs:19` |
| Sepolia bridge | `BridgeVault 0x4A96…5472`, `EcdsaRootVerifier 0x20F7…2876`, `CONFIG_ID 0xd998…7a8e`, Groth16 verifier v3.0.0 `0x2a09…a84D` | [sepolia.json](../contracts/bridge/deployments/sepolia.json) |

## 1. Overview and component map

RFP-021 is one immutable LEZ program, the attest program, that follows Ethereum's finalised chain with the Altair sync-committee light client. Other programs use it in their own transaction to check that an account, a storage slot or a receipt log exists under a finalised execution header and satisfies predicates. RFP-022 is a private bridge between Sepolia and LEZ. Its inbound leg is an RFP-021 private claim. Its outbound leg is a private burn on LEZ and a zk-proven release on Ethereum, behind a burn-root acceptance step that is interim and custodial (§3.1).

```
 Ethereum (Sepolia)                                    LEZ v0.4.0-rc1 (local sequencer, dev mode)
 beacon API, EL JSON-RPC                               attest program (RFP-021, immutable)
   |                                                     Instance PDA : config, light-client Store, header accumulator
 relayer / eth_attest_module -- Update (1 tx) ------>    Header PDA   : write-once record per finalised EL block
   (untrusted, liveness only)                            Root PDA     : write-once accumulator root
                                                         Job PDA      : split-update fallback only (K > 170)
                                                           ^ Attest / CheckHeader / CheckRoot (same tx)
 consumer client -- Claim / PrivateClaim ----------->  consumer programs (erc20_receiver, eth_receiver, inline)

 BridgeVault (one per config)                          bridge program (RFP-022)
   deposit(tok, d, C) -- Deposit(C, tok, cfg, d) -->     Claim (private): verify_ref inline, CheckRoot, N PDA
   acceptBurnRoot <-- 2-of-2 root signers                config PDA, token PDA (supply, caps, burn trees),
     IBurnRootVerifier = EcdsaRootVerifier               leaf PDAs, N PDAs, holdings on private accounts
     [INTERIM, CUSTODIAL]                                Burn (private) -> RecordBurn -> leaf PDA
   release(..., seal)                                    Transfer (private) -> sealed Credit
     RiscZeroGroth16Verifier v3.0.0  <-- burn_member guest (user side, Groth16-wrapped)
```

| Component | Role |
|---|---|
| `crates/lc-core` | Light client: bootstrap, update preparation (all but the pairing), apply |
| `crates/inclusion` | Execution-header RLP, MPT proofs, ancestry, predicates, `StatementId` |
| `crates/attest-program` | LEZ guest program; BLS kernel with a residue-witness final exponentiation |
| `crates/consumers` | Reference consumers: ERC-20 and native-ETH public claims, inline variant, private claim |
| `crates/relayer`, `crates/lez-client`, `modules/eth_attest_module` | Update submitters (operator loop, Logos core module) |
| `crates/bridge-core`, `crates/bridge` | Bridge formats and derivations; LEZ bridge program (private-only) |
| `crates/program-methods/release-guest/src/bin/burn_member.rs` | Release membership guest |
| `contracts/bridge/src` | `BridgeVault`, `IBurnRootVerifier`, `EcdsaRootVerifier` (Foundry), deployed on Sepolia |
| `crates/bridge-cli` (`b22`), `modules/bridge_module` | Client, root signer, end-to-end driver; Logos core module |

See also [TRUST-ASSUMPTIONS.md](TRUST-ASSUMPTIONS.md), [PRIVACY.md](PRIVACY.md), [DECISIONS.md](DECISIONS.md).

## 2. RFP-021: Ethereum state attestation

### 2.1 Accounts (BUILT)

LEZ v0.4 handlers see only their own `(account, program)` state, so every cross-account effect is a chained message to one of the program's own PDAs. Each handler checks that it runs at the canonical PDA for its seed (`require_at`, `crates/attest-program/src/program.rs:46-52`), and internal messages are accepted only from the expected sender PDA (`require_from`, `:55-63`). Decision `D-ATT-1`.

All accounts are public PDAs of the attest program with domain-separated sha256 seeds:

| Account | Seed | State |
|---|---|---|
| Instance | `"rfp021/instance" ‖ id` | `InstanceState { cfg, store, headers: Frontier }`, about 49 KB with both committees |
| Header | `"rfp021/header" ‖ id ‖ block_hash` | `HeaderRecord { instance_id, chain_id, genesis_validators_root, beacon_slot, beacon_root, execution_block_hash, period }`, write-once (`program.rs:258-269`) |
| Root | `"rfp021/hroot" ‖ id ‖ root` | the root; write-once marker that it was an accumulator root |
| Job | `"rfp021/job" ‖ id ‖ job_id_le` | prepared update for the split path; cleared by `UpdateVerify` |

`Init` requires `id = sha256("rfp021/instance-id" ‖ borsh(InstanceConfig) ‖ trusted_block_root)`, where `InstanceConfig` is the `ChainConfig` plus the beacon genesis time. It also enforces `342 <= min_participation <= 512` and `ws_period_epochs <= 3,558` (`program.rs:138-146`). Pinning an id pins the config and checkpoint; no one can squat an id with a weak config. Decision `D-ATT-3`.

Each header that advances finality is appended to the accumulator as `sha256("rfp021/hleaf" ‖ borsh(HeaderRecord))`, and the new root goes to a Root PDA (`apply_verified`, `program.rs:98-118`); private claims prove membership against it (§2.6).

### 2.2 Instructions (BUILT)

`Msg` is a borsh enum in `crates/attest-program/src/lib.rs`; new variants were appended, so tags never changed. Errors are typed codes 1001 to 1204, and the guest exits with `code − 1000` (`crates/lc-core/src/lib.rs:46-61`).

| Instruction | To | Checks and effect | Code |
|---|---|---|---|
| `Init { id, cfg, trusted_block_root, bootstrap, now_slot }` | Instance | empty (else 1106); id and config floor (1001); bootstrap matches the checkpoint and its committee branch; checkpoint within the weak-subjectivity period (1105). Writes Store, first Header and Root PDAs | `program.rs:127-160` |
| `Update { id, update, non_signers, witness, now_slot }` | Instance | prepare, BLS, pairing, apply, Header and Root writes in one transaction | `:161-179` |
| `UpdateBegin` / `UpdateVerify` | Instance / Job | the same, split over two transactions through the Job PDA | `:180-257` |
| `Attest(AttestRequest)` | Header | §2.4; replies `AttestReply` to a chained caller, emits event `Attested` for a root call | `:306-328` |
| `CheckRoot { id, root }` | Root | 1101 unless the root exists | `:277-283` |
| `CheckHeader { id, chain_id, gvr, block_hash }` | Header | 1101 unless the record exists; 1204 unless it carries this chain | `:284-302` |
| `WriteJob`, `Apply`, `WriteHeader`, `WriteRoot` | own PDAs | internal only | `:208-276` |

The program cannot read a clock. `Init`, `Update` and `UpdateBegin` take `now_slot` and set a validity window of ±120 s around `genesis_time + 12·now_slot`, which the sequencer enforces (`now_window`, `program.rs:91-95`).

### 2.3 Update flow: one transaction, split fallback (BUILT)

lc-core (`crates/lc-core/src/sync.rs:197-305`) requires a finalised header, `current_slot >= signature_slot > attested_slot >= finalized_slot`, participation of at least `min_participation`, a signature period equal to the store's (or the next one once known), and an update that advances finality or supplies the unknown next committee (else 1106). The finality, execution and next-committee branches verify against the attested state root with Electra or Gloas generalised indices.

Non-signers are derived in the program from the sync bitmap against the stored committee. The caller supplies only uncompressed hints, and each must recompress to the stored key at that index (else 1102). `apply_update` re-checks the base finalised root, so a prepared update cannot be applied to a store that has moved (`sync.rs:337-354`). Decision `D-ATT-2`.

BLS runs in the guest (`crates/attest-program/src/bls.rs`): the aggregate key minus the non-signers, the G2 subgroup check and hash-to-G2. A residue-witness check replaces the final exponentiation (`residue.rs`). The 864-byte witness is untrusted input ([TRUST-ASSUMPTIONS.md](TRUST-ASSUMPTIONS.md)), and a bad witness or signature returns 1102 rather than trapping the guest (decision `D-ATT-4`).

`Msg::Update` runs every update kind in one atomic transaction: finality, period rotation and committee learning. The client (`LezClient::submit_update_json`, shared by the relayer and `eth_attest_module`) sends `Update` whenever there are `K <= 170` non-signers, with a declared gas limit of `7.4M + 11.5k·K`, capped at the 10M per-block cap (`crates/lez-client/src/lib.rs:30-32`, `:63-65`). K = 170 is the most the 342-of-512 floor allows, so the split path `UpdateBegin` + `UpdateVerify` is reachable only if the floor is relaxed. It stays in the program as the fallback. Decisions `D-UPD-1`, `D-UPD-2`, `D-UPD-3`.

Executor cycles (`onetx_cycles_by_non_signers`, `crates/program-tests/tests/onetx.rs`): 6.4M to 7.0M typical; 8.47M to 8.87M at K = 170, under a 9.5M budget. Live, the Sepolia rotation across sync periods 1405 → 1406 landed as one `Update` of 6,411,261 cycles. See [../evidence/onetx.md](../evidence/onetx.md) and [../evidence/rfp021-final-run.md](../evidence/rfp021-final-run.md). After inclusion the client confirms the exact expected `HeaderRecord` (or next committee) and never retries an uncertain write through the other path.

### 2.4 Attest: header binding, ancestry, proofs, predicates (BUILT)

`verify_ref(&HeaderRecord, &AttestRequestRef)` is the one verification core. `Msg::Attest`, the inline consumer and both private claim paths call it.

1. Header: `keccak(exec_header_rlp)` must equal the record's `execution_block_hash` (1201).
2. Ancestry: `[H_target, …, H_anchor−1]` walks back from the recorded header by `parentHash`. A broken link is 1201; more than 448 headers is 1001 before any hashing (`crates/inclusion/src/lib.rs:101-121`). The proof is checked against the target, and the `Fact` carries the target's hash and number, so the `StatementId` does not depend on the anchor (test `same_fact_via_two_anchors_has_one_statement_id`). Decision `D-ATT-6`.
3. The bound: guest keccak uses the risc0 keccak coprocessor, about 15.6k cycles per header. A log attest over 448 real headers measured 7,106,902 cycles (`fixtures/ancestry/log448.json`). 448 headers (14 epochs) is the largest epoch multiple with at least 0.7M headroom under 8M. Decision `D-ATT-7`.
4. Proofs by locator: `Account { address }` (against `stateRoot`); `Storage { address, slot }` (account proof, then storage proof); `Log { tx_index, log_index }` (receipt proof against `receiptsRoot`; `LogCompact` takes the receipt from the proof's final leaf).
5. Predicates: a conjunction of `Eq/Ne` (bytes) and `Lt/Le/Gt/Ge` (32-byte big-endian uints) over `Nonce, Balance, StorageRoot, CodeHash, Slot, LogAddress, LogTopic(i), LogDataWord(i), LogStatus`. A missing field is false; a false predicate is 1203 (`inclusion/src/lib.rs:589-693`).
6. Statement: `{ id, fact, preds }`, `id = sha256("rfp021/fact/v1" ‖ borsh(chain_id, genesis_validators_root, execution_block_hash, locator))` (`:573-586`).

A chained `Attest` replies `AttestReply { instance_id, statement, ctx }` to the caller. Its sender is the Header PDA that was called, which binds the reply to an instance. Executor cycles: ERC-20 log 69,316, ETH log 58,785, storage slot 153,495, plus about 10,870 per ancestry header ([BENCHMARKS.md](BENCHMARKS.md) §1).

### 2.5 Consumer pattern (BUILT)

The reference consumers are in `crates/consumers/src/lib.rs`, with guests in `crates/program-methods/consumers-guest/src/bin/`. `erc20_receiver` claims ERC-20 transfers to a vault address. `eth_receiver` claims native ETH through the EIP-7708 Transfer log from `0xff…fe`. `erc20_inline_receiver` verifies inline. Integration rules: [CONSUMER-GUIDE.md](CONSUMER-GUIDE.md).

- Program id: consumers hard-code `ATTEST_PROGRAM` (`consumers/src/lib.rs:21-27`) and accept replies only from it.
- Chained claim: `Claim` to the vault PDA chains `Attest` to the anchor's Header PDA. In `on_reply` (`:729-795`) the vault checks the sender is `PDA(attest, header_seed(pinned_instance, anchor))`, that instance, chain and genesis validators root match its config, and that `statement_id` recomputes. It re-evaluates its own predicates on the proven fact. The credit goes to the proven Transfer `from`; the claim has no recipient input, so a third party cannot redirect it.
- Nullifier: `Nullify` writes `PDA(sha256("rfp021/nullifier/v2" ‖ vault_id ‖ statement_id))`; a replay is 1250. The vault id is in the seed because `InitVault` is permissionless, and a statement-only nullifier would let a clone vault claim first (test `clone_vault_cannot_steal_deposit`).
- Inline: `verify_at` locally, with `CheckHeader` chained first to bind the anchor (`claim_inline`, `:593-636`).

Claims: 155,845 cycles chained ERC-20, 120,855 inline, 135,145 ETH ([BENCHMARKS.md](BENCHMARKS.md) §1; 149,489 / 117,041 / 133,526 before the per-vault nullifier fix).

### 2.6 Private claim (BUILT; inbound primitive of RFP-022)

A chained `Attest` would publish the Header PDA, and so the Ethereum block. The private path verifies inline and crosses to public state only with values that do not identify the deposit.

- Deposit: `Deposit(bytes32 indexed C, uint256 amount)` with `C = commit(nk) = sha256("rfp021/commit" ‖ nk)` (`contracts/DepositVault.sol`).
- Claim: `PrivateClaim` is an authorized root call on the claimant's own private account (`consumers/src/lib.rs:638-727`). Inside the private transition it computes `root = merkle_root(header_leaf(header), index, path)`, runs `verify_ref` with `status = 1`, `address`, `topic0`, `topic1 = commit(nk)` and `data word 0 = denomination`, and credits a `PrivateBalance` bound to the vault config.
- Crossing: only `RedeemCheck { vault_id, cfg_hash, root, pnf(nk) }`. The vault accepts it only from this program's actors, checks `cfg_hash`, chains `CheckRoot` (1101) and `Spend` to `PDA(pnf(nk))` (1250 if present).
- Nullifier: `pnf(nk) = sha256("rfp021/pnf/v2" ‖ nk)` is global per consumer program, so a deposit is spent once across all private vaults (decision `D-PRIV-3`, test `same_deposit_via_second_vault_is_1250`). It depends only on `nk`, so it is unlinkable to `C`, the block and the claimant.

## 3. RFP-022: private wrapped ERC-20 / ETH bridge

### 3.1 Custody, stated first

Burn-root acceptance on Ethereum is interim, custodial and not trustless. The vault accepts a LEZ burn root when `EcdsaRootVerifier` sees 2-of-2 secp256k1 signatures from fixed keys held on two machines, signer host 1 and signer host 2. Both signers read the same LEZ sequencer over RPC, so they share one view of LEZ.

- Whoever holds both keys can forge a root that contains their own burn commitments and release against it. That drains the escrow of every token of the vault, slowed only by the release delay and caps and stopped only by a freezer pause or root revocation (§4.2).
- `TRUSTLESS()` returns `false` (`contracts/bridge/src/EcdsaRootVerifier.sol:45-47`).
- The signer set and threshold are immutable. Losing either key means no new root is ever accepted, so later burns cannot be released. Signer rotation, or a timelocked escape, is NOT BUILT.
- The signers cannot redirect or deanonymise an honest release: the recipient is inside the burn commitment (§3.5).
- Each acceptance names `lezHeight` and `lezBlockHash`, so replaying the sequencer's blocks detects a forged root.

Upgrade option (NOT BUILT). The vault reaches the root verifier only through `IBurnRootVerifier`, at an immutable address. Upgrading means deploying a new verifier and a new vault; the old vault freezes deposits and keeps releasing its own burns until drained. Planned verifiers, in order:
1. Optional milestone O, a committee-certified checkpoint verifier. At least q of the N accredited LEZ sequencer committee keys (N ≥ 3, q = the channel's threshold) co-sign a finalised checkpoint message (burn roots per token and denomination, LEZ block id and hash, the Bedrock position it is final at, channel id, Bedrock network, vault, Ethereum chain id, previous checkpoint) through the channel signing the committee already uses for zone withdrawals. A bridge-program `Checkpoint` instruction computes the root; a RISC0 guest checks the q-of-N Ed25519 threshold against the key set tracked from a pinned genesis through threshold-signed configuration changes, Groth16-wrapped. The vault then checks `minLezDepth` itself, and the signer hosts become veto-only watchers. Trust: fewer than q of N committee keys corrupt, the Logos zone-withdrawal trust level; not trustless. A single inscription signature is not used: it would let any one committee member forge a root, and inscription signatures of descendant blocks do not prove Bedrock finality.
2. A trustless verifier: a Bedrock (Cryptarchia) light client plus a validity proof of LEZ execution, in zk (research; neither exists today).

### 3.2 LEZ accounts and formats (BUILT)

Formats: `crates/bridge-core/src/lib.rs`, pinned for Solidity by `fixtures/b22/vectors.json`. Hashes are domain-prefixed sha256. Integers are little-endian in LEZ formats (`d` 16 bytes, indices 8 bytes). `tok` is a 20-byte Ethereum address, and `0x00…00` means native ETH.

| Item | Definition |
|---|---|
| `BridgeConfig` | `{ instance_id, evm_chain_id, genesis_validators_root, vault, deposit_topic0, zone_id, bridge_program_id, admin, freezer, salt }` |
| `cfg` = `CONFIG_ID` | `sha256("b022/cfg" ‖ borsh(BridgeConfig))`; `zone_id` is the placeholder `sha256("b022/zone/local-standalone")` |
| Config PDA | `PDA(bridge, sha256("b022/config" ‖ cfg))`: `{ config, paused_mint, paused_burn }` |
| Token PDA | `PDA(bridge, sha256("b022/token" ‖ cfg ‖ tok))`: `{ cfg, entry, supply, fees, trees: [(d, Frontier)] }`; `entry = { tok, decimals, denoms: [{ d, fee_mint, fee_burn }], supply_cap, mint_open, paused_mint, paused_burn }` |
| Leaf PDA | `PDA(bridge, sha256("b022/bleaf" ‖ cfg ‖ tok ‖ d ‖ index))`: `B`, write-once |
| N PDA | `PDA(bridge, pnf(nk))`: `[1]` |
| Holding | bridge actor state on the holder's private account: `BTreeMap<(cfg, tok), u128>` |

LEZ v0.4 has no general token program, so wrapped balances are bridge-program state (decision `B22-1`). The prototype is private-only. Public holdings, public mint and burn, shield, unshield and public transfer are NOT BUILT.

The holder's seed is the secret spending key `ssk` of the LEZ wallet's root private account, so the wallet mnemonic is the only secret: `sk = sha256("b022/sk" ‖ "b022/lez-wallet/v1" ‖ ssk)` (`crates/bridge-cli/src/lib.rs:16`, `:101-103`). The derivations are in `bridge-core/src/lib.rs:50-105`:

```
nk_i = sha256("b022/nk"  ‖ sk ‖ cfg ‖ tok ‖ d ‖ i)     C_i = commit(nk_i)    N = pnf(nk_i)
rk_j = sha256("b022/rk"  ‖ sk ‖ cfg ‖ tok ‖ d ‖ j)
ek_j = sha256("b022/eth" ‖ sk ‖ cfg ‖ j) mod n         recipient_j = address(ek_j)
B_j  = sha256("b022/burn" ‖ rk_j ‖ recipient_j)        Nb = sha256("b022/rnf" ‖ rk_j)
```

### 3.3 LEZ instructions (BUILT)

`BridgeMsg` is in `bridge-core/src/lib.rs:252-327`, and the handler is `crates/bridge/src/program.rs`. New codes: 1301 TokenNotListed, 1302 DenomNotPermitted, 1303 CapExceeded, 1304 Frozen, 1305 InsufficientBalance, 1306 Unauthorized, 1307 TreeFull, 1308 FeeMismatch. They exit the guest as 45 to 52 and are mapped back by `bridge::error_from_exit`.

| Message | Route | Checks and effect | Code |
|---|---|---|---|
| `InitConfig(BridgeConfig)` | root → config PDA | at the PDA of `config_id(c)`, empty, `bridge_program_id` is this program, `deposit_topic0` is the `Deposit` topic | `program.rs:54-71` |
| `Admin(RegisterToken / UpdateToken)` | signed seat → config PDA → token PDA | sender is `cfg.admin`; entry valid: decimals ≤ 18, unique `d > 0`, LEZ fees 0. `UpdateToken` keeps the pause flags | `:389-486` |
| `Freeze(Global / Token)` | signed seat → config PDA (→ token PDA) | sender is `cfg.freezer`; sets the pause of each half | same |
| `Claim { bridge_cfg, token_entry, d, header, header_index, header_path, exec_header_rlp, ancestry, tx_index, log_index, receipt, receipt_proof, nk }` | private root call | authorized, top-level; header binds instance, chain and gvr (1204); `verify_ref` (§3.4). Credits `d`, sends `MintCheck` | `:489-559` |
| `MintCheck { cfg_hash, tok, d, fee_mint, root, n }` | private actor → config PDA → token PDA | config hop: bridge sender, config id, global pause (1304), chains `CheckRoot` (1101). Token hop: sender is that config PDA, `mint_open` (1301), denomination (1302), fee (1308), token pause (1304), `supply + d <= supply_cap` (1303). Sends `Spend` | `:75-147` |
| `Spend { cfg, tok, n }` | token PDA → N PDA | sender is exactly that token PDA (1306); empty, else 1250 | `:148-158` |
| `Transfer { cfg, tok, amount, to }` | private root call | debits (1305); sealed async `Credit` to `to` | `:159-174` |
| `Credit { cfg, tok, amount }` | pending message | from this program, received by the owner (1306) | `:175-184` |
| `Burn { bridge_cfg, token_entry, d, index, b }` | private root call | debits `d` (1305); sends `RecordBurn` | `:185-219` |
| `RecordBurn { cfg_hash, tok, d, fee_burn, b, index }` | private actor → config PDA → token PDA | global and token burn pause (1304), denomination, fee, `index == leaves` (1001), not full (1307). Appends `B`, `supply −= d`, sends `WriteLeaf` | `:220-285` |
| `WriteLeaf { cfg, tok, d, index, b }` | token PDA → leaf PDA | sender is exactly that token PDA (1306); empty | `:286-302` |

`MintCheck` and `RecordBurn` pass the config PDA because the token PDA cannot read the global pause. A delisted token (`mint_open = false`) still burns. Hand-made `MintCheck`, `RecordBurn`, `Spend`, `WriteLeaf` or `Credit` messages are rejected with no state change (test `forged_direct_messages_are_1306`, `crates/program-tests/tests/bridge.rs`).

LEZ fees are 0 by rule: `valid_entry` refuses a non-zero `fee_mint` or `fee_burn` (`program.rs:377-386`). With fixed denominations a non-zero LEZ fee would leave one deposit unexitable. The only fee is the relayer fee at release (§3.6). Test `lez_fees_zero_and_one_deposit_exits`.

### 3.4 Deposit and mint (BUILT)

1. Liveness gate. The client refuses to deposit while the attest instance's latest finalised header is more than 224 EL blocks (half of `MAX_ANCESTRY`) behind the head (`check_attest_live`, `crates/bridge-cli/src/lib.rs:26-37`). See §5 item 3.
2. Deposit, public. `vault.deposit(tok, d, C)` (`contracts/bridge/src/BridgeVault.sol:228-248`) checks that the token is listed with deposits open, that the denomination is permitted, that no global or token freeze is on, that `C` is unseen, and the fixed-window cap. It pulls with `safeTransferFrom` and requires `balanceAfter − balanceBefore == d`, which rejects fee-on-transfer tokens; for ETH it requires `msg.value == d`. It emits `Deposit(bytes32 indexed commitment, address indexed token, bytes32 indexed configId, uint256 amount)` with its immutable `CONFIG_ID`. No LEZ identifier appears on Ethereum.
3. Wait until Sepolia finalises and the instance records a header at or after the deposit block (§2.3).
4. Claim, one privacy-preserving transaction proven by the user. The private transition runs `verify_ref` with `status = 1`, `address = vault`, `topic0 = Deposit`, `topic1 = commit(nk)`, `topic2 = tok`, `topic3 = cfg` and `data word 0 = d` (`claim_preds`, `crates/bridge/src/lib.rs`). It credits `d` privately. Only `MintCheck` crosses, from a blinded sender, and the public side re-checks every value against its own state.
5. Atomicity. Any failure (cap, pause, unknown root, replay, fee) reverts the whole transaction, so N is not created and the deposit stays claimable.

Uniqueness is keyed on `pnf(nk)`, not on `statement_id`, which is public and would link deposit and mint: a deliberate deviation from the RFP text (decision `B22-2`).

`InitConfig` is permissionless, but a look-alike config naming our vault cannot mint against our deposits (the claim requires `topic3 == cfg`), and our vault never accepts its roots (`CONFIG_ID` is in the root digest). Clients take `cfg` from the vault on Ethereum.

### 3.5 Transfer and burn (BUILT)

A transfer is two private transactions (how LEZ v0.4 delivers a private credit). The sender's `Transfer` emits a sealed `Credit`, and the recipient later applies it with `receive_pending_message_with` (test `transfer_two_tx_private_to_foreign_private`).

A burn is one private transaction: `Burn` debits `d` and records `B_j`, which hides a fresh seed-derived `recipient_j`; the token PDA appends `B` to the `(tok, d)` tree and writes the leaf PDA. That leaf PDA is in the proof's public actor list, so two burns of one `(tok, d)` proven against the same leaf count collide. The first to be included wins, and the second reverts and re-proves at the next index (test `two_burners_same_index`). A user-chosen recipient is NOT BUILT (it breaks seed-only recovery).

### 3.6 Root acceptance and release (BUILT; acceptance INTERIM, CUSTODIAL)

Each signer runs `sign_root` (`crates/bridge-cli/src/main.rs:934-976`):
1. Read the vault's effective `minLezDepth`.
2. Find the block that wrote the tree's last leaf PDA. Only a non-reverted transaction that names that account under the bridge program counts (`last_write`, `crates/bridge-cli/src/lez.rs`).
3. Wait for block `n = that block + minLezDepth`.
4. Re-read the tree, and start over if the leaf count changed.
5. Sign the raw digest:

```
keccak256(abi.encode(bytes32("b022/root/v1"), chainid, vault, CONFIG_ID, token, denom,
                     burnRoot, count, lezHeight = n, lezBlockHash))
```

Anyone can call `acceptBurnRoot` (`BridgeVault.sol:253-266`). It requires a root that was never accepted or revoked and calls `ROOT_VERIFIER.verifyRoot`. The verifier recomputes the digest with `msg.sender` as the vault and requires `THRESHOLD` signatures from configured signers, recovered in strictly ascending address order with OpenZeppelin `ECDSA` (low-s) (`EcdsaRootVerifier.sol:71-89`). The vault stores `acceptedAt` and emits `BurnRootAccepted`. A root is accepted once, so replaying it cannot reset the delay. There is no monotonic `count` rule, because every leaf also appears in all later roots of its tree.

The release proof is `burn_member` (`crates/program-methods/release-guest/src/bin/burn_member.rs`). Its private inputs are `rk`, the leaf index and the path. It proves that `B = sha256("b022/burn" ‖ rk ‖ recipient)` is in `burnRoot`, recomputes `Nb`, and commits the 352-byte journal `abi.encode(bytes32("b022/rel/v1"), chainid, vault, CONFIG_ID, token, denom, burnRoot, Nb, recipient, relayer, fee)`. The succinct receipt is Groth16-wrapped with the risc0 Docker prover on an x86 prover host.

Anyone can call `release(token, denom, burnRoot, Nb, recipient, relayer, fee, seal)` (`BridgeVault.sol:286-322`). It checks, in order:
- the root is accepted and not revoked;
- `now >= acceptedAt + releaseDelay`;
- releases are not frozen;
- `fee * 10^4 <= denom * MAX_FEE_BPS` (immutable, 500 on Sepolia);
- the release cap;
- `Nb` is unspent, then marks it spent;
- `GROTH16.verify(seal, MEMBERSHIP_IMAGE_ID, sha256(journal))`.

It pays `denom − fee` to `recipient` and `fee` to `relayer` (`nonReentrant`), from the proven journal only; `standardFee` is never read here. Payment is push-only: if the transfer to `recipient` reverts, the release reverts and `Nb` stays unspent.

### 3.7 Vault administration (BUILT)

`BridgeVault` serves one config. These are immutable, with no setter: `ROOT_VERIFIER`, `GROTH16`, `MEMBERSHIP_IMAGE_ID`, `CONFIG_ID`, `MAX_FEE_BPS`, `FREEZER` and `MIN_TIMELOCK`. The admin is `Ownable2Step`. The constructor refuses a freezer equal to the admin and requires `10 min <= MIN_TIMELOCK <= 30 days` (`:111-134`).

- `setToken` (`:143-162`). The first listing fixes `window`. `listed`, `depositsOpen` and any tightening apply at once. A loosening (a lower delay or a higher cap) is queued for `max(releaseDelay, MIN_TIMELOCK)` and emits `TokenChangeQueued`; the freezer can cancel it until it matures. `releaseDelay <= 7 days` always. `effectiveToken` gives the config in force.
- `setMinLezDepth`. An increase applies at once; a decrease is queued for `MIN_TIMELOCK`.
- Caps use fixed windows `[wW, (w+1)W)`.

Sepolia values ([sepolia.json](../contracts/bridge/deployments/sepolia.json)): ETH `d = 0.01 ETH` and a USDT mock with `d = 100 USDT`; release delay 600 s; window 24 h; deposit cap `4·d` and release cap `2·d` per window; `minLezDepth = 10`; `MIN_TIMELOCK = 6 h`. The live round trip is recorded in [../evidence/rfp022-sepolia.md](../evidence/rfp022-sepolia.md): deposit, claim, transfer, burn, root acceptance, release and seed-only recovery.

### 3.8 Seed-only recovery (BUILT)

Client state and LEZ wallet storage are wiped, and only the mnemonic remains. The client restores the wallet, derives `sk`, and scans every `(tok, d)` pair found in the vault's `Deposit` logs or in the LEZ token PDAs. Each scan stops after 20 consecutive misses (`GAP`, `crates/bridge-cli/src/lib.rs:13`).
- A deposit `C_i` whose N PDA is empty is re-claimed.
- A burn `B_j` found among the leaf PDAs whose `Nb_j` is unspent is re-proven.
- Pending `Credit`s apply only if their `cfg` is the vault's.

## 4. Cross-cutting

### 4.1 Replay and nullifiers

| Path | Key | Replay result |
|---|---|---|
| RFP-021 public claim | `sha256("rfp021/nullifier/v2" ‖ vault_id ‖ statement_id)` | 1250 |
| RFP-021 private claim | `pnf(nk)`, global per consumer program | 1250; a concurrent same-`nk` claim is reverted by the sequencer |
| Bridge mint | `pnf(nk)` in the bridge's N PDA | 1250 |
| Bridge burn leaf | write-once `(cfg, tok, d, index)` | 1001, then re-prove at the next index |
| Ethereum deposit, root, release | `seen[C]`, `acceptedAt[tok][d][root]`, `spent[Nb]` | `CommitmentSeen`, `RootAlreadyAccepted`, `NullifierSpent` |
| Light-client update | base-root check; write-once Header and Root PDAs | 1106 |

The root digest and the release journal both carry `chainid`, `vault` and `CONFIG_ID`, which binds the chain, vault, zone, bridge program and attest instance.

### 4.2 Freeze, pause and admin controls

| Control | Holder | Effect | Code |
|---|---|---|---|
| Ethereum freeze, global or per token | freezer | deposits and releases separately | `BridgeVault.sol:202-210` |
| `revokeRoot` | freezer | permanent, even after the delay has matured; releases already made stay made | `:221-224` |
| `cancelTokenChange` | freezer | drops a queued loosening before it matures | `:213-218` |
| LEZ pause, global or per token | freezer seat | mint and burn separately; `UpdateToken` cannot clear it | `program.rs:410-422`, `:465-477` |
| LEZ registry | admin seat | supply cap, `mint_open`, denominations; immediate, no timelock | `program.rs:435-464` |

A freeze or revocation ordered before a release in the same block stops it (`contracts/bridge/test/Revocation.t.sol`). The bound on loss from compromised root signers is per token. With release delay `D`, cap `C` per window `W`, and the freezer acting `T` after a forged root is accepted, the loss is 0 if `T <= D`; otherwise it is at most `min(escrow, C·(1 + ⌈(T − D)/W⌉))`. With the Sepolia values, a freezer that reacts within 10 minutes loses nothing. A missing or compromised freezer loses the whole escrow. See [TRUST-ASSUMPTIONS.md](TRUST-ASSUMPTIONS.md).

### 4.3 What leaks

Per-signal tables: [PRIVACY.md](PRIVACY.md). In summary:
- Public by design: the depositor, token and amount; the release recipient (a fresh `recipient_j` per burn) and amount. The anonymity set is the equal-denomination `(tok, d)` set.
- Hidden: the LEZ destination of a deposit (only `C` is published). The deposit-to-mint link: a claim publishes `MintCheck` with `root` and `N`, and never the deposit block, its Header PDA or `statement_id`. The burn's Ethereum destination (inside `B`). The burn-to-release link (`Nb` cannot be tied to `B` without `rk`). Byte scans of the round-trip transactions are in the evidence; the end-to-end run asserts them.
- Visible on LEZ: that a mint or burn of `(tok, d)` happened (`supply`), the header root a claim used (coarse time), the burn root a release used, and a reverted claim's `N`.
- Not mitigated:
  - timing (a client-side random delay is NOT BUILT);
  - gas funding of `recipient_j` from a known address;
  - the release prover host learns which leaf is spent and could take the relayer fee up to the bound;
  - whether the succinct receipt the Groth16 wrapper sees is zero-knowledge is not verified;
  - IP-level metadata.

## 5. Known limits

1. Dev mode. The sequencer is trusted for execution validity, not only liveness, because it does not verify private proofs: a forged private mint would be accepted. Supply soundness needs real LEZ proofs and honest root signers.
2. Custodial outbound (§3.1). Losing either signer key locks the remaining escrow.
3. Inbound liveness. With no header backfill and no vault refund, a deposit with no recorded header within 448 EL blocks (about 90 minutes) after it is unclaimable. The client gate narrows this; a historical-root or refund path is NOT BUILT.
4. Weak subjectivity. If no update lands within the period (Sepolia 279 epochs, about 29.8 h), the instance stops and a new `Init` is needed ([OPERATOR-GUIDE.md](OPERATOR-GUIDE.md), [CONSUMER-GUIDE.md](CONSUMER-GUIDE.md)).
5. `ATTEST_PROGRAM` comes from a public dev deploy key; on a shared network anyone can deploy there first.
6. Private-only is not enforced by the program. `Claim`, `Transfer` and `Burn` need only an authorized top-level call, and a signed public account also satisfies that, publicly.
7. The LEZ admin has no timelock. It can raise the supply cap, the only LEZ-side bound on a forged mint, in one transaction, and it can drop a denomination that still has supply (its burns then fail 1302). The LEZ program does not check that the admin and the freezer differ; only the Ethereum constructor and the deploy scripts do.
8. `seen[C]` is global: a front-runner can land the same `C` first, and the user's deposit reverts with no funds moved.
9. Release is push-only: a blacklisted `recipient_j` cannot be paid, with no re-target.
10. One burn per `(tok, d)` per block.
11. `bridge_module` is a package build only; there is no mini-app ([MODULE.md](MODULE.md)).
