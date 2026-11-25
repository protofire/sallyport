# Privacy design: Functionality #8 and R11 on LEZ v0.4

Status: D-ATT-8 and D-PRIV-1 accepted; the reference private claim (section 4) is implemented (section 5) and was run live against a real Sepolia deposit to the reference `DepositVault`, as a real LEZ privacy-preserving tx on a local v0.4.0-rc1 sequencer with dev-mode proofs (section 6; [evidence/rfp021-final-run.md](../evidence/rfp021-final-run.md)). The nullifier is the v2 global form `pnf(nk)` (D-PRIV-3, section 3.3). A real (non-dev) LEZ privacy proof of the claim was produced and accepted once in a test: 423 s, 5.0 GB peak on an M2 Max CPU ([BENCHMARKS.md](BENCHMARKS.md) section 3).

Citations: `L/` = LEZ v0.4.0-rc1 source (https://github.com/logos-blockchain/logos-execution-zone at commit 1806e87, the rev our crates pinned when this was written; since 2026-11-25 they pin `6aaabe5` and these citations have not been re-checked against it). Our code is cited by repo path.

## 1. How a LEZ v0.4 private transaction works

Shape. A privacy-preserving (PP) transaction carries a proof from the privacy-preserving circuit (PPC) plus a public journal, `ProvenExecution` (`L/lee/state_machine/core/src/circuit_io.rs:498`). The whole journal is public and hashed into the message (`L/lee/state_machine/src/privacy_preserving_transaction/message.rs:9`; byte layout pinned by its test, lines 117-145). It holds:

| Journal field | What an observer learns |
|---|---|
| `public_context.actors` (`execution_state.rs:47`) | Every **public** account the tx touches, as `(account_id, program_id)`. |
| `boundary: Vec<BoundaryStep>` (`execution_state.rs:132`) | Every message crossing private to public (`PrivateToPublic`) or public to private (`PublicToPrivate`), **in plaintext**: sender, receiver, message bytes, PDA seeds, disclosed grants. |
| `private_actions` (`circuit_io.rs:470`) | One `(nullifier, commitment-set root, new commitment, encrypted note)` per private account touched. Nullifier = `H(commitment, nsk)` (`core/src/nullifier.rs:129`), unlinkable without the key. |
| `async_messages` | Sealed (encrypted) messages between private actors. |
| `public_root` | The root call only if it targets a public actor. A private root call is **not** published (`circuit_io.rs:208-216`). |
| `program_image_claims` (`circuit_io.rs:99`) | Which program images ran privately: `Disclosed` names the image, `Undisclosed` proves membership among immutable programs and hides which. |
| `validity`, `fee` | Validity windows the programs set; fee refund target and fallback. |

Execution. The prover runs the whole call graph locally (`WholeExecution`), then proves only the private part (`PrivatePart`). Each private program transition is a separate RISC0 receipt verified inside the PPC with `env::verify` (`L/lee/privacy_preserving_circuit/src/private_backend.rs:77`), so the consumer's own cycles are proven on the user's machine. The sequencer re-executes the public part against live state (`PublicPart`) and requires it to reproduce the proven boundary step by step (`execution_state.rs:840-870`, `L/lee/state_machine/src/validated_state_diff/mod.rs:293-380`). If the public part fails, no private action is applied (test `a_failing_public_transition_leaves_the_state_untouched`, `L/lee/state_machine/src/state/tests/privacy_preserving.rs:353`).

Private accounts. A regular private account id is derived from `(npk, vpk)`. A private PDA is `H(program, seed, npk, vpk)` (`core/src/program/mod.rs:210`): it depends on the owner's keys, so **a private PDA is unique per owner, not globally**. A private PDA keyed on `statement_id` therefore cannot stop a second claim made under different keys. Initialization spends the nullifier of the fixed empty predecessor (`nullifier.rs:140`).

Private to public chained calls: supported. A private transition may send a sync message to a public actor. `PrivateMode::deliver_to_public` (`execution_state.rs:770-790`) records it as `BoundaryStep::PrivateToPublic`, and the public replies come back as predicted `PublicToPrivate` deliveries. The sequencer replays the call (`execution_state.rs:848`) and rejects any reply that differs from the prediction. LEZ's own test `a_nested_boundary_settles_both_public_writes` (`privacy_preserving.rs:701`) shows public P → private A → public Q. Costs of such a call:
- The callee `(account, program)` is published in `public_context.actors`, and the message and reply bytes are published in `boundary`.
- The private sender appears as `Canonical` (its real private account id) or `Blinded(factor)` (a one-off alias `H(id, factor)`), chosen by the prover (`execution_state.rs:1409-1430`). The sender's **program id is always disclosed** (`Actor.program_account_id`).
- Existing public accounts are admitted (`L/lee/state_machine/src/validated_state_diff/public_backend.rs:104`). A new public PDA is admitted only if the issuing program passes its seed (`execution_state.rs:1190`).

Reading public accounts. A private program cannot read public state directly. Each actor sees only its own state, and the only route to public state is a call to the public actor whose reply crosses the boundary. A private consumer that "reads the HeaderRecord" is therefore calling the header PDA, which publishes that PDA, and so the Ethereum block.

Events. Private execution emits no events (`PrivateMode::EMITS_EVENTS = false`, `execution_state.rs:753`). Events come only from the public part.

Fees. `FeeTransfer` (`circuit_io.rs:148`) debits a payer that may be a private account holding a `FeeOnly` key (`circuit_io.rs:309`). A private tx is charged a fixed verification gas, `PRIVATE_VERIFY_GAS = 409,764`, plus the cycles of its public effects, plus a fixed `PRIVATE_GAS_STOR` (`L/lez/programs/fee/core/src/assess.rs:93-103`, `market.rs:49`). The private transitions' own cycles are not metered; they are paid in prover time, not in fee. (A public tx pays its metered `user_cycles` plus its data bytes.)

Padding. Wallets pad to 7 private slots and support `dummy_inputs` and `ciphertext_padding` (`circuit_io.rs:194-197`; `L/docs/benchmarks/cycle_bench.md:104`), so the number of private accounts and the note sizes can be made uniform.

## 2. F8 audit of the current program and reference consumers

Current path: a **public** tx `Claim` → chained `Attest` to `PDA(attest, header_seed(instance, block_hash))` → `AttestReply` → `Nullify` to `PDA(consumer, H("rfp021/nullifier/v2" ‖ vault_id ‖ statement_id))` (per vault since D-CON-3) holding `Credit{vault_id, statement_id, eth_sender, amount}` (`crates/consumers/src/lib.rs`, `crates/attest-program/src/program.rs:179-215`).

Running the same path from a private actor works mechanically, because private-to-public calls exist. It leaks the same facts, though, because the `AttestRequest` and `AttestReply` cross the boundary in plaintext.

### Leak table

"Added by" says who introduces the signal: **A** = the attestation path (our program or its required usage), **C** = the consumer's design, **I** = inherent to LEZ or to the chosen tx type.

| # | Signal (event or state diff) | Current public path | Private path, naive (private consumer calls `Attest`) | Proposed private path (section 3) | Added by |
|---|---|---|---|---|---|
| 1 | Consuming LEZ account: tx signer and nonce | Revealed | Hidden (private root, private payer) | Hidden | I (public tx type) |
| 2 | Fee payer identity | Revealed (public payer) | Hidden if payer is private (`FeeOnly`) | Hidden | I |
| 3 | Root `Claim` message (block hash, receipt, tx and log index, amount) | Public tx body | Hidden (private root) | Hidden | C |
| 4 | Header PDA touched, which reveals the **Ethereum block** | Account list of the tx | `public_context.actors` | Not touched. Only a root PDA shared by all claims built at the same time | **A** |
| 5 | `AttestRequest` bytes (locator, receipt, MPT proof, preds, `ctx` with vault, amount and anchor) | Re-derivable by re-executing the public tx | `boundary` plaintext | Not sent. Verification runs inside the private transition | **A** (request shape) + C (`ctx` contents) |
| 6 | `AttestReply` (full `Fact`, `Statement.id`, `ctx`) | Re-derivable | `boundary` plaintext | Not sent | **A** |
| 7 | `Attested` event (root-call Attest) | Emitted with the full reply (`program.rs:213`) | n/a | n/a | A: deliberate public "record" path. The caller opts in |
| 8 | Nullifier PDA `H(statement_id)` | Created. `statement_id` is a public function of Ethereum data, so anyone maps nullifier ↔ deposit | Same | Replaced by `N = sha256("rfp021/pnf/v2" ‖ nk)`, with `nk` secret and committed on Ethereum (global per consumer program, D-PRIV-3) | C, but the current guidance (CONSUMER-GUIDE §uniqueness) tells consumers to do it, so **A (guidance)** |
| 9 | `Credit` contents (`eth_sender`, `amount`, `statement_id`) in the nullifier account | Public state | Public state | Nullifier account is empty. Credit lives in the claimant's private account | C |
| 10 | Vault counters `credited_total`, `claims` | Public state diff | Public state diff | Not written by the private path | C |
| 11 | Sender identity on the boundary | n/a | Private account id if `Canonical` | `Blinded` with a fresh factor per tx (MUST) | I (prover choice) |
| 12 | Consumer program id | Public | Disclosed via sender `Actor.program_account_id` and the touched vault PDA | Same: which consumer, not which account | C/I (accepted: it identifies the application, not the user) |
| 13 | Instance id, headers root | Via header PDA | Via header PDA | One root PDA per accepted header, shared by every claim built while it is current. The wallet MUST use the latest root (an old root bounds the deposit block) | A (residual: coarse time, about one finalized header per epoch, already implied by tx inclusion time) |
| 14 | Fee amount, which tracks public cycles (receipt size, trie depth fingerprint the Ethereum tx) | Revealed. Attest gas is the metered cycles (0.09-0.28M without ancestry, up to 7.1M with it; docs/BENCHMARKS.md section 1) and varies with the receipt and ancestry depth | Private tx: fixed verification gas plus public-effect cycles, but Attest's request still crosses the boundary (row 5) | Independent of the receipt: private txs pay fixed verification gas plus the public part's cycles and storage gas (section 1 "Fees"). The fee transfer itself is public (section 6) | **A** in public and naive; removed |
| 15 | Number of private accounts, note sizes | n/a | Varies | Pad (7 slots, `ciphertext_padding`) | I |
| 16 | Timing: LEZ inclusion vs Ethereum deposit | Revealed | Revealed | Revealed | I. Consumer's job (delay, fixed denominations), RFP "What the attestation does not do" |
| 17 | Validity windows | Attest sets none (only `Init`, `Update` and the fallback `UpdateBegin` do) | None | None | none |

Conclusions:
- The public path cannot meet F8 at all (row 1), which is consistent with the RFP: privacy needs the private path.
- The attestation path itself adds rows 4, 5, 6, 8 (through guidance) and 14. Rows 9 and 10 are faults of the reference consumer.
- Front-running of a public claim was fixed: `Claim` has no caller-chosen beneficiary, and the credit lands on the `from` topic of the attested Transfer (D-CON-1). The private path binds the claim to the commitment (section 3).

## 3. Minimal change: private consumption

### 3.1 Principle

Run verification **inside** the private consumer's transition as a library call, not as a chained call into the attest program. The only public effects are three:
- one read-only check that the header the consumer verified against is in the instance's verified set, without naming the header;
- one unlinkable nullifier;
- nothing else.

The verified statement never leaves the private transition. Its "public inputs" are what the consumer publishes: the instance and root (shared), the vault and config hash (application constants), and the nullifier (random-looking).

### 3.2 Program changes (attest-program, new image)

1. Single verification core (RFP-020 pattern). Move the body of `attest()` (`program.rs:179-210`: header bind, locator/proof match, `Fact` build, `inclusion::attest`) into a feature-free `pub fn verify(rec: &HeaderRecord, req: &AttestRequest) -> Result<Statement, u16>` in `attest-program/src/lib.rs`. The public `Msg::Attest` handler becomes decode + `verify` + reply/event. The private consumer calls the same `verify`. One audit surface, one cycle profile.
2. Header accumulator. Add `headers: Frontier { leaves: u64, nodes: [[u8;32]; 20] }` (an incremental sha256 Merkle tree, depth 20 ≈ 1M headers, about 650 B) to `InstanceState`.
   - Leaf = `sha256("rfp021/hleaf" ‖ borsh(HeaderRecord))`.
   - Append in `Init` and in `Apply`, only when `finalized_header.slot` grows.
   - Each append also sends `WriteRoot{instance_id, root}` to `PDA(attest, sha256("rfp021/hroot" ‖ instance_id ‖ root))`. That PDA is write-once and immutable, like `WriteHeader`.
3. `Msg::CheckRoot{instance_id, root}` at the root PDA: fail (1101) if the PDA is empty, otherwise `keep_state`, no reply, no event.
   - Root PDAs never expire. A private tx proven against root R stays valid however many headers land before inclusion (R11).
   - No shared mutable account is touched, so any number of private claims fit in one block (R11).

Cost on the public update path: `Apply` gains 20 sha256 compressions (well under 0.1M cycles) and one extra chained PDA write. `Verify` is 5.6-6.7M today against a 10M cap. Changing the program means a **new image id and redeploy** (decision D-ATT-8).

### 3.3 Uniqueness without linkage (consumer side, documented by us)

- Any nullifier that is a public function of the Ethereum fact, including `statement_id`, links the claim to the deposit (row 8).
- A LEZ private PDA is not globally unique (section 1).
- So an unlinkable, globally unique nullifier needs **a secret bound to the deposit on Ethereum**. This is the Tornado-style note:
  - The depositor picks `nk` and deposits through a contract that emits `Deposit(bytes32 indexed C, uint256 amount)` with `C = sha256("rfp021/commit" ‖ nk)`. A storage slot `commitments[C] = amount` works equally well, through `Locator::Storage`.
  - The claim publishes `N = sha256("rfp021/pnf/v2" ‖ nk)` as a public PDA of the consumer program.
  - v2, not v1. The first version was `sha256("rfp021/pnf/v1" ‖ vault_id ‖ nk)`. Because `InitPrivateVault` is permissionless, the same deposit could then be credited once per vault with a matching config (test `same_deposit_via_second_vault_is_1250` fails on v1). v2 drops `vault_id`, so a deposit is spent at most once across all private vaults of the consumer program (D-PRIV-3). Privacy is unchanged: `N` still depends only on the secret `nk`, and `vault_id` was already public in `RedeemCheck`. Constraint: one `nk` per deposit.
- A plain ERC-20 `Transfer` to a fixed vault has no room for `C`. Such deposits cannot be claimed both privately and unlinkably (decision D-PRIV-1; this aligns with RFP-022's fixed-denomination pool).
- `statement_id` stays the uniqueness key for the **public** path only. The CONSUMER-GUIDE must say so.

### 3.4 Private claim flow

The root call is private: `Actor(claimant private account, consumer program)`, `PrivateClaim{vault_cfg, header_rec, header_path, attest_req, nk}`, authorized by the claimant's key. Fees come from a private payer.

1. Check `sha256(borsh(vault_cfg))` matches the vault's (step 4 below), and `header_rec.instance_id == vault_cfg.instance_id`.
2. `root = merkle_root(leaf(header_rec), header_path)`. `stmt = attest_program::verify(&header_rec, &attest_req)` with the consumer's predicates:
   - log address == `cfg.deposit_contract`;
   - topic0 == the `Deposit` selector;
   - topic1 == `sha256("rfp021/commit" ‖ nk)`;
   - data word 0 == `cfg.denomination`.
3. Set the claimant's private actor state to `balance += denomination`. This produces a new commitment plus an encrypted note; nothing is visible.
4. Send one sync message to the public vault PDA: `RedeemCheck{vault_id, cfg_hash, root, nullifier: N}`, sender `Blinded`. The vault actor:
   - checks `cfg_hash` against its own state;
   - chains `CheckRoot{instance_id, root}` to the attest root PDA;
   - creates `PDA(consumer, N)` with empty or one-byte state (fails with 1250 if it exists);
   - does `keep_state` (no counters).

Public diff of the whole tx:
- nullifier and commitment of the claimant's account;
- one new empty PDA `N`;
- boundary: `RedeemCheck` (vault_id, cfg_hash, root, N) and the chained `CheckRoot` (public to public, not on the boundary but re-derivable: same data);
- `public_context.actors` = {vault PDA, root PDA, N PDA};
- fee refund target, if any;
- no events.

None of these depends on which deposit or which account, except through the consumer's own denomination and timing (rows 12, 13, 16).

### 3.5 Cycles and proving (pre-implementation estimate; measured values in sections 5-6 and [BENCHMARKS.md](BENCHMARKS.md))

- Private transition: the same as `Attest` today, 0.60-2.2M cycles (RFP Performance #1, `cycle_table`). Add about 20 sha256 for the header path and a few for `C`/`N`, under 0.05M. Total ≈ 0.65-2.25M.
- Public part: constant and small, about the current `Claim` minus `Attest` and well under 1M. The fee becomes uniform.
- Prover time (P4): LEZ's bench gives about 73 µs per total cycle with po2 bucketing, and 25 s for a padded PPE native transfer on an M2 Pro without GPU (`L/docs/benchmarks/cycle_bench.md:85-104`). Extrapolated: about 25 s + (0.65-2.25M × 73 µs) ≈ **70 s - 3 min** on an M2 Pro CPU, proof about 225 KB. Must be measured (P4). Measured later: 423 s for the real LEZ privacy proof of the claim on an M2 Max CPU, including test overhead (docs/BENCHMARKS.md section 3), so this extrapolation was optimistic.

## 4. Reference private ERC-20 claim: what the tests assert

The reference consumer (`crates/consumers`, tests in `crates/program-tests/tests/private.rs`) claims a `Deposit(C, amount)` event from the reference deposit contract as a LEZ privacy-preserving transaction with dev-mode proofs. The fixture is synthetic: one receipt with a `Deposit(C, denom)` log, a real header JSON with `receiptsRoot` replaced, and an `InstanceState` whose frontier contains the header leaf. The claimant is proven with `lee::privacy_preserving_transaction::circuit::execute_and_prove`, public actors are {vault PDA, root PDA, `N` PDA}, and the result is settled with `transition_from_privacy_preserving_transaction`. The tests assert:

- (a) the claimant's private balance increases by the denomination (the note is decrypted);
- (b) the journal's `public_context.actors` and the state diff contain neither the header PDA, the `statement_id`, `H(statement_id)`, `block_hash`, the claimant account id, nor `C` (byte search);
- (c) events are empty;
- (d) replaying the same `nk` fails with 1250;
- (e) an unknown root fails with 1101 and no private action applies;
- (f) two claims with different `nk` proven against the same root settle in one block in either order;
- (g) a wrong `nk` (`C` mismatch) fails with 1203 before proving.

Not covered by these tests: a real Ethereum deposit contract (see section 6), real-proof timing (see [BENCHMARKS.md](BENCHMARKS.md) section 3), wallet integration, and withdrawing the private balance (RFP-022).

## 5. Prototype status (first prototype, commit `aad20e6`, dev mode)

Implementation notes:
- No separate guest binary: the private path (`InitPrivateVault`, `PrivateClaim`, `RedeemCheck`, `Spend`) lives in the `erc20_receiver` image (`crates/consumers/src/lib.rs`). `eth_receiver` refuses `InitPrivateVault`.
- Fresh claimant account. The claimant's private account is created by the claim (`NullifierWitness::Init`) instead of a pre-funded one, because `lee`'s `test-utils` feature does not compile in release builds and the tests run with `--release`.
- Nullifier PDA write. The vault chains `Spend{vault_id, nullifier}` to `PDA(consumer, N)` (state `[1]`, since D-CON-3 `[0xA4]`; 1250 if present). `RedeemCheck` is accepted only from an actor of the consumer program, so a public `RedeemCheck` copied from a pending tx cannot burn `N` (1001).
- Unknown root. Without admission evidence, LEZ refuses the non-existent root PDA before `CheckRoot` runs ("Program violated execution rules"); with evidence, `CheckRoot` returns 1101. Both leave state untouched.
- `Apply` appends only when `finalized_header.slot` grows; `WriteHeader` behaviour is unchanged.

Tests: `crates/program-tests/tests/private.rs` (8 tests, assertions a-g of section 4, plus the shared-core check and a mempool-griefing check). Existing executor tests still pass on the new image.

Leak table after the change (private claim, measured on the serialized tx and the applied diff):

| Public item | Value | Linkable to deposit/block/account? |
|---|---|---|
| `public_context.actors` | {vault PDA, root PDA, `N` PDA} | No (application constant, shared root, random-looking `N`) |
| State diff | one new account `PDA(consumer, N)` = `[1]` | No |
| Boundary | one `PrivateToPublic` `RedeemCheck{vault_id, cfg_hash, root, N}`, sender blinded | Root: coarse time only (row 13) |
| `public_root` | none (private root call) | - |
| Events | none | - |
| Byte search | absent: block hash, header PDA, header leaf, `statement_id`, `H(statement_id)`, public-path nullifier PDA, claimant account id, `C`, `nk`, receipt bytes | - |
| Fee basis | fixed private-tx verification gas plus the public part's cycles (49,581; the public part does not see the Ethereum receipt) and storage gas (section 1) | No (row 14 removed) |

Cycles (dev mode, synthetic one-log receipt, software keccak, prototype code at `aad20e6`): private transition about 471K (`PrivateClaim` run as a public root call, 520,550, minus the public part); public part 49,581. With the keccak coprocessor (D-ATT-7) the private transition is ≈119.5K. Init and UpdateVerify re-measured in `cycle_table` (Init 2.96M, UpdateVerify with header write 5.73M; both under 10M).

Gaps in that first prototype, since closed: the relayer and `program-e2e` now declare the root PDA (D-CLI-1); a real deposit contract, a private fee payer and slot padding are used in the live run (section 6). Still open: withdrawal of the private balance (RFP-022).

## 6. Live run (dev-mode proofs)

Final run (2026-11-10, development commit `c380d4b`, v2 nullifier). Details, tx hashes and the byte scan: "Private claim" in
[evidence/rfp021-final-run.md](../evidence/rfp021-final-run.md) section 1, which also lists the ImageIDs of the final guests.
An earlier release-candidate run (2026-11-04) is summarised in section 3 of that file.
- Deposit source: `contracts/DepositVault.sol` on Sepolia (`0x179360c68dd8099fb3b862d8271ed37398f4ef43`),
  `Deposit(bytes32 indexed commitment, uint256 amount)`, `C = commit(nk)`. No withdrawal (RFP-022).
- Claim: deposit D1 (Sepolia block 12,101,233, not a checkpoint block) claimed through 3 ancestry headers to a
  relayer-recorded header (leaf 3 of 9), as a LEZ privacy-preserving tx through the wallet's PP path (LEZ block 278, padded to
  7 private actions, private fee payer, blinded senders). `PrivateClaim` carries `ancestry`, passed into the shared `verify` (bound
  `MAX_ANCESTRY` = 448).
- Replay and double credit, all refused:
  - the same `nk` proven concurrently by a second private account: reverted by the sequencer in the same block;
  - the same `nk` after inclusion: the wallet's simulation refuses with 1250;
  - the same deposit through a second private vault with the same config (the v1 double-credit path): refused with 1250,
    because `pnf(nk)` is already spent (D-PRIV-3).
- Public footprint of the claim tx (31,905 B): public actors = vault PDA, fee inbox, `N` PDA and root PDA;
  boundary = `RedeemCheck{vault_id, cfg_hash, root, N}` plus a 17-byte fee message, both from blinded senders; state
  diff = `N` PDA empty → `a4` (the spent tag); no events; no `public_root`. This is the section 5 table plus what fees add (fee inbox, the
  fee crossing, one recovery binding). The private-tx fee is fixed verification gas plus the public part's cycles and storage gas (section 1); none of these
  depends on the receipt, so it does not fingerprint it, but it is public.
- Byte scan of the tx found none of: deposit block hash, its header PDA, anchor block hash/PDA/leaf, `statement_id`,
  `H(statement_id)`, both claimant ids, `C`, `nk`, receipt bytes, deposit contract address.
- Remaining: live run with real proofs; a reverted claim still pays its fee (LEZ fee fallback); the Ethereum deposit
  itself is public (the EIP-7708 Transfer log names the depositor), so unlinkability rests on the anonymity set of
  equal-denomination deposits and on timing (row 16).

## Decisions (accepted 2026-11-04)

- D-ATT-8: Accept a new attest-program image (accumulator plus root PDAs). Without it, the private path must touch the per-block header PDA and leak the Ethereum block (row 4).
- D-PRIV-1: The reference private consumer claims `Deposit(commitment)` events, not raw ERC-20 `Transfer`s. A raw `Transfer` cannot be claimed unlinkably (section 3.3).
