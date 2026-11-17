# Trust assumptions

Scope: what a consumer of this attestation primitive relies on. Covers RFP Supportability #6, Verification Security #4 and #5. Status: dev-mode prototype run on a local LEZ v0.4.0-rc1 sequencer against live Sepolia ([evidence/rfp021-final-run.md](../evidence/rfp021-final-run.md)); nothing here describes a deployed system. Items marked "not yet" are not implemented.

## 1. The trust model in one paragraph

The LEZ program tracks Ethereum through the Altair light-client protocol. It starts from a checkpoint fixed at instance creation, then accepts an update only if (a) its merkle branches verify, (b) at least 342 of the 512 sync-committee members signed (`min_participation`, `crates/lc-core/src/lib.rs`), and (c) the BLS aggregate verifies against the committee the program itself stored. Nobody off-chain is trusted for validity, provided the proofs are real: in the recorded runs the LEZ sequencer ran in dev mode (`RISC0_DEV_MODE=1`), which does not check proofs, so there the sequencer was trusted for execution validity (section 7). Off-chain parties supply data and pay gas; if they lie, the program rejects the update. Safety rests on two things: the honest-supermajority assumption (section 2) and a correct checkpoint (section 3).

## 2. Honest sync-committee supermajority

Assumption. At every point where the instance accepts a header, fewer than 342 of the 512 members of the signing committee are willing to sign a header that is not on the canonical finalised chain. Equivalently: at least 171 members (more than one third) of any signing committee must be honest, or merely unwilling to sign something false.

What a violation admits. A quorum of 342 can sign any `attested_header` whose state contains any `finalized_header`, `next_sync_committee` and execution commitments they choose. The program cannot tell this from the real thing. They can therefore (1) make the instance record a fake finalized header, so inclusion proofs for events that never happened verify, and (2) hand off to a committee they control, which keeps the instance captured permanently (until replaced under F10). Attestations already produced stay "valid" in the sense of R3, which is also why a captured instance's earlier statements cannot be told apart from forged ones after the fact.

**What the attack costs, stated precisely.**

- *Slashing: none for this offence.* The Altair `process_sync_aggregate` (consensus-specs, `specs/altair/beacon-chain.md`, read 2026-11-04) has one consequence for a committee member: if its bit is set it earns `participant_reward`; if not set it is debited the same `participant_reward`. There is no slashing condition for signing a wrong sync-committee message; the only slashing conditions in that spec are proposer slashing and attester slashing. Signing a fake header with the sync-committee key is therefore not slashable by itself. Stake behind the keys (342 x 32 ETH = 10,944 ETH at the 32 ETH level; post-Electra effective balances can be larger, and selection is weighted by effective balance) is a measure of how much stake the colluding keys represent, **not** an amount that is forfeited. This is the key difference from attestation slashing and it makes the attack cheaper than "342 validators' stake at risk" suggests.
- *Reputational/social cost:* a fake header that is then used to steal from a bridge would be public evidence of which keys signed it, and the community could respond socially or by a fork. That is not an on-chain penalty and is not quantified here.
- *Cost of getting 342 keys into one committee.* The committee is a stake-weighted random sample of the active validator set. If an adversary holds fraction p of the sampled stake and each seat were independent, the chance that one committee has at least 342 adversarial seats is (computed with an exact binomial, n=512; the real sampling is not exactly independent):

| adversary share p | P(>=342 of 512 seats) per committee |
|---|---|
| 1/3 | 8e-54 |
| 0.5 | 1.2e-14 |
| 0.6 | 8.9e-4 (about one committee in 1,100; a committee lasts about 27.3 h) |
| 2/3 | 0.50 |

  So random selection alone does not hand a minority a quorum; an attacker needs a large majority of staked ETH, or must **corrupt or bribe the specific members after the committee is known**. A committee is known one period ahead (the `next_sync_committee` is in the beacon state), so targeting 342 known members is the realistic route. Its cost is the price of 342 operators' cooperation or key compromise, which this repo cannot price. We have no measured number for it and do not claim one.
- *Blast radius.* Forged signatures work against every instance of the same chain and every consumer of those instances at once; instances do not isolate this risk.

Conclusion for consumers: treat the primitive as weaker than Ethereum economic finality. Bound exposure per section 8.

## 3. Weak-subjectivity checkpoint

What it is. `Init` takes `trusted_block_root` and a `LightClientBootstrap` and checks the committee against that root (`lc_core::bootstrap`; vectors `bootstrap_checkpoint_mismatch`, `bootstrap_committee_branch_tampered` reject mismatches). The root, the chain id, `genesis_validators_root`, fork schedule and `ws_period_epochs` are then written to the instance and no instruction changes them (`Msg` in `crates/attest-program/src/lib.rs` has no setter).

Who supplies it. Whoever calls `Init`; `Init` is permissionless and unprivileged. There is no registry. The caller cannot pick the id: `Init` accepts only `instance_id = sha256("rfp021/instance-id" ‖ borsh(InstanceConfig) ‖ trusted_block_root)` (`attest_program::instance_id`; `borsh(InstanceConfig)` = `borsh(ChainConfig) ‖ genesis_time`), else 1001. So an id names exactly one (config, checkpoint) pair: nobody can occupy it with a weaker config, and a second `Init` of the same pair is 1106. The program also enforces a floor: `342 <= min_participation <= 512` and `ws_period_epochs <= 3_558` (the maximum of the Electra formula), else 1001 (test `init_binds_instance_id_to_config_and_enforces_floor`). A consumer pins one `instance_id` (and checks the reply comes from that instance's header PDA, see CONSUMER-GUIDE.md), so the consumer's trust in the checkpoint and config is a trust in that choice.

How anyone verifies it independently. The Logos core-module call for this (F9) does not exist yet. Manual procedure, using only public sources:
0. Read the instance PDA's `InstanceState.cfg` and recompute `instance_id(cfg, trusted_block_root)`; it must equal the id you pin. Then check **every** config field, since all of them are bound into the id:
   - `chain.chain_id` and `chain.genesis_validators_root`: the published values for the chain (step 5).
   - `chain.fork_versions`: every (epoch, version) pair equals the chain's published fork schedule (client configs, e.g. `config.yaml` of the network), ascending, no extra or missing entry.
   - `chain.electra_fork_epoch`, `chain.gloas_fork_epoch`: the chain's Electra / Gloas activation epochs (`u64::MAX` if Gloas is not scheduled).
   - `chain.min_participation`: 342 unless you deliberately want more (the program refuses less).
   - `chain.ws_period_epochs`: recompute with `lc_core::compute_ws_period_epochs(total active balance)` from current stake; a larger value widens the window in which a stale checkpoint is accepted.
   - `genesis_time`: the chain's beacon genesis time (`/eth/v1/beacon/genesis`); it ties `now_slot` to LEZ block time.
   - `trusted_block_root`: the checkpoint itself, steps 1-4.
1. Read the instance's stored `trusted` header: `finalized_header.beacon.slot` and its hash-tree root, and `genesis_validators_root` / `chain_id`.
2. Query at least two independent beacon APIs (different operators) for the block root at that slot (`/eth/v1/beacon/headers/<slot>`); the roots must match, and the block must be in the finalized chain (`/eth/v1/beacon/states/head/finality_checkpoints` shows a later finalized epoch).
3. Compare the stored committee to `/eth/v1/beacon/light_client/bootstrap/<root>` from two providers.
4. Optionally compare the root with a block explorer or a weak-subjectivity checkpoint published by a client team.
5. Check `genesis_validators_root` against the published value for the chain.
Independence is as good as the number of unrelated sources you can reach. Fixtures in this repo (`fixtures/`) were fetched from public lodestar/publicnode endpoints on 2026-11-04 (D-LC-3).

Staleness. An update or bootstrap older than `ws_period_epochs` is refused with 1105 (`check_not_stale`). The period is computed with the consensus-specs Electra weak-subjectivity formula from the current validator set: 279 epochs (~29.8 h) for Sepolia and 3,537 epochs (~15.7 days) for mainnet at the time of writing (D-LC-6 in [DECISIONS.md](DECISIONS.md)). It is fixed per instance at Init; an operator initialising a new instance should recompute it from current stake. An instance past its limit is replaced, not refreshed (F10; CONSUMER-GUIDE.md). Time is tied to the chain through `now_slot`, accepted only if the LEZ block time is within 120 s of that slot (`NOW_TOLERANCE_MS`).

## 4. What an attestation proves and does not prove

Proves (given section 2 and 3): the named execution block, identified by `execution_block_hash`, is the one referenced by a finalised beacon header on the chain the instance is configured for; the claimed account / slot / receipt log is in that block's state or receipts under the keccak-checked header; and the consumer's predicates hold of that value. The Statement is bound to `chain_id` and `genesis_validators_root`.

Does not prove:
- Gloas parent-block semantics. On Gloas the light-client header carries the bid's `parent_block_hash`, so `execution_block_hash` is the EL block that is the *parent* of the finalised beacon block (the latest EL block at that slot), not a payload carried in that block (D-LC-2). Consequences: a fact is about that parent block's post-state/receipts; latency is one block longer. It is a labelling difference, not a safety weakness, but a consumer that reasons about "the block at beacon slot S" must account for it.
- Not ordering or recency beyond finality. It says a fact was finalised, not when the LEZ side learned it.
- Not a statement about the predicate's meaning. The Statement id identifies the *fact* (`sha256("rfp021/fact/v1"‖...)`), not the predicate. Uniqueness is the consumer's job (nullifier).
- Not private on the public path. A public `Claim` reveals the block, the request and the nullifier `H(statement_id)`. The private path ([PRIVACY.md](PRIVACY.md)) hides them, but only for deposits that commit a secret on Ethereum (`C = commit(nk)`); the Ethereum deposit itself, the fee and timing stay public.
- Native ETH before Amsterdam: native-ETH facts rely on EIP-7708 transfer logs (the EIP-7708 decision in DECISIONS.md), which exist only from the Amsterdam activation; earlier blocks have none, so they cannot be attested.
- Not proof of correctness of this code. The code is unaudited (S8 milestone).

## 5. Off-chain participants

| Participant | Sees | Safety impact | Liveness impact | Notes |
|---|---|---|---|---|
| Relayer / operator | Public beacon data and its own LEZ gas account | None: updates are accepted on proof validity only; wrong data is rejected (vectors `update_*`, `fab_*`). | Can delay or not submit | Anyone may run one; "no party is obliged to operate". |
| Beacon API provider | Which periods/updates the operator requests (IP, timing) | None: responses are verified in-program against the stored committee | Can withhold or serve stale data | Operators may use several endpoints (`beacon_endpoints` list). |
| EL RPC provider (header, proofs, receipts), reached through the Logos `eth_rpc_module` | Which block/address/slot a user asks to prove, linked to their IP | None: the header is keccak-checked against the finalised hash, ancestry headers by parent-hash linkage, and every proof against its root (D-MOD-2) | Can refuse or serve proofs outside its window (publicnode's window was too short, see D-MOD-2) | Leaks user interest in a fact to the provider; `exec_proxy` (socks5h) can hide the IP. |
| Residue-witness prover (`witness.rs`, relayer-side) | Public pairing inputs only | None, see section 6 | A wrong or missing witness makes the update tx (the atomic `Update`; `UpdateVerify` only on the fallback above K=170) fail with 1102 | Typed 1102, no guest trap (D-ATT-4). |
| Consumer's user (Claim submitter) | Own data | None: the consumer program re-checks everything | Can fail to submit | - |
| LEZ sequencer | All public transactions | Can censor or reorder (outside this design) | Can block | LEZ-level assumption, not addressed here. |

Can the class block attestation forever? Each role is replaceable: any funded account can fetch public data and submit. Liveness fails only if every interested party declines to pay gas, if all beacon providers are unavailable, or if the LEZ sequencer censors. This is a liveness argument, not a measured guarantee. The program has no role or allowlist check. Two live runs had two relayers (op1, op2) and the module advance one instance; the updates came from three accounts (op1, op2 and the module's fresh random key). Protofire ran all of them, so the runs show that the flow works without an allowlist, not that unrelated third parties use it; the permissionless claim rests on the code. The final run is 2026-11-10; the earlier one is 2026-11-05 ([evidence/rfp021-final-run.md](../evidence/rfp021-final-run.md) sections 1 and 2).

## 6. Residue witness: why it is untrusted

The BLS check uses a final-exponentiation witness (Novakovic-Eagen, ePrint 2024/640) so that a complete update, pairing included, runs in one transaction at 6.4–7.0M cycles of LEZ's 10M per-action limit (at most 8.87M at K=170 non-signers; D-UPD-3 in [DECISIONS.md](DECISIONS.md), [evidence/rfp021-final-run.md](../evidence/rfp021-final-run.md)). The prover supplies `(c, s)` with `s` in Fp6; the kernel checks `f * s == c^lambda` with lambda = p - x. A math review in the project concluded that this implies `f^((p^12-1)/r) = 1` for **any** witness, so a malicious prover cannot make a false pairing pass; a wrong witness only fails the check. The 27th-root issue affects completeness only and is absorbed by `s` in Fp6. An implementation review against the Ethereum spec found one integration obligation, now handled: the kernel does not check non-signer membership, so the program derives the non-signer set from `sync_committee_bits` against the stored committee and requires each relayer hint to compress to the stored key at that index (D-ATT-2; tests in `non_signer_hints_are_bound_to_stored_keys`). Since then `residue::check` returns `false` instead of asserting, with identical accept conditions, so a wrong signature is the typed 1102 (D-ATT-4). Neither review is independent of the team; the kernel is in the external audit scope.

## 7. Conditions under which guarantees degrade or fail

| Condition | Effect |
|---|---|
| >= 342 committee seats collude or are compromised | Forged finalised headers accepted (section 2). Unbounded unless consumer caps. |
| Wrong checkpoint at `Init` (typo, malicious initialiser) | Whole instance follows the wrong chain; fixed forever. Replace the instance. |
| Instance not advanced for longer than `ws_period_epochs` | Further updates refused (1105). Existing recorded headers still verify (R7). Replace the instance. |
| Instance not advanced past a sync-committee period | Update from a too-new period is refused (1104); the missing period updates must be submitted in order. |
| Chain hard fork not in `ChainConfig` | 1003 / signature failures; new instance needed. |
| Ethereum non-finality | No new finalised headers; attestations stop being producible (liveness only). |
| BLS or inclusion code bug | Not covered: no audit yet (S8). |
| `ATTEST_PROGRAM` constant rebuilt wrong / dev key used | Consumers talk to the wrong program (CONSUMER-GUIDE.md). Current constant is a dev key. |
| Dev mode | On-chain evidence executes guests without proofs. Real proofs are measured separately (docs/BENCHMARKS.md); a real LEZ privacy proof of a private claim was produced and accepted once in a test. |

## 8. Bounding consumer exposure

The primitive cannot remove the section 2 risk; the consumer can limit what a forged statement can take. RFP-022 specifies caps and freeze authorities on the consumer side; this repo's reference consumers do **not** implement them (`VaultState` only tracks `credited_total` and `claims`). Recommended, not yet built:
- A per-window mint/credit cap and a global cap sized to what you can lose.
- A freeze authority (multisig) that can pause claims, with a delay before large claims finalise.
- Pin one `instance_id`; run a second independent instance only if you can reconcile disagreements.
- Prefer facts with an on-chain counterpart you can later cross-check.

## 9. RFP-022 bridge

Sections 1 to 8 describe the RFP-021 attestation primitive. This section summarises the trust model of the RFP-022 bridge built on it; the full text is in [ARCHITECTURE.md](ARCHITECTURE.md) section 3.1 (custody), 3.6 and 3.7, and in [../proposal/COVERAGE.md](../proposal/COVERAGE.md) Part B.2. Contract facts below are from `contracts/bridge/src/BridgeVault.sol` and `EcdsaRootVerifier.sol`.

**Inbound (Ethereum to LEZ) is trustless in the RFP-021 sense.** A deposit is minted against a header the attest program recorded after Ethereum finality, so it carries the assumptions of sections 2 and 3 and nothing more. In the recorded runs LEZ proofs were in dev mode, so there the sequencer was also trusted for execution validity (section 7).

**Outbound (LEZ to Ethereum) is interim and custodial, not trustless.**
- The vault accepts a LEZ burn root when `EcdsaRootVerifier` sees 2-of-2 secp256k1 signatures from two fixed keys, both held by Protofire. `TRUSTLESS()` on that verifier returns `false`. The signer set, threshold and verifier address are immutable; there is no rotation. If either key is lost, no new root is ever accepted: burns under already accepted roots still release, later burns and the remaining escrow are locked.
- Whoever holds both keys can sign a root that contains burns that never happened and release against it, for every token the vault holds. The loss is bounded only by the release delay, the per-window release caps and the freezer (loss formula in COVERAGE B.2). The signers cannot redirect or deanonymise an honest release: the recipient is inside the burn commitment.
- Both signers read the same LEZ sequencer, so they share one view of LEZ. Each acceptance names `lezHeight` and `lezBlockHash`, so replaying the sequencer's blocks can detect a forged root after the fact; the contract does not check them.
- **Outbound LEZ depth (`minLezDepth`) is enforced only by the signers.** The signers' software waits until the block that wrote the tree's last leaf is `minLezDepth` blocks old before it signs. The vault stores the value but never checks it, so signers that skip the wait are not stopped by the contract. A change to `minLezDepth` does not affect roots already accepted.
- The freezer can only pause, revoke and cancel; it cannot move funds.

**Freezer.** `FREEZER` is an immutable address set in the constructor; it must differ from the admin and there is no setter, so it cannot be replaced. It can pause deposits and releases separately, globally or per token (`setFrozen`, `setTokenFrozen`), revoke any burn root permanently, even after the delay has matured (`revokeRoot`; releases already made stay made), and cancel a queued loosening of a token config (`cancelTokenChange`). It cannot freeze one user. If the freezer key is lost, nobody can ever freeze or revoke, and a forged root is then bounded only by the delay and caps: the whole escrow of every token is at risk. If it is compromised, it can halt all deposits and releases and strand honest burns of a revoked tree, but it cannot take funds. The first-block loss bound assumes the freezer acts.

**Admin.** The admin lists tokens, sets fees, caps, `releaseDelay` (at most 7 days), denominations and `minLezDepth`. It cannot change the verifier, the Groth16 verifier, the image ID or a proven payout. A loosening (lower delay, higher cap) is queued for `max(releaseDelay, MIN_TIMELOCK)` and the freezer can cancel it. A tightening applies at once, so **the admin can lower a release or deposit cap to 0 immediately**. That halts releases (or deposits) for that token, and the freezer has no veto: it can only cancel queued changes, not immediate ones. Reversing the change is itself a loosening and waits out the timelock. A compromised admin can therefore deny service but cannot steal.

**Option O (committee-certified checkpoint).** In this option a verifier replaces the two Protofire signers with a check, inside a zk proof, that at least q of the N accredited LEZ sequencer committee keys (N ≥ 3, q = the channel's threshold) co-signed a finalised checkpoint of the burn roots, using the channel signing the committee already uses for zone withdrawals. The key set is tracked from a pinned genesis through threshold-signed configuration changes. Custody trust moves from our two keys to fewer than q of N committee keys being corrupt, the same trust Logos' own zone exit places in the committee; q colluding members can still have a bad root accepted. The vault checks `minLezDepth` itself, and our signer hosts become veto-only watchers (pause or revoke, never release). It is still not trustless, and it needs a new verifier and a new vault (the old vault keeps releasing its own burns). A trustless verifier needs a Bedrock (Cryptarchia) light client and a validity proof of LEZ execution; neither exists, and that is not part of this grant.
