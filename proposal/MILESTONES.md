# RFP-022 + RFP-021 milestones: deliverables and acceptance criteria

Companion to the proposal (filed as a GitHub issue in logos-co/rfp) and `proposal/COVERAGE.md` (requirement-by-requirement status, trust model, correlations, disclosures, sources). Total requested: $88,000 over 14 weeks, plus audit remediation: RFP-021 milestones M1–M6 ($29,000) and RFP-022 milestones B1–B5 ($59,000), run in one schedule. It delivers the hard requirements except those that cannot be met on today's Logos stack; these exceptions, listed under "Not met at final acceptance" in the issue body and `proposal/COVERAGE.md` §B.1, are RFP-022 F7 (trustless release), Sec6 (supply soundness) and the RFP's trust model, and R4 unless Logos accepts the B1 recovery criterion; these and every partial deviation are in "Deviations from the RFP requirements" below. Three optional add-ons are priced separately and are not in the requested total: X1 (RFP-021 soft requirements SR1 and SR4, $2,000), X2 (RFP-022 soft requirements 1–3, $4,000) and X3 (LEZ token-program integration, conditional, $4,000), $10,000 in all. Logos may fund any of them; none is needed for that coverage. Without X3, wrapped balances held by the bridge program, a documented deviation for 22-F3 and the LP-0013 token-program dependency. Optional milestone O (+$35,000) is gated and not in the total. The external audit is a separate line (allowance $64,000–74,000 for both RFPs in one engagement, from written auditor quotes), procured directly by Logos or, if Logos prefers, by Protofire at cost. Each milestone is paid on acceptance. A criterion counts as met when Logos reviewers can reproduce it from the repository at the milestone tag, using a command or document named in the criterion.

Requirement IDs. RFP-021 rows use RFP-021's IDs (F = Functionality, U = Usability, R = Reliability, P = Performance, S = Supportability, VS = Verification Security, SR = Soft Requirement). RFP-022 rows (B1–B5, X2, X3, O) use RFP-022's IDs prefixed `22-` (`22-F`, `22-U`, `22-R`, `22-P`, `22-Sup` = Supportability, `22-Sec` = Security, `22-PP` = Privacy Preservation, `22-Soft`). RFP-021 scope comes from the rows of `proposal/COVERAGE.md` Part A that are not marked Done (28 Done, 28 Partial, 5 Not yet, 3 Milestone, counted from its Status column), plus the owed tests of two Done rows (F13 in M1, R3 in M5); SR2, SR3 beyond the 448-header window and SR5 are outside this budget (see below). RFP-022 scope comes from the rows of `proposal/COVERAGE.md` §B.1 not marked Done, and from the deferred items assigned to B1–B5 below. Decision IDs (`D-…`, `B22-…`) refer to `docs/DECISIONS.md`.

| # | Milestone | RFP | Weeks | Payout |
|---|---|---|---|---|
| M1 | CI on GitHub, hardening | 021 | 1–2 | $3,000 |
| M2 | Real proving and cost measurement | 021 | 1–3 | $5,000 |
| M3 | Privacy path, real proofs | 021 | 2–4 | $6,000 |
| M4 | Logos module, CLI, catalog | 021 | 3–5 | $7,000 |
| M5 | Testnet 0.4 deployment, end-to-end | 021 | 5–7 | $4,000 |
| M6 | Audit remediation (RFP-021 scope) | 021 | report + 2 | $4,000 |
| B1 | Bridge contracts and program to full scope | 022 | 1–6 | $13,000 |
| B2 | Privacy path with real proofs, first-time users | 022 | 4–9 | $13,000 |
| B3 | Logos modules, daemons, mini-app, admin UI | 022 | 6–12 | $17,000 |
| B4 | Testnet, end-to-end CI, measurements, documentation | 022 | 11–14 | $10,500 |
| B5 | Audit remediation (RFP-022 scope) | 022 | report + 2 (with M6) | $5,500 |
| | **Total requested (M1–M6 + B1–B5)** | | **14 weeks + remediation** | **$88,000** |
| X1 | *Optional add-on:* RFP-021 soft requirements SR1, SR4 | 021 | 5–7 | $2,000 |
| X2 | *Optional add-on:* RFP-022 soft requirements 1–3 | 022 | 9–13 | $4,000 |
| X3 | *Optional add-on, conditional:* LEZ token program | 022 | 1–6 | $4,000 |
| O | *Optional, gated:* committee-certified checkpoint verifier (custody moves from two signers to q of N LEZ sequencer committee keys) | 022 | 4–14 | *+$35,000* |
| — | External audit, both RFPs (separate line; Logos may procure it directly) | both | lead time outside the 14 weeks | $64,000–74,000 allowance (written quotes) |

Shared work is done once: the M1 workflow also runs the bridge's executor and Foundry tests; the M4 catalog and release action also publish `bridge_module` and the mini-app (B3); M5 and B4 deploy to the same public testnet; one audit engagement, one remediation window (M6, B5).

## Deviations from the RFP requirements

Every requirement the bid does not fully meet at final acceptance, in one place. The first two rows are not met; the others are met in part or with a stated deviation. Rows that are open today but closed by a milestone (for example RFP-021 P5, re-measured in M2) are in `proposal/COVERAGE.md` and not repeated here.

| Requirement | What the RFP asks | What we deliver | Why | Milestone that changes it |
|---|---|---|---|---|
| 22-F7, 22-Sec6, RFP-022 trust model | Release verified natively on Ethereum, with no trusted party and backed supply | A real Groth16 membership proof at release, but burn roots are accepted by interim custodial 2-of-2 signers held by Protofire. The signers could forge a root and drain the escrow, bounded by the release delay, the caps and the freezer (`proposal/COVERAGE.md` §B.2). | LEZ has no finality or state-root primitive that Ethereum can verify today. | O moves custody to q of N LEZ sequencer committee keys, the trust Logos' own zone exit uses; still not trustless. Otherwise none. |
| 22-R4 | Claims never expire | A deposit is claimable while a recorded header covers it within 448 EL blocks; the client refuses to deposit while the attest instance lags more than 224 blocks. Without a recovery path, a deposit outside that window is lost. | The prototype has no backfill of headers between recorded ones and no refund path. | B1 recovery criterion, only if Logos accepts the mechanism. |
| 22-F3, LP-0013 dependency | Mint uniqueness keyed on the statement identifier; LP-0013 token authority | Private mint: uniqueness keyed on the nullifier `pnf(nk)`, not the statement id. Public mint (B1): keyed on `StatementId`, and tests show the two nullifier sets cannot double-mint one deposit. Wrapped balances move to the LEZ token program with ATA derivation only through X3; without X3 they stay bridge-program state. | A statement id in a private claim would link the deposit to the mint. X3 needs a v0.4 token program, which does not exist yet. | B1 (public path), X3 (token program; removable and conditional). Private-path keying: none. |
| 22-F11 | Global and per-token caps over a rolling window | Global caps on the vault and rolling-window caps on LEZ (B1). The vault's per-token deposit and release caps use a fixed window set at listing, so up to twice a cap can pass around a window boundary; the loss bound in `proposal/COVERAGE.md` §B.2 is computed for fixed windows. | The vault keeps one counter per token per window, and the window cannot change after listing, so the counters cannot be reset. | B1 for the global and LEZ caps. Vault per-token window: none. |
| 22-F12 | Admin-configurable finality depth before a claim and before a release | Inbound: Ethereum finality, plus admin-configurable extra depth (B1). Outbound: the vault stores `minLezDepth` but does not check it; only the custodial signers' software waits for that depth before it signs a root. | While roots are accepted on signatures, the vault has no view of LEZ block depth. | B1 (inbound depth), B4 (recommended defaults). Outbound check in the vault: only with O. |
| F9 (RFP-021) | Logos Ethereum core module exposes a checkpoint-verification API | M4 adds the call to our module (`eth_attest_module`): it compares an instance's checkpoint, committee, genesis validators root and config against at least two beacon sources. | The Ethereum core module is maintained by Logos; where the call lives is an open question for Logos. | M4 (in our module); upstream only if Logos prefers it. |
| Ethereum core module dependency (both RFPs) | Use the Logos Ethereum core module, including its verified proxy | Header and receipt reads go through `verified_proxy_module` (M5); `eth_getProof` stays on `eth_rpc_module`. | The verified proxy does not expose `eth_getProof`. | none until the proxy exposes it. |
| S8 (RFP-021), 22-Sec1 | Independent third-party security audit, report published | Audit scope, a frozen tag, remediation (M6, B5) and publication of the report with our notes. The audit itself is a separate line (allowance $64,000–74,000), outside the $88,000 total. | The auditor is chosen with Logos; Logos procures the audit directly or Protofire contracts it at cost. | M6 and B5, once the audit line is funded; without it, none. |
| S1 (RFP-021), 22-Sup1 | Deploy and test on public LEZ testnet 0.4 | The deployments and recorded runs on the public testnet once it runs v0.4; otherwise the same steps on a local v0.4 standalone sequencer, with $2,000 of M5 and $3,000 of B4 withheld until the testnet run. | The public LEZ testnet runs v0.3.x. | M5, B4 (conditional on the testnet upgrade). |
| 22-F10, 22-F14 | Admin authority per RFP-001, freeze authority per RFP-002 | The RFP-001/002 libraries if a release pinned to our LEZ version exists by week 4; otherwise in-program roles on the RFP-001 seat route, with the reason recorded in the decision log. | Availability of v0.4 releases of those libraries is not confirmed. | B1, if the libraries are released in time. |
| Licence (both RFPs) | All code released under the MIT and Apache-2.0 dual licence | The repository is "all rights reserved" and shared for evaluation of this proposal. On a grant award we release the code under MIT and Apache-2.0, as the program terms require for work produced under the grant. | The prototype was built before any award. | none; the commitment takes effect on award. |
| Soft requirements | Soft requirements listed in each RFP | Not offered: RFP-021 SR2 (batching), SR3 beyond the 448-header window, SR5 (operator incentive); RFP-022 Soft5 (common-wallet compatibility). RFP-021 SR1 and SR4 only through X1; RFP-022 Soft1, Soft2 and the LEZ-side part of Soft3 only through X2. | Outside this budget. | none; can be scoped separately. |

## RFP-021 (M1–M6)

Already built and not charged (evidence in `proposal/COVERAGE.md` Part A): light client, with every update kind, committee rotation included, in one transaction at 6.4–7.0M cycles typical, 8.5–8.9M in the worst case K=170 non-signers, all under the 10M limit (measured at sampled K including 170; cost grows monotonically with K) and the 2-tx split kept as fallback (F1, F2; rotation across the period 1405→1406 boundary done live on the local sequencer on 2026-11-06, one tx at 6.41M cycles; M5 repeats it on public testnet 0.4); gas per action, measured in the executor at `82bb54d` and live (P2 in part, `docs/BENCHMARKS.md` §1, §1a; formerly an M2 item); optional inline consumer (D-GAS-7); inclusion, ancestry ≤ 448 headers and predicates (F3, F4, F6 in part: log ids are value-complete, state-fact ids carry no value, see COVERAGE; the remainder is an M1 criterion); same-address chain binding test with Sepolia data on both sides (F5 in part; the mainnet-data repeat is M1); direct consumption (F7); config-bound instances and permissionless operation, live with no allowlist (F11, F13, VS6); multi-instance (F15); reference consumers (U6); typed errors including bad signatures (U5); standalone relayer daemon and module submit/read (U3 and U1 in part; module-driven lag detection is M4); SPEL-format IDL (U4 partly); host and guest adversarial suites (R1, VS1, VS2); replay, retry and contention handling (R2, R8, R10, and R9 in part: the client logs a reverted duplicate send as included, being fixed; the remainder is an M1 criterion); private claim prototype, live in dev mode (F8 in part; R11 in part: two different-`nk` claims against one root settle in either order in the executor, and two same-`nk` claims landed in one block live; only the live different-`nk` case is charged, as an M3 criterion); live latency breakdown (P5, from the superseded release-candidate run); trust, consumer and operator docs (S3–S6, VS4, VS5); decision log (S11).

### M1 — CI on GitHub, hardening ($3,000, weeks 1–2)

The F6 ids, the G1 subgroup check and the LP-0012 events below change the attest and consumer guests. Every ImageID published with this proposal, and every final-run figure, belongs to the prototype build; M1 publishes the new ImageIDs and re-runs the executor cycle table on the M1 build.

| Criterion | RFP IDs |
|---|---|
| GitHub Actions on the default branch runs host tests, host and guest vectors (89 vectors, 74 adversarial cases and 15 positive controls: 89/89 host; guest 84 PASS / 5 UNSUPPORTED / 0 MISMATCH / 0 PANIC or better), executor and private tests, the IDL check, and blocking `cargo fmt --check` and clippy. The latest default-branch run is green. | R12, S2 |
| The sequencer e2e workflow initialises from a freshly fetched checkpoint (not an aging fixture) and runs Init, an update, a claim and a rejected replay. A scheduled run against live Sepolia records at least one new HeaderRecord. | S2, R12 |
| Statement ids for account and storage facts are value-scoped: the same value at the same location under two finalised blocks yields one id, a different value a different id (tests for account, storage slot and absent account); log ids unchanged; the consumer guide and IDL are updated. | F6 |
| A negative test confirms that no `Msg` variant changes an initialised instance's config or checkpoint. | F13, F9 |
| The F5 test (same contract address, slot and log locator under a Sepolia and a mainnet instance give different statement ids, and a consumer bound to one chain rejects the other's) is repeated with a real mainnet fixture (block header, account proof and receipt) on the mainnet side. | F5 |
| A stalled instance is resumed by an operator account that never submitted to it before, with no manual repair and no gap in the handoff chain. | R7, F12 |
| Two relayers run against one instance on a live sequencer with forced contention (deferral window 0) until at least three updates were sent by both: each duplicate reverts 1106, nothing is double-applied, and the losing relayer logs its transaction as reverted, not included (log assertion in the test). The operator guide states the deferral window or leader rule for more than two operators. | R9, R8 |
| The attest program emits LP-0012 events for `Init`, each header recorded and each committee rotation (fields documented in the IDL); executor tests assert each event, and the relayer follows them instead of polling where the event suffices. | LP-0012 events dependency |
| The guest checks the aggregate sync-committee key for G1 subgroup membership before the pairing check (today only the infinity point is rejected and membership rests on deposit-time proof-of-possession, `docs/RESIDUE-SOUNDNESS.md` R-2); an executor test rejects an off-subgroup aggregate with a typed code. | F1, VS2 |
| New ImageIDs of the M1 build are published and reproduced with `scripts/image-ids.sh` on macOS and Linux; the executor cycle table is re-run on that build. | VS3, P1 |
| Fault-injection tests (endpoint errors, restart mid-job, sequencer unavailable) against a real sequencer show the relayer resumes from its last verified state without duplicate submission. | R4, R5 |
| The same workflow runs the bridge's executor tests (`cargo test -p bridge`, `program-tests --test bridge`) and `forge test` in `contracts/bridge`, green on the default branch. | R12, 22-R10 (unit part) |

### M2 — Real proving and cost measurement ($5,000, weeks 1–3)

| Criterion | RFP IDs |
|---|---|
| `docs/BENCHMARKS.md` reports, on the release code and a quiet machine, for `Init`, `Update` (and the `UpdateBegin`/`UpdateVerify` fallback), `Attest` (account, storage slot, receipt log, with and without ancestry) and both reference claims: proof time, proof size and peak RSS with real RISC0 proving, next to the cycles and LEZ gas units already measured. One documented command reproduces it. | P2 |
| Amortised per-attestation cost of tracking at the recommended cadence, separate from per-attestation verification cost, in gas units and, if a fee-charging v0.4 network exists by then, in tokens. | P3, S7 |
| Wall-clock time and peak memory of every user-side proof, including the private claim, measured on a mid-range laptop and on a device at the declared minimum specification (not extrapolated). | P4 |
| End-to-end attestation latency, from the Ethereum event to a verified statement usable on LEZ, re-measured on the release code for a public and a private claim and broken down by finality wait, update availability and on-chain verification. | P5 |
| CPU, RAM and time of the relayer and of the module's `submit_update`, including the residue-witness build. | P6 |
| Storage growth of instance, header, root, job and nullifier accounts projected over one and five years at the recommended cadence. | P7 |
| A test varies accumulated header and nullifier state across at least two orders of magnitude and shows no change in per-action cycles. | P9 |
| The in-program BLS vs precompile delta is stated as an upper bound, with the note that a precompile is reachable only from public transactions. | P8 |

### M3 — Privacy path, real proofs ($6,000, weeks 2–4)

| Criterion | RFP IDs |
|---|---|
| A private claim of a real Sepolia deposit settles on a LEZ v0.4 sequencer with real (non-dev) proofs; inclusion and predicate evaluation happen inside the private transition. | F8, F7 |
| A test over that transaction asserts the public footprint contains only the fields `docs/PRIVACY.md` allows (byte scan for block hash, header PDA, statement id, claimant, commitment, receipt). | F8 |
| Two private claims with different secrets, proven against the same root, settle in one block on a live sequencer. | R11 |
| The consumer guide documents what remains the consumer's job: fixed denominations, delays, fee and timing leaks, one secret per deposit (per RFP-022). | S3, S4 |

### M4 — Logos module, CLI, catalog ($7,000, weeks 3–5)

| Criterion | RFP IDs |
|---|---|
| Module `produce_attestation` builds material for any finalised block (ancestry to a recorded header), shown in a headless `logosctl` transcript. | U1 |
| The module detects instance lag against Ethereum's finalised head and submits the needed updates itself (no separate relayer binary), shown in a headless `logosctl` transcript against a live instance. | U3, U1 |
| The module exposes a checkpoint-verification call that compares an instance's stored checkpoint, committee, genesis validators root and config against at least two independent beacon sources and returns a verdict. RFP-021 F9 places this API in the Logos Ethereum core module; we deliver it in our module unless Logos prefers it upstream (question for Logos). | F9 |
| The CLI covers: produce an attestation for a `(chain, contract, slot or log, predicate)` tuple, dry-run verify with the same typed codes as the on-chain path (tested against the vector set), submit an update, and read instance configuration. | U2, U5 |
| A consumer is built from the published IDL (or from a client generated from it), and its claim succeeds on the sequencer. | U4, F7 |
| Module builds for aarch64-linux, x86_64-linux and darwin are released to a Protofire module catalog built from `logos-modules-release-base` using `logos-modules-release-action`. | S9, S10 |

### M5 — Testnet 0.4 deployment, end-to-end ($4,000, weeks 5–7)

Sync-committee rotation in one transaction already runs on the local sequencer; M5 shows it on public testnet 0.4.

| Criterion | RFP IDs |
|---|---|
| The attest program and both reference consumers are deployed immutable on LEZ testnet 0.4, attesting live Sepolia. A relayer advances the instance across at least one sync-committee rotation, and ERC-20 and native-ETH claims (plus rejected replays) are recorded with tx hashes. **Conditional:** the public testnet currently runs v0.3.x. If it is not on v0.4 by week 6, M5 is accepted on a local v0.4 standalone sequencer with the same steps, minus $2,000, which is paid when the testnet run is delivered (target: within 2 weeks of the upgrade). If the public testnet is not on v0.4 within 12 months of milestone acceptance, the withheld amount lapses. | S1, F1, F14 |
| A statement attested before two or more committee rotations still verifies afterwards. | R3 |
| A replacement instance is initialised and a reference consumer is migrated to it following the consumer guide (the migration drill that Disclosure 7 in `proposal/COVERAGE.md` calls for). | F10, F12 |
| Header and receipt reads in the module and relayer go through `verified_proxy_module`; `eth_getProof` stays on `eth_rpc_module` until the proxy exposes it, as documented in `docs/MODULE.md`. | Ethereum core module dependency |
| Core module, CLI, operator and trust-assumption docs are final and match the released code. | S3, S5, S6 |

SR1 and SR4 are in the optional add-on X1. Not in this budget: SR2 (batching), SR3 beyond the 448-header ancestry window (historical state), SR5 (operator incentive). We can scope them separately on request.

### M6 — Audit remediation ($4,000, 2 weeks from receipt of the audit report)

| Criterion | RFP IDs |
|---|---|
| Every finding is fixed, or accepted with a written rationale that Logos agrees to. The auditor confirms the fixes. | S8, R6 (our unaudited code, residue kernel included) |
| The audit report and our remediation notes are published in the repository. | S8 |
| ImageIDs of the audited program build are published and reproducible from the tagged source. | S8, VS3 |


## RFP-022 (B1–B5, optional O)

Already built and not charged (evidence in `evidence/rfp022-sepolia.md`; status per requirement in `proposal/COVERAGE.md` §B.1): `BridgeVault` with ERC-20 via `SafeERC20` (USDT-behaviour mock, 22-F17), native ETH, fixed denominations, repeated-commitment rejection, per-token caps, freeze per half, immutable verifiers (22-F1, 22-F2, 22-F8, 22-F14, 22-Sec8); private claim through RFP-021 `verify_ref` with nullifier `pnf(nk)` (22-F3, deviation documented); client deposit gate when the attest instance lags > 224 EL blocks; private two-transaction transfer; private burn with destination committed inside `B` (22-F5); per-(token, denomination) burn accumulator; release with a real Groth16 membership proof binding recipient, relayer and fee (22-F7 membership part, 22-Sec3); `CONFIG_ID` pairing in claim predicates, root digest and release journal (22-F15 except the zone id placeholder, 22-F16); release delay with loosening cap and delay changes queued behind max(current delay, `MIN_TIMELOCK`) and cancellable by the freezer, `MAX_DELAY` 7 days (22-Sec4 in part); recovery from the LEZ wallet mnemonic alone, shown on Sepolia in the final run (22-F9, 22-R5); early, replayed, revoked-root and frozen release/deposit refusals on Sepolia (22-R3, 22-Sec2 in part); leak scans of the round trip (22-PP1–PP3 in part); one real LEZ `Burn` proof (22-P4 in part). The interim 2-of-2 ECDSA root verifier is built and is **not** offered as meeting 22-F7 (see O).

### B1 — Bridge contracts and program to full scope ($13,000, weeks 1–6)

| Criterion | RFP IDs |
|---|---|
| Mint into a public LEZ account, and burn from one, each by explicit choice; the public mint path keys uniqueness on the RFP-021 `StatementId`. Executor tests show a public mint, a public burn, a replay refused (1250) and that the private and public nullifier sets cannot double-mint one deposit. | 22-F3, 22-F4, 22-F6, 22-R3 |
| Shield (public → private) and unshield (private → public) of wrapped balances, and public transfer, with supply unchanged; executor tests. | 22-F4, 22-F6 |
| A burn can name a custom Ethereum recipient; the recipient is stored in recoverable on-chain private state, and a wipe-and-recover test releases it from the seed alone. | 22-F5, 22-F9, 22-R5 |
| **Scope addition (same B1 price):** a deposit not covered by any recorded header within the 448-header ancestry window stays recoverable by its owner: either claimable on LEZ through a historical-root path (headers between recorded ones backfilled by ancestry proof), or refunded on Ethereum to a destination the depositor proves from the same seed, with the LEZ claim of that commitment then refused. The mechanism is agreed with Logos by week 3 and recorded in the decision log; an executor and Foundry test simulates a relayer outage longer than 448 blocks after a deposit, then recovers it, and a second recovery or claim of the same deposit is refused. | 22-R4, 22-Sec6 |
| Burn leaves keyed by commitment: two burns of the same (token, denomination) proven on the same state both land in one block (test). | 22-R3 |
| Global caps on the vault, rolling-window caps on LEZ through the clock program; Foundry and executor tests at window boundaries. The vault's existing per-token deposit and release caps keep their fixed window, set at listing (a stated deviation from 22-F11's rolling window). | 22-F11, 22-Sec4 |
| The LEZ bridge program emits LP-0012 events for registry, configuration and freeze changes, burn-root updates and public mint and burn (fields documented in the IDL); no event carries a field that links a private claim, transfer or burn to its deposit or destination (executor tests; included in the B2 leak scan). | LP-0012 events dependency |
| Admin-configurable extra inbound depth (blocks beyond Ethereum finality); a change does not invalidate a claim already valid (test). | 22-F12, 22-R4 |
| A configurable LEZ protocol fee on mint and on burn (the prototype fixes both at 0), collected so that one deposit can still be burned and released in full (for example out of `d` at release against a proven fee); fee routing to the configured destination, and an admin-selectable fee denomination (wrapped token or native LEZ), each fee a fixed value per (token, denomination); fee set to zero works (tests). | 22-F13 |
| `seen` deposit commitments keyed by (token, denomination, `C`), so a copied commitment under another pair cannot block a deposit (Foundry test). | 22-Sec2 |
| Admin and freeze through RFP-001/002 v0.4 libraries if a release pinned to the LEZ version we build against exists by week 4; otherwise the in-program roles on the RFP-001 seat route, with the reason recorded in the decision log. Registration rejects decimals that cannot be represented exactly; delisting keeps burns open (tests). | 22-F10, 22-F14, 22-Sec5 |

### B2 — Privacy path with real proofs, first-time users ($13,000, weeks 4–9)

| Criterion | RFP IDs |
|---|---|
| Claim, transfer (both transactions) and burn settle on a LEZ v0.4 sequencer with real (non-dev) proofs and proof checking on; transaction hashes recorded. | 22-Sec6, 22-P4 |
| A user whose fresh private account holds no native LEZ completes a claim through a relayer-funded fee note (or LEZ's sponsored private fees if they exist by then); what the relayer learns is documented and asserted in a test. | 22-PP6, 22-R9 |
| Tests show every private transaction padded to the fixed slot count and the fee refund going to the payer's bound alias, not to a public account. | 22-PP3, 22-PP4 |
| A rejected claim, a repeated claim and a cap rejection produce the same public footprint apart from the error code, and the code does not identify the deposit (test). | 22-PP5, 22-U8 |
| A full round trip's event and state diffs on both chains are scanned for every destination and linking identifier; the scan is a test. | 22-PP1–PP3 |
| A written check, with a test where possible, that the succinct receipt given to the Groth16 wrapper reveals no witness data. | 22-PP4, 22-PP6 |
| The release fee can pay gas dust to the fresh release address so a user can move an ERC-20 out of it without funding it from a known address. | 22-PP2 |
| Wall time and peak memory of every user-side proof (claim, burn, membership) on a mid-range laptop and on the declared minimum device. | 22-P4 |

### B3 — Logos modules, daemons, mini-app, admin UI ($17,000, weeks 6–12)

| Criterion | RFP IDs |
|---|---|
| `bridge_module` exposes deposit, claim, transfer, burn, release, recovery and registry read/administration; shown in a headless `logosctl` transcript. Ethereum access goes through the Logos Ethereum core module, headers and receipts via its verified proxy. | 22-U1, Ethereum core module dependency |
| Root-acceptance submitter, release relayer and fee relayer each run as a Logos module with a headless daemon: configurable finality depth, structured logs, clean shutdown; an RPC outage on either chain is resumed without duplicate work (fault-injection test). Operator journey documented. | 22-U3, 22-R6, 22-R9 |
| Mini-app (ui module) covers deposit, redemption, recovery and a registry view with permitted amounts, caps and utilisation; private destination, fixed denomination, delayed submission and a relayer are pre-selected; a leak indicator shows what the current choices reveal; RPC and sequencer are user-configurable. Admin UI covers registration, fees, caps, depth and freeze. Built on the LP-0021 wallet SDK if it is available by week 8; otherwise on our LEZ client, with the switch documented. | 22-U2, 22-U5–U7, 22-U9 |
| A user-side operation interrupted at each step (deposit sent but not recorded, claim proven but not submitted, burn submitted, release proven but not submitted) resumes from the client state or the seed without losing, duplicating or exposing the entitlement (client tests, one per step). | 22-R7 |
| SPEL IDL for the bridge program, generated from source with a drift check. | 22-U4 |
| Linux and macOS builds of every module released to the catalog from M4 with `logos-modules-release-action`. | 22-U10, 22-Sup2, 22-Sup3 |

### B4 — Testnet, end-to-end CI, measurements, documentation ($10,500, weeks 11–14)

| Criterion | RFP IDs |
|---|---|
| Vault on Sepolia and bridge program on public LEZ testnet 0.4; a recorded round trip (deposit, claim, transfer, burn, root acceptance, release) with transaction hashes. **Conditional:** if the public testnet is not on v0.4 by week 13, B4 is accepted on a local v0.4 standalone sequencer with the same steps, minus $3,000, paid when the testnet run is delivered (target: within 2 weeks of the upgrade). If the public testnet is not on v0.4 within 12 months of milestone acceptance, the withheld amount lapses. | 22-Sup1 |
| The full deposit-and-redemption round trip runs in CI against a standalone LEZ sequencer and an Ethereum fork. | 22-R10 |
| A requirement → test map with at least one test per hard requirement. | 22-R11 |
| Reports: claim compute by component (P1), any extra LEZ-side verification and its amortised cost (P2), Ethereum gas for deposit, root acceptance and release (P3), latency per direction broken down by finality wait, proving, privacy delay and verification (P5), off-chain component CPU/RAM/time (P6), state growth at 1M and 10M operations (P7). | 22-P1–P3, 22-P5–P7 |
| Recommended default finality depth for each direction, with the residual risk it leaves (final values; provisional ones are in `proposal/COVERAGE.md` §B.4). | 22-F12 |
| USDC, USDT, DAI and WETH registered on the Sepolia vault (the Sepolia deployments where they exist, otherwise behaviour-matching mocks, each named) with denominations, caps and fees; one deposit and claim per token recorded with tx hashes. | 22-F1 |
| `CONFIG_ID` binds the LEZ zone or chain identifier Logos names (Q3 in `proposal/COVERAGE.md` §B.5); tests show a claim, a burn root and a release built for another zone id are refused. | 22-F15 |
| Recommended cap defaults per token (deposit cap, release cap, window, release delay), with the reasoning and the loss bound they give; the deployer guide uses them. | 22-Sec4 |
| Migration mechanism for a new verifier or program version, including how in-flight deposits and burns are honoured, exercised once on Sepolia + local LEZ; failsafe specification meeting Sec9's constraints, or a documented reason why none should be built. The specification covers root-signer key loss: a signer-set rotation or a timelocked escape for unreleased burns, behind the freezer's veto, so a lost key cannot lock the escrow. | 22-Sec8, 22-Sec9, 22-Soft4 |
| User documentation of the trust model and the liveness-only role of off-chain participants; developer (both flows and recovery), operator and deployer journeys; correlation table final; design decision log current. | 22-Sec7, 22-R12–R14, 22-U7, 22-Sup4 |

### B5 — Audit remediation, RFP-022 scope ($5,500, 2 weeks from receipt of the audit report, with M6)

| Criterion | RFP IDs |
|---|---|
| Every finding in the vault, the root-verifier interface, the bridge program and the `burn_member` guest is fixed, or accepted with a written rationale that Logos agrees to. The auditor confirms the fixes. | 22-Sec1 |
| The audit report and our remediation notes are published in the repository. | 22-Sec1 |
| ImageIDs and contract bytecode of the audited build are published and reproducible from the tagged source. | 22-Sec1, 22-Sec8 |

## Optional add-ons (X1–X3)

The requested total ($88,000, M1–M6 and B1–B5) delivers the hard requirements except those that cannot be met on today's Logos stack; these exceptions (22-F7, 22-Sec6 and the RFP-022 trust model; 22-R4 unless Logos accepts the B1 recovery criterion) are listed under "Not met at final acceptance" in `proposal/COVERAGE.md` §B.1, and with every partial deviation in "Deviations from the RFP requirements" above. X1–X3 are optional add-ons: soft requirements and one conditional integration, each priced separately. Logos may fund any of them; none is needed for that coverage; without X3, wrapped balances stay bridge-held (a documented deviation for 22-F3 and the LP-0013 dependency).

### X1 — RFP-021 soft requirements SR1 and SR4 ($2,000, weeks 5–7)

| Criterion | RFP IDs |
|---|---|
| SR1: a recorded-statement path writes a verified statement to a public account. It calls the same verification core as the direct path, and its documentation states that readers trust the writer. | SR1 |
| SR4: one statement evaluates a compound predicate over at least two facts (for example, a balance and a storage slot) under one header. | SR4 |

### X2 — RFP-022 soft requirements 1–3 ($4,000, weeks 9–13)

| Criterion | RFP IDs |
|---|---|
| A migration path from fixed denominations to committed amounts is documented: how the vault, the bridge program and the accumulated anonymity sets carry over, and what a user sees during the switch. | 22-Soft1 |
| An optional viewing key, derived from the user's seed, lets a user voluntarily disclose their own deposits, claims, burns and releases to a chosen party; the client exports it and verifies a disclosure against chain data. Tests show the key reveals that user's activity and nothing about other users' deposits, notes or burns. The key is view-only: it is distinct from the spending secret `nk` and from `rk`, and gives no spend authority (it cannot authorise a claim, burn or release or change a fee); tests use it to try a claim of an unclaimed deposit, a burn of the user's note and a release of an unreleased burn, and all three are refused. Export and verification are client-side only, with no program or vault change and no protocol-level disclosure capability. | 22-Soft2 |
| Soft 3 as RFP-022 words it (a per-token delay before funds leave the vault) is already met in the base by the vault's `releaseDelay[token]` (admin-set, loosening changes timelocked, freezer-cancellable; 600 s on Sepolia) and is not charged here. X2 adds the LEZ-side equivalent: a per-token release delay on the LEZ side (wrapped burns wait a configurable delay before they enter a burn root), set by the admin, with loosening changes queued behind the current delay and cancellable by the freezer as on the vault; executor tests at the delay boundary and for a cancelled change. | 22-Soft3, 22-Sec4 |

### X3 — Conditional: wrapped balances on the LEZ token program ($4,000, weeks 1–6)

| Criterion | RFP IDs |
|---|---|
| **Conditional ($4,000):** wrapped balances held through the LEZ token program with ATA derivation, minted and burned under a bridge-PDA authority. If no v0.4 token program exists by week 6, B1 is accepted unchanged, X3 is deferred, the migration from bridge-held balances is documented, and X3 ($4,000) is paid when the integration is delivered (target: within 3 weeks of the token program's availability). If Logos drops X3, wrapped balances stay bridge-program state without ATA compatibility, a documented deviation for 22-F3 and the LP-0013 dependency. | 22-F3, LP-0013 dependency |

### O — Optional, gated: committee-certified checkpoint verifier (custody moves from two signers to q of N LEZ sequencer committee keys) (+$35,000, weeks 4–14)

Mechanism. At least q of the N accredited keys of the LEZ sequencer committee (N ≥ 3, q = the channel's threshold) co-sign a finalised checkpoint message with the channel-signing mechanism the committee already uses for zone withdrawals (`ChannelWithdrawOp`). The message carries the burn-accumulator root of each (token, denomination), the LEZ block id and hash, the Bedrock position at which that block is final, the channel id, the Bedrock network, the vault address and Ethereum chain id, and the previous checkpoint. We deliver an immutable `Checkpoint` instruction in the LEZ bridge program that computes the root from program state (a caller never supplies it); a RISC0 guest that verifies the q-of-N Ed25519 threshold against the committee key set, tracked from a pinned genesis configuration through threshold-signed configuration changes; and a Groth16 wrap to a new `IBurnRootVerifier` that replaces the interim root signers. The vault checks `minLezDepth` itself (22-F12 becomes a contract check) and keeps the release delay, caps and freezer. It keeps a ring of recently accepted roots; a release may use any accepted root, and the spent set is global, not per root. Our signer hosts become veto-only watchers: a watcher can pause releases or revoke a root that differs from the root it recomputes from Bedrock-final LEZ blocks, and cannot release.

Trust after O: fewer than q of the N committee keys corrupt, the same trust Logos' own zone exit places in the committee. O is not trustless; 22-F7, 22-Sec6 and the RFP trust model stay partly met at best. A trustless leg needs a Bedrock (Cryptarchia) light client and a validity proof of LEZ execution; neither exists today. We name it as future work and do not price it.

Gate: by the end of week 3, before any O money is spent, Logos confirms that (1) the committee will co-sign checkpoints through channel signing or an equivalent message, and (2) the target network runs N ≥ 3 committee members without dev-mode verification. If either is not confirmed, O is not started and not invoiced.

Why the earlier O (a verifier of one sequencer's inscription signature) is dropped. With a committee, one inscription signature lets any single member forge a root (1 of N), which is weaker than Logos' own exit. Inscription signatures of descendant blocks do not prove Bedrock finality: honest sequencers build on non-final Bedrock heads, so a root proven from an orphaned branch allows a double spend.

| Criterion | RFP IDs |
|---|---|
| Immutable `Checkpoint` instruction in the LEZ bridge program: it computes each (token, denomination) root and leaf count from program state; a call that supplies a root is rejected (test). | 22-F7, 22-Sec2 |
| A RISC0 guest verifies q-of-N Ed25519 signatures over the checkpoint message against the tracked committee key set; a configuration change is accepted only under the old threshold; signer key bytes must be distinct; block hashes are recomputed; parsing is canonical with full consumption of the input. Groth16-wrapped. | 22-F7, 22-Sec2 |
| A new `IBurnRootVerifier` implementation verifies that proof; a vault deployed against it checks `minLezDepth`, keeps a root-history ring and a global spent set (test: one burn under two accepted roots is released once), and releases a real burn on Sepolia. | 22-F7, 22-F12, 22-Sec6 |
| Forced-reorg test (Bedrock slow-finality settings): a checkpoint from the orphaned branch is rejected and the canonical checkpoint is accepted. | 22-Sec2, 22-Sec6 |
| A proof against a stale committee configuration is rejected after a rotation; a configuration with N < 3 is rejected. | 22-Sec2 |
| Cross-domain replay is rejected: another channel, Bedrock network, vault or Ethereum chain id. | 22-Sec2 |
| Watcher mode: a watcher key can pause and revoke a mismatched root and cannot release (tests). | 22-Sec5 |
| Release calldata reveals no burn leaf, index or path (byte scan in a test). | 22-PP1–PP3 |
| Gas of root acceptance and release, and proving time per checkpoint, measured and published. | 22-P3 |
| Migration from the interim ECDSA verifier exercised: the old vault stops deposits, drains its outstanding burns, new deposits go to the new configuration. | 22-Sec8 |

## External audit (separate line, not part of $88,000)

- One engagement for both RFPs.
- RFP-021 scope, everything we wrote rather than reused: light-client logic (`crates/lc-core`: sync rules, update validation, handoff, weak subjectivity); SSZ merkleisation; execution-header and ancestry decoding, RLP/MPT integration and predicates (`crates/inclusion`, including the keccak sponge over the RISC Zero coprocessor); the residue-witness BLS12-381 kernel and non-signer derivation (`crates/attest-program/src/residue.rs`, `bls.rs`, with the host witness builder for context); program integration (`crates/attest-program`: PDAs, instance-id binding and config floor, one-transaction `Update` and the 2-tx fallback split, header accumulator, `CheckRoot`, `CheckHeader`); reference consumers (`crates/consumers`: public and private nullifiers, private claim).
- RFP-022 scope: `contracts/bridge` (`BridgeVault`, `IBurnRootVerifier`, caps, roles, revocation, release); the LEZ bridge program (`crates/bridge`: message authentication, nullifiers, burn accumulator, caps, roles, fee accounting); the `burn_member` guest; derivations in `crates/bridge-core`. The interim `EcdsaRootVerifier` is reviewed only as a testnet component. Note: this part of the allowance audits a design whose release path still runs through that interim custodial verifier; the verifier that replaces it (O, or a Logos primitive) is not covered by this allowance.
- Allowance: $64,000–74,000 (RFP-021 scope $37,500–40,000, RFP-022 scope $26,250–34,000), based on written quotes from zk-specialist audit firms for the core and off-chain components (relayers, client, Logos modules); the upper end includes dedicated cryptography review of the BLS kernel. Final fee is fixed at code freeze. If O is exercised, its guest and verifier are added to the same engagement and quoted then.
- Auditor: chosen with Logos from zk-specialist audit firms that have quoted this scope.
- Procurement: left to be procured separately (RFP-022 asks proposals to state which). Option (a): **Logos procures the audit directly**, selecting, contracting and paying the auditor; we supply the scope, a frozen tag and remediation under M6 and B5. Option (b): Protofire contracts the auditor chosen with Logos and passes the cost through at cost. Logos chooses. Lead time is outside the 14-week build, as both RFPs state.
