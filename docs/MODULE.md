# eth_attest_module — Logos core module (RFP-021 U1, U3, S9, S10)

Status 2026-11-10 (final run, development commit `c380d4b`). All four RFP U1 calls work: `produce_attestation` and `verify_attestation_dry_run` on the host, `submit_update` and `read_instance` against a live local LEZ v0.4.0-rc1 sequencer (final run, [evidence/rfp021-final-run.md](../evidence/rfp021-final-run.md): try 8 applied Finality(11,545,216) at LEZ block 373; an earlier run is recorded below). Ethereum access only through the Logos Ethereum core modules: CL via `beacon_api_module`, EL headers and receipts via `verified_proxy_module`, `eth_getProof` via `eth_rpc_module` (D-MOD-3). Built and run on aarch64-linux inside Docker; x86_64-linux and darwin outputs exist in the flake but have not been built. Gaps: `produce_attestation` covers only the latest finalised EL block (no ancestry), catalog release not run.

## Layout

| Path | What |
|---|---|
| `modules/eth_attest_module/` | The module: `metadata.json`, `flake.nix`, `CMakeLists.txt`, `rust-lib/` (Rust crate) |
| `modules/eth_attest_module/rust-lib/src/verify.rs` | Host dry run: lc-core (blst BLS) + inclusion, with the U5 error codes |
| `modules/eth_attest_module/rust-lib/src/produce.rs` | Builds the material from beacon LC data and EL JSON-RPC |
| `modules/eth_attest_module/rust-lib/src/glue.rs` | The Logos trait (the LIDL is derived from it), and the `beacon_api_module`, `verified_proxy_module` and `eth_rpc_module` clients |
| `modules/eth_attest_module/rust-lib/crates/*` | Symlinks to `crates/{lc-core,inclusion,attest-program,lez-client}`. `flake.nix` stages real copies |
| `modules/eth_attest_module/lez-headless.sh` | Headless `submit_update` + `read_instance` against a live LEZ sequencer on the Docker host; recorded output: [evidence/module/lez-transcript.txt](../evidence/module/lez-transcript.txt) |
| `modules/nix-docker.sh` | Runs Nix only in Docker (`nixos/nix`, named volume `rfp021-nix`, Logos cache) |
| `modules/headless/run.sh` | Headless Logos Core run (`logosctl` daemon); recorded output: [evidence/module/headless-transcript.txt](../evidence/module/headless-transcript.txt) |
| `modules/catalog/` | Catalog skeleton (logos-modules-release-base shape) and release workflows |

## Build

```
git add -A modules                      # git+file flake: untracked files are invisible to Nix
modules/nix-docker.sh build             # -> modules/out/{lib/..., *.lgx}
```

Output of the recorded build (with the LEZ submit path):

```
lib: /nix/store/iy1yh9f8n4dxq0q59ag6mjmlilqlf411-logos-eth_attest_module-module-lib-0.1.0
lgx: /nix/store/7shihj239dww3pvkpxq9k3b92c2zvgs7-logos-eth_attest_module-module-lib-lgx-0.1.0
modules/out/lib/lib/eth_attest_module_plugin.so      19.2 MB  ELF aarch64
modules/out/lib/share/logos/eth_attest_module.lidl   derived contract
modules/out/lib/share/logos/beacon_api_module.lidl   dependency contract
modules/out/logos-eth_attest_module-module-lib.lgx   6.4 MB
```

Rust toolchain: `lee_core` (LEZ v0.4, via `lez-client`) needs rustc >= 1.98, so `metadata.json` sets
`nix.rust.toolchain = "1.98.1"` (builder option, rust-overlay toolchain instead of nixpkgs rustc) and
`flake.nix` makes the builder's `rust-overlay` input follow a newer `rust-overlay` (the builder's pin,
2026-08-26, has no 1.98.1). `rust-lib/Cargo.toml` `rust-version = "1.98"`.

Build times on an M2 with Docker limited to 12 GB:
- Cold, meaning the builder closure, Qt and logosctl from the caches: about 6 min.
- First module compile: about 55 s.
- Warm rebuild: about 11 s.

The `/nix` volume is about 16 GB.

Nix is never installed on the host. The flake must be referenced as
`git+file://<repo>?dir=modules/eth_attest_module`, because `../../crates` has to be inside the flake
source. A `path:` reference to the module directory alone cannot resolve those crates.

Unit tests (host, no Nix) need the SDK source at `modules/eth_attest_module/logos-rust-sdk-src`,
which is gitignored. Clone logos-rust-sdk at the rev in the builder's flake.lock
(`040e94e` today) and symlink it there:
```
cd modules/eth_attest_module/rust-lib && cargo +1.98.1 test --no-default-features
```
That runs 3 tests:
- All 89 vectors (74 adversarial cases and 15 positive controls) go through the dry run with no panic and each returns its expected code or an `accept_also` code (exact, `src/tests.rs`).
- Garbage material returns 1001.
- produce → verify round-trips over `fixtures/sepolia`, including the account and log statement IDs equal to the `expected_fact` of the adversarial fixtures.

## Headless run (U3)

```
modules/nix-docker.sh headless          # fixtures only
LIVE=1 modules/nix-docker.sh headless   # + live Sepolia produce_attestation
```

The run uses `logosctl` from logos-logoscore-cli (`daemon start`, `install <lgx>`, `module load`,
`call`), the same flow as the beacon module's doctest. It installs `beacon_api_module`, `eth_rpc_module` and `verified_proxy_module` at the revs
pinned in `flake.lock`, and `eth_attest_module`, then calls the module. See
[evidence/module/headless-transcript.txt](../evidence/module/headless-transcript.txt).

Observed results:
- `ok_attest_{account,storage,log}`: errorCode 0, with statementId and block 12062742.
- Rejections:
  - `attest_predicate_false` → 1203
  - `attest_el_state_root_tampered` → 1201
  - `attest_account_proof_node_tampered` → 1202
  - `bootstrap_committee_branch_tampered` → 1107
  - malformed material → 1001
- The full vector set is checked by the unit test above (89/89); the headless run shows a sample.
- Live run (`LIVE=1`): beacon data comes over Logos IPC from `beacon_api_module` (lodestar) and EL
  data over Logos IPC from `eth_rpc_module` (`sepolia.gateway.tenderly.co`). `produce_attestation` for the WETH account at the current finalized
  block (12064807, transcript [evidence/module/headless-transcript.txt](../evidence/module/headless-transcript.txt)) built the material and dry-ran it: `ok`, errorCode 0.

### Verified-proxy run (D-MOD-3)

`LIVE=1 VP_HTTP=1 VP_HOLD=900 DOCKER_ARGS="-p 127.0.0.1:18545:18545" modules/nix-docker.sh headless`
(2026-11-06T10:22Z, aarch64-linux, `verified_proxy_module` 1e15ae4 v0.1.8 built from source in the
container, no substitute was used for its nimbus `libverifproxy` here; about 25 min cold).
Transcript [evidence/module/vproxy-transcript.txt](../evidence/module/vproxy-transcript.txt):
- `produce_attestation` before the proxy is configured → `el_config` "verified_proxy_module is not
  configured", nothing fetched raw.
- `verified_proxy_module configure {network: sepolia, trustedBlockRoot: <the module's checkpointRoot>}`
  + `start` → light client synced from that root (beacon providers from `beacon_api_module`:
  lodestar, nimbus-unstable), `status` network sepolia, httpServer on :18545.
- `rpc eth_getProof` on the proxy → `bad request: unknown method` (why `eth_getProof` stays raw).
- `produce_attestation` WETH account (`nonce >= 0`) at finalized block 12,075,946
  (`0x94431b57…106b`): header via the proxy, `eth_getProof` via `eth_rpc_module`; dry run `ok`,
  errorCode 0.
- `produce_attestation` receipt log tx 0 / log 0 (`log.status == 1`) in the same block: header and
  block receipts via the proxy; dry run `ok`, errorCode 0. This is a claim's inclusion material.
  (The "463 receipts" line in this recording counted `transactionIndex` fields, receipts plus logs;
  the script now counts `cumulativeGasUsed`.)

The standalone relayer used the same proxy through its JSON-RPC endpoint during `VP_HOLD`
([evidence/module/vproxy-relayer-transcript.txt](../evidence/module/vproxy-relayer-transcript.txt), x86_64 box, port tunnelled): `fetch-attest`
for that log with `--anchor` 5 blocks up and `--exec` pointed at a closed port wrote the material
(3 receipt nodes, 5 ancestry headers), so every header, receipt and ancestry read came from the
verified endpoint; WETH slot 0 with a real `--exec` wrote 11 account + 6 storage nodes; with
`--exec` closed it failed at `eth_getProof`. `submit_update` reads only beacon data (no EL call),
so it was not rerun against a sequencer.

## API (LIDL derived from the trait; RFP name → method)

| RFP U1 | Method | State |
|---|---|---|
| produceAttestation(chain, blockHash, address, slot \| txIndex+logIndex, predicate) | `produce_attestation(chain_id, block_hash, address, slot, tx_index, log_index, predicate_json)` | Works. Limitation: only the latest finalized EL block is attestable (any other `block_hash` → 1101): the module does not yet build ancestry material. The program itself accepts any block up to 448 headers below a recorded one; use `rfp021 fetch-attest --anchor` for that today |
| verifyAttestationDryRun(material) → {ok, errorCode} | `verify_attestation_dry_run(material)` | Works. Material is the adversarial-vector `input` shape, or a whole vector file |
| submitUpdate | `submit_update(instance_id, material)` | `material` = Beacon-API LC update JSON (envelope or `data`); empty or `{}` = latest finality update fetched through `beacon_api_module`. lc-core pre-check, then atomic `Update` for any update kind (finality, rotation, committee-learning) with K <= `lez_client::ONE_TX_MAX_NON_SIGNERS` (170, D-UPD-3), otherwise `UpdateBegin` + `UpdateVerify` (residue witness), signed with the operator key file. Requires a program image supporting `Update` (D-UPD-1); this new route is executor-tested, not live-deployed. Returns the `read_instance` shape plus `txs` (one hash after inclusion and expected-state confirmation, or `<begin>+<verify>`); errors `lez_config`, `bad_request`, `lez_submit` (message carries the U5 code for pre-check rejections). Same `lez_client::LezClient` code as `rfp021 run-relayer` |
| readInstance | `read_instance(instance_id)` | Works against a live sequencer: `{ok, chainId, period, finalizedSlot, executionBlockHash, nextKnown, headers, headerRoot}` via `lez_client::read_instance` (`getAccountView` JSON-RPC + borsh `InstanceState`), the same function the relayer uses. Sepolia instances only |
| (config) | `set_chain_config(chain_id, {checkpointRoot, elRpc, lezRpc, attestProgram, operatorKeyFile})` | Settings are in memory only. `lezRpc` = sequencer JSON-RPC URL, `attestProgram` = base58 program account, `operatorKeyFile` = path of the operator key (see "Operator key") |

Ethereum CL access goes through the Logos Ethereum core module (`beacon_api_module`), declared
as a flake input and a `metadata.dependencies` entry, the same way logos-verified-proxy-module
does it. EL access goes through two Logos modules, both declared the same way (flake input +
`metadata.dependencies`): `verified_proxy_module` (pinned 1e15ae4, v0.1.8) and `eth_rpc_module`
(pinned b39bebf, its optional `verified_proxy_module` input follows ours). The route of each call is
decided in one place, `inclusion::host::el_route` (shared with the relayer, pinned by test
`el_routing_table`; D-MOD-3):

| EL call | Route | Through |
|---|---|---|
| `eth_getBlockByHash` (attested header) | verified | `modules().verified_proxy_module.rpc` |
| `eth_getBlockByNumber` (relayer ancestry) | verified | same |
| `eth_getBlockReceipts` (by block number: the proxy takes a block tag, not a hash) | verified | same |
| `eth_getProof` (account / storage proof) | raw | `modules().eth_rpc_module.raw_rpc` |

`eth_getProof` is raw because `verified_proxy_module` does not expose it (nimbus uses it internally
only; a call answers "method not found", see the transcript). When it does, moving it is one line in
`el_route`. The verified leg never falls back to raw: an unconfigured proxy, or one on another network,
makes `produce_attestation` return `el_config`. The proxy is shared by every app on the device, so the
module does not configure it; the operator runs `configure({network, trustedBlockRoot})` + `start()`
(use the instance's checkpoint root, so both light clients start from the same anchor; its default
Sepolia execution endpoint, ethpandaops, keeps proof history). `elRpc` is pushed into
`eth_rpc_module`'s chain record (`set_chain_config` when the operator set it, `ensure_chain_config`
for the default so a shared record is not retuned). `eth_rpc_module`'s own `verifiedProxyMode` is not
used: it is per chain, so `required` would also send `eth_getProof` to the proxy, which cannot answer
it. Soundness never depended on either route: the dry run and the program check the header against
the BLS-verified block hash, receipts against `receiptsRoot` and proofs against `stateRoot` (D-MOD-2).
The dry run trusts the
config and checkpoint inside the material. It checks consistency, not a trust anchor, which belongs
to the program instance.

## LEZ submit + read path

`modules/nix-docker.sh -- "ATTEST=<b58> INSTANCE=0x.. KEY_FILE=<path, 0600> bash modules/eth_attest_module/lez-headless.sh"`
builds logosctl, both lgx files, loads them in a headless daemon and calls the module against the
sequencer on the Docker host (`LEZ_RPC`, default `http://host.docker.internal:3040`; the sequencer
must listen on `0.0.0.0`). `LOGOSCTL_TIMEOUT` defaults to 300 s in the script: a submit waits for
two LEZ blocks (15 s each locally) and logosctl's default call budget is 20 s (the first attempt
timed out client-side while the update still applied).

Recorded 2026-11-05T12:03Z ([evidence/module/lez-transcript.txt](../evidence/module/lez-transcript.txt),
aarch64-linux) against a local LEZ v0.4 standalone sequencer (1806e87, `RISC0_DEV_MODE=1`), attest program
`4ZyXXGxa…8WhR9wd` and instance `0x5a6e9b86…806d9`, with two relayers running. The key was the module's own
0600 key file. Results:
- `read_instance` before `set_chain_config` returns `lez_config`; after it, the instance state
  (`finalizedSlot 11512128`, `headers 2`); an unknown instance returns `lez_read`.
- `submit_update` without `operatorKeyFile` returns `lez_config`; with a 0644 copy of the key it returns
  `lez_submit`, `mode 644; must be 0600`, and nothing is sent.
- Tries 1 to 5 (every 20 s) were refused by the module's pre-check, `1106 UpdateNotNewer`, and nothing was
  sent: finality had not moved past the stored slot.
- Try 6 (12:05:16) applied Finality(11,512,160) as one `Update` transaction,
  `7714963e…5794`, LEZ block 105, 6,604,390 cycles, `headers 3`; `read_instance` then returns the same slot and
  header root. The same transaction is row 3 of the table in section 2.1 of
  [evidence/rfp021-final-run.md](../evidence/rfp021-final-run.md).

The final run (2026-11-10, development commit `c380d4b`) repeated this against a fresh instance: tries 1 to 7
were refused by the pre-check and try 8 applied Finality(11,545,216), tx `fce07006…a93f`, LEZ block 373
([evidence/rfp021-final-run.md](../evidence/rfp021-final-run.md), section 1, "Logos module submit path"). Its raw module transcript is not committed.

### Submit path
`crates/lez-client` feature `submit` builds the LEZ public transaction itself on `lee_core` types:
borsh layout of `lee::public_transaction::Message` (public context, root call, `FeeDeclaration`
{payer, gas = `update_gas_limit(K)` (7.4M + 11.5k·K, measured cycles + ~5%; 10M on the K > 170 fallback), tip 0,
max_fee = `max_fee_for(gas, …)` from the sequencer's `getFeeState` next-block ceilings, doubled}, payer nonce, PDA admission evidence), BIP-340
signature over `sha256("/LEE/v0.3/Message/Public/"‖borsh)` with k256, `LeeTransaction::Public` (tag 0),
base64 `sendTransaction`, `getTransaction` polled (1 s, 300 s cap) for the block. Revert check: the
client sends one atomic `Update` (D-UPD-3) and confirms it by reading back the expected HeaderRecord, or the stored
`next_sync_committee` for a committee-learning update that does not advance finality (a reverted tx changes no state);
on the `UpdateBegin`/`UpdateVerify` fallback above K=170 the job PDA is non-empty after Begin and empty after Verify. No
block decoding (`common::Block`) is needed. No `lee`, `common`,
`wallet` or `sequencer_service_rpc` in the module's dependency tree (`cargo tree` checked), so no
rocksdb / rapidsnark / circuit natives. `lee` stays a dev-dependency only: `public_tx_matches_lee`
decodes our bytes as `lee::PublicTransaction`, runs its `check_stateless` (signer, nonce, signature)
and re-encodes byte-identically. Feature `wallet` (default; the relayer) only adds
`LezClient::new` (key + URL from the LEZ wallet); signing and sending are the same code.

### Operator key
The module signs with an operator key read from the file named in `operatorKeyFile`, the same
custody model as the relayer's operator (a local key the operator process holds; one payer per
process, see D-CLI-1 in [DECISIONS.md](DECISIONS.md)):
- 32-byte secp256k1 secret as hex (optional `0x`, surrounding whitespace ignored).
- The file must not be group/other accessible (`mode & 077 == 0`, i.e. 0600 or 0400) or the
  submit is refused with `lez_submit` and nothing is sent.
- Read at every `submit_update`, never stored in settings, never logged or returned; `set_chain_config`
  echoes only the path. Error messages name the path, never contents.
- The payer is the key's public account (`sha256("/LEE/v0.3/AccountId/Public/"‖x-only pubkey)`); it must
  hold enough native balance for two fee-paying txs.
- Inside `logosctl` in Docker the path is a container path (the repo is bind-mounted at the same path).

## Catalog / release (S9, S10)

`modules/catalog/` is meant to be the root of a separate catalog repo:
1. Fork logos-modules-release-base, or copy this directory in its place.
2. Run `git submodule add https://github.com/protofire/sallyport submodules/sallyport`.
3. Replace the `protofire/<catalog-repo>` placeholders in `logos-repo.json` (the catalog repository name is not decided yet).

Running **Release eth_attest_module** then calls
`logos-co/logos-modules-release-action/.github/workflows/release.yml@v1` with
`module_path: submodules/sallyport/modules/eth_attest_module`. The action supports a path
inside a submodule, and building inside that checkout makes the flake a git+file flake, so
`../../crates` resolves. The action then:
1. Builds `.#lgx-portable` for darwin-arm64, linux-amd64 and linux-arm64. Windows is dropped because there is no x86_64-windows output.
2. Runs `lgx merge` and `lgx verify`. Signing is off (`signing_mode: none`).
3. Publishes the release `eth_attest_module-v0.1.0` with a sidecar file.
4. Runs `rebuild-index`, which updates `index.json` on the rolling `index` release.

Clients add the raw `logos-repo.json` URL.

None of this has been pushed or run. `lgx-portable` has not been built locally either: only `lib` and
`lgx` were built.

## Not built

- Ancestry material in `produce_attestation` (the program side exists: accumulator, ancestry up to 448 headers).
- Persisted chain settings (instance persistence path) and a configurable predicates list.
- `eth_getProof` through `verified_proxy_module`, once it exposes it (one line in `el_route`).
- `lgx-portable` and x86_64/darwin builds, the catalog repository, a first CI release and a signing key.
