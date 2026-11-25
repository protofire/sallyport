//! LEZ v0.4 client for the RFP-021 attest program: reads an instance and submits
//! atomic Update (K <= ONE_TX_MAX_NON_SIGNERS) or UpdateBegin + UpdateVerify. Used by `relayer` (feature `lez`) and `eth_attest_module`.
//! `read_instance` needs only JSON-RPC. `LezClient` (feature `submit`) builds, signs and sends
//! public transactions on `lee_core` alone; feature `wallet` adds `LezClient::new` (key from the LEZ wallet).
use anyhow::{anyhow, bail, Context, Result};
use attest_program::instance_seed;
pub use attest_program::{InstanceId, InstanceState};
use lee_core::account::{Account, AccountId, Actor};
use lee_core::program::PdaSeed;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(feature = "submit")]
pub use submit::LezClient;

/// Largest non-signer count K the client sends as one atomic `Update`; above it, UpdateBegin +
/// UpdateVerify. Measured (program-tests/tests/onetx.rs `onetx_cycles_by_non_signers`): every
/// shape (finality, rotation, committee-learning) fits the 9.5M budget (MAX_GAS_EXEC 10M) up to
/// K=170 (max 8.47M), which is also the 2/3 participation limit, so the split is only a fallback.
pub const ONE_TX_MAX_NON_SIGNERS: usize = 170;

/// LEZ `MAX_GAS_EXEC`: per-block execution gas cap (target 5M, `fee/core/src/market.rs:10-15`), and
/// so the most one tx may declare. The sequencer admits a tx only if the block's used gas plus its
/// declared `gas_limit` fits under it (`sequencer/core/src/lib.rs:144`).
pub const MAX_GAS_EXEC: u64 = 10_000_000;

/// Declared `gas_limit` of a one-tx `Update` with `k` non-signers: the measured cycles
/// (`onetx_cycles_by_non_signers`: about 6.54M-6.98M at K<=2 plus about 11.3k per non-signer, every update
/// kind) plus about 5% margin, capped at [`MAX_GAS_EXEC`]. Out of gas reverts and is charged the
/// whole limit; a smaller limit lets other txs (claims) share the block.
pub fn update_gas_limit(k: usize) -> u64 {
    (7_400_000 + 11_500 * k as u64).min(MAX_GAS_EXEC)
}

/// Declared `gas_limit` for a reference-consumer claim: the largest measured claim transaction
/// (eth_receiver Claim with 30 ancestry headers, 577,512 cycles, docs/BENCHMARKS.md) plus ~70% margin.
/// Small enough that a claim shares a block with a typical one-tx `Update` (see `update_gas_limit`).
pub const CLAIM_GAS: u64 = 1_000_000;

/// Bytes a public tx is assumed to occupy for the storage part of its fee (LEZ wallet `ASSUMED_DATA_BYTES`).
const ASSUMED_DATA_BYTES: u128 = 100_000;

/// `max_fee` for a public tx declaring `gas`, from the sequencer's next-block base-fee ceilings
/// (`getFeeState`): LEZ refuses a tx whose reserve `gas·base_fee_exec + bytes·base_fee_stor` exceeds
/// `max_fee` (`fee/core/src/validity.rs`), and the base fee moves up to 12.5% per block, so a fixed
/// price would lock the client out under congestion. Doubled: headroom for several blocks of rise.
/// Only a cap: the fee charged is the actual base fee for the cycles used.
pub fn max_fee_for(gas: u64, base_fee_exec: u64, base_fee_stor: u64) -> u128 {
    (gas as u128 * base_fee_exec as u128 + ASSUMED_DATA_BYTES * base_fee_stor as u128)
        .saturating_mul(2)
}

/// Default ceiling on any `max_fee` the client signs: the reserve of a full-block (`MAX_GAS_EXEC`) tx at
/// base fees of 1024 (128x the floor of 8), doubled. Bounds what a hostile or broken sequencer quote can make
/// the payer authorize; override with `LezClient::with_max_fee_cap` (relayer `[lez] max_fee_cap`).
pub const DEFAULT_MAX_FEE_CAP: u128 = 2 * (MAX_GAS_EXEC as u128 * 1024 + ASSUMED_DATA_BYTES * 1024);

/// `max_fee_for` clamped to `cap`. Above the cap the sequencer refuses the tx (reserve > max_fee): the
/// payer never authorizes more than the cap.
pub fn capped_max_fee(gas: u64, base_fee_exec: u64, base_fee_stor: u64, cap: u128) -> u128 {
    max_fee_for(gas, base_fee_exec, base_fee_stor).min(cap)
}

/// Client policy, not a consensus rule: any update kind with K <= ONE_TX_MAX_NON_SIGNERS.
pub fn prefers_single_tx(u: &lc_core::LightClientUpdate) -> bool {
    lc_core::SYNC_COMMITTEE_SIZE - u.sync_aggregate.participants() <= ONE_TX_MAX_NON_SIGNERS
}

fn pda(program: AccountId, seed: [u8; 32]) -> Actor {
    Actor::new(
        AccountId::for_public_pda(&program, &PdaSeed::new(seed)),
        program,
    )
}

/// One sequencer JSON-RPC call; returns `result`.
fn rpc(url: &str, method: &str, params: Value) -> Result<Value> {
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let r: Value = reqwest::blocking::Client::new()
        .post(url)
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.text())
        .map_err(|e| anyhow!("{method}: {e}"))
        .and_then(|t| {
            serde_json::from_str(&t).with_context(|| format!("{method}: response not JSON"))
        })?;
    if let Some(e) = r.get("error") {
        bail!("{method}: {e}");
    }
    Ok(r["result"].clone())
}

/// `getAccountView`: the account's nonce and its state as seen by `a.program`.
fn account_view(url: &str, a: Actor) -> Result<Option<Account>> {
    serde_json::from_value(rpc(url, "getAccountView", serde_json::json!([a]))?)
        .context("getAccountView: account")
}

/// Raw state of the attest-program PDA `seed` (empty if absent).
fn pda_state(url: &str, attest: AccountId, seed: [u8; 32]) -> Result<Vec<u8>> {
    Ok(account_view(url, pda(attest, seed))?
        .map(|acc| acc.data.actor_state(attest).to_vec())
        .unwrap_or_default())
}

/// Reads the attest-program instance `instance_id` via the sequencer's `getAccountView` JSON-RPC.
pub fn read_instance(
    sequencer_url: &str,
    attest: AccountId,
    instance_id: &InstanceId,
) -> Result<InstanceState> {
    let bytes = pda_state(sequencer_url, attest, instance_seed(instance_id))?;
    if bytes.is_empty() {
        bail!("instance {} not initialised", hex(instance_id));
    }
    borsh::from_slice(&bytes).context("instance state")
}

/// Base58 account id, with or without the wallet's `Public/` prefix.
pub fn account_id(s: &str) -> Result<AccountId> {
    s.trim_start_matches("Public/")
        .parse()
        .map_err(|e| anyhow!("account id {s}: {e:?}"))
}

#[cfg(feature = "submit")]
mod submit {
    use super::*;
    use attest_program::{
        bls, header_leaf, header_record, header_seed, hroot_seed, job_seed, witness, Msg,
    };
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use borsh::BorshSerialize;
    use k256::schnorr::SigningKey;
    use lee_core::account::Nonce;
    use lee_core::execution_state::PublicExecutionContext;
    use lee_core::RootCall;
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::time::Duration;

    const MSG_PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/Public/\x00\x00\x00\x00\x00\x00\x00";
    const ACCOUNT_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/Public/\x00\x00\x00\x00\x00";
    const POLL: Duration = Duration::from_secs(1);
    const POLL_MAX: u32 = 300;

    // Byte-for-byte the borsh layout of LEZ 6aaabe5 `lee::public_transaction::Message`
    // (TransactionMessage<PublicExecution>; PublicExecution's `root` inlined, `fee` after `nonces`) and
    // `common::LeeTransaction::Public(PublicTransaction)`. Pinned by the test against `lee`.
    #[derive(BorshSerialize)]
    struct FeeDeclaration {
        payer: AccountId,
        gas_limit: u64,
        tip: u64,
        max_fee: u128,
    }
    #[derive(BorshSerialize)]
    #[allow(dead_code)] // `Key` only fixes the borsh tag of `Pda`
    enum Evidence {
        Key([u8; 32]),
        Pda { program: AccountId, seed: PdaSeed },
    }
    #[derive(BorshSerialize)]
    struct Message {
        public_context: PublicExecutionContext,
        root: RootCall,
        nonces: BTreeMap<AccountId, Nonce>,
        fee: Option<FeeDeclaration>,
        admission_evidence: Vec<Evidence>,
    }
    #[derive(BorshSerialize)]
    enum LeeTransaction {
        Public {
            message: Message,
            witness_set: Vec<([u8; 64], [u8; 32])>,
        },
    }

    /// Public account id of a signing key (LEE `AccountId::from(&PublicKey)`).
    fn account_of(key: &SigningKey) -> AccountId {
        let pk: [u8; 32] = key.verifying_key().to_bytes().into();
        AccountId::new(
            Sha256::new()
                .chain_update(ACCOUNT_PREFIX)
                .chain_update(pk)
                .finalize()
                .into(),
        )
    }

    /// Fee-paying public tx from `payer` (signer = payer) declaring `gas`, borsh-encoded as `LeeTransaction`.
    #[allow(clippy::too_many_arguments)]
    fn public_tx(
        key: &SigningKey,
        gas: u64,
        max_fee: u128,
        nonce: Nonce,
        to: Actor,
        actors: Vec<Actor>,
        evidence: Vec<(AccountId, [u8; 32])>,
        msg: &impl BorshSerialize,
    ) -> Result<Vec<u8>> {
        let payer = account_of(key);
        let message = Message {
            public_context: PublicExecutionContext::new(actors, [payer]),
            root: RootCall {
                to,
                message: borsh::to_vec(msg)?,
            },
            fee: Some(FeeDeclaration {
                payer,
                gas_limit: gas,
                tip: 0,
                max_fee,
            }),
            nonces: BTreeMap::from([(payer, nonce)]),
            admission_evidence: evidence
                .into_iter()
                .map(|(program, seed)| Evidence::Pda {
                    program,
                    seed: PdaSeed::new(seed),
                })
                .collect(),
        };
        let hash: [u8; 32] = Sha256::new()
            .chain_update(MSG_PREFIX)
            .chain_update(borsh::to_vec(&message)?)
            .finalize()
            .into();
        let sig = key
            .sign_prehash_with_aux_rand(&hash, &rand::random())
            .map_err(|e| anyhow!("sign: {e}"))?;
        let pk: [u8; 32] = key.verifying_key().to_bytes().into();
        Ok(borsh::to_vec(&LeeTransaction::Public {
            message,
            witness_set: vec![(sig.to_bytes(), pk)],
        })?)
    }

    /// Operator key file: 32-byte hex (optional `0x`), owner-only permissions. Never logged.
    fn load_key(path: &Path) -> Result<SigningKey> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(path)
                .with_context(|| format!("operator key {}", path.display()))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                bail!(
                    "operator key {} has mode {:o}; must be 0600 (owner-only)",
                    path.display(),
                    mode & 0o777
                );
            }
        }
        let s = std::fs::read_to_string(path)
            .with_context(|| format!("operator key {}", path.display()))?;
        let s = s.trim().trim_start_matches("0x");
        let mut b = [0u8; 32];
        if s.len() != 64 || !s.is_ascii() {
            bail!("operator key {}: expected 32-byte hex", path.display());
        }
        for (i, x) in b.iter_mut().enumerate() {
            *x = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|_| anyhow!("operator key {}: expected 32-byte hex", path.display()))?;
        }
        SigningKey::from_bytes(&b)
            .map_err(|_| anyhow!("operator key {}: not a valid secp256k1 key", path.display()))
    }

    use super::prefers_single_tx;

    pub struct LezClient {
        url: String,
        key: SigningKey,
        payer: AccountId,
        attest: AccountId,
        instance_id: InstanceId,
        max_fee_cap: u128,
    }

    impl LezClient {
        /// Ceiling on the `max_fee` of every tx this client signs (default [`DEFAULT_MAX_FEE_CAP`]).
        pub fn with_max_fee_cap(mut self, cap: u128) -> Self {
            self.max_fee_cap = cap;
            self
        }

        /// Signer from an operator key file (see `load_key`); the payer is the key's public account.
        pub fn from_key_file(
            sequencer_url: &str,
            key_file: &Path,
            attest: &str,
            instance_id: InstanceId,
        ) -> Result<Self> {
            let key = load_key(key_file)?;
            Ok(Self {
                url: sequencer_url.into(),
                payer: account_of(&key),
                key,
                attest: account_id(attest)?,
                instance_id,
                max_fee_cap: DEFAULT_MAX_FEE_CAP,
            })
        }

        /// Wallet from `LEE_WALLET_HOME_DIR` (its config names the sequencer); `payer` must be imported there.
        #[cfg(feature = "wallet")]
        pub fn new(payer: &str, attest: &str, instance_id: InstanceId) -> Result<Self> {
            let w = wallet::WalletCore::from_env().map_err(|e| anyhow!("wallet: {e}"))?;
            let payer = account_id(payer)?;
            let k = w
                .get_account_public_signing_key(payer)
                .ok_or_else(|| anyhow!("payer {payer} not in wallet"))?;
            let key = SigningKey::from_bytes(k.value()).map_err(|_| anyhow!("payer key"))?;
            if account_of(&key) != payer {
                bail!("wallet key does not derive payer {payer}");
            }
            Ok(Self {
                url: w.client_url().to_string(),
                key,
                payer,
                attest: account_id(attest)?,
                instance_id,
                max_fee_cap: DEFAULT_MAX_FEE_CAP,
            })
        }

        pub fn payer(&self) -> AccountId {
            self.payer
        }

        pub fn instance(&self) -> Result<InstanceState> {
            read_instance(&self.url, self.attest, &self.instance_id)
        }

        /// Signed fee-paying public tx; waits for inclusion. Ok((hash, block)).
        fn send(
            &self,
            gas: u64,
            to: Actor,
            mut actors: Vec<Actor>,
            new_pdas: &[[u8; 32]],
            msg: &Msg,
        ) -> Result<(String, u64)> {
            actors.push(to);
            let nonce = account_view(&self.url, Actor::native_balance(self.payer))?
                .unwrap_or_default()
                .nonce;
            let ev = new_pdas.iter().map(|s| (self.attest, *s)).collect();
            let q = rpc(&self.url, "getFeeState", serde_json::json!([]))?;
            let fee = |k: &str| {
                q.get(k)
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("getFeeState: no {k}"))
            };
            let max_fee = capped_max_fee(
                gas,
                fee("next_base_fee_exec_ceiling")?,
                fee("next_base_fee_stor_ceiling")?,
                self.max_fee_cap,
            );
            let tx = public_tx(&self.key, gas, max_fee, nonce, to, actors, ev, msg)?;
            let hash = rpc(
                &self.url,
                "sendTransaction",
                serde_json::json!([STANDARD.encode(tx)]),
            )?;
            for _ in 0..POLL_MAX {
                // `getTransaction` -> null | [tx, block_id]
                if let Ok(r) = rpc(&self.url, "getTransaction", serde_json::json!([hash])) {
                    if let Some(block) = r.get(1).and_then(Value::as_u64) {
                        return Ok((hash.as_str().unwrap_or_default().to_string(), block));
                    }
                }
                std::thread::sleep(POLL);
            }
            bail!(
                "tx {hash} not included after {} s",
                POLL_MAX as u64 * POLL.as_secs()
            )
        }

        /// Job PDA state: non-empty after a successful UpdateBegin, empty after a successful UpdateVerify.
        /// A reverted tx leaves no state change, so this is the revert check (no block decoding needed).
        fn job_open(&self, job_id: u64) -> Result<bool> {
            Ok(!pda_state(&self.url, self.attest, job_seed(&self.instance_id, job_id))?.is_empty())
        }

        /// Why an update would be rejected now (lc-core pre-check against the current on-chain store).
        fn recheck(&self, u: &lc_core::LightClientUpdate) -> String {
            match self.instance() {
                Ok(st) => match lc_core::prepare_update(
                    &st.cfg.chain,
                    &st.store,
                    u,
                    now_slot(st.cfg.genesis_time),
                ) {
                    Ok(_) => "still applicable".into(),
                    Err(e) => format!("{} {e:?}", e as u16),
                },
                Err(e) => e.to_string(),
            }
        }

        /// Beacon-API JSON update → local pre-check → atomic Update for K <= ONE_TX_MAX_NON_SIGNERS
        /// (any kind), otherwise UpdateBegin + UpdateVerify. Requires a program supporting Msg::Update.
        /// Returns one hash (inclusion + expected header confirmed, possibly by a competing
        /// submitter), or `"<begin hash>+<verify hash>"`. A one-tx `Update` that is included but whose
        /// state is unconfirmed while the update is still applicable (most likely out of gas at
        /// `update_gas_limit`) is resent once at `MAX_GAS_EXEC`; otherwise no retry.
        pub fn submit_update_json(&self, raw: &serde_json::Value) -> Result<String> {
            let u =
                lc_core::json::update_from_value(raw).map_err(|e| anyhow!("update JSON: {e:?}"))?;
            let st = self.instance()?;
            let now = now_slot(st.cfg.genesis_time);
            let p = lc_core::prepare_update(&st.cfg.chain, &st.store, &u, now)
                .map_err(|e| anyhow!("pre-check rejected update: {} {e:?}", e as u16))?;
            let wit = witness::for_pairing(&p.pairing)
                .ok_or_else(|| anyhow!("sync aggregate signature invalid (1102)"))?;
            let hints = bls::uncompress_non_signers(&p.pairing);
            let id = self.instance_id;
            let inst = pda(self.attest, instance_seed(&id));
            let mut actors = vec![];
            let mut seeds = vec![];
            if let Some(f) = &p.verified.finalized_header {
                let seed = header_seed(&id, &f.execution_block_hash);
                actors.push(pda(self.attest, seed));
                seeds.push(seed);
                // Apply appends to the header accumulator and writes a new root PDA when finality advances.
                if f.beacon.slot > st.store.finalized_header.beacon.slot {
                    let root = st
                        .headers
                        .clone()
                        .append(header_leaf(&header_record(id, &st.cfg, f)))
                        .ok_or_else(|| anyhow!("header accumulator full"))?;
                    let seed = hroot_seed(&id, &root);
                    actors.push(pda(self.attest, seed));
                    seeds.push(seed);
                }
            }
            if prefers_single_tx(&u) {
                let update = Msg::Update {
                    instance_id: id,
                    update: u.clone(),
                    non_signers: hints,
                    witness: wit,
                    now_slot: now,
                };
                let k = lc_core::SYNC_COMMITTEE_SIZE - u.sync_aggregate.participants();
                // Inclusion alone is not execution success; a concurrent relayer may have applied
                // the same update. Confirm the intended state: the immutable header when finality
                // advances (rotation is atomic with it), else the learned next committee.
                let confirmed = || -> Result<bool> {
                    Ok(match &p.verified.finalized_header {
                        Some(f) => {
                            let record = header_record(id, &st.cfg, f);
                            pda_state(
                                &self.url,
                                self.attest,
                                header_seed(&id, &record.execution_block_hash),
                            )? == borsh::to_vec(&record)?
                        }
                        None => {
                            self.instance()?.store.next_sync_committee
                                == p.verified.next_sync_committee
                        }
                    })
                };
                let mut gas = update_gas_limit(k);
                let (mut hash, mut block) =
                    self.send(gas, inst, actors.clone(), &seeds, &update)?;
                if !confirmed()? {
                    let why = self.recheck(&u);
                    if why != "still applicable" || gas >= MAX_GAS_EXEC {
                        bail!("Update {hash} included (block {block}) but expected state unconfirmed; re-check now: {why}");
                    }
                    // a revert that leaves the update applicable: most likely out of gas at the
                    // measured limit, so resend once with the whole block
                    tracing::warn!(tx = %hash, block, gas, "Update unconfirmed but still applicable; resending once at MAX_GAS_EXEC");
                    gas = MAX_GAS_EXEC;
                    (hash, block) = self.send(gas, inst, actors, &seeds, &update)?;
                    if !confirmed()? {
                        bail!("Update {hash} included (block {block}, gas {gas}) but expected state unconfirmed; re-check now: {}", self.recheck(&u));
                    }
                }
                // getTransaction returns only [tx, block_id], with no revert flag, so a lost race (our tx
                // reverted 1106, other operator applied it) is indistinguishable here; do not claim ours applied.
                tracing::info!(tx = %hash, block, "Update included; expected state reached (by us or another operator)");
                return Ok(hash);
            }
            let job_id: u64 = rand::random();
            let job = pda(self.attest, job_seed(&id, job_id));
            let begin = Msg::UpdateBegin {
                instance_id: id,
                job_id,
                update: u.clone(),
                non_signers: hints,
                now_slot: now,
            };
            // Split fallback (K > ONE_TX_MAX_NON_SIGNERS, unreachable at the 342 participation floor): not
            // re-measured on the current code, so it keeps the whole block.
            let (bh, bb) = self.send(
                MAX_GAS_EXEC,
                inst,
                vec![job],
                &[job_seed(&id, job_id)],
                &begin,
            )?;
            let rev = !self.job_open(job_id)?;
            tracing::info!(tx = %bh, block = bb, reverted = rev, job_id, "UpdateBegin");
            if rev {
                bail!(
                    "UpdateBegin {bh} reverted (block {bb}); re-check now: {}",
                    self.recheck(&u)
                );
            }
            let verify = Msg::UpdateVerify {
                instance_id: id,
                job_id,
                witness: wit,
            };
            actors.push(inst);
            let (vh, vb) = self.send(MAX_GAS_EXEC, job, actors, &seeds, &verify)?;
            let rev = self.job_open(job_id)?;
            tracing::info!(tx = %vh, block = vb, reverted = rev, job_id, "UpdateVerify");
            if rev {
                bail!(
                    "UpdateVerify {vh} reverted (block {vb}); re-check now: {}",
                    self.recheck(&u)
                );
            }
            let s = self.instance()?.store;
            tracing::info!(
                finalized_slot = s.finalized_header.beacon.slot,
                execution_block_hash = %hex(&s.finalized_header.execution_block_hash),
                next_known = s.next_sync_committee.is_some(),
                "applied"
            );
            Ok(format!("{bh}+{vh}"))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn every_update_kind_routes_to_one_tx_up_to_k170() {
            let mut u = lc_core::json::update_from_json(include_str!(
                "../../../fixtures/sepolia/finality_update.json"
            ))
            .unwrap();
            assert!(prefers_single_tx(&u));
            u.sync_aggregate.sync_committee_bits = [0xff; 64];
            u.sync_aggregate.sync_committee_bits[..21].fill(0);
            u.sync_aggregate.sync_committee_bits[21] = 0xfc; // K=170
            assert_eq!(u.sync_aggregate.participants(), 512 - 170);
            assert!(prefers_single_tx(&u));
            u.sync_aggregate.sync_committee_bits[21] = 0xf8; // K=171
            assert!(!prefers_single_tx(&u), "K=171 splits");
            let mut learn = lc_core::json::updates_from_json(include_str!(
                "../../../fixtures/sepolia/updates.json"
            ))
            .unwrap()
            .remove(1);
            assert!(learn.next_sync_committee.is_some());
            assert!(prefers_single_tx(&learn), "committee-learning takes one tx");
            learn.sync_aggregate.sync_committee_bits = u.sync_aggregate.sync_committee_bits;
            assert!(
                !prefers_single_tx(&learn),
                "committee-learning K=171 splits"
            );
        }

        /// Our encoding decodes as LEZ's own `PublicTransaction` and passes its stateless checks
        /// (signer = nonce = authorized account, BIP-340 signature over LEZ's message hash).
        #[test]
        fn public_tx_matches_lee() {
            let key = SigningKey::from_bytes(&[7u8; 32]).unwrap();
            let attest = AccountId::new([9; 32]);
            let to = pda(attest, [1; 32]);
            let job = pda(attest, [2; 32]);
            let msg = Msg::UpdateVerify {
                instance_id: [3; 32],
                job_id: 5,
                witness: Default::default(),
            };
            let raw = public_tx(
                &key,
                1_234_567,
                max_fee_for(1_234_567, 64, 64),
                Nonce(4),
                to,
                vec![job, to],
                vec![(attest, [2; 32])],
                &msg,
            )
            .unwrap();
            assert_eq!(raw[0], 0, "LeeTransaction::Public tag");
            let tx: lee::PublicTransaction = borsh::from_slice(&raw[1..]).unwrap();
            assert_eq!(tx.check_stateless().unwrap(), vec![account_of(&key)]);
            let m = tx.message();
            let fee = m.fee.unwrap();
            assert_eq!(
                (fee.payer, fee.gas_limit, fee.tip, fee.max_fee),
                (
                    account_of(&key),
                    1_234_567,
                    0,
                    2 * (1_234_567 + 100_000) * 64
                )
            );
            assert_eq!(m.nonces, BTreeMap::from([(account_of(&key), Nonce(4))]));
            assert_eq!(m.execution.root.to, to);
            assert_eq!(m.execution.root.message, borsh::to_vec(&msg).unwrap());
            assert_eq!(
                m.admission_evidence,
                vec![lee::PublicAccountEvidence::Pda {
                    program: attest,
                    seed: PdaSeed::new([2; 32])
                }]
            );
            // Re-encoding LEZ's decoded tx gives our bytes back.
            assert_eq!(borsh::to_vec(&tx).unwrap(), raw[1..]);
        }

        #[cfg(unix)]
        #[test]
        fn key_file_must_be_owner_only() {
            use std::os::unix::fs::PermissionsExt as _;
            let p = std::env::temp_dir().join(format!("lez-client-key-{}", std::process::id()));
            std::fs::write(&p, format!("0x{}\n", "07".repeat(32))).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
            let e = load_key(&p).err().unwrap().to_string();
            assert!(e.contains("0600") && !e.contains("0707"), "{e}");
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            let k = load_key(&p).unwrap();
            assert_eq!(
                account_of(&k),
                account_of(&SigningKey::from_bytes(&[7u8; 32]).unwrap())
            );
            std::fs::remove_file(&p).unwrap();
        }
    }
}

pub fn now_slot(genesis_time: u64) -> u64 {
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - genesis_time)
        / 12
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod gas_tests {
    use super::*;

    /// LEZ 6aaabe5 admits a tx into a block only if the block's used exec gas plus its declared
    /// `gas_limit` is <= MAX_GAS_EXEC (10M, `sequencer/core/src/lib.rs:139`). A 10M Update limit
    /// means no other tx can share its block. The limit must cover the measured cycles (executor,
    /// `onetx_cycles_by_non_signers`; that test runs every K under exactly this limit) with margin.
    #[test]
    fn update_gas_limit_covers_measured_cycles_and_leaves_block_room() {
        // (K, largest measured Update cycles at that K over finality/rotation/committee-learning)
        for (k, measured) in [(0, 6_539_551u64), (2, 6_981_423), (170, 8_866_373)] {
            let g = update_gas_limit(k);
            assert!(
                g >= measured + measured / 20,
                "K={k}: {g} < measured {measured} + 5%"
            );
            assert!(g < 10_000_000, "K={k}: {g} fills the whole block");
        }
        // the reference-consumer claim (CLAIM_GAS) fits beside a typical update (K <= 2) in one block
        const {
            assert!(
                CLAIM_GAS >= 577_512 + 577_512 / 2,
                "claim gas below measured + 50%"
            )
        };
        assert!(
            update_gas_limit(2) + CLAIM_GAS <= MAX_GAS_EXEC,
            "typical update leaves no room for a claim"
        );
    }

    /// `max_fee` covers LEZ's reserve at the quoted base fees, also far above the old fixed 64.
    #[test]
    fn max_fee_follows_the_sequencer_base_fee() {
        let g = update_gas_limit(2) as u128;
        for (exec, stor) in [(8u64, 8u64), (64, 64), (500, 120)] {
            let reserve = g * exec as u128 + 100_000 * stor as u128;
            assert!(
                max_fee_for(g as u64, exec, stor) >= reserve,
                "{exec}/{stor}"
            );
        }
        assert!(max_fee_for(g as u64, 500, 120) > (g + 100_000) * 64);
    }

    /// A hostile or broken sequencer quoting a huge base fee cannot make the payer authorize more than the cap.
    #[test]
    fn max_fee_is_capped() {
        let g = update_gas_limit(2);
        assert_eq!(
            capped_max_fee(g, 8, 8, DEFAULT_MAX_FEE_CAP),
            max_fee_for(g, 8, 8)
        );
        assert_eq!(
            capped_max_fee(g, u64::MAX, u64::MAX, DEFAULT_MAX_FEE_CAP),
            DEFAULT_MAX_FEE_CAP
        );
        assert_eq!(capped_max_fee(g, u64::MAX, 8, 5), 5);
        assert!(DEFAULT_MAX_FEE_CAP >= max_fee_for(MAX_GAS_EXEC, 1024, 1024));
    }
}
