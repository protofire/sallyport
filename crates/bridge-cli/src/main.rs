//! `b22`: RFP-022 client, root signer and e2e driver (docs/ARCHITECTURE.md §3).
//!
//! Every command works on a run home (`B22_HOME`, default `target/b22-<network>`):
//! `deployment.json` (the public facts an app ships: RPC, vault, config, operator accounts),
//! `cache.json` (attest headers scanned so far; rebuildable), the operator's LEZ wallet
//! (`<home>/wallet`) and one LEZ wallet per holder (`<home>/wallets/<holder>`). A holder is its
//! wallet's root private account, and its b22 keys come from that account's secret spending key,
//! so the wallet mnemonic alone recovers everything (`mnemonics/<holder>.txt` is the test's
//! stand-in for the user's written-down phrase). `notes/<holder>.json` is client state.
//!
//! ```text
//! b22 e2e --local                      anvil + local vault + fresh LEZ sequencer, mock seal (RISC0_DEV_MODE)
//! b22 e2e --sepolia --groth16-host prover-host  one run, no resume (needs `b22 setup --sepolia` + the deploy)
//! b22 derive <holder> <tok> <d> <i>     C_i, recipient_i
//! b22 deposit|claim|burn <holder> <tok> <d>
//! b22 transfer <from> <to> <tok> <amount> ; b22 receive <holder>
//! b22 sign-root <tok> <d> (--key-file <f> | --key-env <VAR>) [--out <file>] [--loop]
//! b22 gen-signer [--key-file <f>]       new root-signer key on THIS machine; prints the address only
//! b22 accept-root <sig-file>... ; b22 revoke-root <tok> <d> <root>
//! b22 recover <holder> [--mnemonic-file <f>] ; b22 freeze eth|lez mint|burn|both on|off
//! b22 freezer cancel <tok> ; b22 freezer watch [--loop]   (queued vault token changes, freezer key)
//! b22 addr <ENV_VAR> ; b22 setup --local | --sepolia --signer-2 <addr>
//! (prove-release, release and the per-tx leak scans run inside `e2e`; see `Ctx::prove_release`)
//! ```
//! Keys are never printed: Sepolia user/freezer/relayer keys from the environment (`B22_USER_KEY`,
//! `B22_FREEZER_KEY`, `B22_RELAYER_KEY`); root signer 1 from `B22_ROOT_SIGNER_1_KEY`, root
//! signer 2 only on signer host 2 (`gen-signer` there, `sign-root --key-file` there over ssh; this
//! machine never reads it). `--local` uses anvil's well-known dev keys and two LOCAL DEV root
//! signer keys (public constants, both on one machine: not the Sepolia trust setup).
//! `--local` attests anvil blocks through a DEVNET BEACON (see `beacon.rs`), never used on Sepolia.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use alloy_primitives::U256;
use anyhow::{anyhow, bail, ensure, Context, Result};
use attest_program::{
    bls, header_leaf, header_record, header_seed, hroot_seed, instance_id, instance_seed, witness,
    HeaderRecord, InstanceState, Msg,
};
use bridge_cli::eth::*;
use bridge_cli::lez::{pda_mention, Lez, LezTx};
use bridge_cli::*;
use bridge_core::*;
use lee::{AccountId, Actor};
use serde::{Deserialize, Serialize};
use wallet::AccountIdentity;

/// LEZ checkout (1806e87) with `sequencer_service` and `wallet` built; `B22_LEZ_VENDOR` overrides (default `vendor/lez`).
const VENDOR: &str = "vendor/lez";
const CONTRACTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/bridge");
/// `--local` root signers: LOCAL DEV KEYS (public constants, both on this machine). Sepolia uses
/// signer 1 from `B22_ROOT_SIGNER_1_KEY` and signer 2 generated and kept on signer host 2 only.
const LOCAL_ROOT_SIGNERS: [&str; 2] = [
    "1b22000000000000000000000000000000000000000000000000000000000001",
    "1b22000000000000000000000000000000000000000000000000000000000002",
];
/// Where signer host 2 keeps root signer 2 (`b22 gen-signer` writes it; only `b22 sign-root` there reads it).
const PC_SIGNER_KEY: &str = "~/.b22/root-signer-2.key";
/// Environment variable holding the hex key of root signer 1.
const SIGNER_1_ENV: &str = "B22_ROOT_SIGNER_1_KEY";
/// Dev genesis key A of the local sequencer (funded at genesis): LEZ payer, bridge admin.
const LEZ_PAYER_KEY: &str = "10a26a9aec7d34b82364eeae45c5294dbb0a764b000b94eeb9b58511dc487c4d";
const ATTEST_DEPLOY_KEY: &str = "2121212121212121212121212121212121212121212121212121212121212121";
/// anvil's well-known dev accounts 0..2 (public test keys): deployer/depositor, freezer, relayer.
const ANVIL_KEYS: [&str; 3] = [
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
];
const ANVIL_PORT: u16 = 8547;
const LEZ_PORT: u16 = 3052;
/// Fresh sequencer of the Sepolia run (the RFP-021 live one on :3040 is never touched).
const LEZ_PORT_SEPOLIA: u16 = 3053;
/// Sepolia deployer (contracts/bridge/script/Deploy.s.sol); no tx from it before the vault exists.
/// Dev genesis key B: the RFP-021 relayer's LEZ payer (one payer per process).
const LEZ_RELAYER_KEY: &str = "717940b1cc55e5d6b2066dbf1d9a3f26f212f4db08d02388177fcfedd8a9be1b";
const DEVNET_KEY: [u8; 32] = [0xDE; 32];
const D_USDT: u128 = 100_000_000;
const D_ETH: u128 = 10_000_000_000_000_000;
const ETH: Tok = [0; 20];

fn vendor() -> String {
    std::env::var("B22_LEZ_VENDOR").unwrap_or_else(|_| VENDOR.into())
}

// ------------------------------------------------------------------ run home

/// `deployment.json`: public facts of one deployment (what an app ships). No holder data.
#[derive(Serialize, Deserialize, Clone, Default)]
struct State {
    network: String,
    eth_rpc: String,
    vault: String,
    usdt: String,
    /// hex borsh of the `BridgeConfig` (checked against the vault's `CONFIG_ID` on every load)
    bridge_config: String,
    payer: String,
    freezer_lez: String,
    lez_from: u64,
    eth_from: u64,
    devnet_genesis_time: u64,
}

/// `cache.json`: recorded attest headers in acceptance order and the LEZ block scanned up to
/// (public chain data; deleting it only costs a rescan).
#[derive(Serialize, Deserialize, Clone, Default)]
struct Cache {
    recorded: Vec<String>,
    scanned_to: u64,
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct Notes {
    deposits: Vec<Dep>,
    burns: Vec<BurnRec>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Dep {
    tok: String,
    d: String,
    i: u64,
    block_hash: String,
    block_number: u64,
    tx_index: u32,
    log_index: u32,
}

#[derive(Serialize, Deserialize, Clone)]
struct BurnRec {
    tok: String,
    d: String,
    j: u64,
    index: u64,
}

/// Credits for display, each with its config prefix (a look-alike config can reuse a token address).
fn fmt_credits(cs: &[(u64, Cfg, Tok, u128)]) -> String {
    let v: Vec<String> = cs
        .iter()
        .map(|(_, c, t, a)| format!("{} {a} (cfg 0x{})", tname(t), hex::encode(&c[..4])))
        .collect();
    format!("[{}]", v.join(", "))
}

fn hx<const N: usize>(s: &str) -> Result<[u8; N]> {
    hex::decode(s.trim_start_matches("0x"))?
        .try_into()
        .map_err(|_| anyhow!("expected {N} bytes of hex")) // never echo the input: it may be a key
}

fn tok_of(s: &str, usdt: &str) -> Result<Tok> {
    match s {
        "eth" | "ETH" => Ok(ETH),
        "usdt" | "USDT" => hx(usdt),
        x => hx(x),
    }
}

fn tname(t: &Tok) -> &'static str {
    if *t == ETH {
        "ETH"
    } else {
        "USDT"
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn short(b: &[u8]) -> String {
    let h = hex::encode(b);
    format!("0x{}…{}", &h[..8], &h[h.len() - 4..])
}

fn env_key(name: &str) -> Result<[u8; 32]> {
    hx(std::env::var(name)
        .with_context(|| format!("{name} not set"))?
        .trim())
}

/// Leak scan: panics on a hit (the scan is part of the evidence).
fn scan(step: &str, hay: &[u8], needles: Vec<(&str, Vec<u8>)>) {
    let n: Vec<(String, Vec<u8>)> = needles
        .into_iter()
        .map(|(a, b)| (a.to_string(), b))
        .collect();
    let hit = leaks(hay, &n);
    let names: Vec<&str> = n.iter().map(|(a, _)| a.as_str()).collect();
    assert!(hit.is_empty(), "scan-leaks {step}: FOUND {hit:?}");
    println!(
        "    scan-leaks {step}: clean ({} bytes; absent: {})",
        hay.len(),
        names.join(", ")
    );
}

struct Log {
    lat: Vec<(String, f64)>,
    txs: Vec<(String, String, String)>,
}

impl Log {
    fn lat(&mut self, step: &str, t: Instant) {
        let s = t.elapsed().as_secs_f64();
        println!("    [{s:.1} s] {step}");
        self.lat.push((step.into(), s));
    }
    fn tx(&mut self, step: &str, chain: &str, info: String) {
        println!("  {chain} {step}: {info}");
        self.txs.push((step.into(), chain.into(), info));
    }
}

struct Ctx {
    home: PathBuf,
    st: State,
    cache: Cache,
    eth: Eth,
    lez: Lez,
    bc: BridgeConfig,
    cfg: Cfg,
    vault: [u8; 20],
    usdt: Tok,
    log: Log,
    local: bool,
}

fn save_json<T: Serialize>(p: &Path, v: &T) -> Result<()> {
    std::fs::create_dir_all(p.parent().unwrap())?;
    std::fs::write(p, serde_json::to_string_pretty(v)? + "\n")?;
    Ok(())
}

fn wallet_cli(home: &Path, args: &[&str]) -> Result<String> {
    wallet_cli_at(&home.join("wallet"), args)
}

/// The vendored `wallet` CLI on the wallet at `dir`.
fn wallet_cli_at(dir: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new(format!("{}/target/release/wallet", vendor()))
        .args(args)
        .env("LEE_WALLET_HOME_DIR", dir)
        .env("LEE_WALLET_PASSWORD", "")
        .env("SUPPRESS_VERBOSE_PRINTS", "1")
        .output()?;
    let s =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    ensure!(
        out.status.success(),
        "wallet {}: {s}",
        args.first().unwrap_or(&"")
    );
    Ok(s)
}

fn set_wallet_env(home: &Path) {
    std::env::set_var("LEE_WALLET_HOME_DIR", home.join("wallet"));
    std::env::set_var("LEE_WALLET_PASSWORD", "");
    std::env::set_var("SUPPRESS_VERBOSE_PRINTS", "1");
}

impl Ctx {
    async fn load(home: &Path) -> Result<Self> {
        let st: State =
            serde_json::from_str(&std::fs::read_to_string(home.join("deployment.json"))?)?;
        let cache: Cache = match std::fs::read_to_string(home.join("cache.json")) {
            Ok(s) => serde_json::from_str(&s)?,
            Err(_) => Cache {
                recorded: vec![],
                scanned_to: st.lez_from,
            },
        };
        set_wallet_env(home);
        let mut eth = Eth::new(&st.eth_rpc).await?;
        let local = st.network == "local";
        if local {
            eth.poll = Duration::from_millis(200);
        } else {
            eth.poll = Duration::from_secs(4);
        }
        let bc: BridgeConfig = borsh::from_slice(&hex::decode(&st.bridge_config)?)?;
        let vault = hx(&st.vault)?;
        // cfg only from the vault's immutable CONFIG_ID (docs/ARCHITECTURE.md §3.4); the local config must hash to it
        let cfg = check_cfg(
            &Vault {
                eth: &eth,
                addr: vault,
            }
            .config_id()
            .await?,
            &bc,
        )?;
        let mut lez = Lez::open(st.payer.parse().map_err(|e| anyhow!("{e:?}"))?)?;
        // the deployed program is the one the config names; a machine whose own build differs (image
        // ids are build-path dependent) can still read and sign, but must not prove
        if lez.bridge.value() != &bc.bridge_program_id {
            eprintln!(
                "note: local BRIDGE_ID build differs from the deployed bridge; read/sign only"
            );
            lez.bridge = AccountId::new(bc.bridge_program_id);
        }
        Ok(Self {
            home: home.into(),
            usdt: hx(&st.usdt)?,
            st,
            cache,
            eth,
            lez,
            bc,
            cfg,
            vault,
            log: Log {
                lat: vec![],
                txs: vec![],
            },
            local,
        })
    }

    fn save(&self) -> Result<()> {
        save_json(&self.home.join("cache.json"), &self.cache)
    }

    fn vault(&self) -> Vault<'_> {
        Vault {
            eth: &self.eth,
            addr: self.vault,
        }
    }

    fn wallet_dir(&self, holder: &str) -> PathBuf {
        self.home.join("wallets").join(holder)
    }

    /// The holder's own LEZ wallet (its private txs are built and paid there).
    fn hlez(&self, holder: &str) -> Result<Lez> {
        let dir = self.wallet_dir(holder);
        ensure!(
            dir.join("storage.json").exists(),
            "no LEZ wallet for {holder} (recover it with `b22 recover {holder} --mnemonic-file …`)"
        );
        let mut l = Lez::open_at(&dir, self.lez.payer)?;
        l.bridge = self.lez.bridge;
        Ok(l)
    }

    /// b22 keys of `holder`, from its LEZ wallet (mnemonic-derived, no other secret).
    fn keys(&self, holder: &str) -> Result<Keys> {
        Ok(self.hlez(holder)?.holder()?.keys)
    }

    fn holder(&self, holder: &str) -> Result<AccountId> {
        Ok(self.hlez(holder)?.holder()?.account)
    }

    fn holder_names(&self) -> Result<Vec<String>> {
        let mut v: Vec<String> = std::fs::read_dir(self.home.join("wallets"))?
            .filter_map(|e| Some(e.ok()?.file_name().to_str()?.to_string()))
            .collect();
        v.sort();
        Ok(v)
    }

    fn notes_path(&self, holder: &str) -> PathBuf {
        self.home.join(format!("notes/{holder}.json"))
    }

    /// Missing notes = none yet (or wiped: run `recover`); a corrupt file is an error, never an
    /// empty set (that would restart `i`/`j` at 0).
    fn notes(&self, holder: &str) -> Result<Notes> {
        match std::fs::read_to_string(self.notes_path(holder)) {
            Ok(s) => serde_json::from_str(&s).with_context(|| {
                format!(
                    "notes/{holder}.json is corrupt; move it away and run `b22 recover {holder}`"
                )
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Notes::default()),
            Err(e) => Err(e.into()),
        }
    }

    fn save_notes(&self, holder: &str, n: &Notes) -> Result<()> {
        save_json(&self.notes_path(holder), n)
    }

    fn eth_key(&self, role: usize) -> Result<[u8; 32]> {
        if self.local {
            return hx(ANVIL_KEYS[role]);
        }
        // fresh keys from the environment (never the deployer: no deployer tx before the vault exists)
        env_key(["B22_USER_KEY", "B22_FREEZER_KEY", "B22_RELAYER_KEY"][role])
    }

    fn inst(&self) -> Actor {
        let a = self.lez.attest;
        Actor::new(
            program_tests::pda(a, instance_seed(&self.bc.instance_id)),
            a,
        )
    }

    async fn instance(&self) -> Result<InstanceState> {
        Ok(borsh::from_slice(&self.lez.state(self.inst()).await?)?)
    }

    async fn token_state(&self, tok: &Tok) -> Result<TokenState> {
        self.token_state_opt(tok)
            .await?
            .ok_or_else(|| anyhow!("token {} not registered on LEZ", hex::encode(tok)))
    }

    /// `None` when the token has no LEZ token PDA under this config.
    async fn token_state_opt(&self, tok: &Tok) -> Result<Option<TokenState>> {
        let s = self
            .lez
            .pda_state(self.lez.bridge, token_seed(&self.cfg, tok))
            .await?;
        if s.is_empty() {
            return Ok(None);
        }
        Ok(Some(borsh::from_slice(&s)?))
    }

    // ---------------------------------------------------------------- Ethereum: deposit

    async fn deposit(&mut self, holder: &str, tok: Tok, d: u128) -> Result<Dep> {
        let keys = self.keys(holder)?;
        let mut notes = self.notes(holder)?;
        // liveness gate: never deposit while the attest instance is stale (022-compliance)
        let fin = self
            .instance()
            .await?
            .store
            .finalized_header
            .execution_block_hash;
        let fb = self
            .eth
            .call("eth_getBlockByHash", serde_json::json!([h(&fin), false]))
            .await?;
        ensure!(
            !fb.is_null(),
            "the attest instance's finalized block {} is unknown to the Ethereum RPC",
            h(&fin)
        );
        check_attest_live(qty(&fb["number"])?, self.eth.block_number().await?)?;
        let i = notes
            .deposits
            .iter()
            .filter(|x| x.tok == hex::encode(tok) && x.d == d.to_string())
            .map(|x| x.i + 1)
            .max()
            .unwrap_or(0);
        let c = keys.commitment(&self.cfg, &tok, d, i);
        let key = self.eth_key(0)?;
        let t = Instant::now();
        if tok != ETH {
            let a = self
                .eth
                .send(
                    &key,
                    &tok,
                    U256::ZERO,
                    &abi(SIG_APPROVE, &[w_addr(&self.vault), w_u(d)], None),
                )
                .await?;
            ensure!(a.ok, "approve reverted");
        }
        let data = abi(SIG_DEPOSIT, &[w_addr(&tok), w_u(d), c], None);
        let value = if tok == ETH {
            U256::from(d)
        } else {
            U256::ZERO
        };
        let r = self.eth.send(&key, &self.vault, value, &data).await?;
        ensure!(r.ok, "deposit reverted");
        let topic0 = h(&deposit_topic0());
        let log_index = r
            .logs
            .iter()
            .position(|l| l["topics"][0].as_str() == Some(topic0.as_str()))
            .ok_or_else(|| anyhow!("no Deposit log"))? as u32;
        let dep = Dep {
            tok: hex::encode(tok),
            d: d.to_string(),
            i,
            block_hash: r.block_hash.clone(),
            block_number: r.block,
            tx_index: r.tx_index,
            log_index,
        };
        self.log.lat(
            &format!("deposit {} i={i} (Ethereum inclusion)", tname(&tok)),
            t,
        );
        self.log.tx(
            &format!("deposit {holder} {} i={i}", tname(&tok)),
            "eth",
            format!("{} block {} C={}", r.hash, r.block, short(&c)),
        );
        let nk = keys.nk(&self.cfg, &tok, d, i);
        scan(
            "deposit calldata",
            &data,
            vec![
                ("nk", nk.to_vec()),
                ("holder LEZ account", self.holder(holder)?.value().to_vec()),
            ],
        );
        notes.deposits.push(dep.clone());
        self.save_notes(holder, &notes)?;
        Ok(dep)
    }

    // ---------------------------------------------------------------- attest headers

    /// HeaderRecords the attest instance accepted, in acceptance order (scans LEZ blocks for
    /// successful Init/Update txs to the instance; checked against the instance's frontier).
    async fn recorded(&mut self) -> Result<Vec<HeaderRecord>> {
        let head = self.lez.head().await?;
        let inst = self.inst().account_id;
        let id = self.bc.instance_id;
        for b in self.cache.scanned_to.max(self.st.lez_from)..=head {
            let Some(block) = self
                .lez
                .w
                .get_block(b)
                .await
                .map_err(|e| anyhow!("{e:?}"))?
            else {
                continue;
            };
            for (pos, tx) in block.body.transactions.iter().enumerate() {
                let common::transaction::LeeTransaction::Public(p) = tx else {
                    continue;
                };
                if p.message.execution.root.to.account_id != inst || block.body.is_reverted(pos) {
                    continue;
                }
                let ebh = match borsh::from_slice::<Msg>(&p.message.execution.root.message) {
                    Ok(Msg::Init { bootstrap, .. }) => bootstrap.header.execution_block_hash(),
                    Ok(Msg::Update { update, .. }) | Ok(Msg::UpdateBegin { update, .. }) => {
                        match update.finalized_header {
                            Some((f, _)) => f.execution_block_hash(),
                            None => continue,
                        }
                    }
                    _ => continue,
                };
                let e = hex::encode(ebh);
                if !self.cache.recorded.contains(&e)
                    && !self
                        .lez
                        .pda_state(self.lez.attest, header_seed(&id, &ebh))
                        .await?
                        .is_empty()
                {
                    self.cache.recorded.push(e);
                }
            }
        }
        self.cache.scanned_to = head + 1;
        self.save()?;
        let mut recs = vec![];
        for e in &self.cache.recorded {
            let s = self
                .lez
                .pda_state(self.lez.attest, header_seed(&id, &hx(e)?))
                .await?;
            recs.push(borsh::from_slice::<HeaderRecord>(&s)?);
        }
        let mut f = Frontier::default();
        for r in &recs {
            f.append(header_leaf(r)).unwrap();
        }
        ensure!(
            f.root() == self.instance().await?.headers.root(),
            "recorded header list does not rebuild the instance frontier"
        );
        Ok(recs)
    }

    /// `--local`: the devnet beacon finalizes EL block `ebh` (one attest `Update` tx).
    async fn devnet_record(&mut self, ebh: [u8; 32]) -> Result<LezTx> {
        let dn = beacon::Devnet::new(self.eth.chain_id, self.st.devnet_genesis_time, &DEVNET_KEY);
        let st = self.instance().await?;
        let u = dn.finality(st.store.finalized_header.beacon.slot, ebh);
        let now = dn.now_slot();
        let p = lc_core::prepare_update(&st.cfg.chain, &st.store, &u, now)
            .map_err(|e| anyhow!("update pre-check {e:?}"))?;
        let wit =
            witness::for_pairing(&p.pairing).ok_or_else(|| anyhow!("bad devnet signature"))?;
        let hints = bls::uncompress_non_signers(&p.pairing);
        let id = self.bc.instance_id;
        let f = p.verified.finalized_header.clone().unwrap();
        let root = st
            .headers
            .clone()
            .append(header_leaf(&header_record(id, &st.cfg, &f)))
            .unwrap();
        let a = self.lez.attest;
        let seeds = [
            header_seed(&id, &f.execution_block_hash),
            hroot_seed(&id, &root),
        ];
        let actors = seeds
            .iter()
            .map(|s| Actor::new(program_tests::pda(a, *s), a))
            .collect();
        let ev: Vec<_> = seeds.iter().map(|s| (a, *s)).collect();
        let msg = Msg::Update {
            instance_id: id,
            update: u,
            non_signers: hints,
            witness: wit,
            now_slot: now,
        };
        let r = self
            .lez
            .public(self.lez.payer, self.inst(), actors, &ev, &msg, 10_000_000)
            .await?;
        ensure!(r.ok, "devnet Update reverted");
        Ok(r)
    }

    // ---------------------------------------------------------------- LEZ: claim / transfer / burn

    async fn claim(&mut self, holder: &str, dep: &Dep) -> Result<LezTx> {
        let keys = self.keys(holder)?;
        let (tok, d): (Tok, u128) = (hx(&dep.tok)?, dep.d.parse()?);
        let nk = keys.nk(&self.cfg, &tok, d, dep.i);
        let recs = self.recorded().await?;
        let leaves: Vec<[u8; 32]> = recs.iter().map(header_leaf).collect();
        // anchor: the earliest recorded EL block at or after the deposit block
        let mut anchor = None;
        for (k, r) in recs.iter().enumerate() {
            let b = self
                .eth
                .call(
                    "eth_getBlockByHash",
                    serde_json::json!([h(&r.execution_block_hash), false]),
                )
                .await?;
            if b.is_null() {
                continue;
            }
            let n = qty(&b["number"])?;
            if n >= dep.block_number && anchor.is_none_or(|(_, m)| n < m) {
                anchor = Some((k, n));
            }
        }
        let (k, an) = anchor.ok_or_else(|| {
            anyhow!(
                "no recorded header at or after deposit block {} yet",
                dep.block_number
            )
        })?;
        ensure!(
            an - dep.block_number <= inclusion::MAX_ANCESTRY as u64,
            "anchor too far"
        );
        let (rpc, chain, vault) = (self.st.eth_rpc.clone(), self.eth.chain_id, h(&self.vault));
        let (bh, aeb) = (dep.block_hash.clone(), h(&recs[k].execution_block_hash));
        let (ti, li) = (dep.tx_index, dep.log_index);
        let (m, anc) = tokio::task::spawn_blocking(move || -> Result<_> {
            let el = relayer::el::El::new(chain, &rpc, None, None)?;
            let m = el.fetch_attest(&bh, &vault, None, Some((ti, li)))?;
            let anc = if aeb == bh {
                None
            } else {
                Some(el.fetch_ancestry(&bh, &aeb, inclusion::MAX_ANCESTRY)?)
            };
            Ok((m, anc))
        })
        .await??;
        let (exec_header_rlp, ancestry) = match anc {
            None => (m.exec_header_rlp.to_vec(), vec![]),
            Some((a, v)) => (a.to_vec(), v.iter().map(|x| x.to_vec()).collect()),
        };
        let tst = self.token_state(&tok).await?;
        let msg = BridgeMsg::Claim {
            bridge_cfg: self.bc.clone(),
            token_entry: tst.entry.clone(),
            d,
            header: recs[k].clone(),
            header_index: k as u64,
            header_path: merkle_path(&leaves, k),
            exec_header_rlp,
            ancestry,
            tx_index: ti,
            log_index: li,
            receipt: m.receipt.to_vec(),
            receipt_proof: m.receipt_proof_nodes.iter().map(|x| x.to_vec()).collect(),
            nk,
        };
        let root = bridge::host::claim_root(&msg).ok_or_else(|| anyhow!("bad header path"))?;
        let id = self.bc.instance_id;
        let who = self.holder(holder)?;
        let b = self.lez.bridge;
        let mentions = vec![
            AccountIdentity::PrivateOwned(who).select_program_actor_state(b),
            pda_mention(b, config_seed(&self.cfg)),
            pda_mention(self.lez.attest, hroot_seed(&id, &root)),
            pda_mention(b, token_seed(&self.cfg, &tok)),
            pda_mention(b, pnf(&nk)),
        ];
        let t = Instant::now();
        let r = self
            .hlez(holder)?
            .private(mentions, borsh::to_vec(&msg)?, vec![])
            .await?;
        self.log.lat(
            &format!(
                "claim {} i={} (LEZ dev-mode tx + inclusion)",
                tname(&tok),
                dep.i
            ),
            t,
        );
        self.log.tx(
            &format!("claim {holder} {} i={}", tname(&tok), dep.i),
            "lez",
            format!(
                "{} block {} {} (anchor leaf {k}, {} ancestry)",
                r.hash,
                r.block,
                if r.ok { "ok" } else { "REVERTED" },
                an - dep.block_number
            ),
        );
        ensure!(r.ok, "claim reverted");
        scan(
            "claim",
            &r.bytes,
            vec![
                ("deposit block hash", hx::<32>(&dep.block_hash)?.to_vec()),
                (
                    "header PDA",
                    program_tests::pda(self.lez.attest, header_seed(&id, &hx(&dep.block_hash)?))
                        .value()
                        .to_vec(),
                ),
                ("commitment C", commit(&nk).to_vec()),
                ("nk", nk.to_vec()),
                ("holder account", who.value().to_vec()),
                ("receipt", m.receipt[..m.receipt.len().min(48)].to_vec()),
                ("vault address", self.vault.to_vec()),
            ],
        );
        Ok(r)
    }

    async fn transfer(&mut self, from: &str, to: &str, tok: Tok, amount: u128) -> Result<LezTx> {
        let (a, bh) = (self.holder(from)?, self.hlez(to)?.holder()?);
        let bacc = bh.account;
        let b = self.lez.bridge;
        let msg = BridgeMsg::Transfer {
            cfg: self.cfg,
            tok,
            amount,
            to: bacc,
        };
        let t = Instant::now();
        // B is another wallet: A seals the Credit to B's public keys only
        let r = self
            .hlez(from)?
            .private(
                vec![AccountIdentity::PrivateOwned(a).select_program_actor_state(b)],
                borsh::to_vec(&msg)?,
                vec![bh.foreign.select_program_actor_state(b)],
            )
            .await?;
        self.log.lat(
            &format!("transfer {from}→{to} send (LEZ dev-mode tx + inclusion)"),
            t,
        );
        self.log.tx(
            &format!("transfer {from}→{to} {} {amount} (send)", tname(&tok)),
            "lez",
            format!(
                "{} block {} {}",
                r.hash,
                r.block,
                if r.ok { "ok" } else { "REVERTED" }
            ),
        );
        ensure!(r.ok, "transfer reverted");
        scan(
            "transfer send",
            &r.bytes,
            vec![
                ("sender account", a.value().to_vec()),
                ("recipient account", bacc.value().to_vec()),
            ],
        );
        Ok(r)
    }

    async fn receive(&mut self, holder: &str) -> Result<Vec<LezTx>> {
        let mut hl = self.hlez(holder)?;
        let who = hl.holder()?.account;
        let mut others = vec![];
        for n in self.holder_names()? {
            others.push((n.clone(), self.holder(&n)?.value().to_vec()));
        }
        let mut out = vec![];
        for p in hl.pending_bridge().await? {
            if p.body.to.account_id != who {
                continue;
            }
            let credit = bridge_credits(
                self.lez.bridge.value(),
                &[(0, *self.lez.bridge.value(), p.body.message.clone())],
            );
            let (ours, foreign) = split_credits(&credit, &self.cfg);
            if ours.is_empty() {
                // a look-alike config's Credit (or not a Credit): not this vault's money, not applied
                println!(
                    "  receive {holder}: IGNORED pending bridge message (not a Credit of cfg 0x{}): {}",
                    hex::encode(self.cfg),
                    fmt_credits(&foreign)
                );
                continue;
            }
            let t = Instant::now();
            let r = hl.receive(who, p).await?;
            self.log.lat(
                &format!("receive {holder} (LEZ dev-mode tx + inclusion)"),
                t,
            );
            self.log.tx(
                &format!("receive {holder} {credit:?}"),
                "lez",
                format!(
                    "{} block {} {}",
                    r.hash,
                    r.block,
                    if r.ok { "ok" } else { "REVERTED" }
                ),
            );
            ensure!(r.ok, "receive reverted");
            scan(
                "transfer receive",
                &r.bytes,
                others
                    .iter()
                    .map(|(n, a)| (n.as_str(), a.clone()))
                    .collect(),
            );
            out.push(r);
        }
        Ok(out)
    }

    async fn burn(&mut self, holder: &str, tok: Tok, d: u128) -> Result<(BurnNote, u64, LezTx)> {
        let keys = self.keys(holder)?;
        let mut notes = self.notes(holder)?;
        let mut j = notes.burns.iter().map(|x| x.j + 1).max().unwrap_or(0);
        let note = loop {
            if let Some(n) = keys.burn(&self.cfg, &tok, d, j) {
                break n;
            }
            j += 1;
        };
        let tst = self.token_state(&tok).await?;
        let index = bridge::host::next_index(&tst, d);
        let call = bridge::host::burn(self.lez.bridge, &self.bc, &tst.entry, d, index, note.b);
        let who = self.holder(holder)?;
        let b = self.lez.bridge;
        let mentions = vec![
            AccountIdentity::PrivateOwned(who).select_program_actor_state(b),
            pda_mention(b, config_seed(&self.cfg)),
            pda_mention(b, token_seed(&self.cfg, &tok)),
            pda_mention(b, leaf_seed(&self.cfg, &tok, d, index)),
        ];
        let t = Instant::now();
        let r = self
            .hlez(holder)?
            .private(mentions, borsh::to_vec(&call.msg)?, vec![])
            .await?;
        self.log.lat(
            &format!(
                "burn {holder} {} (LEZ dev-mode tx + inclusion)",
                tname(&tok)
            ),
            t,
        );
        self.log.tx(
            &format!("burn {holder} {} j={j} leaf {index}", tname(&tok)),
            "lez",
            format!(
                "{} block {} {} B={}",
                r.hash,
                r.block,
                if r.ok { "ok" } else { "REVERTED" },
                short(&note.b)
            ),
        );
        ensure!(r.ok, "burn reverted");
        scan(
            "burn",
            &r.bytes,
            vec![
                ("rk", note.rk.to_vec()),
                ("recipient_j", note.recipient.to_vec()),
                ("Nb", note.nb.to_vec()),
                ("holder account", who.value().to_vec()),
            ],
        );
        notes.burns.push(BurnRec {
            tok: hex::encode(tok),
            d: d.to_string(),
            j,
            index,
        });
        self.save_notes(holder, &notes)?;
        Ok((note, index, r))
    }

    // ---------------------------------------------------------------- root signing (INTERIM, CUSTODIAL)

    /// Picks `n = change + minLezDepth`, where change = the block that wrote the last leaf of the
    /// `(tok, d)` tree (only a `RecordBurn` for that tree writes it; claims, transfers and other
    /// denominations do not move `n`), waits for `n`, re-reads the tree and restarts if a burn for
    /// `(tok, d)` landed meanwhile, then signs the attestation at `n`.
    async fn sign_root(
        &self,
        key: &[u8; 32],
        tok: Tok,
        d: u128,
    ) -> Result<(RootAttestation, [u8; 65])> {
        let depth = self.vault().min_lez_depth().await?;
        loop {
            let count = tree_count(&self.token_state(&tok).await?, d);
            ensure!(count > 0, "no burn in the {} {d} tree yet", tname(&tok));
            let leaf = Actor::new(
                leaf_pda(&self.lez.bridge, &self.cfg, &tok, d, count - 1),
                self.lez.bridge,
            );
            let head = self.lez.head().await?;
            let change = self
                .lez
                .last_write(leaf, self.st.lez_from, head)
                .await?
                .ok_or_else(|| anyhow!("leaf {} of the {d} tree never written", count - 1))?;
            let n = sign_height(change, depth);
            while self.lez.head().await? < n {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            // read after n: an unchanged count means no (tok, d) burn at or before n
            let st = self.token_state(&tok).await?;
            if tree_count(&st, d) != count {
                continue;
            }
            let att = root_attestation(
                self.eth.chain_id,
                self.vault,
                &st,
                d,
                n,
                self.lez.block_hash(n).await?,
            );
            return Ok((att.clone(), sign_digest(key, &att.digest())?));
        }
    }

    async fn accept_root(&mut self, att: &RootAttestation, sigs: &[[u8; 65]]) -> Result<TxOut> {
        let a = combine_sigs(&att.digest(), sigs)?;
        let data = abi(
            SIG_ACCEPT,
            &[
                w_addr(&att.token),
                w_u(att.denom),
                att.burn_root,
                w_u(att.count.into()),
                w_u(att.lez_height.into()),
                att.lez_block_hash,
            ],
            Some(&a),
        );
        let t = Instant::now();
        let r = self
            .eth
            .send(&self.eth_key(2)?, &self.vault, U256::ZERO, &data)
            .await?;
        self.log.lat(
            &format!("acceptBurnRoot {} (Ethereum inclusion)", tname(&att.token)),
            t,
        );
        self.log.tx(
            &format!(
                "acceptBurnRoot {} root {} count {} lezHeight {}",
                tname(&att.token),
                short(&att.burn_root),
                att.count,
                att.lez_height
            ),
            "eth",
            format!(
                "{} block {} gas {} lezBlockHash {}",
                r.hash,
                r.block,
                r.gas_used,
                short(&att.lez_block_hash)
            ),
        );
        ensure!(r.ok, "acceptBurnRoot reverted");
        Ok(r)
    }

    async fn revoke_root(&mut self, tok: Tok, d: u128, root: [u8; 32]) -> Result<TxOut> {
        let r = self
            .eth
            .send(
                &self.eth_key(1)?,
                &self.vault,
                U256::ZERO,
                &abi(SIG_REVOKE, &[w_addr(&tok), w_u(d), root], None),
            )
            .await?;
        self.log.tx(
            &format!("revokeRoot {} {}", tname(&tok), short(&root)),
            "eth",
            format!("{} block {}", r.hash, r.block),
        );
        ensure!(r.ok, "revokeRoot reverted");
        Ok(r)
    }

    // ---------------------------------------------------------------- release

    async fn leaves(&self, tok: &Tok, d: u128, count: u64) -> Result<Vec<[u8; 32]>> {
        let mut out = vec![];
        for i in 0..count {
            out.push(hx::<32>(&hex::encode(
                self.lez
                    .pda_state(self.lez.bridge, leaf_seed(&self.cfg, tok, d, i))
                    .await?,
            ))?);
        }
        Ok(out)
    }

    /// Membership proof request + seal for releasing `note` (leaf `index`) under accepted `att`.
    async fn prove_release(
        &mut self,
        note: &BurnNote,
        index: u64,
        att: &RootAttestation,
        groth16_host: Option<&str>,
    ) -> Result<(ReleaseJournal, Vec<u8>)> {
        let leaves = self.leaves(&att.token, att.denom, att.count).await?;
        let path = merkle_path(&leaves, index as usize);
        ensure!(
            is_member(note, index, &path, &att.burn_root),
            "burn is not leaf {index} of root {}",
            short(&att.burn_root)
        );
        let relayer = signer_address(&self.eth_key(2)?)?;
        let j = ReleaseJournal {
            chain_id: self.eth.chain_id,
            vault: self.vault,
            config_id: self.cfg,
            token: att.token,
            denom: att.denom,
            burn_root: att.burn_root,
            nb: note.nb,
            recipient: note.recipient,
            relayer,
            fee: self.vault().standard_fee(&att.token, att.denom).await?,
        };
        let t = Instant::now();
        let seal = match groth16_host {
            None => {
                ensure!(
                    std::env::var("RISC0_DEV_MODE").is_ok_and(|v| v == "1"),
                    "mock seal only under RISC0_DEV_MODE=1"
                );
                let image: [u8; 32] = self.vault().image_id().await?;
                let mut w = [0u32; 8];
                for (k, c) in image.chunks(4).enumerate() {
                    w[k] = u32::from_le_bytes(c.try_into().unwrap());
                }
                mock_seal(w, &j.encode())
            }
            Some(host) => remote_groth16(host, &self.home, &note.rk, index, &path, &j)?,
        };
        self.log.lat(
            &format!(
                "membership proof + wrap ({})",
                groth16_host.unwrap_or("mock seal")
            ),
            t,
        );
        Ok((j, seal))
    }

    async fn release(&mut self, j: &ReleaseJournal, seal: &[u8]) -> Result<TxOut> {
        let data = abi(
            SIG_RELEASE,
            &[
                w_addr(&j.token),
                w_u(j.denom),
                j.burn_root,
                j.nb,
                w_addr(&j.recipient),
                w_addr(&j.relayer),
                w_u(j.fee),
            ],
            Some(seal),
        );
        let t = Instant::now();
        let r = self
            .eth
            .send(&self.eth_key(2)?, &self.vault, U256::ZERO, &data)
            .await?;
        self.log.lat(
            &format!("release {} (Ethereum inclusion)", tname(&j.token)),
            t,
        );
        self.log.tx(
            &format!(
                "release {} to {} fee {}",
                tname(&j.token),
                h(&j.recipient),
                j.fee
            ),
            "eth",
            format!("{} block {} gas {}", r.hash, r.block, r.gas_used),
        );
        ensure!(r.ok, "release reverted");
        Ok(r)
    }

    // ---------------------------------------------------------------- recovery

    /// Recovery from the holder's wallet alone (mnemonic-derived keys): every `(tok, d)` the
    /// vault's `Deposit` logs and the LEZ token PDAs show, gap-limit scans, then the notes rebuilt.
    async fn recover(&mut self, holder: &str) -> Result<Recovered> {
        let keys = self.keys(holder)?;
        struct Live {
            seen: std::collections::HashSet<(Tok, u128, [u8; 32])>,
            trees: BTreeMap<(Tok, u128), Vec<[u8; 32]>>,
            claimed: std::collections::HashSet<[u8; 32]>,
            spent: std::collections::HashSet<[u8; 32]>,
        }
        impl ChainView for Live {
            fn deposit_seen(&self, t: &Tok, d: u128, c: &[u8; 32]) -> bool {
                self.seen.contains(&(*t, d, *c))
            }
            fn claimed(&self, n: &[u8; 32]) -> bool {
                self.claimed.contains(n)
            }
            fn burn_leaves(&self, t: &Tok, d: u128) -> Vec<[u8; 32]> {
                self.trees.get(&(*t, d)).cloned().unwrap_or_default()
            }
            fn released(&self, nb: &[u8; 32]) -> bool {
                self.spent.contains(nb)
            }
        }
        let mut v = Live {
            seen: Default::default(),
            trees: Default::default(),
            claimed: Default::default(),
            spent: Default::default(),
        };
        // every Deposit of this config, any token (one bulk query; filtered locally)
        let logs = self
            .eth
            .logs(
                &self.vault,
                &[Some(deposit_topic0()), None, None, Some(self.cfg)],
                self.st.eth_from,
            )
            .await?;
        let mut deps = vec![];
        for l in &logs {
            let tok: Tok = unhex(&l["topics"][2])?[12..].try_into()?;
            let d = U256::from_be_slice(&unhex(&l["data"])?).to::<u128>();
            v.seen.insert((tok, d, b32(&unhex(&l["topics"][1])?)?));
            deps.push((tok, d));
        }
        let mut toks: Vec<Tok> = deps.iter().map(|x| x.0).collect();
        toks.sort();
        toks.dedup();
        let mut states = vec![];
        for t in &toks {
            match self.token_state_opt(t).await? {
                Some(st) => states.push(st),
                None => println!(
                    "  recover {holder}: WARNING token {} has vault deposits but no LEZ token PDA; skipped",
                    tname(t)
                ),
            }
        }
        deps.retain(|(t, _)| states.iter().any(|s| s.entry.tok == *t));
        v.seen
            .retain(|(t, _, _)| states.iter().any(|s| s.entry.tok == *t));
        let pairs = recovery_pairs(&deps, &states);
        for (tok, d) in &pairs {
            let st = states.iter().find(|s| s.entry.tok == *tok).unwrap();
            let n = bridge::host::next_index(st, *d);
            v.trees.insert((*tok, *d), self.leaves(tok, *d, n).await?);
        }
        // pass 1 finds candidates (seen deposits, own leaves); pass 2 with their chain status
        let first = recover(&keys, &self.cfg, &pairs, &v);
        for u in &first.unclaimed {
            if !self
                .lez
                .pda_state(self.lez.bridge, pnf(&u.nk))
                .await?
                .is_empty()
            {
                v.claimed.insert(pnf(&u.nk));
            }
        }
        for u in &first.unreleased {
            if self.vault().spent(&u.note.nb).await? {
                v.spent.insert(u.note.nb);
            }
        }
        let r = recover(&keys, &self.cfg, &pairs, &v);
        // rebuild the client notes from chain data alone
        let mut notes = Notes::default();
        for l in &logs {
            let tok: Tok = unhex(&l["topics"][2])?[12..].try_into()?;
            let d = U256::from_be_slice(&unhex(&l["data"])?).to::<u128>();
            let c = b32(&unhex(&l["topics"][1])?)?;
            let next = r
                .next_i
                .iter()
                .find(|x| x.0 == tok && x.1 == d)
                .map_or(0, |x| x.2);
            let Some(i) = (0..next).find(|i| keys.commitment(&self.cfg, &tok, d, *i) == c) else {
                continue;
            };
            let rc = self
                .eth
                .call(
                    "eth_getTransactionReceipt",
                    serde_json::json!([l["transactionHash"]]),
                )
                .await?;
            let li = rc["logs"]
                .as_array()
                .ok_or_else(|| anyhow!("receipt without logs"))?
                .iter()
                .position(|x| x["logIndex"] == l["logIndex"])
                .ok_or_else(|| anyhow!("log not in its receipt"))? as u32;
            notes.deposits.push(Dep {
                tok: hex::encode(tok),
                d: d.to_string(),
                i,
                block_hash: l["blockHash"].as_str().unwrap_or_default().into(),
                block_number: qty(&l["blockNumber"])?,
                tx_index: qty(&l["transactionIndex"])? as u32,
                log_index: li,
            });
        }
        for u in &r.unreleased {
            notes.burns.push(BurnRec {
                tok: hex::encode(u.tok),
                d: u.d.to_string(),
                j: u.note.j,
                index: u.index,
            });
        }
        if r.next_j > 0 && !notes.burns.iter().any(|b| b.j + 1 == r.next_j) {
            notes.burns.push(BurnRec {
                tok: String::new(),
                d: "0".into(),
                j: r.next_j - 1,
                index: u64::MAX,
            });
        }
        self.save_notes(holder, &notes)?;
        let mut hl = self.hlez(holder)?;
        let who = hl.holder()?.account;
        let pending = hl.pending_bridge().await?;
        let credits: Vec<_> = pending
            .iter()
            .filter(|p| p.body.to.account_id == who)
            .map(|p| {
                (
                    p.position,
                    *p.body.to.program_account_id.value(),
                    p.body.message.clone(),
                )
            })
            .collect();
        // the holder's private bridge balance, as the (restored) wallet decrypted it
        hl.w.sync_to_latest_block()
            .await
            .map_err(|e| anyhow!("{e:?}"))?;
        let bal: Holdings =
            hl.w.storage()
                .key_chain()
                .private_account(who)
                .map(|f| f.account.data.actor_state(self.lez.bridge).to_vec())
                .filter(|s| !s.is_empty())
                .map(|s| borsh::from_slice(&s))
                .transpose()?
                .unwrap_or_default();
        let (ours, foreign) = split_credits(
            &bridge_credits(self.lez.bridge.value(), &credits),
            &self.cfg,
        );
        println!(
            "  recover {holder} (account {who}, vault cfg 0x{}): pairs scanned {}; unclaimed deposits {:?}; unreleased burns {:?}; claimed {} released {}; pending credits {}; IGNORED credits of other configs {}; LEZ holdings {}",
            hex::encode(self.cfg),
            pairs.len(),
            r.unclaimed.iter().map(|u| (tname(&u.tok), u.i)).collect::<Vec<_>>(),
            r.unreleased.iter().map(|u| (tname(&u.tok), u.note.j, u.index)).collect::<Vec<_>>(),
            r.claimed,
            r.released,
            fmt_credits(&ours),
            fmt_credits(&foreign),
            bal.iter()
                .map(|((c, t), a)| format!(
                    "{} {a} (cfg 0x{}{})",
                    tname(t),
                    hex::encode(&c[..4]),
                    if *c == self.cfg { "" } else { ", OTHER CONFIG: not this vault" }
                ))
                .collect::<Vec<_>>()
                .join(", ")
        );
        Ok(r)
    }

    // ---------------------------------------------------------------- freeze

    /// `b22 freeze`: reads the current global flags of that chain and changes only the named half
    /// (`both` writes both without reading), then re-reads and prints the resulting state. The
    /// read-modify-write is not atomic: a concurrent freezer tx in between can be overwritten, which
    /// the printed state shows; `both` has no such window.
    async fn freeze_half(&mut self, eth: bool, half: FreezeHalf, on: bool) -> Result<()> {
        if eth {
            let (d, r) = freeze_flags(self.vault().frozen().await?, half, on);
            self.freeze_eth(d, r).await?;
            let (d, r) = self.vault().frozen().await?;
            println!("  Ethereum vault now: deposits frozen {d}, releases frozen {r}");
        } else {
            let (m, b) = freeze_flags(self.lez_paused().await?, half, on);
            self.freeze_lez(m, b).await?;
            let (m, b) = self.lez_paused().await?;
            println!("  LEZ config now: mint paused {m}, burn paused {b}");
        }
        Ok(())
    }

    /// `(paused_mint, paused_burn)` of this config's LEZ config PDA.
    async fn lez_paused(&self) -> Result<(bool, bool)> {
        let s = self
            .lez
            .pda_state(self.lez.bridge, config_seed(&self.cfg))
            .await?;
        ensure!(!s.is_empty(), "LEZ config PDA not found");
        let st: ConfigState = borsh::from_slice(&s)?;
        Ok((st.paused_mint, st.paused_burn))
    }

    /// `b22 freezer cancel <tok>`: drops a queued, unmatured `setToken` change (freezer key).
    async fn cancel_token_change(&mut self, tok: Tok) -> Result<()> {
        let r = self
            .eth
            .send(
                &self.eth_key(1)?,
                &self.vault,
                U256::ZERO,
                &abi(SIG_CANCEL_TOKEN_CHANGE, &[w_addr(&tok)], None),
            )
            .await?;
        self.log.tx(
            &format!("vault cancelTokenChange({})", tname(&tok)),
            "eth",
            format!("{} block {}", r.hash, r.block),
        );
        ensure!(r.ok, "cancelTokenChange reverted");
        println!(
            "  cancelled; pendingTokenAt now {}",
            self.vault().pending_token_at(&tok).await?
        );
        Ok(())
    }

    /// `b22 freezer watch [--loop]`: reports every `TokenChangeQueued` / `MinLezDepthChangeQueued`
    /// of the vault since `from`, with whether it is still pending and the values it would apply.
    /// Returns the next block to scan.
    async fn watch_queued(&self, from: u64) -> Result<u64> {
        let head = self.eth.block_number().await?;
        let now = qty(&self.eth.block("latest").await?["timestamp"])?;
        let t0 = |sig: &str| alloy_primitives::keccak256(sig.as_bytes()).0;
        for l in self
            .eth
            .logs(&self.vault, &[Some(t0(TOKEN_CHANGE_QUEUED))], from)
            .await?
        {
            let (tok, at) = token_change_queued(&l)?;
            let v = self.vault();
            let live = v.pending_token_at(&tok).await? == at && now < at;
            let (cd, cdc, crc) = v.token_params("effectiveToken", &tok).await?;
            let (pd, pdc, prc) = v.token_params("pendingToken", &tok).await?;
            println!(
                "  TokenChangeQueued {} block {} activeAt {at} ({}): delay {cd} -> {pd}, deposit cap {cdc} -> {pdc}, release cap {crc} -> {prc}{}",
                h(&tok),
                qty(&l["blockNumber"])?,
                if live {
                    format!("PENDING, matures in {} s", at - now)
                } else {
                    "matured, cancelled or replaced".into()
                },
                if live {
                    format!("; cancel: b22 freezer cancel {}", h(&tok))
                } else {
                    String::new()
                }
            );
        }
        for l in self
            .eth
            .logs(&self.vault, &[Some(t0(MIN_DEPTH_CHANGE_QUEUED))], from)
            .await?
        {
            let d = unhex(&l["data"])?;
            println!(
                "  MinLezDepthChangeQueued block {}: depth -> {} at {} (decrease; no cancel, signers are trusted anyway)",
                qty(&l["blockNumber"])?,
                word_u64(&d, 0)?,
                word_u64(&d, 1)?
            );
        }
        Ok(head + 1)
    }

    async fn freeze_eth(&mut self, deposits: bool, releases: bool) -> Result<TxOut> {
        let r = self
            .eth
            .send(
                &self.eth_key(1)?,
                &self.vault,
                U256::ZERO,
                &abi(SIG_FROZEN, &[w_bool(deposits), w_bool(releases)], None),
            )
            .await?;
        self.log.tx(
            &format!("vault setFrozen(deposits={deposits}, releases={releases})"),
            "eth",
            format!("{} block {}", r.hash, r.block),
        );
        ensure!(r.ok, "setFrozen reverted");
        Ok(r)
    }

    async fn freeze_lez(&mut self, paused_mint: bool, paused_burn: bool) -> Result<LezTx> {
        let f: AccountId = self.st.freezer_lez.parse().map_err(|e| anyhow!("{e:?}"))?;
        let b = self.lez.bridge;
        let cp = Actor::new(config_pda(&b, &self.cfg), b);
        let msg = BridgeMsg::Freeze(FreezeOp::Global {
            cfg: self.cfg,
            paused_mint,
            paused_burn,
        });
        let r = self
            .lez
            .public(f, Actor::new(f, b), vec![cp], &[], &msg, 2_000_000)
            .await?;
        self.log.tx(
            &format!("LEZ Freeze Global(mint={paused_mint}, burn={paused_burn})"),
            "lez",
            format!(
                "{} block {} {}",
                r.hash,
                r.block,
                if r.ok { "ok" } else { "REVERTED" }
            ),
        );
        ensure!(r.ok, "Freeze reverted");
        Ok(r)
    }
}

/// Groth16 wrap on another machine (the prover host): ships the request over ssh, runs `bridge-prover`
/// there, returns `selector ‖ seal`. The request holds `rk` for one burn only (it is the prover's
/// private input); it is written 0600 and deleted on both sides.
fn remote_groth16(
    host: &str,
    home: &Path,
    rk: &[u8; 32],
    index: u64,
    path: &[[u8; 32]],
    j: &ReleaseJournal,
) -> Result<Vec<u8>> {
    let req = serde_json::json!({
        "rk": hex::encode(rk), "index": index,
        "path": path.iter().map(hex::encode).collect::<Vec<_>>(),
        "journal": hex::encode(j.encode()),
    });
    let local = home.join("release-req.json");
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&local)?;
        std::io::Write::write_all(&mut f, req.to_string().as_bytes())?;
    }
    let remote_dir = std::env::var("B22_SIGNER2_REPO").unwrap_or_else(|_| "~/b22-prover".into());
    // a private (0700) directory on the prover host, not a predictable /tmp name
    let mk = Command::new("ssh")
        .args([host, "umask 077 && mktemp -d \"$HOME/b22-rel.XXXXXX\""])
        .output()?;
    ensure!(mk.status.success(), "mktemp on {host} failed");
    let rdir = String::from_utf8(mk.stdout)?.trim().to_string();
    ensure!(rdir.contains("/b22-rel."), "unexpected remote dir {rdir}");
    let st = Command::new("scp")
        .args([
            "-q",
            local.to_str().unwrap(),
            &format!("{host}:{rdir}/req.json"),
        ])
        .status()?;
    std::fs::remove_file(&local)?;
    ensure!(st.success(), "scp to {host} failed");
    let out = Command::new("ssh")
        .args([host, &format!("cd {remote_dir} && env -u RISC0_DEV_MODE RISC0_WORK_DIR=$HOME/r0work ./target/release/bridge-prover prove --request {rdir}/req.json --out {rdir}/seal.json >&2; rc=$?; cat {rdir}/seal.json; rm -rf {rdir}; exit $rc")])
        .output()?;
    ensure!(
        out.status.success(),
        "remote prover failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).context("remote prover output")?;
    ensure!(
        unhex(&v["journal"])? == j.encode(),
        "remote journal differs"
    );
    unhex(&v["seal"])
}

// ------------------------------------------------------------------ local setup

fn spawn(home: &Path, name: &str, cmd: &mut Command) -> Result<()> {
    let log = std::fs::File::create(home.join(format!("{name}.log")))?;
    let child = cmd
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()
        .with_context(|| format!("spawn {name}"))?;
    std::fs::write(home.join(format!("{name}.pid")), child.id().to_string())?;
    Ok(())
}

fn kill_pid(home: &Path, name: &str) {
    if let Ok(p) = std::fs::read_to_string(home.join(format!("{name}.pid"))) {
        let _ = Command::new("kill").arg(p.trim()).status();
    }
}

fn forge(dir: &Path, args: &[&str], env: &[(&str, String)]) -> Result<String> {
    let home = std::env::var("HOME")?;
    let mut c = Command::new(format!("{home}/.foundry/bin/forge"));
    c.args(args).current_dir(dir);
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c.output()?;
    let s =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    ensure!(out.status.success(), "forge {}: {s}", args[0]);
    Ok(s)
}

fn after<'a>(s: &'a str, label: &str) -> Result<&'a str> {
    let i = s
        .find(label)
        .ok_or_else(|| anyhow!("'{label}' not in forge output"))?;
    s[i + label.len()..]
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("no value after {label}"))
}

fn parse_account(s: &str, prefix: &str) -> Result<String> {
    let i = s
        .find(prefix)
        .ok_or_else(|| anyhow!("no {prefix} in: {s}"))?;
    Ok(s[i + prefix.len()..]
        .split_whitespace()
        .next()
        .unwrap()
        .to_string())
}

#[derive(Serialize, Deserialize)]
struct LezSetup {
    payer: String,
    freezer: String,
    holders: BTreeMap<String, String>,
    lez_from: u64,
    devnet_genesis_time: u64,
    instance_id: String,
}

/// Writes `text` to a new 0600 file (refuses to overwrite).
fn write_secret(path: &Path, text: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::create_dir_all(path.parent().unwrap())?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("{} exists; not overwriting", path.display()))?;
    std::io::Write::write_all(&mut f, text.as_bytes())?;
    Ok(())
}

/// A user's own LEZ wallet with a fresh mnemonic (unencrypted test storage). Its root private
/// account is the bridge holder (b22 keys from that account's secret spending key); its root
/// public account is funded by the payer and shields fee funds to the holder. The mnemonic goes
/// to `mnemonics/<name>.txt`, the test's stand-in for the phrase the user writes down.
async fn new_holder_wallet(home: &Path, name: &str, payer: &str) -> Result<AccountId> {
    let dir = home.join("wallets").join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::copy(
        home.join("wallet/wallet_config.json"),
        dir.join("wallet_config.json"),
    )?;
    let hd = {
        let (mut w, m) = bridge_cli::lez::Wallet::new_init_storage(
            dir.join("wallet_config.json"),
            dir.join("storage.json"),
            None,
            "",
        )
        .map_err(|e| anyhow!("{e:?}"))?;
        w.start_at_chain_tip().await.map_err(|e| anyhow!("{e:?}"))?;
        w.store_persistent_data().map_err(|e| anyhow!("{e:?}"))?;
        let mp = home.join("mnemonics").join(format!("{name}.txt"));
        let _ = std::fs::remove_file(&mp);
        write_secret(&mp, &m.to_string())?;
        bridge_cli::lez::wallet_holder(w.storage().key_chain())?
    };
    wallet_cli(
        home,
        &[
            "auth-transfer",
            "send",
            "--from",
            &format!("Public/{payer}"),
            "--to-pk",
            &hex::encode(hd.public_key),
            "--amount",
            "100100000000",
        ],
    )?;
    wallet_cli_at(
        &dir,
        &[
            "auth-transfer",
            "send",
            "--from",
            &format!("Public/{}", hd.public),
            "--to",
            &format!("Private/{}", hd.account),
            "--amount",
            "100000000000",
        ],
    )?;
    Ok(hd.account)
}

/// Fresh LEZ side: sequencer, wallet, accounts, program deploys, devnet attest instance.
/// How the attest instance is initialised: devnet beacon over anvil, or a real Sepolia checkpoint
/// (`rfp021 fetch-update --bootstrap-root finalized` material).
enum InitWith<'a> {
    Devnet(&'a Eth),
    Sepolia(PathBuf),
}

async fn setup_lez(home: &Path, port: u16, init_with: InitWith<'_>) -> Result<LezSetup> {
    // local runs listen on loopback only; the Sepolia run also serves signer 2 on signer host 2 over the
    // LAN (anyone who can reach it can submit txs: docs/ARCHITECTURE.md §3.1), so it binds all interfaces
    let bind = match &init_with {
        InitWith::Devnet(_) => "127.0.0.1",
        InitWith::Sepolia(_) => "0.0.0.0",
    };
    kill_pid(home, "sequencer");
    for d in ["seqhome", "wallet", "wallets", "mnemonics"] {
        let _ = std::fs::remove_dir_all(home.join(d));
    }
    let mut c: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(format!(
        "{}/lez/sequencer/service/networks/local.json",
        vendor()
    ))?)?;
    c["block_create_timeout"] = "3s".into();
    save_json(&home.join("seq-config.json"), &c)?;
    let seq = format!("{}/target/release/sequencer_service", vendor());
    let st = Command::new(&seq)
        .args([
            "setup",
            home.join("seqhome").to_str().unwrap(),
            "--config",
            home.join("seq-config.json").to_str().unwrap(),
        ])
        .args([
            "--funding-public-key",
            "2e03b2eff5a45478e7e79668d2a146cf2c5c7925bce927f2b1c67f2ab4fc0d26",
            "--create-channel",
        ])
        .output()?;
    ensure!(
        st.status.success(),
        "sequencer setup: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    spawn(
        home,
        "sequencer",
        Command::new(&seq)
            .args(["start", home.join("seqhome").to_str().unwrap()])
            .args([
                "--rpc-listen-address",
                &format!("{bind}:{port}"),
                "--metrics-listen-address",
                "127.0.0.1:0",
            ])
            .env("RISC0_DEV_MODE", "1"),
    )?;
    let mut wc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(format!(
        "{}/lez/wallet/configs/debug/wallet_config.json",
        vendor()
    ))?)?;
    wc["sequencer"]["sequencer_addr"] = format!("http://127.0.0.1:{port}").into();
    save_json(&home.join("wallet/wallet_config.json"), &wc)?;
    for _ in 0..60 {
        if wallet_cli(home, &["check-health"]).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let bridge_key = hex::encode(bridge::host::deploy_key(program_methods::BRIDGE_ID));
    let payer = parse_account(
        &wallet_cli(
            home,
            &[
                "account",
                "import",
                "public",
                "--private-key",
                LEZ_PAYER_KEY,
            ],
        )?,
        "Public/",
    )?;
    wallet_cli(
        home,
        &[
            "account",
            "import",
            "public",
            "--private-key",
            ATTEST_DEPLOY_KEY,
        ],
    )?;
    wallet_cli(
        home,
        &["account", "import", "public", "--private-key", &bridge_key],
    )?;
    let freezer = parse_account(&wallet_cli(home, &["account", "new", "public"])?, "Public/")?;
    wallet_cli(
        home,
        &[
            "auth-transfer",
            "send",
            "--from",
            &format!("Public/{payer}"),
            "--to",
            &format!("Public/{freezer}"),
            "--amount",
            "10000000000",
        ],
    )?;
    let mut holders = BTreeMap::new();
    for name in ["A", "B"] {
        holders.insert(
            name.to_string(),
            new_holder_wallet(home, name, &payer).await?.to_string(),
        );
    }
    println!("  LEZ sequencer :{port} (fresh, RISC0_DEV_MODE=1); payer {payer}, freezer {freezer}; holders (one LEZ wallet each, root private account) A {} B {}", holders["A"], holders["B"]);

    set_wallet_env(home);
    let mut lez = Lez::open(payer.parse().map_err(|e| anyhow!("{e:?}"))?)?;
    let lez_from = lez.head().await?;
    let (attest, bridge) = (lez.attest, lez.bridge);
    lez.deploy(attest, program_methods::ATTEST_ELF).await?;
    lez.deploy(bridge, program_methods::BRIDGE_ELF).await?;
    println!(
        "  deployed attest {attest} and bridge {bridge} (immutable); BRIDGE_ID image {}",
        hex::encode(risc0_zkvm::sha::Digest::from(program_methods::BRIDGE_ID))
    );

    let (id, genesis_time) = match init_with {
        InitWith::Devnet(eth) => {
            // devnet beacon instance over anvil (genesis 4000 slots ago; bootstrap at slot 100)
            let genesis_time = now() - 4000 * 12;
            let dn = beacon::Devnet::new(eth.chain_id, genesis_time, &DEVNET_KEY);
            let ebh = b32(&unhex(&eth.block("latest").await?["hash"])?)?;
            let (root, bootstrap) = dn.bootstrap(100, ebh);
            let r = attest_init(&lez, &dn.cfg, root, bootstrap, dn.now_slot()).await?;
            println!("  attest instance 0x{} (DEVNET BEACON over anvil chain {}, local only): Init tx {} block {}", hex::encode(r.0), eth.chain_id, r.1.hash, r.1.block);
            (r.0, genesis_time)
        }
        InitWith::Sepolia(material) => {
            let m: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(material)?)?;
            let root = hx(m["bootstrap_root"]
                .as_str()
                .ok_or_else(|| anyhow!("material has no bootstrap_root"))?)?;
            let bootstrap = lc_core::json::bootstrap_from_value(&m["bootstrap"])
                .map_err(|e| anyhow!("{e:?}"))?;
            let cfg = program_tests::sepolia_cfg();
            let slot = (now() - cfg.genesis_time) / 12;
            let r = attest_init(&lez, &cfg, root, bootstrap, slot).await?;
            println!(
                "  attest instance 0x{} (Sepolia, checkpoint 0x{}): Init tx {} block {}",
                hex::encode(r.0),
                hex::encode(root),
                r.1.hash,
                r.1.block
            );
            (r.0, 0)
        }
    };
    let s = LezSetup {
        payer,
        freezer,
        holders,
        lez_from,
        devnet_genesis_time: genesis_time,
        instance_id: hex::encode(id),
    };
    let _ = attest;
    save_json(&home.join("lez.json"), &s)?;
    Ok(s)
}

/// Attest `Init` (instance id derived from the checkpoint root, as the program requires).
async fn attest_init(
    lez: &Lez,
    cfg: &attest_program::InstanceConfig,
    root: [u8; 32],
    bootstrap: lc_core::LightClientBootstrap,
    now_slot: u64,
) -> Result<([u8; 32], LezTx)> {
    let attest = lez.attest;
    let id = instance_id(cfg, &root);
    let f = bootstrap
        .header
        .to_finalized(&cfg.chain)
        .map_err(|e| anyhow!("{e:?}"))?;
    let first = Frontier::default()
        .append(header_leaf(&header_record(id, cfg, &f)))
        .unwrap();
    let seeds = [
        instance_seed(&id),
        header_seed(&id, &f.execution_block_hash),
        hroot_seed(&id, &first),
    ];
    let init = Msg::Init {
        instance_id: id,
        cfg: cfg.clone(),
        trusted_block_root: root,
        bootstrap,
        now_slot,
    };
    let r = lez
        .public(
            lez.payer,
            Actor::new(program_tests::pda(attest, seeds[0]), attest),
            seeds[1..]
                .iter()
                .map(|s| Actor::new(program_tests::pda(attest, *s), attest))
                .collect(),
            &seeds.iter().map(|s| (attest, *s)).collect::<Vec<_>>(),
            &init,
            5_000_000,
        )
        .await?;
    ensure!(r.ok, "attest Init reverted");
    Ok((id, r))
}

/// `--local` setup. `B22_REUSE_LEZ=1` keeps a previous run's sequencer, wallet and deploys
/// (development speed-up; every run still gets fresh notes, a fresh anvil, vault and config).
async fn setup_local(home: &Path) -> Result<()> {
    let t = Instant::now();
    kill_pid(home, "anvil");
    let reuse =
        std::env::var("B22_REUSE_LEZ").is_ok_and(|v| v == "1") && home.join("lez.json").exists();
    if !reuse {
        kill_pid(home, "sequencer");
        let _ = std::fs::remove_dir_all(home);
    }
    for d in ["notes", "contracts"] {
        let _ = std::fs::remove_dir_all(home.join(d));
    }
    let _ = std::fs::remove_file(home.join("cache.json"));
    std::fs::create_dir_all(home)?;
    let hm = std::env::var("HOME")?;
    spawn(
        home,
        "anvil",
        Command::new(format!("{hm}/.foundry/bin/anvil")).args([
            "--port",
            &ANVIL_PORT.to_string(),
            "--chain-id",
            "31337",
        ]),
    )?;
    let rpc = format!("http://127.0.0.1:{ANVIL_PORT}");
    let mut eth = None;
    for _ in 0..30 {
        if let Ok(e) = Eth::new(&rpc).await {
            eth = Some(e);
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let eth = eth.ok_or_else(|| anyhow!("anvil did not start"))?;
    let ls = if reuse {
        println!("  reusing the LEZ side of {}", home.display());
        serde_json::from_str::<LezSetup>(&std::fs::read_to_string(home.join("lez.json"))?)?
    } else {
        setup_lez(home, LEZ_PORT, InitWith::Devnet(&eth)).await?
    };
    set_wallet_env(home);
    let lez = Lez::open(ls.payer.parse().map_err(|e| anyhow!("{e:?}"))?)?;
    let bridge = lez.bridge;
    let id: [u8; 32] = hx(&ls.instance_id)?;
    let dn = beacon::Devnet::new(eth.chain_id, ls.devnet_genesis_time, &DEVNET_KEY);
    let (payer, freezer) = (ls.payer.clone(), ls.freezer.clone());
    // Ethereum: mock Groth16 verifier, predicted vault → cfg → verifier + vault (contracts/bridge/script/Deploy.s.sol)
    let cdir = home.join("contracts");
    let st = Command::new("rsync")
        .args([
            "-a",
            "--exclude",
            "out",
            "--exclude",
            "cache",
            "--exclude",
            "broadcast",
            &format!("{CONTRACTS}/"),
            cdir.to_str().unwrap(),
        ])
        .status()?;
    ensure!(st.success(), "copy contracts");
    let deployer = h(&signer_address(&hx(ANVIL_KEYS[0])?)?);
    let mock = forge(
        &cdir,
        &[
            "create",
            "lib/risc0-ethereum/contracts/src/test/RiscZeroMockVerifier.sol:RiscZeroMockVerifier",
            "--rpc-url",
            &rpc,
            "--private-key",
            ANVIL_KEYS[0],
            "--broadcast",
            "--constructor-args",
            "0xFFFFFFFF",
        ],
        &[],
    )?;
    let mock = after(&mock, "Deployed to:")?.to_string();
    // shortcut: L1's Deploy.s.sol resolves the USDT mock as "TetherToken.sol:TetherToken", which
    // forge cannot find; pre-deploy the mock and pass USDT= (the script's supported path)
    let usdt_out = forge(
        &cdir,
        &[
            "create",
            "test/mocks/TetherToken.sol:TetherToken",
            "--rpc-url",
            &rpc,
            "--private-key",
            ANVIL_KEYS[0],
            "--broadcast",
            "--constructor-args",
            "1000000000000",
            "Tether USD (b22 mock)",
            "USDT",
            "6",
        ],
        &[],
    )?;
    let usdt = after(&usdt_out, "Deployed to:")?.to_string();
    let pred = forge(
        &cdir,
        &[
            "script",
            "script/Deploy.s.sol",
            "--sig",
            "predict(address)",
            &deployer,
            "--rpc-url",
            &rpc,
        ],
        &[("USDT", usdt.clone())],
    )?;
    let vault = after(&pred, "expected vault")?.to_string();
    let freezer_eth = h(&signer_address(&hx(ANVIL_KEYS[1])?)?);
    let bc = BridgeConfig {
        instance_id: id,
        evm_chain_id: eth.chain_id,
        genesis_validators_root: dn.cfg.chain.genesis_validators_root,
        vault: hx(&vault)?,
        deposit_topic0: deposit_topic0(),
        zone_id: local_zone_id(),
        bridge_program_id: *bridge.value(),
        admin: payer.parse().map_err(|e| anyhow!("{e:?}"))?,
        freezer: freezer.parse().map_err(|e| anyhow!("{e:?}"))?,
        salt: {
            let mut x = [0u8; 32];
            x[..8].copy_from_slice(&now().to_le_bytes());
            x
        },
    };
    let cfg = config_id(&bc);
    // LOCAL DEV root signer keys (public constants): both on this machine, local only
    let (s1, s2): ([u8; 32], [u8; 32]) = (hx(LOCAL_ROOT_SIGNERS[0])?, hx(LOCAL_ROOT_SIGNERS[1])?);
    let image = h(
        &risc0_zkvm::sha::Digest::from(program_methods::BURN_MEMBER_ID)
            .as_bytes()
            .to_vec(),
    );
    let out = forge(
        &cdir,
        &[
            "script",
            "script/Deploy.s.sol",
            "--rpc-url",
            &rpc,
            "--broadcast",
            "--private-key",
            ANVIL_KEYS[0],
        ],
        &[
            ("CONFIG_ID", h(&cfg)),
            ("SIGNER_1", h(&signer_address(&s1)?)),
            ("SIGNER_2", h(&signer_address(&s2)?)),
            ("MEMBERSHIP_IMAGE_ID", image),
            ("EXPECTED_VAULT", vault.clone()),
            ("FREEZER", freezer_eth),
            ("GROTH16", mock.clone()),
            ("USDT", usdt.clone()),
        ],
    )?;
    ensure!(
        after(&out, "usdt mock")?.eq_ignore_ascii_case(&usdt),
        "script used another USDT"
    );
    println!("  anvil: RiscZeroMockVerifier {mock}, USDT mock {usdt}, BridgeVault {vault} (CONFIG_ID 0x{})", hex::encode(cfg));
    println!(
        "  root signers: LOCAL DEV KEYS {} and {} (both on this machine; local only)",
        h(&signer_address(&s1)?),
        h(&signer_address(&s2)?)
    );

    register_on_lez(&lez, &bc, &hx(&usdt)?).await?;
    let st = State {
        network: "local".into(),
        eth_rpc: rpc,
        vault,
        usdt,
        bridge_config: hex::encode(borsh::to_vec(&bc)?),
        payer,
        freezer_lez: freezer,
        lez_from: ls.lez_from,
        eth_from: 0,
        devnet_genesis_time: ls.devnet_genesis_time,
    };
    save_json(&home.join("deployment.json"), &st)?;
    println!("  setup {:.0} s", t.elapsed().as_secs_f64());
    Ok(())
}

/// Sepolia LEZ side (coordinator order): fresh sequencer, attest Init on a real finalized checkpoint,
/// RFP-021 relayer, bridge deploy, LEZ InitConfig + registration; then `cfg` for the vault that L1's
/// Deploy.s.sol will create at CREATE(deployer, N+2) (USDT mock at N, verifier at N+1).
async fn setup_sepolia(home: &Path, signer2: Option<String>) -> Result<()> {
    let rpc = std::env::var("SEPOLIA_RPC")
        .unwrap_or_else(|_| "https://sepolia.gateway.tenderly.co".into());
    let beacon = std::env::var("SEPOLIA_BEACON")
        .unwrap_or_else(|_| "https://lodestar-sepolia.chainsafe.io".into());
    let eth = Eth::new(&rpc).await?;
    ensure!(eth.chain_id == 11_155_111, "not Sepolia");
    kill_pid(home, "relayer");
    let _ = std::fs::remove_dir_all(home);
    std::fs::create_dir_all(home)?;
    let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release/rfp021");
    let period = (now() - program_tests::SEPOLIA_GENESIS_TIME) / 12 / 8192;
    let material = home.join("init-material.json");
    let st = Command::new(&bin)
        .args([
            "fetch-update",
            "--period",
            &period.to_string(),
            "--bootstrap-root",
            "finalized",
            "--beacon",
            &beacon,
            "--out",
            material.to_str().unwrap(),
        ])
        .status()?;
    ensure!(st.success(), "rfp021 fetch-update failed");
    // B22_LEZ_PORT: run beside an older Sepolia-run sequencer that still holds 3053
    let port = std::env::var("B22_LEZ_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(LEZ_PORT_SEPOLIA);
    let ls = setup_lez(home, port, InitWith::Sepolia(material)).await?;
    // RFP-021 relayer with its own wallet home and payer (dev genesis key B)
    let rw = home.join("relayer-wallet");
    std::fs::create_dir_all(&rw)?;
    std::fs::copy(
        home.join("wallet/wallet_config.json"),
        rw.join("wallet_config.json"),
    )?;
    let out = Command::new(format!("{}/target/release/wallet", vendor()))
        .args([
            "account",
            "import",
            "public",
            "--private-key",
            LEZ_RELAYER_KEY,
        ])
        .env("LEE_WALLET_HOME_DIR", &rw)
        .env("LEE_WALLET_PASSWORD", "")
        .env("SUPPRESS_VERBOSE_PRINTS", "1")
        .output()?;
    let rpayer = parse_account(&String::from_utf8_lossy(&out.stdout), "Public/")?;
    std::fs::write(
        home.join("relayer.toml"),
        format!(
            "beacon_endpoints = [\"{beacon}\", \"https://ethereum-sepolia-beacon-api.publicnode.com\"]\nstate_file = \"{}\"\noperator_key = \"bridge-op\"\nmax_defer_secs = 0\npoll_secs = 12\n[lez]\npayer = \"{rpayer}\"\nattest_program = \"{}\"\ninstance_id = \"0x{}\"\n",
            home.join("relayer-state.json").display(),
            AccountId::new(consumers::ATTEST_PROGRAM),
            ls.instance_id
        ),
    )?;
    spawn(
        home,
        "relayer",
        Command::new(&bin)
            .args([
                "run-relayer",
                "--config",
                home.join("relayer.toml").to_str().unwrap(),
            ])
            .env("LEE_WALLET_HOME_DIR", &rw)
            .env("LEE_WALLET_PASSWORD", "")
            .env("SUPPRESS_VERBOSE_PRINTS", "1"),
    )?;
    println!(
        "  RFP-021 relayer started (payer {rpayer}, log {})",
        home.join("relayer.log").display()
    );

    // vault address from the deployer's CREATE nonce
    // the account that will send the deploy: SEPOLIA_DEPLOYER (address) or the address of SEPOLIA_KEY
    let deployer: [u8; 20] = match std::env::var("SEPOLIA_DEPLOYER") {
        Ok(a) => hx(&a)?,
        Err(_) => signer_address(&env_key("SEPOLIA_KEY")?)?,
    };
    let n = qty(&eth
        .call(
            "eth_getTransactionCount",
            serde_json::json!([h(&deployer), "pending"]),
        )
        .await?)?;
    let d = alloy_primitives::Address::from(deployer);
    let (usdt, vault) = (d.create(n), d.create(n + 2));
    set_wallet_env(home);
    let lez = Lez::open(ls.payer.parse().map_err(|e| anyhow!("{e:?}"))?)?;
    let bc = BridgeConfig {
        instance_id: hx(&ls.instance_id)?,
        evm_chain_id: eth.chain_id,
        genesis_validators_root: lc_core::ChainConfig::sepolia().genesis_validators_root,
        vault: vault.into(),
        deposit_topic0: deposit_topic0(),
        zone_id: local_zone_id(),
        bridge_program_id: *lez.bridge.value(),
        admin: ls.payer.parse().map_err(|e| anyhow!("{e:?}"))?,
        freezer: ls.freezer.parse().map_err(|e| anyhow!("{e:?}"))?,
        salt: {
            let mut x = [0u8; 32];
            x[..8].copy_from_slice(&now().to_le_bytes());
            x
        },
    };
    let cfg = register_on_lez(&lez, &bc, &usdt.0 .0).await?;
    let st = State {
        network: "sepolia".into(),
        eth_rpc: rpc,
        vault: h(vault.as_slice()),
        usdt: h(usdt.as_slice()),
        bridge_config: hex::encode(borsh::to_vec(&bc)?),
        payer: ls.payer.clone(),
        freezer_lez: ls.freezer.clone(),
        lez_from: ls.lez_from,
        eth_from: eth.block_number().await?,
        devnet_genesis_time: 0,
    };
    save_json(&home.join("deployment.json"), &st)?;
    let a = |s: &str| -> Result<String> { Ok(h(&signer_address(&env_key(s)?)?)) };
    println!("\nSEPOLIA DEPLOY INPUTS (for contracts/bridge/script/Deploy.s.sol)");
    println!(
        "  deployer {} nonce N = {n} → USDT mock {usdt} (N), verifier (N+1), vault {vault} (N+2)",
        h(&deployer)
    );
    println!("  CONFIG_ID 0x{}", hex::encode(cfg));
    println!(
        "  BridgeConfig (borsh) {}",
        hex::encode(borsh::to_vec(&bc)?)
    );
    println!(
        "  SIGNER_1 {} (env) SIGNER_2 {} (signer host 2 only) FREEZER {} (B22_FREEZER_KEY); relayer {} user {}",
        a(SIGNER_1_ENV)?,
        signer2.unwrap_or_else(|| "<run `b22 gen-signer` on signer host 2; pass --signer-2 <addr>>".into()),
        a("B22_FREEZER_KEY")?,
        a("B22_RELAYER_KEY")?,
        a("B22_USER_KEY")?
    );
    println!(
        "  bridge_program_id 0x{} (BRIDGE_ID {}); attest instance 0x{}",
        hex::encode(lez.bridge.value()),
        hex::encode(risc0_zkvm::sha::Digest::from(program_methods::BRIDGE_ID)),
        ls.instance_id
    );
    println!("  MEMBERSHIP_IMAGE_ID: L3's burn_member image (not set here)");
    Ok(())
}

/// LEZ `InitConfig` + `RegisterToken` (USDT, ETH) through the admin seat; returns `cfg`.
async fn register_on_lez(lez: &Lez, bc: &BridgeConfig, usdt: &Tok) -> Result<Cfg> {
    let bridge = lez.bridge;
    let cfg = config_id(bc);
    let r = lez
        .public(
            lez.payer,
            Actor::new(config_pda(&bridge, &cfg), bridge),
            vec![],
            &[(bridge, config_seed(&cfg))],
            &BridgeMsg::InitConfig(bc.clone()),
            2_000_000,
        )
        .await?;
    ensure!(r.ok, "InitConfig reverted");
    println!("  InitConfig tx {} block {}", r.hash, r.block);
    for (tok, decimals, d) in [(*usdt, 6u8, D_USDT), (ETH, 18, D_ETH)] {
        let entry = TokenEntry {
            tok,
            decimals,
            denoms: vec![DenomEntry {
                d,
                fee_mint: 0,
                fee_burn: 0,
            }],
            supply_cap: 4 * d,
            mint_open: true,
            paused_mint: false,
            paused_burn: false,
        };
        let r = lez
            .public(
                lez.payer,
                Actor::new(lez.payer, bridge),
                vec![
                    Actor::new(config_pda(&bridge, &cfg), bridge),
                    Actor::new(token_pda(&bridge, &cfg, &tok), bridge),
                ],
                &[(bridge, token_seed(&cfg, &tok))],
                &BridgeMsg::Admin(AdminOp::RegisterToken { cfg, entry }),
                2_000_000,
            )
            .await?;
        ensure!(r.ok, "RegisterToken reverted");
        println!(
            "  RegisterToken {} tx {} block {}",
            tname(&tok),
            r.hash,
            r.block
        );
    }
    Ok(cfg)
}

// ------------------------------------------------------------------ e2e

async fn wait_release_delay(c: &Ctx, tok: &Tok, d: u128, root: &[u8; 32]) -> Result<f64> {
    let at = c.vault().accepted_at(tok, d, root).await?.to::<u64>();
    let delay = c.vault().release_delay(tok).await?;
    let t = Instant::now();
    if c.local {
        let ts = qty(&c.eth.block("latest").await?["timestamp"])?;
        let need = (at + delay).saturating_sub(ts);
        c.eth
            .call("evm_increaseTime", serde_json::json!([need]))
            .await?;
        c.eth.call("evm_mine", serde_json::json!([])).await?;
        println!("    (anvil: evm_increaseTime {need} s for the {delay} s release delay)");
        return Ok(delay as f64);
    }
    loop {
        let ts = qty(&c.eth.block("latest").await?["timestamp"])?;
        if ts >= at + delay {
            return Ok(t.elapsed().as_secs_f64());
        }
        tokio::time::sleep(Duration::from_secs(12)).await;
    }
}

/// Both root signatures for `(tok, d)`: local = the two LOCAL DEV keys on this machine;
/// sepolia = signer 1 from `B22_ROOT_SIGNER_1_KEY`, signer 2 by running `b22 sign-root` on signer host 2 over
/// ssh (the key never leaves signer host 2; this side only receives the signature).
async fn sign_both(c: &mut Ctx, tok: Tok, d: u128) -> Result<(RootAttestation, Vec<[u8; 65]>)> {
    let t = Instant::now();
    let k1 = if c.local {
        hx(LOCAL_ROOT_SIGNERS[0])?
    } else {
        env_key(SIGNER_1_ENV)?
    };
    let (a1, s1) = c.sign_root(&k1, tok, d).await?;
    let (a2, s2) = if c.local {
        c.sign_root(&hx(LOCAL_ROOT_SIGNERS[1])?, tok, d).await?
    } else {
        remote_sign(tok, d)?
    };
    ensure!(
        a1.digest() == a2.digest(),
        "signers disagree: {:?} vs {:?}",
        a1,
        a2
    );
    c.log.lat(
        &format!(
            "root signing, both signers ({}; includes LEZ depth wait)",
            tname(&tok)
        ),
        t,
    );
    println!(
        "    both signers: digest {} at lezHeight {} (count {})",
        short(&a1.digest()),
        a1.lez_height,
        a1.count
    );
    Ok((a1, vec![s1, s2]))
}

fn remote_sign(tok: Tok, d: u128) -> Result<(RootAttestation, [u8; 65])> {
    let host = std::env::var("B22_SIGNER2_HOST").unwrap_or_else(|_| "signer2".into());
    let dir = std::env::var("B22_SIGNER2_CLIENT").unwrap_or_else(|_| "~/b22-client".into());
    let out = Command::new("ssh")
        .args([&host, &format!("cd {dir} && target/release/b22 sign-root {} {d} --sepolia --key-file {PC_SIGNER_KEY}", hex::encode(tok))])
        .output()?;
    ensure!(
        out.status.success(),
        "signer host 2 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.starts_with('{'))
        .last()
        .unwrap_or_default()
        .to_string();
    let v: serde_json::Value = serde_json::from_str(&line).context("signer host 2 output")?;
    let att: RootAttestation = borsh::from_slice(&unhex(&v["attestation"])?)?;
    Ok((
        att,
        unhex(&v["sig"])?
            .try_into()
            .map_err(|_| anyhow!("sig length"))?,
    ))
}

/// An Ethereum probe that must revert with custom error `want` (asserted on the selector).
async fn probe_eth(
    what: &str,
    want: &str,
    r: impl std::future::Future<Output = Result<TxOut>>,
) -> Result<()> {
    match r.await {
        Ok(t) => bail!("{what}: LANDED {} (expected {want})", t.hash),
        Err(e) => {
            let got = revert_selector(&e.to_string());
            println!(
                "    probe {what}: reverted, selector {} = {want} expected 0x{}",
                got.map_or("none".into(), |x| format!("0x{}", hex::encode(x))),
                hex::encode(selector(want))
            );
            ensure!(
                got == Some(selector(want)),
                "{what}: wanted {want}, got {e}"
            );
            Ok(())
        }
    }
}

/// A LEZ probe that must fail with bridge error `want` (asserted on the decoded exit code).
async fn probe_lez<T>(
    what: &str,
    want: u16,
    r: impl std::future::Future<Output = Result<T>>,
) -> Result<()> {
    match r.await {
        Ok(_) => bail!("{what}: LANDED (expected error {want})"),
        Err(e) => {
            let got = lez_error_code(&format!("{e:?}"));
            println!("    probe {what}: refused, LEZ error code {got:?} (expected {want})");
            ensure!(got == Some(want), "{what}: wanted {want}, got {e:?}");
            Ok(())
        }
    }
}

/// One e2e run. Any failure aborts the run (no resume): the transcript of a failed run says so
/// in its last lines and is not evidence.
async fn e2e(home: &Path, local: bool, groth16_host: Option<&str>) -> Result<()> {
    let net = if local { "local" } else { "sepolia" };
    let r = e2e_run(home, local, groth16_host).await;
    if let Err(e) = &r {
        println!("\n!!! b22 e2e --{net}: FAILED: {e:#}");
        println!("!!! this run is NOT a pass; fix and rerun from setup (there is no resume)");
    }
    r
}

async fn e2e_run(home: &Path, local: bool, groth16_host: Option<&str>) -> Result<()> {
    let t0 = Instant::now();
    if local {
        println!("== setup (--local)");
        setup_local(home).await?;
    }
    let mut c = Ctx::load(home).await?;
    ensure!(
        c.holder_names()?
            .iter()
            .all(|n| c.notes_path(n).metadata().is_err()),
        "single run: notes/ must be empty (a fresh setup); there is no resume"
    );
    let (usdt, du, de) = (c.usdt, D_USDT, D_ETH);
    println!("== TRANSCRIPT HEADER");
    println!(
        "   LEZ: sequencer runs with RISC0_DEV_MODE=1. LEZ private proofs are NOT generated and NOT\n   \
         verified in this run; every \"LEZ dev-mode tx + inclusion\" time is execution + inclusion,\n   \
         not proving. (One real LEZ Burn proof is measured separately, evidence/rfp022-sepolia.md.)"
    );
    println!(
        "   Ethereum releases: {}",
        match groth16_host {
            Some(h) => format!("real Groth16 seals proven on {h}, verified on chain"),
            None => "RISC0_DEV_MODE mock seal against RiscZeroMockVerifier (local only)".into(),
        }
    );
    println!(
        "   root signers: {}",
        if local {
            "two LOCAL DEV KEYS on this machine (local only)"
        } else {
            "signer 1 from the environment, signer 2 on signer host 2 (sign-root over ssh); INTERIM CUSTODIAL"
        }
    );
    println!(
        "   holders: one LEZ wallet each; b22 keys derived from the wallet mnemonic; single run, no resume"
    );
    println!(
        "== cfg 0x{} (read from vault {} CONFIG_ID)",
        hex::encode(c.cfg),
        h(&c.vault)
    );

    println!("== 1. A deposits USDT twice (one left unclaimed) and ETH twice");
    let u0 = c.deposit("A", usdt, du).await?;
    let u1 = c.deposit("A", usdt, du).await?;
    let e0 = c.deposit("A", ETH, de).await?;
    let e1 = c.deposit("A", ETH, de).await?;

    println!("== 2. Ethereum finality + attest relay");
    let t = Instant::now();
    if c.local {
        for dep in [&u0, &u1, &e0, &e1] {
            let r = c.devnet_record(hx(&dep.block_hash)?).await?;
            c.log.tx(
                "attest Update (devnet beacon finalizes deposit block)",
                "lez",
                format!("{} block {}", r.hash, r.block),
            );
        }
        c.log.lat(
            "Ethereum finality + attest relay (devnet beacon: 4 Update txs)",
            t,
        );
    } else {
        let last = [&u0, &u1, &e0, &e1]
            .iter()
            .map(|x| x.block_number)
            .max()
            .unwrap();
        loop {
            let recs = c.recorded().await?;
            let mut ok = false;
            for r in recs.iter().rev() {
                let b = c
                    .eth
                    .call(
                        "eth_getBlockByHash",
                        serde_json::json!([h(&r.execution_block_hash), false]),
                    )
                    .await?;
                if !b.is_null() && qty(&b["number"])? >= last {
                    ok = true;
                    break;
                }
            }
            if ok {
                break;
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        c.log
            .lat("Ethereum finality + attest relay (RFP-021 relayer)", t);
    }

    println!("== 3. A claims USDT i=0, ETH i=0 and ETH i=1 privately");
    c.claim("A", &u0).await?;
    c.claim("A", &e0).await?;
    c.claim("A", &e1).await?;

    println!("== 4. A transfers {du} USDT to B's own wallet (send tx + B's receive tx)");
    c.transfer("A", "B", usdt, du).await?;
    let got = c.receive("B").await?;
    ensure!(got.len() == 1, "B received {} credits", got.len());

    println!(
        "== 5. B burns USDT; both signers sign; root accepted; freezer revokes that fresh root"
    );
    let (b_note, b_index, _) = c.burn("B", usdt, du).await?;
    let (att1, sigs) = sign_both(&mut c, usdt, du).await?;
    c.accept_root(&att1, &sigs).await?;
    c.revoke_root(usdt, du, att1.burn_root).await?;

    println!("== 6. A burns ETH i=0's unit (no release yet); ETH root accepted");
    c.burn("A", ETH, de).await?;
    let (atte, sigs) = sign_both(&mut c, ETH, de).await?;
    c.accept_root(&atte, &sigs).await?;

    println!("== 7. wipe A's client state AND A's LEZ wallet; recover from A's mnemonic alone");
    let a_before = c.holder("A")?;
    let phrase = std::fs::read_to_string(home.join("mnemonics/A.txt"))?;
    let wd = c.wallet_dir("A");
    for f in [
        c.notes_path("A"),
        home.join("cache.json"),
        wd.join("storage.json"),
        wd.join("storage.nullifiers"),
    ] {
        let _ = std::fs::remove_file(&f);
        ensure!(!f.exists(), "{} survived the wipe", f.display());
    }
    c.cache = Cache {
        recorded: vec![],
        scanned_to: c.st.lez_from,
    };
    println!(
        "    wiped: notes/A.json, cache.json, wallets/A/storage.json (+ .nullifiers); kept: \
         deployment.json (public deployment facts), wallets/A/wallet_config.json (RPC endpoint)"
    );
    let t = Instant::now();
    Lez::restore_at(&wd, &phrase, c.lez.payer).await?;
    let a_after = c.holder("A")?;
    ensure!(
        a_after == a_before,
        "restored wallet's holder {a_after} differs from {a_before}"
    );
    println!(
        "    restored A's wallet from the mnemonic: holder account {a_after} (same as before)"
    );
    let rec = c.recover("A").await?;
    c.log.lat("recovery: wallet restore + chain scan (A)", t);
    ensure!(
        rec.unclaimed.len() == 1 && rec.unclaimed[0].i == u1.i && rec.unclaimed[0].tok == usdt,
        "recovery missed the unclaimed deposit"
    );
    ensure!(
        rec.unreleased.len() == 1 && rec.unreleased[0].tok == ETH,
        "recovery missed the unreleased ETH burn"
    );
    let notes = c.notes("A")?;
    let rd = notes
        .deposits
        .iter()
        .find(|x| x.i == u1.i && x.tok == hex::encode(usdt))
        .ok_or_else(|| anyhow!("recovered notes lack USDT i={}", u1.i))?
        .clone();
    println!("== 8. A claims the recovered deposit (from the restored wallet)");
    c.claim("A", &rd).await?;
    let ue = rec.unreleased[0].clone();

    println!("== 9. A burns the recovered USDT → a later USDT root; B releases under it (after the revoked one)");
    c.burn("A", usdt, du).await?;
    let (att2, sigs) = sign_both(&mut c, usdt, du).await?;
    ensure!(att2.count == 2 && att2.burn_root != att1.burn_root);
    c.accept_root(&att2, &sigs).await?;
    let (jb, seal) = c
        .prove_release(&b_note, b_index, &att2, groth16_host)
        .await?;
    probe_eth(
        "release before the delay",
        "ReleaseTooEarly()",
        c.release(&jb, &seal),
    )
    .await?;
    let t = Instant::now();
    let w = wait_release_delay(&c, &usdt, du, &att2.burn_root).await?;
    c.log.lat.push(("release delay D".into(), w));
    println!("    [{:.1} s] release delay", t.elapsed().as_secs_f64());
    let before = c
        .eth
        .eth_call(&usdt, &abi(SIG_BALANCE, &[w_addr(&b_note.recipient)], None))
        .await?;
    let rr = c.release(&jb, &seal).await?;
    let bkeys = c.keys("B")?;
    let rtx = c
        .eth
        .call("eth_getTransactionByHash", serde_json::json!([rr.hash]))
        .await?;
    scan(
        "release (B)",
        &[unhex(&rtx["input"])?, serde_json::to_vec(&rr.logs)?].concat(),
        vec![
            ("burn commitment B", b_note.b.to_vec()),
            ("rk", b_note.rk.to_vec()),
            ("B's LEZ account", c.holder("B")?.value().to_vec()),
            ("B's sk", bkeys.sk.to_vec()),
        ],
    );
    let after = c
        .eth
        .eth_call(&usdt, &abi(SIG_BALANCE, &[w_addr(&b_note.recipient)], None))
        .await?;
    let paid = U256::from_be_slice(&after) - U256::from_be_slice(&before);
    println!(
        "    B's recipient_{} {} USDT +{paid}",
        b_note.j,
        h(&b_note.recipient)
    );
    ensure!(
        paid == U256::from(du - jb.fee),
        "B was paid {paid}, not d - fee"
    );
    probe_eth(
        "replayed release",
        "NullifierSpent()",
        c.release(&jb, &seal),
    )
    .await?;
    let mut jr = jb.clone();
    jr.burn_root = att1.burn_root;
    probe_eth(
        "release under the revoked root",
        "RootRevoked()",
        c.release(&jr, &seal),
    )
    .await?;

    println!(
        "== 10. freeze each half and probe it (Ethereum vault deposits/releases, LEZ mint/burn)"
    );
    // Ethereum deposits
    c.freeze_eth(true, false).await?;
    let (k0, vault) = (c.eth_key(0)?, c.vault);
    let probe = abi(SIG_DEPOSIT, &[w_addr(&ETH), w_u(de), [0x77; 32]], None);
    probe_eth(
        "deposit while deposits frozen",
        "Frozen()",
        c.eth.send(&k0, &vault, U256::from(de), &probe),
    )
    .await?;
    c.freeze_eth(false, false).await?;
    // Ethereum releases: A's recovered ETH burn, refused while frozen, then released
    let t = Instant::now();
    wait_release_delay(&c, &ETH, de, &atte.burn_root).await?;
    println!("    [{:.1} s] ETH release delay", t.elapsed().as_secs_f64());
    let (je, seal) = c
        .prove_release(&ue.note, ue.index, &atte, groth16_host)
        .await?;
    c.freeze_eth(false, true).await?;
    probe_eth(
        "release while releases frozen",
        "Frozen()",
        c.release(&je, &seal),
    )
    .await?;
    c.freeze_eth(false, false).await?;
    let before = c.eth.balance(&ue.note.recipient).await?;
    let re = c.release(&je, &seal).await?;
    let after = c.eth.balance(&ue.note.recipient).await?;
    println!(
        "    A's recovered recipient_{} {} ETH {before} → {after}",
        ue.note.j,
        h(&ue.note.recipient)
    );
    ensure!(
        after - before == U256::from(de - je.fee),
        "A was paid {}, not d - fee",
        after - before
    );
    let akeys = c.keys("A")?;
    let etx = c
        .eth
        .call("eth_getTransactionByHash", serde_json::json!([re.hash]))
        .await?;
    scan(
        "release (A, ETH)",
        &[unhex(&etx["input"])?, serde_json::to_vec(&re.logs)?].concat(),
        vec![
            ("burn commitment B", ue.note.b.to_vec()),
            ("rk", ue.note.rk.to_vec()),
            ("A's LEZ account", c.holder("A")?.value().to_vec()),
            ("A's sk", akeys.sk.to_vec()),
        ],
    );
    // LEZ mint: a replayed claim of e0 reaches the config PDA's pause check before the nullifier
    c.freeze_lez(true, false).await?;
    probe_lez("claim while LEZ mint paused", ERR_FROZEN, c.claim("A", &e0)).await?;
    c.freeze_lez(false, false).await?;
    probe_lez(
        "same replayed claim, mint unpaused",
        ERR_ALREADY_CLAIMED,
        c.claim("A", &e0),
    )
    .await?;
    // LEZ burn: A still holds ETH i=1's unit
    c.freeze_lez(false, true).await?;
    probe_lez(
        "burn while LEZ burn paused",
        ERR_FROZEN,
        c.burn("A", ETH, de),
    )
    .await?;
    c.freeze_lez(false, false).await?;

    println!("\n== transcript: transactions");
    println!("| step | chain | tx |\n|---|---|---|");
    for (s, ch, i) in &c.log.txs {
        println!("| {s} | {ch} | {i} |");
    }
    println!("\n== latency table (LEZ rows: dev mode, no proving)");
    println!("| step | seconds |\n|---|---:|");
    for (s, x) in &c.log.lat {
        println!("| {s} | {x:.1} |");
    }
    println!(
        "\nb22 e2e --{}: PASS in {:.0} s (one run, no resume)",
        if local { "local" } else { "sepolia" },
        t0.elapsed().as_secs_f64()
    );
    Ok(())
}

// ------------------------------------------------------------------ CLI

fn expand_home(p: &str) -> Result<PathBuf> {
    Ok(match p.strip_prefix("~/") {
        Some(r) => PathBuf::from(std::env::var("HOME")?).join(r),
        None => PathBuf::from(p),
    })
}

fn arg(args: &[String], i: usize) -> Result<&str> {
    args.get(i)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("missing argument {i}; see `b22` doc comment"))
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

const USAGE: &str = "\
b22 e2e --local                      anvil + local vault + fresh LEZ sequencer, mock seal (RISC0_DEV_MODE)
b22 e2e --sepolia --groth16-host prover-host  one run, no resume (needs `b22 setup --sepolia` + the deploy)
b22 derive <holder> <tok> <d> <i>     C_i, recipient_i
b22 deposit|claim|burn <holder> <tok> <d>
b22 transfer <from> <to> <tok> <amount> ; b22 receive <holder>
b22 sign-root <tok> <d> (--key-file <f> | --key-env <VAR>) [--out <file>] [--loop]
b22 gen-signer [--key-file <f>]       new root-signer key on THIS machine; prints the address only
b22 accept-root <sig-file>... ; b22 revoke-root <tok> <d> <root>
b22 recover <holder> [--mnemonic-file <f>] ; b22 freeze eth|lez mint|burn|both on|off
b22 freezer cancel <tok> ; b22 freezer watch [--loop]
b22 addr <ENV_VAR> ; b22 setup --local | --sepolia --signer-2 <addr>
Run home: B22_HOME (default target/b22-<network>). Keys come from the environment only; see the
doc comment of crates/bridge-cli/src/main.rs.
";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty()
        || args
            .iter()
            .any(|a| a == "-h" || a == "--help" || a == "help")
    {
        print!("{USAGE}");
        return Ok(());
    }
    let cmd = arg(&args, 0)?.to_string();
    let local = args.iter().any(|a| a == "--local");
    let home = PathBuf::from(std::env::var("B22_HOME").unwrap_or_else(|_| {
        format!(
            "{}/target/b22-{}",
            env!("CARGO_MANIFEST_DIR").trim_end_matches("/crates/bridge-cli"),
            if local || cmd != "e2e" && !args.iter().any(|a| a == "--sepolia") {
                "local"
            } else {
                "sepolia"
            }
        )
    }));
    if cmd == "e2e" {
        return e2e(&home, local, flag(&args, "--groth16-host").as_deref()).await;
    }
    if cmd == "setup" && local {
        return setup_local(&home).await;
    }
    if cmd == "setup" {
        return setup_sepolia(&home, flag(&args, "--signer-2")).await;
    }
    if cmd == "fund-sepolia" {
        // after the vault exists: deployer (SEPOLIA_KEY, env only) funds the user and relayer keys
        let st: State =
            serde_json::from_str(&std::fs::read_to_string(home.join("deployment.json"))?)?;
        let eth = Eth::new(&st.eth_rpc).await?;
        let dk = env_key("SEPOLIA_KEY")?;
        ensure!(
            !eth.call("eth_getCode", serde_json::json!([st.vault, "latest"]))
                .await?
                .as_str()
                .unwrap_or("0x")
                .eq("0x"),
            "vault not deployed yet"
        );
        let (user, relayer, freezer) = (
            signer_address(&env_key("B22_USER_KEY")?)?,
            signer_address(&env_key("B22_RELAYER_KEY")?)?,
            signer_address(&env_key("B22_FREEZER_KEY")?)?,
        );
        for (to, wei) in [
            (user, 35_000_000_000_000_000u128),
            (relayer, 15_000_000_000_000_000),
            (freezer, 5_000_000_000_000_000),
        ] {
            if eth.balance(&to).await? > U256::ZERO {
                println!("{} already funded", h(&to));
                continue;
            }
            let r = eth.send(&dk, &to, U256::from(wei), &[]).await?;
            println!(
                "fund {} with {wei} wei: {} block {} {}",
                h(&to),
                r.hash,
                r.block,
                r.ok
            );
        }
        let r = eth
            .send(
                &dk,
                &hx(&st.usdt)?,
                U256::ZERO,
                &abi(
                    "transfer(address,uint256)",
                    &[w_addr(&user), w_u(2 * D_USDT)],
                    None,
                ),
            )
            .await?;
        println!(
            "fund {} with {} USDT mock: {} block {} {}",
            h(&user),
            2 * D_USDT,
            r.hash,
            r.block,
            r.ok
        );
        return Ok(());
    }
    if cmd == "gen-signer" {
        // run on the machine that will hold the key (signer 2: signer host 2); prints the address only
        let p = expand_home(&flag(&args, "--key-file").unwrap_or_else(|| PC_SIGNER_KEY.into()))?;
        let key = loop {
            let mut k = [0u8; 32];
            std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut k)?;
            if signer_address(&k).is_ok() {
                break k;
            }
        };
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = p.parent().unwrap();
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        write_secret(&p, &hex::encode(key))?;
        println!("{}", h(&signer_address(&key)?));
        return Ok(());
    }
    if cmd == "addr" {
        // address of a key read from an environment variable (the key itself is never printed)
        println!("{}", h(&signer_address(&env_key(arg(&args, 1)?)?)?));
        return Ok(());
    }
    let mut c = Ctx::load(&home).await?;
    let pair = |c: &Ctx, i: usize| -> Result<(Tok, u128)> {
        Ok((
            tok_of(arg(&args, i)?, &c.st.usdt)?,
            arg(&args, i + 1)?.parse()?,
        ))
    };
    match cmd.as_str() {
        "derive" => {
            let k = c.keys(arg(&args, 1)?)?;
            let (tok, d) = pair(&c, 2)?;
            let i: u64 = arg(&args, 4)?.parse()?;
            println!(
                "C_{i} = 0x{}",
                hex::encode(k.commitment(&c.cfg, &tok, d, i))
            );
            if let Some(n) = k.burn(&c.cfg, &tok, d, i) {
                println!(
                    "recipient_{i} = {}  B_{i} = 0x{}",
                    h(&n.recipient),
                    hex::encode(n.b)
                );
            }
        }
        "deposit" => {
            let (tok, d) = pair(&c, 2)?;
            c.deposit(arg(&args, 1)?, tok, d).await?;
        }
        "claim" => {
            let holder = arg(&args, 1)?;
            let (tok, d) = pair(&c, 2)?;
            let r = c.recover(holder).await?;
            let u = r
                .unclaimed
                .iter()
                .find(|u| u.tok == tok && u.d == d)
                .ok_or_else(|| anyhow!("no unclaimed deposit"))?;
            let dep = c
                .notes(holder)?
                .deposits
                .into_iter()
                .find(|x| x.i == u.i && x.tok == hex::encode(tok))
                .unwrap();
            c.claim(holder, &dep).await?;
        }
        "transfer" => {
            let (tok, amount) = pair(&c, 3)?;
            c.transfer(arg(&args, 1)?, arg(&args, 2)?, tok, amount)
                .await?;
        }
        "receive" => {
            c.receive(arg(&args, 1)?).await?;
        }
        "burn" => {
            let (tok, d) = pair(&c, 2)?;
            c.burn(arg(&args, 1)?, tok, d).await?;
        }
        "sign-root" => {
            // runs on the machine holding the key: `--key-file` (signer host 2: signer 2) or `--key-env`
            // (signer 1); `--loop` re-signs whenever the (tok, d) tree moves
            let key = match (flag(&args, "--key-file"), flag(&args, "--key-env")) {
                (Some(f), None) => hx(std::fs::read_to_string(expand_home(&f)?)?.trim())?,
                (None, Some(svc)) => env_key(&svc)?,
                _ => bail!("sign-root needs exactly one of --key-file <f> | --key-env <VAR>"),
            };
            let (tok, d) = pair(&c, 1)?;
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let s2 = stop.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                s2.store(true, std::sync::atomic::Ordering::SeqCst);
                eprintln!("{{\"event\":\"shutdown\"}}");
            });
            let mut last = None;
            loop {
                let (att, sig) = c.sign_root(&key, tok, d).await?;
                if last != Some(att.digest()) {
                    let v = serde_json::json!({
                        "signer": h(&signer_address(&key)?), "digest": h(&att.digest()),
                        "lez_height": att.lez_height, "count": att.count, "burn_root": h(&att.burn_root),
                        "attestation": hex::encode(borsh::to_vec(&att)?), "sig": hex::encode(sig),
                    });
                    match flag(&args, "--out") {
                        Some(p) => std::fs::write(p, v.to_string())?,
                        None => println!("{v}"),
                    }
                    eprintln!(
                        "{{\"event\":\"signed\",\"lez_height\":{},\"count\":{}}}",
                        att.lez_height, att.count
                    );
                    last = Some(att.digest());
                }
                if !args.iter().any(|a| a == "--loop")
                    || stop.load(std::sync::atomic::Ordering::SeqCst)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
        "accept-root" => {
            let mut atts = vec![];
            let mut sigs = vec![];
            for p in &args[1..] {
                let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p)?)?;
                atts.push(borsh::from_slice::<RootAttestation>(&hex::decode(
                    v["attestation"].as_str().unwrap(),
                )?)?);
                sigs.push(
                    hex::decode(v["sig"].as_str().unwrap())?
                        .try_into()
                        .map_err(|_| anyhow!("sig"))?,
                );
            }
            ensure!(
                atts.windows(2).all(|w| w[0] == w[1]),
                "signature files attest different roots"
            );
            c.accept_root(&atts[0], &sigs).await?;
        }
        "register-token" => {
            // admin seat RegisterToken of one token (same demo entry as setup); fees on LEZ stay 0
            let (tok, d) = pair(&c, 1)?;
            let decimals = if tok == ETH { 18 } else { 6 };
            let entry = TokenEntry {
                tok,
                decimals,
                denoms: vec![DenomEntry {
                    d,
                    fee_mint: 0,
                    fee_burn: 0,
                }],
                supply_cap: 4 * d,
                mint_open: true,
                paused_mint: false,
                paused_burn: false,
            };
            let b = c.lez.bridge;
            let r = c
                .lez
                .public(
                    c.lez.payer,
                    Actor::new(c.lez.payer, b),
                    vec![
                        Actor::new(config_pda(&b, &c.cfg), b),
                        Actor::new(token_pda(&b, &c.cfg, &tok), b),
                    ],
                    &[(b, token_seed(&c.cfg, &tok))],
                    &BridgeMsg::Admin(AdminOp::RegisterToken { cfg: c.cfg, entry }),
                    2_000_000,
                )
                .await?;
            println!(
                "RegisterToken {} tx {} block {} {}",
                h(&tok),
                r.hash,
                r.block,
                if r.ok { "ok" } else { "REVERTED" }
            );
        }
        "revoke-root" => {
            let (tok, d) = pair(&c, 1)?;
            c.revoke_root(tok, d, hx(arg(&args, 3)?)?).await?;
        }
        "recover" => {
            // `--mnemonic-file`: the holder's LEZ wallet was lost; rebuild it from the phrase first
            let holder = arg(&args, 1)?;
            if let Some(f) = flag(&args, "--mnemonic-file") {
                let dir = c.wallet_dir(holder);
                ensure!(
                    !dir.join("storage.json").exists(),
                    "{holder}'s wallet storage exists; move it away before restoring"
                );
                std::fs::create_dir_all(&dir)?;
                if !dir.join("wallet_config.json").exists() {
                    std::fs::copy(
                        home.join("wallet/wallet_config.json"),
                        dir.join("wallet_config.json"),
                    )?;
                }
                Lez::restore_at(&dir, &std::fs::read_to_string(f)?, c.lez.payer).await?;
            }
            c.recover(holder).await?;
        }
        "freeze" => {
            let on = arg(&args, 3)? == "on";
            match (arg(&args, 1)?, arg(&args, 2)?) {
                (chain @ ("eth" | "lez"), half) => {
                    c.freeze_half(chain == "eth", half.parse()?, on).await?
                }
                x => bail!("freeze eth|lez mint|burn|both on|off, got {x:?}"),
            }
        }
        "freezer" => match arg(&args, 1)? {
            "cancel" => {
                let tok = tok_of(arg(&args, 2)?, &c.st.usdt)?;
                c.cancel_token_change(tok).await?
            }
            "watch" => {
                let mut from = c.st.eth_from;
                loop {
                    from = c.watch_queued(from).await?;
                    if !args.iter().any(|a| a == "--loop") {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(12)).await;
                }
            }
            x => bail!("freezer cancel <tok> | freezer watch [--loop], got {x:?}"),
        },
        x => bail!("unknown command {x}; see the doc comment of crates/bridge-cli/src/main.rs"),
    }
    Ok(())
}
