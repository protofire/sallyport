use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use relayer::{beacon::Beacon, config::Config, el::El, operator::Source};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

/// Mirrors `inclusion::MAX_ANCESTRY` (the program rejects longer chains with 1001).
const MAX_ANCESTRY: usize = 448;

#[derive(Parser)]
#[command(name = "rfp021", about = "RFP-021 relayer / fetch tooling")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Fetch LC update material for a sync-committee period.
    FetchUpdate {
        #[arg(long)]
        period: u64,
        /// Also fetch a bootstrap for this trusted block root ("finalized" = current finalized checkpoint).
        #[arg(long)]
        bootstrap_root: Option<String>,
        /// Beacon API endpoint(s); default: module built-ins.
        #[arg(long)]
        beacon: Vec<String>,
        #[arg(long, default_value_t = 11155111)]
        chain_id: u64,
        #[arg(long, default_value = "update-material.json")]
        out: PathBuf,
    },
    /// Fetch header RLP + account/storage/receipt proofs under an execution block hash.
    FetchAttest {
        #[arg(long)]
        block_hash: String,
        #[arg(long)]
        address: String,
        #[arg(long)]
        slot: Option<String>,
        #[arg(long, requires = "log_index")]
        tx_index: Option<u32>,
        #[arg(long, requires = "tx_index")]
        log_index: Option<u32>,
        /// Recorded (checkpoint) block hash to link `block_hash` to; fetches the header chain between.
        #[arg(long)]
        anchor: Option<String>,
        #[arg(long, default_value = "https://sepolia.gateway.tenderly.co")]
        exec: String,
        /// Optional socks5h:// proxy for EL requests.
        #[arg(long)]
        exec_proxy: Option<String>,
        /// JSON-RPC endpoint of a running verified_proxy_module (`localEndpoint()`): headers and
        /// receipts go there, light-client verified. Unset = all EL reads go to `--exec`.
        #[arg(long)]
        exec_verified: Option<String>,
        #[arg(long, default_value_t = 11155111)]
        chain_id: u64,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Run the operator loop against the LEZ instance in the config (needs `--features lez`).
    RunRelayer {
        #[arg(long)]
        config: PathBuf,
    },
    /// Print which material would be submitted now; submits nothing.
    DryRun {
        #[arg(long)]
        config: PathBuf,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .init();
    match Cli::parse().cmd {
        Cmd::FetchUpdate {
            period,
            bootstrap_root,
            beacon,
            chain_id,
            out,
        } => {
            let m =
                Beacon::new(chain_id, &beacon)?.fetch_update(period, bootstrap_root.as_deref())?;
            std::fs::write(&out, serde_json::to_vec_pretty(&m)?)?;
            println!("wrote {} ({} updates)", out.display(), m.updates.len());
        }
        Cmd::FetchAttest {
            block_hash,
            address,
            slot,
            tx_index,
            log_index,
            anchor,
            exec,
            exec_proxy,
            exec_verified,
            chain_id,
            out,
        } => {
            let log = tx_index.zip(log_index);
            let el = El::new(
                chain_id,
                &exec,
                exec_proxy.as_deref(),
                exec_verified.as_deref(),
            )?;
            let mut m = el.fetch_attest(&block_hash, &address, slot.as_deref(), log)?;
            if let Some(a) = &anchor {
                // Request shape: exec_header_rlp = recorded anchor header, ancestry = [block, …, anchor-1].
                (m.exec_header_rlp, m.ancestry) =
                    el.fetch_ancestry(&block_hash, a, MAX_ANCESTRY)?;
            }
            let out = out.unwrap_or_else(|| {
                format!("attest-{}.json", &block_hash[2..10.min(block_hash.len())]).into()
            });
            std::fs::write(&out, serde_json::to_vec_pretty(&m)?)?;
            println!(
                "wrote {} (header rlp {} bytes; account nodes {}, storage nodes {}, receipt nodes {}, ancestry {})",
                out.display(), m.exec_header_rlp.len(), m.account_proof.len(), m.storage_proof.len(), m.receipt_proof_nodes.len(), m.ancestry.len()
            );
        }
        Cmd::DryRun { config } => {
            let (op, head) = build(&config)?;
            match op.next_job()? {
                Some(job) => {
                    let m = Beacon::new(head.chain_id, &head.beacon_endpoints)?.material(&job)?;
                    println!(
                        "would submit {job:?}: {} update(s), bootstrap={}",
                        m.updates.len(),
                        m.bootstrap.is_some()
                    );
                }
                None => println!("nothing to submit"),
            }
        }
        Cmd::RunRelayer { config } => {
            let (mut op, cfg) = build(&config)?;
            let stop = Arc::new(AtomicBool::new(false));
            let s = stop.clone();
            ctrlc::set_handler(move || s.store(true, Ordering::SeqCst))?;
            op.run(Duration::from_secs(cfg.poll_secs), &stop);
        }
    }
    Ok(())
}

#[cfg(feature = "lez")]
fn build(
    path: &PathBuf,
) -> Result<(
    relayer::operator::Operator<relayer::lez::LezChain, Beacon>,
    Config,
)> {
    let cfg = Config::load(path)?;
    if cfg.beacon_endpoints.is_empty() {
        bail!("beacon_endpoints must not be empty");
    }
    let Some(l) = &cfg.lez else {
        bail!("config has no [lez] section")
    };
    let id: [u8; 32] = l
        .instance_id
        .parse::<alloy_primitives::B256>()
        .map_err(|e| anyhow::anyhow!("instance_id: {e}"))?
        .0;
    let mut chain = relayer::lez::LezChain::new(&l.payer, &l.attest_program, id)?;
    if let Some(cap) = l.max_fee_cap {
        chain = chain.with_max_fee_cap(cap.into());
    }
    let beacon = Beacon::new(cfg.chain_id, &cfg.beacon_endpoints)?;
    let op = relayer::operator::Operator::new(
        chain,
        beacon,
        &cfg.operator_key,
        Duration::from_secs(cfg.max_defer_secs),
        cfg.state_file.clone(),
    )?;
    Ok((op, cfg))
}

#[cfg(not(feature = "lez"))]
fn build(
    _: &PathBuf,
) -> Result<(
    relayer::operator::Operator<relayer::operator::MockChain, Beacon>,
    Config,
)> {
    bail!("built without the LEZ submitter: cargo +1.98.1 build -p relayer --features lez")
}
