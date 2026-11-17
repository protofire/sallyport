//! `b22` client library (docs/ARCHITECTURE.md §3.4-3.8): seed-derived notes, seed-only
//! recovery over a [`ChainView`], the INTERIM CUSTODIAL root-signing digest and signature combination,
//! the dev-mode mock seal, and the byte leak scan. Pure; the live paths are in `eth`, `lez`, `beacon`.

pub mod beacon;
pub mod eth;
pub mod lez;

use anyhow::{bail, ensure, Result};
use bridge_core::*;

/// Recovery gap limit (docs/ARCHITECTURE.md §3.8).
pub const GAP: u64 = 20;

/// Domain of the b22 seed taken from a LEZ wallet holder's secret spending key.
pub const LEZ_WALLET_DOMAIN: &[u8] = b"b022/lez-wallet/v1";

/// Largest lag (EL blocks) between the head and the attest instance's latest finalized header at
/// which the client still deposits: half the claim ancestry window, so the relayer has at least
/// as long again to record a header the deposit can reach (docs/ARCHITECTURE.md §3.4).
pub const MAX_ATTEST_LAG: u64 = inclusion::MAX_ANCESTRY as u64 / 2;

/// Liveness gate before a deposit (022-compliance): a deposit is claimable only if the attest
/// instance records a header within `MAX_ANCESTRY` EL blocks after it, and the vault has no
/// refund path, so the client refuses while the instance is stale.
pub fn check_attest_live(latest_finalized_block: u64, head: u64) -> Result<()> {
    let lag = head.saturating_sub(latest_finalized_block);
    ensure!(
        lag <= MAX_ATTEST_LAG,
        "refusing to deposit: the attest instance's latest finalized header is EL block \
         {latest_finalized_block}, {lag} blocks behind the head {head} (bound {MAX_ATTEST_LAG}). A \
         deposit is claimable only if the instance records a header within {} blocks after it, \
         and the vault cannot refund; wait until the RFP-021 relayer has posted a recent update",
        inclusion::MAX_ANCESTRY
    );
    Ok(())
}

/// Every `(tok, d)` recovery must scan: the pairs of the vault's `Deposit` logs for this config
/// plus, for each token seen there, every denomination its LEZ token PDA lists or has a burn tree
/// for (a denomination dropped by `UpdateToken` keeps its tree). Sorted, unique.
pub fn recovery_pairs(deposits: &[(Tok, u128)], tokens: &[TokenState]) -> Vec<(Tok, u128)> {
    let mut out: std::collections::BTreeSet<(Tok, u128)> = deposits.iter().copied().collect();
    for st in tokens {
        out.extend(st.entry.denoms.iter().map(|x| (st.entry.tok, x.d)));
        out.extend(st.trees.iter().map(|(d, _)| (st.entry.tok, *d)));
    }
    out.into_iter().collect()
}

/// Leaves of the `(tok, d)` burn tree in `st`.
pub fn tree_count(st: &TokenState, d: u128) -> u64 {
    st.trees
        .iter()
        .find(|(x, _)| *x == d)
        .map_or(0, |(_, f)| f.leaves)
}

/// The 4-byte custom-error selector in an `eth_estimateGas`/`eth_call` revert error (`"data":"0x…"`).
pub fn revert_selector(err: &str) -> Option<[u8; 4]> {
    let i = err.find("\"data\":\"0x")? + 10;
    hex::decode(err.get(i..i + 8)?).ok()?.try_into().ok()
}

/// The bridge error code (1001, 1301–1308, …) of a LEZ simulation failure
/// (`ProgramExitedWithCode { .., code: N }`), decoded with [`bridge::error_from_exit`].
pub fn lez_error_code(err: &str) -> Option<u16> {
    let rest = &err[err.find("ProgramExitedWithCode")?..];
    let digits: String = rest[rest.find("code: ")? + 6..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    Some(bridge::error_from_exit(digits.parse().ok()?))
}

/// Every secret of one holder, from the seed alone (docs/ARCHITECTURE.md §3.2, DECISIONS.md B22-8).
#[derive(Clone)]
pub struct Keys {
    pub sk: [u8; 32],
}

/// One burn's seed-derived secrets. `j` is a per-config counter shared by all `(tok, d)` so that
/// `recipient_j` (which depends on `(cfg, j)` only) is fresh per burn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurnNote {
    pub j: u64,
    pub rk: [u8; 32],
    pub recipient: [u8; 20],
    pub b: [u8; 32],
    pub nb: [u8; 32],
}

impl Keys {
    pub fn from_seed(seed: &[u8]) -> Self {
        Self { sk: sk(seed) }
    }

    /// The b22 keys of a LEZ wallet's holder account, from that account's secret spending key
    /// (itself derived from the wallet mnemonic, see `lez::wallet_holder`): the mnemonic alone
    /// recovers them, with no second secret (F9).
    pub fn from_lez_secret(ssk: &[u8; 32]) -> Self {
        Self::from_seed(&[LEZ_WALLET_DOMAIN, ssk.as_slice()].concat())
    }

    pub fn nk(&self, cfg: &Cfg, tok: &Tok, d: u128, i: u64) -> [u8; 32] {
        nk(&self.sk, cfg, tok, d, i)
    }

    /// Deposit commitment `C_i = commit(nk_i)`.
    pub fn commitment(&self, cfg: &Cfg, tok: &Tok, d: u128, i: u64) -> [u8; 32] {
        commit(&self.nk(cfg, tok, d, i))
    }

    /// `None` only when `ek_j` reduces to zero (the client skips that `j`).
    pub fn burn(&self, cfg: &Cfg, tok: &Tok, d: u128, j: u64) -> Option<BurnNote> {
        let rk = rk(&self.sk, cfg, tok, d, j);
        let recipient = recipient(&self.sk, cfg, j)?;
        Some(BurnNote {
            j,
            rk,
            recipient,
            b: burn_commitment(&rk, &recipient),
            nb: burn_nullifier(&rk),
        })
    }

    pub fn release_key(&self, cfg: &Cfg, j: u64) -> Option<[u8; 32]> {
        ek(&self.sk, cfg, j)
    }
}

/// What recovery reads from the two chains (live: vault logs + LEZ PDAs; tests: synthetic).
pub trait ChainView {
    /// A vault `Deposit` log with topic1 = `c` exists for `(tok, d)`.
    fn deposit_seen(&self, tok: &Tok, d: u128, c: &[u8; 32]) -> bool;
    /// `PDA(bridge, n)` is non-empty (the deposit was claimed).
    fn claimed(&self, n: &[u8; 32]) -> bool;
    /// Leaf PDAs `0..leaves` of the `(tok, d)` burn tree, in index order.
    fn burn_leaves(&self, tok: &Tok, d: u128) -> Vec<[u8; 32]>;
    /// `vault.spent(Nb)`.
    fn released(&self, nb: &[u8; 32]) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unclaimed {
    pub tok: Tok,
    pub d: u128,
    pub i: u64,
    pub nk: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreleased {
    pub tok: Tok,
    pub d: u128,
    pub index: u64,
    pub note: BurnNote,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recovered {
    pub unclaimed: Vec<Unclaimed>,
    pub unreleased: Vec<Unreleased>,
    /// Next unused deposit index per `(tok, d)`.
    pub next_i: Vec<(Tok, u128, u64)>,
    /// Next unused burn counter `j` (over all `(tok, d)`).
    pub next_j: u64,
    pub claimed: usize,
    pub released: usize,
}

/// Seed-only recovery (docs/ARCHITECTURE.md §3.8): gap-limit scans of deposits and burns for each registered `(tok, d)`.
pub fn recover(keys: &Keys, cfg: &Cfg, pairs: &[(Tok, u128)], view: &impl ChainView) -> Recovered {
    let mut r = Recovered::default();
    for (tok, d) in pairs {
        let (mut i, mut miss, mut next) = (0u64, 0u64, 0u64);
        while miss < GAP {
            let nk = keys.nk(cfg, tok, *d, i);
            if view.deposit_seen(tok, *d, &commit(&nk)) {
                miss = 0;
                next = i + 1;
                if view.claimed(&pnf(&nk)) {
                    r.claimed += 1;
                } else {
                    r.unclaimed.push(Unclaimed {
                        tok: *tok,
                        d: *d,
                        i,
                        nk,
                    });
                }
            } else {
                miss += 1;
            }
            i += 1;
        }
        r.next_i.push((*tok, *d, next));
    }
    // j is shared by every (tok, d): scan each tree until GAP consecutive j miss in all trees.
    let trees: Vec<_> = pairs
        .iter()
        .map(|(tok, d)| (*tok, *d, view.burn_leaves(tok, *d)))
        .collect();
    let (mut j, mut miss) = (0u64, 0u64);
    while miss < GAP {
        let mut hit = false;
        for (tok, d, leaves) in &trees {
            let Some(note) = keys.burn(cfg, tok, *d, j) else {
                continue;
            };
            if let Some(index) = leaves.iter().position(|l| *l == note.b) {
                hit = true;
                if view.released(&note.nb) {
                    r.released += 1;
                } else {
                    r.unreleased.push(Unreleased {
                        tok: *tok,
                        d: *d,
                        index: index as u64,
                        note,
                    });
                }
            }
        }
        if hit {
            miss = 0;
            r.next_j = j + 1;
        } else {
            miss += 1;
        }
        j += 1;
    }
    r
}

/// Bridge `Credit`s among decoded pending-message bodies `(position, program, message)`, i.e. the
/// pending private transfers the wallet has not yet received (docs/ARCHITECTURE.md §3.8).
pub fn bridge_credits(
    bridge: &[u8; 32],
    pending: &[(u64, [u8; 32], Vec<u8>)],
) -> Vec<(u64, Cfg, Tok, u128)> {
    pending
        .iter()
        .filter(|(_, program, _)| program == bridge)
        .filter_map(|(pos, _, m)| match borsh::from_slice(m).ok()? {
            BridgeMsg::Credit { cfg, tok, amount } => Some((*pos, cfg, tok, amount)),
            _ => None,
        })
        .collect()
}

/// Splits bridge credits `(position, cfg, tok, amount)` into those of `cfg` (the selected vault's
/// `CONFIG_ID`) and those of any other config. `InitConfig` is permissionless, so a look-alike config
/// can register the same token address; its credits are not claims on this vault's escrow.
#[allow(clippy::type_complexity)]
pub fn split_credits(
    credits: &[(u64, Cfg, Tok, u128)],
    cfg: &Cfg,
) -> (Vec<(u64, Cfg, Tok, u128)>, Vec<(u64, Cfg, Tok, u128)>) {
    credits.iter().copied().partition(|c| c.1 == *cfg)
}

/// Which half `b22 freeze` writes: mint (Ethereum deposits), burn (Ethereum releases), or both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreezeHalf {
    Mint,
    Burn,
    Both,
}

impl std::str::FromStr for FreezeHalf {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "mint" => Self::Mint,
            "burn" => Self::Burn,
            "both" => Self::Both,
            x => anyhow::bail!("expected mint|burn|both, got {x:?}"),
        })
    }
}

/// `b22 freeze`: the new `(mint/deposits, burn/releases)` flags from the current ones, changing
/// only the named half (`setFrozen` and `Freeze Global` write both). `Both` ignores `cur`.
pub fn freeze_flags(cur: (bool, bool), half: FreezeHalf, on: bool) -> (bool, bool) {
    match half {
        FreezeHalf::Mint => (on, cur.1),
        FreezeHalf::Burn => (cur.0, on),
        FreezeHalf::Both => (on, on),
    }
}

/// `cfg` comes from the vault's immutable `CONFIG_ID`; a local `BridgeConfig` that does not hash to
/// it is refused (a look-alike LEZ config can never be selected, docs/ARCHITECTURE.md §3.4).
pub fn check_cfg(vault_config_id: &Cfg, local: &BridgeConfig) -> Result<Cfg> {
    let c = config_id(local);
    ensure!(
        &c == vault_config_id,
        "local BridgeConfig hashes to 0x{} but the vault's CONFIG_ID is 0x{}",
        hex::encode(c),
        hex::encode(vault_config_id)
    );
    Ok(c)
}

// ---- root signing (INTERIM, CUSTODIAL, NOT TRUSTLESS) ----

/// The LEZ height every signer signs at: exactly `minLezDepth` blocks after the block that last
/// touched the token PDA, so independent signers pick the same height and digest.
pub fn sign_height(change: u64, min_depth: u64) -> u64 {
    change + min_depth
}

/// The attestation of the `(tok, d)` burn tree in `st` at LEZ block `(height, block_hash)`.
pub fn root_attestation(
    chain_id: u64,
    vault: [u8; 20],
    st: &TokenState,
    d: u128,
    height: u64,
    block_hash: [u8; 32],
) -> RootAttestation {
    let f = st
        .trees
        .iter()
        .find(|(x, _)| *x == d)
        .map(|(_, f)| f.clone())
        .unwrap_or_default();
    RootAttestation {
        chain_id,
        vault,
        config_id: st.cfg,
        token: st.entry.tok,
        denom: d,
        burn_root: f.root(),
        count: f.leaves,
        lez_height: height,
        lez_block_hash: block_hash,
    }
}

/// Ethereum address of a secp256k1 key.
pub fn signer_address(key: &[u8; 32]) -> Result<[u8; 20]> {
    eth_address(key).ok_or_else(|| anyhow::anyhow!("invalid secp256k1 key"))
}

/// 65-byte `r ‖ s ‖ v` (v = 27/28, low s) over the raw digest (no EIP-191 prefix).
pub fn sign_digest(key: &[u8; 32], digest: &[u8; 32]) -> Result<[u8; 65]> {
    let sk = k256::ecdsa::SigningKey::from_slice(key)?;
    let (sig, rec) = sk.sign_prehash_recoverable(digest)?;
    let (sig, rec) = match sig.normalize_s() {
        Some(n) => (
            n,
            k256::ecdsa::RecoveryId::from_byte(rec.to_byte() ^ 1).unwrap(),
        ),
        None => (sig, rec),
    };
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = 27 + rec.to_byte();
    Ok(out)
}

pub fn recover_signer(digest: &[u8; 32], sig: &[u8; 65]) -> Result<[u8; 20]> {
    let s = k256::ecdsa::Signature::from_slice(&sig[..64])?;
    ensure!(sig[64] == 27 || sig[64] == 28, "bad v");
    let rec = k256::ecdsa::RecoveryId::from_byte(sig[64] - 27).unwrap();
    let vk = k256::ecdsa::VerifyingKey::recover_from_prehash(digest, &s, rec)?;
    let p = vk.to_encoded_point(false);
    Ok(alloy_primitives::keccak256(&p.as_bytes()[1..])[12..]
        .try_into()
        .unwrap())
}

/// `attestation` for `acceptBurnRoot`: the signatures concatenated in strictly ascending signer order.
pub fn combine_sigs(digest: &[u8; 32], sigs: &[[u8; 65]]) -> Result<Vec<u8>> {
    let mut by: Vec<([u8; 20], [u8; 65])> = sigs
        .iter()
        .map(|s| Ok((recover_signer(digest, s)?, *s)))
        .collect::<Result<_>>()?;
    by.sort_by_key(|(a, _)| *a);
    if by.windows(2).any(|w| w[0].0 == w[1].0) {
        bail!("two signatures from the same signer");
    }
    Ok(by.iter().flat_map(|(_, s)| s.to_vec()).collect())
}

// ---- release ----

/// RISC0_DEV_MODE seal accepted by risc0-ethereum's `RiscZeroMockVerifier(0xFFFFFFFF)`:
/// `0xffffffff ‖ ReceiptClaim::ok(image_id, journal).digest()` (same as `bridge-prover`'s fake seal).
pub fn mock_seal(image_id: [u32; 8], journal: &[u8]) -> Vec<u8> {
    use risc0_zkvm::sha::Digestible;
    let claim = risc0_zkvm::ReceiptClaim::ok(image_id, journal.to_vec());
    [&[0xff; 4][..], claim.digest().as_bytes()].concat()
}

/// Host-side membership check of a release request (what `burn_member` proves).
pub fn is_member(note: &BurnNote, index: u64, path: &[[u8; 32]], root: &[u8; 32]) -> bool {
    merkle_root(note.b, index, path) == Some(*root)
}

/// Names of the needles found in `hay` (empty = no leak).
pub fn leaks<'a>(hay: &[u8], needles: &'a [(String, Vec<u8>)]) -> Vec<&'a str> {
    needles
        .iter()
        .filter(|(_, n)| !n.is_empty() && hay.windows(n.len()).any(|w| w == n.as_slice()))
        .map(|(name, _)| name.as_str())
        .collect()
}
