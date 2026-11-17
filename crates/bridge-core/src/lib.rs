//! RFP-022 bridge formats (docs/ARCHITECTURE.md §3.2): seed derivations, PDA seeds, LEZ state and
//! message layouts, and the Ethereum-side digests. Pure functions, shared by the LEZ program
//! (`bridge`), the guests, the prover and the `b22` client; `fixtures/b22/vectors.json` pins them
//! for the Solidity side.
//!
//! Integers are little-endian inside LEZ formats (`d` as u128 = 16 bytes, indices as u64 = 8
//! bytes) and ABI words on Ethereum.

use std::collections::BTreeMap;

use alloy_primitives::keccak256;
use attest_program::{HeaderRecord, InstanceId};
use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::account::AccountId;
use lee_core::program::PdaSeed;
use sha2::{Digest, Sha256};

pub use attest_program::{
    merkle_path, merkle_root, Frontier, HEADER_TREE_DEPTH as BURN_TREE_DEPTH,
};
pub use consumers::{commit, pnf, ERR_ALREADY_CLAIMED};

/// Config id (`CONFIG_ID` on Ethereum).
pub type Cfg = [u8; 32];
/// Ethereum token address; `[0; 20]` = native ETH.
pub type Tok = [u8; 20];

// ---- error codes (docs/ARCHITECTURE.md §3.2; 1001/1101/1203/1250 are reused from RFP-021) ----
pub const ERR_MALFORMED: u16 = 1001;
pub const ERR_TOKEN_NOT_LISTED: u16 = 1301;
pub const ERR_DENOM_NOT_PERMITTED: u16 = 1302;
pub const ERR_CAP_EXCEEDED: u16 = 1303;
pub const ERR_FROZEN: u16 = 1304;
pub const ERR_INSUFFICIENT_BALANCE: u16 = 1305;
pub const ERR_UNAUTHORIZED: u16 = 1306;
pub const ERR_TREE_FULL: u16 = 1307;
pub const ERR_FEE_MISMATCH: u16 = 1308;

fn h(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut x = Sha256::new();
    x.update(tag);
    for p in parts {
        x.update(p);
    }
    x.finalize().into()
}

// ---- seed derivations (docs/ARCHITECTURE.md §3.2) ----

/// `sk = sha256("b022/sk" ‖ seed)`.
pub fn sk(seed: &[u8]) -> [u8; 32] {
    h(b"b022/sk", &[seed])
}

/// Deposit note `nk_i = sha256("b022/nk" ‖ sk ‖ cfg ‖ tok ‖ d_le16 ‖ i_le8)`; `C_i = commit(nk_i)`.
pub fn nk(sk: &[u8; 32], cfg: &Cfg, tok: &Tok, d: u128, i: u64) -> [u8; 32] {
    h(
        b"b022/nk",
        &[sk, cfg, tok, &d.to_le_bytes(), &i.to_le_bytes()],
    )
}

/// Burn key `rk_j = sha256("b022/rk" ‖ sk ‖ cfg ‖ tok ‖ d_le16 ‖ j_le8)`.
pub fn rk(sk: &[u8; 32], cfg: &Cfg, tok: &Tok, d: u128, j: u64) -> [u8; 32] {
    h(
        b"b022/rk",
        &[sk, cfg, tok, &d.to_le_bytes(), &j.to_le_bytes()],
    )
}

/// Release key `ek_j = sha256("b022/eth" ‖ sk ‖ cfg ‖ j_le8) mod n` (big-endian scalar);
/// `None` when it reduces to zero (probability ~2^-256): the client skips that `j`.
#[cfg(feature = "host")]
pub fn ek(sk: &[u8; 32], cfg: &Cfg, j: u64) -> Option<[u8; 32]> {
    use k256::elliptic_curve::ops::Reduce;
    let s = <k256::Scalar as Reduce<k256::U256>>::reduce_bytes(
        &h(b"b022/eth", &[sk, cfg, &j.to_le_bytes()]).into(),
    );
    (!bool::from(s.is_zero())).then(|| s.to_bytes().into())
}

/// Ethereum address of a secp256k1 secret key (keccak of the uncompressed public key, last 20 bytes).
#[cfg(feature = "host")]
pub fn eth_address(secret: &[u8; 32]) -> Option<[u8; 20]> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let sk = k256::SecretKey::from_slice(secret).ok()?;
    let p = sk.public_key().to_encoded_point(false);
    Some(keccak256(&p.as_bytes()[1..])[12..].try_into().unwrap())
}

/// Default release address `recipient_j = address(ek_j)`.
#[cfg(feature = "host")]
pub fn recipient(sk: &[u8; 32], cfg: &Cfg, j: u64) -> Option<[u8; 20]> {
    eth_address(&ek(sk, cfg, j)?)
}

/// Burn commitment `B = sha256("b022/burn" ‖ rk ‖ recipient)`.
pub fn burn_commitment(rk: &[u8; 32], recipient: &[u8; 20]) -> [u8; 32] {
    h(b"b022/burn", &[rk, recipient])
}

/// Release nullifier `Nb = sha256("b022/rnf" ‖ rk)`.
pub fn burn_nullifier(rk: &[u8; 32]) -> [u8; 32] {
    h(b"b022/rnf", &[rk])
}

// ---- LEZ config, ids, PDAs (docs/ARCHITECTURE.md §3.2) ----

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BridgeConfig {
    pub instance_id: InstanceId,
    pub evm_chain_id: u64,
    pub genesis_validators_root: [u8; 32],
    pub vault: [u8; 20],
    pub deposit_topic0: [u8; 32],
    pub zone_id: [u8; 32],
    pub bridge_program_id: [u8; 32],
    pub admin: AccountId,
    pub freezer: AccountId,
    pub salt: [u8; 32],
}

/// `cfg = CONFIG_ID = sha256("b022/cfg" ‖ borsh(BridgeConfig))`; also the `cfg_hash` of `MintCheck`/`RecordBurn`.
pub fn config_id(c: &BridgeConfig) -> Cfg {
    h(b"b022/cfg", &[&borsh::to_vec(c).unwrap()])
}

/// Prototype placeholder `zone_id = sha256("b022/zone/local-standalone")` (open question for Logos: the real zone id).
pub fn local_zone_id() -> [u8; 32] {
    h(b"b022/zone/local-standalone", &[])
}

pub fn config_seed(cfg: &Cfg) -> [u8; 32] {
    h(b"b022/config", &[cfg])
}

pub fn token_seed(cfg: &Cfg, tok: &Tok) -> [u8; 32] {
    h(b"b022/token", &[cfg, tok])
}

pub fn leaf_seed(cfg: &Cfg, tok: &Tok, d: u128, index: u64) -> [u8; 32] {
    h(
        b"b022/bleaf",
        &[cfg, tok, &d.to_le_bytes(), &index.to_le_bytes()],
    )
}

fn pda(bridge: &AccountId, seed: [u8; 32]) -> AccountId {
    AccountId::for_public_pda(bridge, &PdaSeed::new(seed))
}

/// Config PDA: state [`ConfigState`].
pub fn config_pda(bridge: &AccountId, cfg: &Cfg) -> AccountId {
    pda(bridge, config_seed(cfg))
}

/// Token PDA: state [`TokenState`]. `Spend`/`WriteLeaf` receivers recompute it from `(cfg, tok)`.
pub fn token_pda(bridge: &AccountId, cfg: &Cfg, tok: &Tok) -> AccountId {
    pda(bridge, token_seed(cfg, tok))
}

/// Write-once burn leaf PDA: state `B` (32 bytes).
pub fn leaf_pda(bridge: &AccountId, cfg: &Cfg, tok: &Tok, d: u128, index: u64) -> AccountId {
    pda(bridge, leaf_seed(cfg, tok, d, index))
}

/// Deposit nullifier PDA `PDA(bridge, n)` with `n = pnf(nk)`: state `[1]`.
pub fn n_pda(bridge: &AccountId, n: &[u8; 32]) -> AccountId {
    pda(bridge, *n)
}

// ---- LEZ state ----

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ConfigState {
    pub config: BridgeConfig,
    pub paused_mint: bool,
    pub paused_burn: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DenomEntry {
    pub d: u128,
    pub fee_mint: u128,
    pub fee_burn: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TokenEntry {
    pub tok: Tok,
    pub decimals: u8,
    pub denoms: Vec<DenomEntry>,
    pub supply_cap: u128,
    pub mint_open: bool,
    pub paused_mint: bool,
    pub paused_burn: bool,
}

impl TokenEntry {
    pub fn denom(&self, d: u128) -> Option<&DenomEntry> {
        self.denoms.iter().find(|e| e.d == d)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TokenState {
    pub cfg: Cfg,
    pub entry: TokenEntry,
    pub supply: u128,
    pub fees: u128,
    /// Burn accumulator per denomination.
    pub trees: Vec<(u128, Frontier)>,
}

/// Private holding: the bridge's actor state on the holder's private account.
pub type Holdings = BTreeMap<(Cfg, Tok), u128>;

// ---- LEZ messages (private-only set) ----

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum AdminOp {
    RegisterToken {
        cfg: Cfg,
        entry: TokenEntry,
    },
    /// Replaces the entry (fees, caps, `mint_open` = listing); `tok` must match.
    UpdateToken {
        cfg: Cfg,
        entry: TokenEntry,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum FreezeOp {
    /// Config PDA: global pause of each half.
    Global {
        cfg: Cfg,
        paused_mint: bool,
        paused_burn: bool,
    },
    /// Token PDA: per-token pause of each half.
    Token {
        cfg: Cfg,
        tok: Tok,
        paused_mint: bool,
        paused_burn: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[allow(clippy::large_enum_variant)] // Claim carries the deposit proof; boxing changes nothing on the wire
pub enum BridgeMsg {
    InitConfig(BridgeConfig),
    Admin(AdminOp),
    Freeze(FreezeOp),
    /// Private root call: verifies the deposit inline, credits `d - fee_mint`, sends `MintCheck`.
    Claim {
        bridge_cfg: BridgeConfig,
        token_entry: TokenEntry,
        d: u128,
        header: HeaderRecord,
        header_index: u64,
        header_path: Vec<[u8; 32]>,
        exec_header_rlp: Vec<u8>,
        ancestry: Vec<Vec<u8>>,
        tx_index: u32,
        log_index: u32,
        receipt: Vec<u8>,
        receipt_proof: Vec<Vec<u8>>,
        nk: [u8; 32],
    },
    /// Private actor → token PDA.
    MintCheck {
        cfg_hash: Cfg,
        tok: Tok,
        d: u128,
        fee_mint: u128,
        root: [u8; 32],
        n: [u8; 32],
    },
    /// Token PDA → N PDA.
    Spend {
        cfg: Cfg,
        tok: Tok,
        n: [u8; 32],
    },
    /// Private root call: debits `amount`, emits a pending (sealed) `Credit` to `to`, the
    /// recipient's private address `AccountId::for_regular_private_account(npk, vpk)`. The guest
    /// sees only its message, so the address must travel here (as `native_token::Transfer{to}`).
    Transfer {
        cfg: Cfg,
        tok: Tok,
        amount: u128,
        to: AccountId,
    },
    /// Pending message applied by `receive_pending_message_with`.
    Credit {
        cfg: Cfg,
        tok: Tok,
        amount: u128,
    },
    /// Private root call: debits `d + fee_burn`, sends `RecordBurn` at leaf `index`.
    Burn {
        bridge_cfg: BridgeConfig,
        token_entry: TokenEntry,
        d: u128,
        index: u64,
        b: [u8; 32],
    },
    /// Private actor → token PDA.
    RecordBurn {
        cfg_hash: Cfg,
        tok: Tok,
        d: u128,
        fee_burn: u128,
        b: [u8; 32],
        index: u64,
    },
    /// Token PDA → leaf PDA.
    WriteLeaf {
        cfg: Cfg,
        tok: Tok,
        d: u128,
        index: u64,
        b: [u8; 32],
    },
}

// ---- Ethereum (docs/ARCHITECTURE.md §3.2) ----

pub const DEPOSIT_EVENT: &str = "Deposit(bytes32,address,bytes32,uint256)";
pub const BURN_ROOT_ACCEPTED_EVENT: &str =
    "BurnRootAccepted(address,uint256,bytes32,uint64,uint64,bytes32)";
pub const BURN_ROOT_REVOKED_EVENT: &str = "BurnRootRevoked(address,uint256,bytes32)";

/// `bytes32("b022/root/v1")`: ASCII, right-padded with zeros.
pub const TAG_ROOT: [u8; 32] = tag(b"b022/root/v1");
/// `bytes32("b022/rel/v1")`.
pub const TAG_REL: [u8; 32] = tag(b"b022/rel/v1");

const fn tag(s: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 32];
    let mut i = 0;
    while i < s.len() {
        w[i] = s[i];
        i += 1;
    }
    w
}

/// Event topic0 = `keccak256(signature)`.
pub fn event_topic0(signature: &str) -> [u8; 32] {
    keccak256(signature.as_bytes()).0
}

/// topic0 of [`DEPOSIT_EVENT`] (goes into `BridgeConfig::deposit_topic0`).
pub fn deposit_topic0() -> [u8; 32] {
    event_topic0(DEPOSIT_EVENT)
}

fn word_uint(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

fn word_addr(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

/// What each root signer signs (INTERIM, CUSTODIAL): `keccak256(abi.encode(TAG_ROOT, chainid,
/// vault, CONFIG_ID, token, denom, burnRoot, count, lezHeight, lezBlockHash))`.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RootAttestation {
    pub chain_id: u64,
    pub vault: [u8; 20],
    pub config_id: Cfg,
    pub token: Tok,
    pub denom: u128,
    pub burn_root: [u8; 32],
    pub count: u64,
    pub lez_height: u64,
    pub lez_block_hash: [u8; 32],
}

impl RootAttestation {
    pub fn digest(&self) -> [u8; 32] {
        let words = [
            TAG_ROOT,
            word_uint(self.chain_id.into()),
            word_addr(&self.vault),
            self.config_id,
            word_addr(&self.token),
            word_uint(self.denom),
            self.burn_root,
            word_uint(self.count.into()),
            word_uint(self.lez_height.into()),
            self.lez_block_hash,
        ];
        keccak256(words.concat()).0
    }
}

/// `burn_member` journal: `abi.encode(TAG_REL, chainid, vault, CONFIG_ID, token, denom, burnRoot,
/// Nb, recipient, relayer, fee)` (11 static words, 352 bytes); the vault verifies the seal
/// against `sha256(journal)`.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReleaseJournal {
    pub chain_id: u64,
    pub vault: [u8; 20],
    pub config_id: Cfg,
    pub token: Tok,
    pub denom: u128,
    pub burn_root: [u8; 32],
    pub nb: [u8; 32],
    pub recipient: [u8; 20],
    pub relayer: [u8; 20],
    pub fee: u128,
}

impl ReleaseJournal {
    pub fn encode(&self) -> Vec<u8> {
        [
            TAG_REL,
            word_uint(self.chain_id.into()),
            word_addr(&self.vault),
            self.config_id,
            word_addr(&self.token),
            word_uint(self.denom),
            self.burn_root,
            self.nb,
            word_addr(&self.recipient),
            word_addr(&self.relayer),
            word_uint(self.fee),
        ]
        .concat()
    }

    /// `sha256(encode())`: the journal digest the Groth16 verifier checks.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
}
