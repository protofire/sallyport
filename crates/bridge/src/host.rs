//! Transaction builders: the message of each private root call plus the public
//! actors it touches and the PDA admission evidence for accounts it may create. The caller proves
//! the call on the holder's private account (`Actor::new(holder, bridge)`), as
//! `program_tests::Chain::prove_private` does.

use attest_program::{header_leaf, hroot_seed, merkle_root};
use bridge_core::*;
use lee_core::account::{AccountId, Actor};

/// A private root call ready to prove: `msg` to `Actor::new(holder, bridge)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateCall {
    pub msg: BridgeMsg,
    /// Public actors the transition reaches, in a stable order.
    pub public_actors: Vec<Actor>,
    /// `(program, seed)` admission evidence for PDAs the tx may create.
    pub evidence: Vec<(AccountId, [u8; 32])>,
}

fn attest() -> AccountId {
    AccountId::new(consumers::ATTEST_PROGRAM)
}

/// Header-accumulator root a `Claim` proves membership in (`None` if the path is malformed).
pub fn claim_root(msg: &BridgeMsg) -> Option<[u8; 32]> {
    let BridgeMsg::Claim {
        header,
        header_index,
        header_path,
        ..
    } = msg
    else {
        return None;
    };
    merkle_root(header_leaf(header), *header_index, header_path)
}

/// `Claim`: public actors {config PDA, attest root PDA, token PDA, N PDA}; evidence for N.
/// `None` unless `msg` is a `Claim` with a well-formed header path.
pub fn claim(bridge: AccountId, msg: BridgeMsg) -> Option<PrivateCall> {
    let root = claim_root(&msg)?;
    let BridgeMsg::Claim {
        bridge_cfg,
        token_entry,
        nk,
        ..
    } = &msg
    else {
        return None;
    };
    let cfg = config_id(bridge_cfg);
    let n = pnf(nk);
    let hroot = hroot_seed(&bridge_cfg.instance_id, &root);
    Some(PrivateCall {
        public_actors: vec![
            Actor::new(config_pda(&bridge, &cfg), bridge),
            Actor::new(
                AccountId::for_public_pda(&attest(), &lee_core::program::PdaSeed::new(hroot)),
                attest(),
            ),
            Actor::new(token_pda(&bridge, &cfg, &token_entry.tok), bridge),
            Actor::new(n_pda(&bridge, &n), bridge),
        ],
        evidence: vec![(bridge, n)],
        msg,
    })
}

/// `Burn` of `d` at leaf `index` (= the `(tok, d)` tree's current `leaves`, [`next_index`]):
/// public actors {config PDA, token PDA, leaf PDA}; evidence for the leaf.
pub fn burn(
    bridge: AccountId,
    bridge_cfg: &BridgeConfig,
    token_entry: &TokenEntry,
    d: u128,
    index: u64,
    b: [u8; 32],
) -> PrivateCall {
    let cfg = config_id(bridge_cfg);
    let tok = token_entry.tok;
    PrivateCall {
        public_actors: vec![
            Actor::new(config_pda(&bridge, &cfg), bridge),
            Actor::new(token_pda(&bridge, &cfg, &tok), bridge),
            Actor::new(leaf_pda(&bridge, &cfg, &tok, d, index), bridge),
        ],
        evidence: vec![(bridge, leaf_seed(&cfg, &tok, d, index))],
        msg: BridgeMsg::Burn {
            bridge_cfg: bridge_cfg.clone(),
            token_entry: token_entry.clone(),
            d,
            index,
            b,
        },
    }
}

/// `Transfer` (send half): no public actors; the `Credit` to `to` is sealed for the recipient
/// (`RecipientEncryption{npk, vpk}`), who applies it with a second tx.
pub fn transfer(cfg: Cfg, tok: Tok, amount: u128, to: AccountId) -> PrivateCall {
    PrivateCall {
        msg: BridgeMsg::Transfer {
            cfg,
            tok,
            amount,
            to,
        },
        public_actors: vec![],
        evidence: vec![],
    }
}

/// Next free leaf index of the `(tok, d)` burn tree in a token PDA's state.
pub fn next_index(token_state: &TokenState, d: u128) -> u64 {
    token_state
        .trees
        .iter()
        .find(|(x, _)| *x == d)
        .map_or(0, |(_, f)| f.leaves)
}

/// Deploy key of the bridge program header account, derived from its risc0 image id:
/// `sha256("b022/deploy-key" ‖ image_id as LE words)`. `bridge_program_id` is the account of
/// this key (`AccountId::from(&PublicKey::new_from_private_key(key))`, as `ATTEST_DEPLOY_KEY`).
/// Public on purpose, like `consumers::ATTEST_DEPLOY_KEY`: the program is deployed immutable,
/// the key only fixes the address. shortcut: anyone can derive the key and deploy first at that
/// address on a shared network; deploy before publishing the image id, or switch to a private
/// deploy key for a public testnet.
pub fn deploy_key(image_id: [u32; 8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"b022/deploy-key");
    for w in image_id {
        h.update(w.to_le_bytes());
    }
    h.finalize().into()
}
