//! Guest handler of the bridge program (docs/ARCHITECTURE.md §3). Private-only message set.
//!
//! Routes (every internal message authenticates its caller, docs/ARCHITECTURE.md §3.3):
//! - `Claim` / `Burn` (private root call, holder authorized) → `MintCheck` / `RecordBurn` to the
//!   **config PDA**, which checks the global pause and `cfg_hash`, chains `CheckRoot` (claim) and
//!   forwards to the **token PDA** (accepted only from the config PDA). The token PDA re-checks
//!   the entry the private side used, updates supply/fees/Frontier, then `Spend` → N PDA or
//!   `WriteLeaf` → leaf PDA (both recompute the token PDA from `(cfg, tok)`).
//! - `Transfer` (private root call) → sealed async `Credit` to `to`; `Credit` is applied only
//!   from this program and only on an authorized (owner-received) account.
//! - `Admin` / `Freeze`: seat (admin or freezer's own account, signed) → config PDA (checks the
//!   role) → token PDA for per-token ops.
//!
//! The config-PDA hop exists because the token PDA cannot read the global pause flags.

use crate::claim_preds;
use attest_program::{header_leaf, hroot_seed, merkle_root, Msg as AttestMsg};
use bridge_core::*;
use inclusion::Locator;
use lee_core::account::{AccountId, Actor};
use lee_core::program::{AsyncMessage, PdaSeed, ReceiveInput, Response, SyncMessage};
use risc0_zkvm::guest::env;

const STATEMENT_MISMATCH: u16 = 1204;

/// Exit code `(code - 1000) mod 256`: 1301–1308 leave the guest as 45–52 ([`crate::error_from_exit`]).
fn fail(code: u16) -> ! {
    env::exit(((code - 1000) % 256) as u8)
}

fn decode<T: borsh::BorshDeserialize>(b: &[u8]) -> T {
    borsh::from_slice(b).unwrap_or_else(|_| fail(ERR_MALFORMED))
}

fn ok_or<T>(v: Option<T>, code: u16) -> T {
    v.unwrap_or_else(|| fail(code))
}

fn holdings(input: &ReceiveInput) -> Holdings {
    if input.pre_state.is_empty() {
        Holdings::new()
    } else {
        decode(&input.pre_state)
    }
}

fn set_holdings(h: &Holdings) -> Response {
    Response::set_state(borsh::to_vec(h).unwrap())
}

pub fn handle(input: &ReceiveInput, message: &[u8]) -> Response {
    let me = input.receiver.program_account_id;
    match decode::<BridgeMsg>(message) {
        BridgeMsg::InitConfig(c) => {
            let cfg = config_id(&c);
            if input.receiver.account_id != config_pda(&me, &cfg)
                || !input.pre_state.is_empty()
                || c.bridge_program_id != *me.value()
                || c.deposit_topic0 != deposit_topic0()
            {
                fail(ERR_MALFORMED);
            }
            Response::set_state(
                borsh::to_vec(&ConfigState {
                    config: c,
                    paused_mint: false,
                    paused_burn: false,
                })
                .unwrap(),
            )
        }
        BridgeMsg::Admin(op) => admin(input, me, Op::Admin(op)),
        BridgeMsg::Freeze(op) => admin(input, me, Op::Freeze(op)),
        m @ BridgeMsg::Claim { .. } => claim(input, me, m),
        BridgeMsg::MintCheck {
            cfg_hash,
            tok,
            d,
            fee_mint,
            root,
            n,
        } => {
            let cp = config_pda(&me, &cfg_hash);
            let tp = token_pda(&me, &cfg_hash, &tok);
            let msg = BridgeMsg::MintCheck {
                cfg_hash,
                tok,
                d,
                fee_mint,
                root,
                n,
            };
            if input.receiver.account_id == cp {
                let st = config_hop(input, me, &cfg_hash);
                if st.paused_mint {
                    fail(ERR_FROZEN);
                }
                let id = st.config.instance_id;
                Response::keep_state()
                    .send(SyncMessage::new(
                        Actor::new(
                            AccountId::for_public_pda(
                                &AccountId::new(consumers::ATTEST_PROGRAM),
                                &PdaSeed::new(hroot_seed(&id, &root)),
                            ),
                            AccountId::new(consumers::ATTEST_PROGRAM),
                        ),
                        &AttestMsg::CheckRoot {
                            instance_id: id,
                            root,
                        },
                    ))
                    .send(SyncMessage::new(Actor::new(tp, me), &msg))
            } else if input.receiver.account_id == tp {
                let mut st = token_hop(input, me, &cfg_hash, &tok);
                let e = &st.entry;
                if !e.mint_open {
                    fail(ERR_TOKEN_NOT_LISTED);
                }
                let de = ok_or(e.denom(d), ERR_DENOM_NOT_PERMITTED);
                if de.fee_mint != fee_mint {
                    fail(ERR_FEE_MISMATCH);
                }
                if e.paused_mint {
                    fail(ERR_FROZEN);
                }
                st.supply = st
                    .supply
                    .checked_add(d)
                    .filter(|s| *s <= st.entry.supply_cap)
                    .unwrap_or_else(|| fail(ERR_CAP_EXCEEDED));
                st.fees = ok_or(st.fees.checked_add(fee_mint), ERR_MALFORMED);
                Response::set_state(borsh::to_vec(&st).unwrap()).send(
                    SyncMessage::new(
                        Actor::new(n_pda(&me, &n), me),
                        &BridgeMsg::Spend {
                            cfg: cfg_hash,
                            tok,
                            n,
                        },
                    )
                    .with_pda_seeds([PdaSeed::new(n)]),
                )
            } else {
                fail(ERR_UNAUTHORIZED)
            }
        }
        BridgeMsg::Spend { cfg, tok, n } => {
            if input.receiver.account_id != n_pda(&me, &n)
                || input.from != Some(Actor::new(token_pda(&me, &cfg, &tok), me))
            {
                fail(ERR_UNAUTHORIZED);
            }
            if !input.pre_state.is_empty() {
                fail(ERR_ALREADY_CLAIMED);
            }
            Response::set_state(vec![1])
        }
        BridgeMsg::Transfer {
            cfg,
            tok,
            amount,
            to,
        } => {
            if !input.is_authorized || input.from.is_some() {
                fail(ERR_UNAUTHORIZED);
            }
            let mut h = holdings(input);
            debit(&mut h, cfg, tok, amount);
            set_holdings(&h).send(AsyncMessage::new(
                Actor::new(to, me),
                &BridgeMsg::Credit { cfg, tok, amount },
            ))
        }
        BridgeMsg::Credit { cfg, tok, amount } => {
            // from this program (a Transfer) and received by the account's owner
            if !input.from_own_program() || !input.is_authorized {
                fail(ERR_UNAUTHORIZED);
            }
            let mut h = holdings(input);
            let b = h.entry((cfg, tok)).or_insert(0);
            *b = ok_or(b.checked_add(amount), ERR_MALFORMED);
            set_holdings(&h)
        }
        BridgeMsg::Burn {
            bridge_cfg,
            token_entry,
            d,
            index,
            b,
        } => {
            if !input.is_authorized || input.from.is_some() {
                fail(ERR_UNAUTHORIZED);
            }
            if bridge_cfg.bridge_program_id != *me.value() {
                fail(ERR_MALFORMED);
            }
            let cfg = config_id(&bridge_cfg);
            let de = ok_or(token_entry.denom(d), ERR_DENOM_NOT_PERMITTED);
            let fee_burn = de.fee_burn;
            let mut h = holdings(input);
            debit(
                &mut h,
                cfg,
                token_entry.tok,
                ok_or(d.checked_add(fee_burn), ERR_MALFORMED),
            );
            set_holdings(&h).send(SyncMessage::new(
                Actor::new(config_pda(&me, &cfg), me),
                &BridgeMsg::RecordBurn {
                    cfg_hash: cfg,
                    tok: token_entry.tok,
                    d,
                    fee_burn,
                    b,
                    index,
                },
            ))
        }
        BridgeMsg::RecordBurn {
            cfg_hash,
            tok,
            d,
            fee_burn,
            b,
            index,
        } => {
            let cp = config_pda(&me, &cfg_hash);
            let tp = token_pda(&me, &cfg_hash, &tok);
            if input.receiver.account_id == cp {
                if config_hop(input, me, &cfg_hash).paused_burn {
                    fail(ERR_FROZEN);
                }
                return Response::keep_state().send(SyncMessage::new(
                    Actor::new(tp, me),
                    &BridgeMsg::RecordBurn {
                        cfg_hash,
                        tok,
                        d,
                        fee_burn,
                        b,
                        index,
                    },
                ));
            }
            if input.receiver.account_id != tp {
                fail(ERR_UNAUTHORIZED);
            }
            // a delisted token (mint_open = false) still burns
            let mut st = token_hop(input, me, &cfg_hash, &tok);
            let de = ok_or(st.entry.denom(d), ERR_DENOM_NOT_PERMITTED);
            if de.fee_burn != fee_burn {
                fail(ERR_FEE_MISMATCH);
            }
            if st.entry.paused_burn {
                fail(ERR_FROZEN);
            }
            let pos = match st.trees.iter().position(|(x, _)| *x == d) {
                Some(p) => p,
                None => {
                    st.trees.push((d, Frontier::default()));
                    st.trees.len() - 1
                }
            };
            let tree = &mut st.trees[pos].1;
            if tree.leaves != index {
                fail(ERR_MALFORMED);
            }
            ok_or(tree.append(b), ERR_TREE_FULL);
            st.supply = ok_or(st.supply.checked_sub(d), ERR_MALFORMED);
            st.fees = ok_or(st.fees.checked_add(fee_burn), ERR_MALFORMED);
            Response::set_state(borsh::to_vec(&st).unwrap()).send(
                SyncMessage::new(
                    Actor::new(leaf_pda(&me, &cfg_hash, &tok, d, index), me),
                    &BridgeMsg::WriteLeaf {
                        cfg: cfg_hash,
                        tok,
                        d,
                        index,
                        b,
                    },
                )
                .with_pda_seeds([PdaSeed::new(leaf_seed(&cfg_hash, &tok, d, index))]),
            )
        }
        BridgeMsg::WriteLeaf {
            cfg,
            tok,
            d,
            index,
            b,
        } => {
            if input.receiver.account_id != leaf_pda(&me, &cfg, &tok, d, index)
                || input.from != Some(Actor::new(token_pda(&me, &cfg, &tok), me))
            {
                fail(ERR_UNAUTHORIZED);
            }
            if !input.pre_state.is_empty() {
                fail(ERR_MALFORMED);
            }
            Response::set_state(b.to_vec())
        }
    }
}

fn debit(h: &mut Holdings, cfg: Cfg, tok: Tok, amount: u128) {
    let b = ok_or(h.get_mut(&(cfg, tok)), ERR_INSUFFICIENT_BALANCE);
    *b = ok_or(b.checked_sub(amount), ERR_INSUFFICIENT_BALANCE);
    if *b == 0 {
        h.remove(&(cfg, tok));
    }
}

/// Config PDA receiving a message relayed from a bridge actor (blinded private holder).
fn config_hop(input: &ReceiveInput, me: AccountId, cfg: &Cfg) -> ConfigState {
    if !input.from.is_some_and(|f| f.program_account_id == me) {
        fail(ERR_UNAUTHORIZED);
    }
    if input.pre_state.is_empty() {
        fail(ERR_TOKEN_NOT_LISTED);
    }
    let st: ConfigState = decode(&input.pre_state);
    if config_id(&st.config) != *cfg {
        fail(ERR_MALFORMED);
    }
    st
}

/// Token PDA receiving a message the config PDA of `cfg` forwarded.
fn token_hop(input: &ReceiveInput, me: AccountId, cfg: &Cfg, tok: &Tok) -> TokenState {
    if input.from != Some(Actor::new(config_pda(&me, cfg), me)) {
        fail(ERR_UNAUTHORIZED);
    }
    if input.pre_state.is_empty() {
        fail(ERR_TOKEN_NOT_LISTED);
    }
    let st: TokenState = decode(&input.pre_state);
    if st.cfg != *cfg || st.entry.tok != *tok {
        fail(ERR_MALFORMED);
    }
    st
}

enum Op {
    Admin(AdminOp),
    Freeze(FreezeOp),
}

impl Op {
    fn cfg(&self) -> Cfg {
        match self {
            Op::Admin(AdminOp::RegisterToken { cfg, .. } | AdminOp::UpdateToken { cfg, .. })
            | Op::Freeze(FreezeOp::Global { cfg, .. } | FreezeOp::Token { cfg, .. }) => *cfg,
        }
    }

    fn tok(&self) -> Option<Tok> {
        match self {
            Op::Admin(
                AdminOp::RegisterToken { entry, .. } | AdminOp::UpdateToken { entry, .. },
            ) => Some(entry.tok),
            Op::Freeze(FreezeOp::Token { tok, .. }) => Some(*tok),
            Op::Freeze(FreezeOp::Global { .. }) => None,
        }
    }

    fn msg(&self) -> BridgeMsg {
        match self {
            Op::Admin(o) => BridgeMsg::Admin(o.clone()),
            Op::Freeze(o) => BridgeMsg::Freeze(o.clone()),
        }
    }
}

/// LEZ-side fees must be 0: fees are charged once, at release on Ethereum (the vault's proven fee).
/// A non-zero LEZ fee would strand a single deposit (mint `d - fee_mint` < burn `d + fee_burn`).
fn valid_entry(e: &TokenEntry) -> bool {
    e.decimals <= 18
        && !e.denoms.is_empty()
        && e.denoms.iter().enumerate().all(|(i, x)| {
            x.d > 0
                && x.fee_mint == 0
                && x.fee_burn == 0
                && !e.denoms[..i].iter().any(|y| y.d == x.d)
        })
}

/// Seat (signed own account) → config PDA (role check) → token PDA.
fn admin(input: &ReceiveInput, me: AccountId, op: Op) -> Response {
    let cfg = op.cfg();
    let cp = config_pda(&me, &cfg);
    let tp = op.tok().map(|t| token_pda(&me, &cfg, &t));
    let at = input.receiver.account_id;
    if at == cp {
        let from = ok_or(
            input.from.filter(|f| f.program_account_id == me),
            ERR_UNAUTHORIZED,
        );
        if input.pre_state.is_empty() {
            fail(ERR_MALFORMED);
        }
        let mut st: ConfigState = decode(&input.pre_state);
        let role = match op {
            Op::Admin(_) => st.config.admin,
            Op::Freeze(_) => st.config.freezer,
        };
        if from.account_id != role {
            fail(ERR_UNAUTHORIZED);
        }
        return match (&op, tp) {
            (
                Op::Freeze(FreezeOp::Global {
                    paused_mint,
                    paused_burn,
                    ..
                }),
                _,
            ) => {
                st.paused_mint = *paused_mint;
                st.paused_burn = *paused_burn;
                Response::set_state(borsh::to_vec(&st).unwrap())
            }
            (_, Some(tp)) => Response::keep_state().send(
                SyncMessage::new(Actor::new(tp, me), &op.msg())
                    .with_pda_seeds([PdaSeed::new(token_seed(&cfg, &op.tok().unwrap()))]),
            ),
            _ => unreachable!(),
        };
    }
    if Some(at) == tp {
        if input.from != Some(Actor::new(cp, me)) {
            fail(ERR_UNAUTHORIZED);
        }
        return match op {
            Op::Admin(AdminOp::RegisterToken { cfg, entry }) => {
                if !input.pre_state.is_empty() || !valid_entry(&entry) {
                    fail(ERR_MALFORMED);
                }
                Response::set_state(
                    borsh::to_vec(&TokenState {
                        cfg,
                        entry,
                        supply: 0,
                        fees: 0,
                        trees: vec![],
                    })
                    .unwrap(),
                )
            }
            Op::Admin(AdminOp::UpdateToken { entry, .. }) => {
                if input.pre_state.is_empty() {
                    fail(ERR_TOKEN_NOT_LISTED);
                }
                let mut st: TokenState = decode(&input.pre_state);
                if !valid_entry(&entry) {
                    fail(ERR_MALFORMED);
                }
                // the pause flags belong to the freezer: only `Freeze` writes them
                let (pm, pb) = (st.entry.paused_mint, st.entry.paused_burn);
                st.entry = entry;
                st.entry.paused_mint = pm;
                st.entry.paused_burn = pb;
                Response::set_state(borsh::to_vec(&st).unwrap())
            }
            Op::Freeze(FreezeOp::Token {
                paused_mint,
                paused_burn,
                ..
            }) => {
                if input.pre_state.is_empty() {
                    fail(ERR_TOKEN_NOT_LISTED);
                }
                let mut st: TokenState = decode(&input.pre_state);
                st.entry.paused_mint = paused_mint;
                st.entry.paused_burn = paused_burn;
                Response::set_state(borsh::to_vec(&st).unwrap())
            }
            Op::Freeze(FreezeOp::Global { .. }) => unreachable!(),
        };
    }
    // seat: the role holder's own account, signed, top-level
    if input.from.is_some() || !input.is_authorized {
        fail(ERR_UNAUTHORIZED);
    }
    Response::keep_state().send(SyncMessage::new(Actor::new(cp, me), &op.msg()))
}

/// Runs in the holder's private transition: only `MintCheck` crosses the boundary.
fn claim(input: &ReceiveInput, me: AccountId, m: BridgeMsg) -> Response {
    let BridgeMsg::Claim {
        bridge_cfg: c,
        token_entry,
        d,
        header,
        header_index,
        header_path,
        exec_header_rlp,
        ancestry,
        tx_index,
        log_index,
        receipt,
        receipt_proof,
        nk,
    } = &m
    else {
        unreachable!()
    };
    if !input.is_authorized || input.from.is_some() {
        fail(ERR_UNAUTHORIZED);
    }
    if c.bridge_program_id != *me.value() {
        fail(ERR_MALFORMED);
    }
    let cfg = config_id(c);
    let de = ok_or(token_entry.denom(*d), ERR_DENOM_NOT_PERMITTED);
    if de.fee_mint >= *d {
        fail(ERR_MALFORMED);
    }
    if header.instance_id != c.instance_id
        || header.chain_id != c.evm_chain_id
        || header.genesis_validators_root != c.genesis_validators_root
    {
        fail(STATEMENT_MISMATCH);
    }
    let root = ok_or(
        merkle_root(header_leaf(header), *header_index, header_path),
        ERR_MALFORMED,
    );
    let req = attest_program::AttestRequestRef {
        instance_id: c.instance_id,
        exec_header_rlp,
        ancestry: ancestry.iter().map(Vec::as_slice).collect(),
        locator: Locator::Log {
            tx_index: *tx_index,
            log_index: *log_index,
        },
        proof: attest_program::ProofRef::Log {
            receipt,
            receipt_proof: receipt_proof.iter().map(Vec::as_slice).collect(),
        },
        preds: claim_preds(c, &cfg, &token_entry.tok, *d, nk),
        ctx: &[],
    };
    attest_program::verify_ref(header, &req).unwrap_or_else(|e| fail(e));
    let mut h = holdings(input);
    let bal = h.entry((cfg, token_entry.tok)).or_insert(0);
    *bal = ok_or(bal.checked_add(d - de.fee_mint), ERR_MALFORMED);
    set_holdings(&h).send(SyncMessage::new(
        Actor::new(config_pda(&me, &cfg), me),
        &BridgeMsg::MintCheck {
            cfg_hash: cfg,
            tok: token_entry.tok,
            d: *d,
            fee_mint: de.fee_mint,
            root,
            n: pnf(nk),
        },
    ))
}
