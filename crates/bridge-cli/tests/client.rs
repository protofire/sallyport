//! Client tests: derivations against the golden vectors, seed-only recovery on a
//! synthetic chain view, R7 (a claim killed before submit leaves the deposit claimable), signer digest
//! agreement and signature combination, `cfg` from the vault only, the mock seal, the leak scan.

use std::collections::{HashMap, HashSet};

use bridge_cli::*;
use bridge_core::*;
use serde_json::Value;

fn vectors() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/b22/vectors.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn hx<const N: usize>(v: &Value) -> [u8; N] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn vec_cfg(v: &Value) -> Cfg {
    hx(&v["config"]["config_id"])
}

const TOK: Tok = [0xAA; 20];
const ETH: Tok = [0; 20];
const D: u128 = 100_000_000;
const DE: u128 = 10_000_000_000_000_000;

#[test]
fn derivations_equal_l0_vectors() {
    let v = vectors();
    let keys = Keys::from_seed(&hex::decode(v["inputs"]["seed"].as_str().unwrap()).unwrap());
    assert_eq!(keys.sk, hx::<32>(&v["sk"]));
    let cfg = vec_cfg(&v);
    for (i, e) in v["per_index"].as_array().unwrap().iter().enumerate() {
        let i = i as u64;
        assert_eq!(keys.nk(&cfg, &TOK, D, i), hx::<32>(&e["nk"]));
        assert_eq!(
            keys.commitment(&cfg, &TOK, D, i),
            hx::<32>(&e["commitment"])
        );
        let n = keys.burn(&cfg, &TOK, D, i).unwrap();
        assert_eq!(n.rk, hx::<32>(&e["rk"]));
        assert_eq!(n.recipient, hx::<20>(&e["recipient"]));
        assert_eq!(n.b, hx::<32>(&e["burn_commitment"]));
        assert_eq!(n.nb, hx::<32>(&e["nb"]));
        assert_eq!(keys.release_key(&cfg, i).unwrap(), hx::<32>(&e["ek"]));
        assert_eq!(signer_address(&hx::<32>(&e["ek"])).unwrap(), n.recipient);
    }
}

/// Synthetic two-chain view: deposit logs, N PDAs, burn trees, spent `Nb`.
#[derive(Default)]
struct View {
    deposits: HashSet<(Tok, u128, [u8; 32])>,
    nullifiers: HashSet<[u8; 32]>,
    trees: HashMap<(Tok, u128), Vec<[u8; 32]>>,
    spent: HashSet<[u8; 32]>,
}

impl ChainView for View {
    fn deposit_seen(&self, tok: &Tok, d: u128, c: &[u8; 32]) -> bool {
        self.deposits.contains(&(*tok, d, *c))
    }
    fn claimed(&self, n: &[u8; 32]) -> bool {
        self.nullifiers.contains(n)
    }
    fn burn_leaves(&self, tok: &Tok, d: u128) -> Vec<[u8; 32]> {
        self.trees.get(&(*tok, d)).cloned().unwrap_or_default()
    }
    fn released(&self, nb: &[u8; 32]) -> bool {
        self.spent.contains(nb)
    }
}

#[test]
fn recovery_finds_unclaimed_deposit_unreleased_burn_and_pending_credit() {
    let cfg = [0xC0; 32];
    let a = Keys::from_seed(b"holder A");
    let other = Keys::from_seed(b"someone else");
    let mut v = View::default();
    // A: USDT deposits 0 (claimed), 1 (unclaimed), 3 after a gap of one (claimed); ETH deposit 0 (claimed)
    for (tok, d, i, claimed) in [
        (TOK, D, 0, true),
        (TOK, D, 1, false),
        (TOK, D, 3, true),
        (ETH, DE, 0, true),
    ] {
        let nk = a.nk(&cfg, &tok, d, i);
        v.deposits.insert((tok, d, commit(&nk)));
        if claimed {
            v.nullifiers.insert(pnf(&nk));
        }
    }
    // someone else's deposits and burns interleave
    v.deposits
        .insert((TOK, D, other.commitment(&cfg, &TOK, D, 0)));
    // burns: A j=0 USDT (released), j=1 ETH (unreleased), j=2 USDT (unreleased); other's j=0 USDT
    let b0 = a.burn(&cfg, &TOK, D, 0).unwrap();
    let b1 = a.burn(&cfg, &ETH, DE, 1).unwrap();
    let b2 = a.burn(&cfg, &TOK, D, 2).unwrap();
    let o0 = other.burn(&cfg, &TOK, D, 0).unwrap();
    v.trees.insert((TOK, D), vec![o0.b, b0.b, b2.b]);
    v.trees.insert((ETH, DE), vec![b1.b]);
    v.spent.insert(b0.nb);
    v.spent.insert(o0.nb);

    let r = recover(&a, &cfg, &[(TOK, D), (ETH, DE)], &v);
    assert_eq!(r.unclaimed.len(), 1);
    assert_eq!((r.unclaimed[0].tok, r.unclaimed[0].i), (TOK, 1));
    assert_eq!(r.unclaimed[0].nk, a.nk(&cfg, &TOK, D, 1));
    assert_eq!(r.claimed, 3);
    assert_eq!(r.next_i, vec![(TOK, D, 4), (ETH, DE, 1)]);
    let un: Vec<(Tok, u64, u64)> = r
        .unreleased
        .iter()
        .map(|u| (u.tok, u.note.j, u.index))
        .collect();
    assert_eq!(un, vec![(ETH, 1, 0), (TOK, 2, 2)]);
    assert_eq!(r.released, 1);
    assert_eq!(r.next_j, 3);

    // nothing of A's beyond the gap limit is found; a deposit at i = 3 + GAP + 1 is missed by design
    let mut far = View::default();
    far.deposits
        .insert((TOK, D, a.commitment(&cfg, &TOK, D, GAP + 1)));
    assert!(recover(&a, &cfg, &[(TOK, D)], &far).unclaimed.is_empty());

    // pending credits: only bridge Credit messages
    let bridge = [0xB2; 32];
    let credit = borsh::to_vec(&BridgeMsg::Credit {
        cfg,
        tok: TOK,
        amount: 7,
    })
    .unwrap();
    let pending = vec![
        (4, bridge, credit.clone()),
        (5, [0x01; 32], credit),
        (6, bridge, vec![9, 9]),
    ];
    assert_eq!(bridge_credits(&bridge, &pending), vec![(4, cfg, TOK, 7)]);
}

/// R7: the client records a claim as "in flight" before proving; killed before submit, nothing on
/// chain changed, so recovery (which reads only chain state) still lists the deposit as claimable.
#[test]
fn claim_killed_before_submit_leaves_deposit_claimable() {
    let cfg = [0xC1; 32];
    let a = Keys::from_seed(b"holder A");
    let mut v = View::default();
    let nk = a.nk(&cfg, &TOK, D, 0);
    v.deposits.insert((TOK, D, commit(&nk)));
    let before = recover(&a, &cfg, &[(TOK, D)], &v);
    // (the claim tx is built and proven here, then the process dies: no N PDA appears)
    let after = recover(&a, &cfg, &[(TOK, D)], &v);
    assert_eq!(before, after);
    assert_eq!(after.unclaimed[0].nk, nk);
    // once the N PDA exists it is no longer offered
    v.nullifiers.insert(pnf(&nk));
    assert!(recover(&a, &cfg, &[(TOK, D)], &v).unclaimed.is_empty());
}

fn token_state(cfg: Cfg, leaves: &[[u8; 32]]) -> TokenState {
    let mut f = Frontier::default();
    for l in leaves {
        f.append(*l).unwrap();
    }
    TokenState {
        cfg,
        entry: TokenEntry {
            tok: TOK,
            decimals: 6,
            denoms: vec![DenomEntry {
                d: D,
                fee_mint: 0,
                fee_burn: 0,
            }],
            supply_cap: 4 * D,
            mint_open: true,
            paused_mint: false,
            paused_burn: false,
        },
        supply: 0,
        fees: 0,
        trees: vec![(D, f)],
    }
}

#[test]
fn two_signers_sign_identical_digest_and_combine_ascending() {
    let v = vectors();
    let cfg = vec_cfg(&v);
    let leaves = [
        hx::<32>(&v["per_index"][0]["burn_commitment"]),
        hx::<32>(&v["per_index"][1]["burn_commitment"]),
    ];
    let vault: [u8; 20] = hx(&v["inputs"]["bridge_config"]["vault"]);
    let chain = v["inputs"]["bridge_config"]["evm_chain_id"]
        .as_u64()
        .unwrap();
    let height = v["inputs"]["lez_height"].as_u64().unwrap();
    let bh = hx::<32>(&v["inputs"]["lez_block_hash"]);
    // each signer reads the token state on its own machine; same height → same attestation
    let signer1 = root_attestation(chain, vault, &token_state(cfg, &leaves), D, height, bh);
    let signer2 = root_attestation(chain, vault, &token_state(cfg, &leaves), D, height, bh);
    assert_eq!(signer1.digest(), signer2.digest());
    assert_eq!(signer1.digest(), hx::<32>(&v["root_attestation"]["digest"]));
    assert_eq!(
        signer1.burn_root,
        hx::<32>(&v["root_attestation"]["burn_root"])
    );
    assert_eq!(sign_height(100, 10), 110);

    let (k1, k2) = ([0x11; 32], [0x22; 32]);
    let digest = signer1.digest();
    let (s1, s2) = (
        sign_digest(&k1, &digest).unwrap(),
        sign_digest(&k2, &digest).unwrap(),
    );
    assert_eq!(
        recover_signer(&digest, &s1).unwrap(),
        signer_address(&k1).unwrap()
    );
    // low s
    let n_half =
        hex::decode("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0").unwrap();
    assert!(s1[32..64] <= n_half[..] && s2[32..64] <= n_half[..]);
    let att = combine_sigs(&digest, &[s2, s1]).unwrap();
    assert_eq!(att, combine_sigs(&digest, &[s1, s2]).unwrap());
    let (a1, a2) = (signer_address(&k1).unwrap(), signer_address(&k2).unwrap());
    let first = if a1 < a2 { s1 } else { s2 };
    assert_eq!(&att[..65], &first[..]);
    assert!(
        combine_sigs(&digest, &[s1, s1]).is_err(),
        "duplicate signer"
    );
}

#[test]
fn cfg_comes_from_the_vault_config_id_only() {
    let v = vectors();
    let c = BridgeConfig {
        instance_id: hx(&v["inputs"]["bridge_config"]["instance_id"]),
        evm_chain_id: v["inputs"]["bridge_config"]["evm_chain_id"]
            .as_u64()
            .unwrap(),
        genesis_validators_root: hx(&v["inputs"]["bridge_config"]["genesis_validators_root"]),
        vault: hx(&v["inputs"]["bridge_config"]["vault"]),
        deposit_topic0: hx(&v["inputs"]["bridge_config"]["deposit_topic0"]),
        zone_id: hx(&v["inputs"]["bridge_config"]["zone_id"]),
        bridge_program_id: hx(&v["inputs"]["bridge_config"]["bridge_program_id"]),
        admin: lee_core::account::AccountId::new(hx(&v["inputs"]["bridge_config"]["admin"])),
        freezer: lee_core::account::AccountId::new(hx(&v["inputs"]["bridge_config"]["freezer"])),
        salt: hx(&v["inputs"]["bridge_config"]["salt"]),
    };
    assert_eq!(check_cfg(&vec_cfg(&v), &c).unwrap(), vec_cfg(&v));
    // a look-alike config (other admin) naming the same vault is refused
    let look_alike = BridgeConfig {
        admin: lee_core::account::AccountId::new([0x99; 32]),
        ..c
    };
    assert!(check_cfg(&vec_cfg(&v), &look_alike).is_err());
}

#[test]
fn mock_seal_matches_burn_member_fake_receipt_format() {
    let journal = hex::decode(vectors()["release_journal"]["abi"].as_str().unwrap()).unwrap();
    let id = [1u32, 2, 3, 4, 5, 6, 7, 8];
    let s = mock_seal(id, &journal);
    assert_eq!(s.len(), 36);
    assert_eq!(&s[..4], &[0xff; 4]);
    assert_ne!(mock_seal(id, &journal[..351]), s);
}

#[test]
fn membership_check_and_leak_scan() {
    let v = vectors();
    let keys = Keys::from_seed(&hex::decode(v["inputs"]["seed"].as_str().unwrap()).unwrap());
    let cfg = vec_cfg(&v);
    let n0 = keys.burn(&cfg, &TOK, D, 0).unwrap();
    let path: Vec<[u8; 32]> = v["burn_tree"]["path_index0"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| hx::<32>(x))
        .collect();
    let root = hx::<32>(&v["burn_tree"]["root"]);
    assert!(is_member(&n0, 0, &path, &root));
    assert!(!is_member(&n0, 1, &path, &root));
    let needles = vec![
        ("rk".to_string(), n0.rk.to_vec()),
        ("B".to_string(), n0.b.to_vec()),
    ];
    let hay = [b"xx".as_slice(), &n0.b, b"yy"].concat();
    assert_eq!(leaks(&hay, &needles), vec!["B"]);
    assert!(leaks(b"clean", &needles).is_empty());
}

/// F9: the b22 keys and the holder account come from the LEZ wallet mnemonic alone. A wallet
/// rebuilt from the phrase (fresh storage, no other file) yields the same holder and keys; another
/// wallet yields different ones; the keys are not the old random-seed derivation.
#[test]
fn holder_keys_come_from_the_wallet_mnemonic_alone() {
    use bridge_cli::lez::wallet_holder;
    use wallet::storage::Storage;
    let (s, m) = Storage::new();
    let h1 = wallet_holder(s.key_chain()).unwrap();
    let phrase = m.to_string();
    drop(s);
    let (mut s2, _) = Storage::new();
    s2.restore(&phrase.parse::<bip39::Mnemonic>().unwrap());
    let h2 = wallet_holder(s2.key_chain()).unwrap();
    assert_eq!(h1.account, h2.account);
    assert_eq!(h1.public, h2.public);
    assert_eq!(h1.keys.sk, h2.keys.sk);
    let cfg = [0xC0; 32];
    assert_eq!(
        h1.keys.commitment(&cfg, &TOK, D, 0),
        h2.keys.commitment(&cfg, &TOK, D, 0)
    );
    let (s3, _) = Storage::new();
    let h3 = wallet_holder(s3.key_chain()).unwrap();
    assert_ne!(h1.account, h3.account);
    assert_ne!(h1.keys.sk, h3.keys.sk);
}

/// Recovery scans every registered `(tok, d)`, not a fixed list: a third token seen only in the
/// deposit logs, and a denomination whose entry was dropped but whose burn tree remains.
#[test]
fn recovery_pairs_cover_every_registered_pair() {
    let cfg = [0xC0; 32];
    const TOK3: Tok = [0x33; 20];
    let mut st = token_state(cfg, &[[1; 32]]);
    st.entry.denoms.push(DenomEntry {
        d: 5 * D,
        fee_mint: 0,
        fee_burn: 0,
    });
    st.trees.push((7 * D, Frontier::default())); // dropped denomination, tree kept
    let pairs = recovery_pairs(&[(TOK3, 42), (TOK, D), (TOK3, 42)], &[st]);
    assert_eq!(
        pairs,
        vec![(TOK3, 42), (TOK, D), (TOK, 5 * D), (TOK, 7 * D)]
    );
    // and recover() then finds a deposit and a burn in those pairs
    let a = Keys::from_seed(b"holder A");
    let mut v = View::default();
    v.deposits
        .insert((TOK3, 42, a.commitment(&cfg, &TOK3, 42, 0)));
    v.trees
        .insert((TOK, 7 * D), vec![a.burn(&cfg, &TOK, 7 * D, 0).unwrap().b]);
    let r = recover(&a, &cfg, &pairs, &v);
    assert_eq!((r.unclaimed.len(), r.unreleased.len()), (1, 1));
    assert!(r.next_i.contains(&(TOK3, 42, 1)));
}

/// Liveness gate: deposit only while the attest instance's latest finalized header is within
/// MAX_ANCESTRY / 2 blocks of the head.
#[test]
fn deposit_refused_when_attest_instance_is_stale() {
    assert_eq!(MAX_ATTEST_LAG, 224);
    check_attest_live(1_000, 1_000 + MAX_ATTEST_LAG).unwrap();
    let e = check_attest_live(1_000, 1_001 + MAX_ATTEST_LAG).unwrap_err();
    assert!(e.to_string().contains("refusing to deposit"), "{e}");
    check_attest_live(1_000, 900).unwrap(); // a lagging RPC head is not staleness
}

/// sign_root: only a live write of the (tok, d) tree's last leaf by the bridge program moves the
/// signing height; a claim (token PDA, N PDA), a reverted burn, another denomination's burn and a
/// third-party tx naming the leaf account under another program (e.g. a dust transfer) do not.
#[test]
fn sign_height_moves_only_on_record_burn_for_that_tree() {
    use bridge_cli::lez::names_live;
    use lee::{AccountId, Actor};
    let bridge = AccountId::new([0xB2; 32]);
    let other = AccountId::new([0x07; 32]);
    let cfg = [0xC0; 32];
    let st = token_state(cfg, &[[1; 32], [2; 32]]);
    assert_eq!(tree_count(&st, D), 2);
    assert_eq!(tree_count(&st, 5 * D), 0);
    let b = |a| Actor::new(a, bridge);
    let watch = b(leaf_pda(&bridge, &cfg, &TOK, D, tree_count(&st, D) - 1));
    let tp = b(token_pda(&bridge, &cfg, &TOK));
    let cp = b(config_pda(&bridge, &cfg));
    let claim = vec![cp, tp, b(n_pda(&bridge, &[9; 32]))];
    let other_denom = vec![cp, tp, b(leaf_pda(&bridge, &cfg, &TOK, 5 * D, 0))];
    let dust = vec![Actor::new(watch.account_id, other)];
    let burn = vec![cp, tp, watch];
    assert!(!names_live(
        &[(false, claim.clone()), (false, other_denom), (false, dust)],
        &watch
    ));
    assert!(!names_live(&[(true, burn.clone())], &watch), "reverted");
    assert!(names_live(&[(false, claim), (false, burn)], &watch));
}

#[test]
fn revert_selector_and_lez_error_code_parse() {
    let e = r#"eth_estimateGas: {"code":3,"data":"0x5bb4ed16","message":"execution reverted"}"#;
    assert_eq!(revert_selector(e), Some([0x5b, 0xb4, 0xed, 0x16]));
    assert_eq!(revert_selector("eth_estimateGas: timeout"), None);
    let l = "ProgramExecutionFailed(ProgramExitedWithCode { program_id: [1, 2], code: 48 })";
    assert_eq!(lez_error_code(l), Some(1304));
    let l = "ProgramExitedWithCode { program_id: [0], code: 250 }";
    assert_eq!(lez_error_code(l), Some(1250));
    assert_eq!(lez_error_code("InsufficientFunds"), None);
}

/// `b22 freeze eth|lez mint|burn on|off` changes only the named half of the current flags.
#[test]
fn freeze_changes_only_the_named_half() {
    use FreezeHalf::*;
    assert_eq!(freeze_flags((false, true), Mint, true), (true, true));
    assert_eq!(freeze_flags((true, true), Mint, false), (false, true));
    assert_eq!(freeze_flags((true, false), Burn, true), (true, true));
    assert_eq!(freeze_flags((true, true), Burn, false), (true, false));
    // `both` is one write, no read needed
    assert_eq!(freeze_flags((false, true), Both, true), (true, true));
    assert_eq!(freeze_flags((true, false), Both, false), (false, false));
    assert_eq!("both".parse::<FreezeHalf>().unwrap(), Both);
    assert!("all".parse::<FreezeHalf>().is_err());
}

/// `b22 freezer watch`: decodes `TokenChangeQueued(address indexed token, uint256 activeAt)`.
#[test]
fn token_change_queued_log_decodes() {
    use bridge_cli::eth::{token_change_queued, TOKEN_CHANGE_QUEUED};
    let t0 = alloy_primitives::keccak256(TOKEN_CHANGE_QUEUED.as_bytes()).0;
    let mut tok = [0u8; 32];
    tok[12..].copy_from_slice(&[0xAB; 20]);
    let mut data = [0u8; 32];
    data[24..].copy_from_slice(&1_700_000_000u64.to_be_bytes());
    let log = serde_json::json!({
        "topics": [format!("0x{}", hex::encode(t0)), format!("0x{}", hex::encode(tok))],
        "data": format!("0x{}", hex::encode(data)),
    });
    assert_eq!(
        token_change_queued(&log).unwrap(),
        ([0xAB; 20], 1_700_000_000)
    );
}

/// Credits from a look-alike config (permissionless `InitConfig`, same token address) are not the
/// selected vault's money: `receive`/recovery keep only `cfg == CONFIG_ID`.
#[test]
fn credits_of_a_lookalike_config_are_split_off() {
    let cfg = [0xC0; 32];
    let fake = [0xFA; 32];
    let cs = vec![(1, cfg, TOK, 5), (2, fake, TOK, 7), (3, cfg, TOK, 9)];
    let (ours, foreign) = split_credits(&cs, &cfg);
    assert_eq!(ours, vec![(1, cfg, TOK, 5), (3, cfg, TOK, 9)]);
    assert_eq!(foreign, vec![(2, fake, TOK, 7)]);
}

/// eth_getLogs ranges: inclusive chunks of at most `step` blocks covering `from..=to`.
#[test]
fn log_ranges_are_chunked() {
    use bridge_cli::eth::block_chunks;
    assert_eq!(block_chunks(5, 4, 10), vec![]);
    assert_eq!(block_chunks(0, 9, 10), vec![(0, 9)]);
    assert_eq!(block_chunks(0, 25, 10), vec![(0, 9), (10, 19), (20, 25)]);
    assert_eq!(block_chunks(7, 7, 10), vec![(7, 7)]);
}
