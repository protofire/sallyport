//! Known-answer tests. Expected values were computed independently of this crate (Python
//! hashlib for sha256/borsh/PDA, Foundry `cast` 1.5.1 for keccak, `abi-encode`,
//! `format-bytes32-string` and `wallet address`), so they bind Rust to the Solidity encodings.
mod common;
use bridge_core::*;
use common::*;

fn rk0() -> [u8; 32] {
    rk(&sk(&SEED), &config_id(&config()), &TOK, D, 0)
}

#[test]
fn zone_and_topics() {
    assert_eq!(
        hex(local_zone_id()),
        "8e0006a1db1c46d6b1c0dc59cd05568ba2d31ea0ed366e2c268adbe9269e1cf3"
    );
    assert_eq!(
        hex(deposit_topic0()),
        "7b8033c50ae5dba139b35a4f92bf1257c21954d40291216edcfc992920ef84b4"
    );
    assert_eq!(
        hex(TAG_ROOT),
        "623032322f726f6f742f76310000000000000000000000000000000000000000"
    );
    assert_eq!(
        hex(TAG_REL),
        "623032322f72656c2f7631000000000000000000000000000000000000000000"
    );
}

#[test]
fn config_id_kat() {
    assert_eq!(
        hex(config_id(&config())),
        "30d8cb579a8707e0e4cf25cb2305f91f6315bd40eb5b3db98237f6f60a9a1922"
    );
}

#[test]
fn seed_derivations_kat() {
    let cfg = config_id(&config());
    let sk = sk(&SEED);
    assert_eq!(
        hex(sk),
        "a36059739f9f5c57570a8a15f4e8022a0a73e8da5c16f1cf441851ca10083db0"
    );
    let nk0 = nk(&sk, &cfg, &TOK, D, 0);
    assert_eq!(
        hex(nk0),
        "eb30370cbcee2540bdbdb3fb420345e5ca77c8282b4d75e15feef74f0013eda9"
    );
    assert_eq!(
        hex(commit(&nk0)),
        "670a77d1ab98d32b5f8ed215f832bc289ba66a3412d309f48f12ff9723f42c75"
    );
    assert_eq!(
        hex(pnf(&nk0)),
        "38241b95210dde214155c6bffa22061481097e5d900a77b8e8ba754956cc92c1"
    );
    assert_eq!(
        hex(rk0()),
        "6f88f0ad370f11f529b1d2cf589f16e21971ddd64c7f3068ee236a7058e764ca"
    );
    assert_eq!(
        hex(ek(&sk, &cfg, 0).unwrap()),
        "42e86b190ca5a6118dbe2dc439104c1c0d4b215dc78f602c84560563dde2ac8c"
    );
    let r0 = recipient(&sk, &cfg, 0).unwrap();
    assert_eq!(hex(r0), "b628cc4a7113e41e8ab3a4d446a00f51a3e5ca75");
    assert_eq!(
        hex(burn_commitment(&rk0(), &r0)),
        "25f4ad6bcc2174bd66981c6ac2b5c81714c09bfd6724b3973cbc8ba6874ab3ca"
    );
    assert_eq!(
        hex(burn_nullifier(&rk0())),
        "5a7d2a0ac256a31b543b478f3a54180ee1b8b13cb73688108f85b9aee7213a36"
    );
}

#[test]
fn derivations_separate_inputs() {
    let (cfg, sk) = (config_id(&config()), sk(&SEED));
    let n = nk(&sk, &cfg, &TOK, D, 0);
    assert_ne!(n, nk(&sk, &cfg, &TOK, D, 1));
    assert_ne!(n, nk(&sk, &cfg, &TOK, D + 1, 0));
    assert_ne!(n, nk(&sk, &cfg, &[0; 20], D, 0));
    assert_ne!(n, nk(&sk, &[0; 32], &TOK, D, 0));
    assert_ne!(n, rk(&sk, &cfg, &TOK, D, 0)); // domain tags differ
    assert_ne!(ek(&sk, &cfg, 0), ek(&sk, &cfg, 1));
}

#[test]
fn eth_address_rejects_zero_and_overflow() {
    assert_eq!(eth_address(&[0; 32]), None);
    assert_eq!(eth_address(&[0xff; 32]), None); // >= n
}

#[test]
fn pda_kat() {
    let cfg = config_id(&config());
    let b = bridge();
    let nk0 = nk(&sk(&SEED), &cfg, &TOK, D, 0);
    assert_eq!(
        hex(config_pda(&b, &cfg)),
        "af91af8d4c9485e83df225ffbe16a826faa7b58146d9c8100b3333ce131b26e0"
    );
    assert_eq!(
        hex(token_pda(&b, &cfg, &TOK)),
        "c6ef7f30b17fecee21b4186f204ea08607df2d5bbcf2cf39b59e37d7c226e9f6"
    );
    assert_eq!(
        hex(leaf_pda(&b, &cfg, &TOK, D, 5)),
        "ff89ce0353014f11a423e8b0ede3e92cbf5262ecbbe3f409f3d6e16f6283f5ab"
    );
    assert_eq!(
        hex(n_pda(&b, &pnf(&nk0))),
        "a33d798165ff8b33deea139d5a3a192ecdc38acf3727c9cfc65080bee7ab5e8d"
    );
}

#[test]
fn root_digest_kat() {
    let a = RootAttestation {
        chain_id: CHAIN_ID,
        vault: VAULT,
        config_id: config_id(&config()),
        token: TOK,
        denom: D,
        burn_root: BURN_ROOT,
        count: COUNT,
        lez_height: LEZ_HEIGHT,
        lez_block_hash: LEZ_BLOCK_HASH,
    };
    assert_eq!(
        hex(a.digest()),
        "f18977f35dc3ce7e3e553a25a9e352818a30d4da1b8d3c31cb6981083d3e61cc"
    );
}

#[test]
fn release_journal_kat() {
    let cfg = config_id(&config());
    let j = ReleaseJournal {
        chain_id: CHAIN_ID,
        vault: VAULT,
        config_id: cfg,
        token: TOK,
        denom: D,
        burn_root: BURN_ROOT,
        nb: burn_nullifier(&rk0()),
        recipient: recipient(&sk(&SEED), &cfg, 0).unwrap(),
        relayer: RELAYER,
        fee: FEE,
    };
    assert_eq!(j.encode().len(), 352);
    assert_eq!(hex(j.encode()), "623032322f72656c2f76310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000aa36a7000000000000000000000000333333333333333333333333333333333333333330d8cb579a8707e0e4cf25cb2305f91f6315bd40eb5b3db98237f6f60a9a1922000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000000000000000000000000000000000000005f5e10088888888888888888888888888888888888888888888888888888888888888885a7d2a0ac256a31b543b478f3a54180ee1b8b13cb73688108f85b9aee7213a36000000000000000000000000b628cc4a7113e41e8ab3a4d446a00f51a3e5ca75000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00000000000000000000000000000000000000000000000000000000000f4240");
    assert_eq!(
        hex(j.digest()),
        "1aeb5afd6d743f6585a6c42c2bc48d56650800ce9152c660e6a611ac56c9ce26"
    );
}

#[test]
fn frontier_layout_and_error_codes() {
    // docs/ARCHITECTURE.md §3.2 says 680 bytes; borsh { leaves: u64, nodes: [[u8; 32]; 20] } is 8 + 640 = 648.
    assert_eq!(borsh::to_vec(&Frontier::default()).unwrap().len(), 648);
    assert_eq!(BURN_TREE_DEPTH, 20);
    assert_eq!(
        [
            ERR_MALFORMED,
            ERR_TOKEN_NOT_LISTED,
            ERR_DENOM_NOT_PERMITTED,
            ERR_CAP_EXCEEDED,
            ERR_FROZEN,
            ERR_INSUFFICIENT_BALANCE,
            ERR_UNAUTHORIZED,
            ERR_TREE_FULL,
            ERR_FEE_MISMATCH,
            ERR_ALREADY_CLAIMED
        ],
        [1001, 1301, 1302, 1303, 1304, 1305, 1306, 1307, 1308, 1250]
    );
}

#[test]
fn token_entry_denom_lookup() {
    let e = TokenEntry {
        tok: TOK,
        decimals: 6,
        denoms: vec![DenomEntry {
            d: D,
            fee_mint: 1,
            fee_burn: 2,
        }],
        supply_cap: 4 * D,
        mint_open: true,
        paused_mint: false,
        paused_burn: false,
    };
    assert_eq!(e.denom(D).unwrap().fee_burn, 2);
    assert!(e.denom(D + 1).is_none());
}

#[test]
fn messages_roundtrip() {
    let m = BridgeMsg::WriteLeaf {
        cfg: [1; 32],
        tok: TOK,
        d: D,
        index: 7,
        b: [2; 32],
    };
    let bytes = borsh::to_vec(&m).unwrap();
    assert_eq!(bytes.len(), 1 + 32 + 20 + 16 + 8 + 32);
    assert_eq!(borsh::from_slice::<BridgeMsg>(&bytes).unwrap(), m);
}
