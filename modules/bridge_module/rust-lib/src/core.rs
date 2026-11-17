//! Plain-Rust module functions over `bridge-core` (no Logos types, host-testable).

use bridge_core::{commit, config_id, config_pda, nk, pnf, sk, token_pda, ConfigState, TokenState, ERR_MALFORMED};
use lee_core::account::AccountId;
use serde_json::{json, Value};

fn err(e: impl std::fmt::Display) -> Value {
    json!({ "ok": false, "errorCode": ERR_MALFORMED, "error": e.to_string() })
}

fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn unhex<const N: usize>(name: &str, s: &str) -> Result<[u8; N], String> {
    hex::decode(s.trim_start_matches("0x")).ok().and_then(|b| b.try_into().ok()).ok_or(format!("{name}: expected {N}-byte hex"))
}

fn unhex_vec(name: &str, s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.trim_start_matches("0x")).map_err(|e| format!("{name}: {e}"))
}

/// `{ ok, commitment, nullifier }` for deposit note `i`; `nk_i` stays inside.
pub fn derive_deposit(seed_hex: &str, cfg_hex: &str, tok_hex: &str, d: &str, i: i64) -> Value {
    let run = || -> Result<Value, String> {
        let seed = unhex_vec("seed", seed_hex)?;
        if seed.is_empty() {
            return Err("seed: empty".into());
        }
        let nk = nk(
            &sk(&seed),
            &unhex::<32>("cfg", cfg_hex)?,
            &unhex::<20>("tok", tok_hex)?,
            d.parse().map_err(|_| "d: expected decimal u128")?,
            u64::try_from(i).map_err(|_| "i: must be >= 0")?,
        );
        Ok(json!({ "ok": true, "commitment": hx(&commit(&nk)), "nullifier": hx(&pnf(&nk)) }))
    };
    run().unwrap_or_else(err)
}

/// Decodes config and token PDA states read from the sequencer; see the glue doc for the shape.
pub fn registry(bridge_program_hex: &str, config_state_hex: &str, token_states_json: &str) -> Value {
    let run = || -> Result<Value, String> {
        let bridge = AccountId::new(unhex::<32>("bridge_program", bridge_program_hex)?);
        let cs: ConfigState = borsh::from_slice(&unhex_vec("config_state", config_state_hex)?).map_err(|e| format!("config_state: {e}"))?;
        let cfg = config_id(&cs.config);
        let tokens = serde_json::from_str::<Vec<String>>(token_states_json)
            .map_err(|e| format!("token_states_json: {e}"))?
            .iter()
            .map(|h| {
                let t: TokenState = borsh::from_slice(&unhex_vec("token_state", h)?).map_err(|e| format!("token_state: {e}"))?;
                if t.cfg != cfg {
                    return Err("token_state: belongs to another config".to_string());
                }
                let e = &t.entry;
                Ok(json!({
                    "tok": hx(&e.tok), "tokenPda": token_pda(&bridge, &cfg, &e.tok).to_string(),
                    "decimals": e.decimals, "mintOpen": e.mint_open,
                    "pausedMint": e.paused_mint, "pausedBurn": e.paused_burn,
                    "supplyCap": e.supply_cap.to_string(), "supply": t.supply.to_string(), "fees": t.fees.to_string(),
                    "denoms": e.denoms.iter().map(|x| json!({ "d": x.d.to_string(), "feeMint": x.fee_mint.to_string(), "feeBurn": x.fee_burn.to_string() })).collect::<Vec<_>>(),
                }))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(json!({
            "ok": true, "cfg": hx(&cfg), "configPda": config_pda(&bridge, &cfg).to_string(),
            "pausedMint": cs.paused_mint, "pausedBurn": cs.paused_burn, "tokens": tokens,
        }))
    };
    run().unwrap_or_else(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bridge_core::*;
    use lee_core::account::AccountId;
    use serde_json::{json, Value};

    const SEED: &str = "0x0102030405";
    const TOK: [u8; 20] = [0xaa; 20];
    const D: u128 = 100_000_000;
    const PROG: [u8; 32] = [0x44; 32];

    fn hx(b: &[u8]) -> String {
        format!("0x{}", hex::encode(b))
    }

    fn config() -> BridgeConfig {
        BridgeConfig {
            instance_id: [0x11; 32],
            evm_chain_id: 11_155_111,
            genesis_validators_root: [0x22; 32],
            vault: [0x33; 20],
            deposit_topic0: deposit_topic0(),
            zone_id: local_zone_id(),
            bridge_program_id: PROG,
            admin: AccountId::new([0x55; 32]),
            freezer: AccountId::new([0x66; 32]),
            salt: [0x77; 32],
        }
    }

    fn entry() -> TokenEntry {
        TokenEntry {
            tok: TOK,
            decimals: 6,
            denoms: vec![DenomEntry { d: D, fee_mint: 1, fee_burn: 2 }],
            supply_cap: 4 * D,
            mint_open: true,
            paused_mint: false,
            paused_burn: true,
        }
    }

    fn tok_state(cfg: Cfg) -> String {
        hx(&borsh::to_vec(&TokenState { cfg, entry: entry(), supply: D, fees: 1, trees: vec![] }).unwrap())
    }

    #[test]
    fn derive_deposit_matches_bridge_core() {
        let cfg = config_id(&config());
        let v = derive_deposit(SEED, &hx(&cfg), &hx(&TOK), &D.to_string(), 3);
        let s = sk(&[1, 2, 3, 4, 5]);
        let n = nk(&s, &cfg, &TOK, D, 3);
        assert_eq!(v["ok"], true);
        assert_eq!(v["commitment"], hx(&commit(&n)));
        assert_eq!(v["nullifier"], hx(&pnf(&n)));
        assert!(!v.to_string().contains(&hex::encode(n)), "nk must not be returned");
    }

    #[test]
    fn derive_deposit_rejects_bad_input() {
        let cfg = hx(&config_id(&config()));
        for (seed, cfg, tok, d, i) in [
            ("zz", cfg.as_str(), "0xaa", "1", 0),
            (SEED, "0x00", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1", 0),
            (SEED, cfg.as_str(), "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "-1", 0),
            (SEED, cfg.as_str(), "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "1", -1),
        ] {
            let v = derive_deposit(seed, cfg, tok, d, i);
            assert_eq!((v["ok"].clone(), v["errorCode"].clone()), (json!(false), json!(1001)), "{seed} {cfg} {tok} {d} {i}");
        }
    }

    #[test]
    fn registry_decodes_and_derives_pdas() {
        let c = config();
        let cfg = config_id(&c);
        let cs = hx(&borsh::to_vec(&ConfigState { config: c, paused_mint: true, paused_burn: false }).unwrap());
        let v = registry(&hx(&PROG), &cs, &json!([tok_state(cfg)]).to_string());
        assert_eq!(v["ok"], true, "{v}");
        let bridge = AccountId::new(PROG);
        assert_eq!(v["cfg"], hx(&cfg));
        assert_eq!(v["configPda"], config_pda(&bridge, &cfg).to_string());
        assert_eq!((v["pausedMint"].clone(), v["pausedBurn"].clone()), (json!(true), json!(false)));
        let t = &v["tokens"][0];
        assert_eq!(t["tok"], hx(&TOK));
        assert_eq!(t["tokenPda"], token_pda(&bridge, &cfg, &TOK).to_string());
        assert_eq!(t["supply"], D.to_string());
        assert_eq!(t["pausedBurn"], true);
        assert_eq!(t["denoms"][0], json!({ "d": D.to_string(), "feeMint": "1", "feeBurn": "2" }));
    }

    #[test]
    fn registry_rejects_foreign_config_and_garbage() {
        let c = config();
        let cs = hx(&borsh::to_vec(&ConfigState { config: c, paused_mint: false, paused_burn: false }).unwrap());
        let v: Value = registry(&hx(&PROG), &cs, &json!([tok_state([9; 32])]).to_string());
        assert_eq!((v["ok"].clone(), v["errorCode"].clone()), (json!(false), json!(1001)));
        for (p, c, t) in [(hx(&PROG), "0x00".to_string(), "[]".to_string()), (hx(&PROG), cs.clone(), "{}".into()), ("0x01".into(), cs.clone(), "[]".into())] {
            assert_eq!(registry(&p, &c, &t)["errorCode"], 1001);
        }
    }
}
