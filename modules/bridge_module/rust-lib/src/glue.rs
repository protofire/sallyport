//! Logos module glue for `bridge_module` (rust-first authoring). Structured values cross as JSON
//! strings: `{ "ok": true, ... }` / `{ "ok": false, "errorCode", "error" }`.

use crate::core;

pub trait BridgeModule: Send + 'static {
    /// Deposit note `i` for `(cfg, tok, d)` from the seed: `{ ok, commitment, nullifier }`.
    /// `commitment` = `C_i` for `vault.deposit`; `nullifier` = `pnf(nk_i)`, the N PDA seed that shows
    /// whether the deposit was claimed. `nk_i` and `sk` are never returned. `d` is a decimal string
    /// (u128). `seed_hex`, `cfg_hex`, `tok_hex` are 0x-hex (32 bytes min 1, 32, 20).
    fn derive_deposit(&mut self, seed_hex: String, cfg_hex: String, tok_hex: String, d: String, i: i64) -> String;
    /// Decodes registry state read from the LEZ sequencer. `bridge_program_hex` = 32-byte program id,
    /// `config_state_hex` = borsh `ConfigState` of the config PDA, `token_states_json` = JSON array of
    /// 0x-hex borsh `TokenState`s. `{ ok, cfg, configPda, pausedMint, pausedBurn, tokens: [...] }`;
    /// each token is checked against `cfg` (1001 on mismatch).
    fn registry(&mut self, bridge_program_hex: String, config_state_hex: String, token_states_json: String) -> String;

    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct Bridge;

impl BridgeModule for Bridge {
    fn derive_deposit(&mut self, seed_hex: String, cfg_hex: String, tok_hex: String, d: String, i: i64) -> String {
        core::derive_deposit(&seed_hex, &cfg_hex, &tok_hex, &d, i).to_string()
    }

    fn registry(&mut self, bridge_program_hex: String, config_state_hex: String, token_states_json: String) -> String {
        core::registry(&bridge_program_hex, &config_state_hex, &token_states_json).to_string()
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<Bridge>();
}
