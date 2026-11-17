//! RFP-022 LEZ bridge program (docs/ARCHITECTURE.md §3). Formats live in `bridge_core`;
//! the handler is [`program`] (feature `guest`), the tx builders [`host`] (feature `host`).
pub use bridge_core;

pub mod host;
#[cfg(feature = "guest")]
pub mod program;

/// Error code from a LEZ `ProgramExitedWithCode { code }` of the bridge program. Guest exit codes
/// are u8, so 1301–1308 exit as 45–52 (`code - 1256`); 1045–1052 are unused by RFP-021/022.
pub fn error_from_exit(exit: u32) -> u16 {
    let c = 1000 + exit as u16;
    if (1045..=1052).contains(&c) {
        c + 256
    } else {
        c
    }
}

use bridge_core::{commit, BridgeConfig, Cfg, Tok};
use inclusion::{FieldSel, Pred};

/// The deposit predicates of docs/ARCHITECTURE.md §3.4 (`private_preds` + token and config topics).
pub fn claim_preds(c: &BridgeConfig, cfg: &Cfg, tok: &Tok, d: u128, nk: &[u8; 32]) -> Vec<Pred> {
    let eq = |field, value: &[u8]| Pred::Eq {
        field,
        value: value.to_vec(),
    };
    let mut tok_word = [0u8; 32];
    tok_word[12..].copy_from_slice(tok);
    let mut d_word = [0u8; 32];
    d_word[16..].copy_from_slice(&d.to_be_bytes());
    vec![
        eq(FieldSel::LogStatus, &[1]),
        eq(FieldSel::LogAddress, &c.vault),
        eq(FieldSel::LogTopic(0), &c.deposit_topic0),
        eq(FieldSel::LogTopic(1), &commit(nk)),
        eq(FieldSel::LogTopic(2), &tok_word),
        eq(FieldSel::LogTopic(3), cfg),
        eq(FieldSel::LogDataWord(0), &d_word),
    ]
}
