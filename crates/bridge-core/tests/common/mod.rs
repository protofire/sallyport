//! Fixed inputs shared by the known-answer and golden-vector tests.
#![allow(dead_code)]
use bridge_core::*;
use lee_core::account::AccountId;

pub const SEED: [u8; 32] = {
    let mut s = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        s[i] = i as u8;
        i += 1;
    }
    s
};
pub const CHAIN_ID: u64 = 11_155_111;
pub const VAULT: [u8; 20] = [0x33; 20];
pub const BRIDGE: [u8; 32] = [0x44; 32];
pub const TOK: Tok = [0xaa; 20];
pub const D: u128 = 100_000_000;
pub const BURN_ROOT: [u8; 32] = [0x88; 32];
pub const COUNT: u64 = 3;
pub const LEZ_HEIGHT: u64 = 1234;
pub const LEZ_BLOCK_HASH: [u8; 32] = [0x99; 32];
pub const RELAYER: [u8; 20] = [0xbb; 20];
pub const FEE: u128 = 1_000_000;

pub fn config() -> BridgeConfig {
    BridgeConfig {
        instance_id: [0x11; 32],
        evm_chain_id: CHAIN_ID,
        genesis_validators_root: [0x22; 32],
        vault: VAULT,
        deposit_topic0: deposit_topic0(),
        zone_id: local_zone_id(),
        bridge_program_id: BRIDGE,
        admin: AccountId::new([0x55; 32]),
        freezer: AccountId::new([0x66; 32]),
        salt: [0x77; 32],
    }
}

pub fn bridge() -> AccountId {
    AccountId::new(BRIDGE)
}

pub fn hex(b: impl AsRef<[u8]>) -> String {
    b.as_ref().iter().map(|x| format!("{x:02x}")).collect()
}
