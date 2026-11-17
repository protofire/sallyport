//! Prints every guest's ImageID (hex of the digest bytes, as `program-e2e image-ids`). Used by `scripts/image-ids.sh`.
use program_methods::*;

fn main() {
    let ids = [
        ("attest", ATTEST_ID),
        ("erc20_receiver", ERC20_RECEIVER_ID),
        ("eth_receiver", ETH_RECEIVER_ID),
        ("erc20_inline_receiver", ERC20_INLINE_RECEIVER_ID),
        ("bridge", BRIDGE_ID),
        ("burn_member", BURN_MEMBER_ID),
        ("spec_selftest (test only)", SPEC_SELFTEST_ID),
        ("sha_selftest (test only)", SHA_SELFTEST_ID),
    ];
    for (name, id) in ids {
        let hex: String = id
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .map(|b| format!("{b:02x}"))
            .collect();
        println!("{name:<26} {hex}");
    }
}
