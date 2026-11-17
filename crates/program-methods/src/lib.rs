//! Guest ELFs (`ATTEST_ELF`, `ERC20_RECEIVER_ELF`, `ETH_RECEIVER_ELF`, ...; `SHA_SELFTEST_ELF` and `SPEC_SELFTEST_ELF` are test-only; RFP-022: `BRIDGE_ELF`, `BURN_MEMBER_ELF`) and image ids.
include!(concat!(env!("OUT_DIR"), "/methods.rs"));
