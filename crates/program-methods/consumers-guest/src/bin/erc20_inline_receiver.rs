//! Optional inline-verifying variant of erc20_receiver (docs/CONSUMER-GUIDE.md, D-GAS-7).
fn main() {
    attest_program::entry::run(|input, msg| consumers::program::handle_inline(input, msg, None))
}
