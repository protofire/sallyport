fn main() {
    attest_program::entry::run(|input, msg| {
        consumers::program::handle(input, msg, Some(inclusion::EIP7708_ETH_LOG_ADDRESS))
    })
}
