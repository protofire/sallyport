fn main() {
    attest_program::entry::run(|input, msg| consumers::program::handle(input, msg, None))
}
