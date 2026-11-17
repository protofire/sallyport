//! Stand-in for the LEZ privacy circuit's assumption resolution: `env::verify_integrity` of N
//! program receipts (what `PrivateBackend::handle_message` does per private transition).
use risc0_zkvm::{guest::env, ReceiptClaim};

fn main() {
    let claims: Vec<ReceiptClaim> = env::read();
    for c in &claims {
        env::verify_integrity(c).expect("assumption");
    }
    env::commit(&(claims.len() as u32));
}
