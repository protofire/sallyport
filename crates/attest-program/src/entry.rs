//! Guest entry point: the journal of `lee_core::program::run_actor_with`, without copying the
//! message out of the input frame or re-encoding the input (gas, docs/DECISIONS.md D-GAS-2).
//!
//! `run_actor_with` commits `frame(borsh(Transition { input, response }))`. borsh decoding is
//! strict and the whole frame must be consumed, so `borsh(input)` is exactly the frame payload
//! read from the host; committing those bytes followed by `borsh(response)` is the same journal.

use lee_core::account::{Actor, ActorState};
use lee_core::program::{ReceiveInput, Response};
use risc0_zkvm::guest::env;

const BAD: &str = "receive input must be valid borsh";

/// Offset just past the borsh `Vec` whose u32 length prefix starts at `at`.
fn skip_vec(raw: &[u8], at: usize) -> usize {
    let b = raw.get(at..at + 4).expect(BAD);
    let n = u32::from_le_bytes(b.try_into().unwrap()) as usize;
    (at + 4).checked_add(n).expect(BAD)
}

/// Splits a borsh `ReceiveInput` into its fields (with an empty `message`) and the message bytes.
pub fn split_input(raw: &[u8]) -> (ReceiveInput, &[u8]) {
    // receiver (64) ‖ from: Option<Actor> ‖ is_authorized: bool ‖ pre_state: Vec ‖ message: Vec
    let from_len = match raw.get(64) {
        Some(1) => 65,
        _ => 1, // 0, or invalid: rejected by the decode below
    };
    let msg = skip_vec(raw, 64 + from_len + 1);
    assert_eq!(skip_vec(raw, msg), raw.len(), "{BAD}");
    let (receiver, from, is_authorized, pre_state): (Actor, Option<Actor>, bool, ActorState) =
        borsh::from_slice(&raw[..msg]).expect(BAD);
    let input = ReceiveInput {
        receiver,
        from,
        is_authorized,
        pre_state,
        message: Vec::new(),
    };
    (input, &raw[msg + 4..])
}

fn as_bytes(w: &mut [u32]) -> &mut [u8] {
    // SAFETY: u32 has no padding or invalid bit patterns; u8 alignment is 1.
    unsafe { core::slice::from_raw_parts_mut(w.as_mut_ptr().cast::<u8>(), w.len() * 4) }
}

/// Handles one delivery (`handler(input, message)`), commits the transition, exits.
///
/// The frame is read into a word-aligned buffer at byte 4 and the response is written behind it,
/// so the journal (`len ‖ input ‖ response`) is committed as one aligned slice: no copy of the
/// input and word-aligned SHA-256 input for the journal digest.
pub fn run(handler: impl FnOnce(&ReceiveInput, &[u8]) -> Response) -> ! {
    let mut len = [0u8; 4];
    env::read_slice(&mut len);
    let n = u32::from_le_bytes(len) as usize;
    // room for the response too (sync messages can be about as large as the input); `vec![0; _]`
    // is a zeroed allocation, which the guest's fresh heap provides without a memset
    let cap = n
        .checked_mul(2)
        .and_then(|x| x.checked_add(1028))
        .expect("frame length overflow");
    let mut buf: Vec<u32> = vec![0; cap.div_ceil(4)];
    env::read_slice(&mut as_bytes(&mut buf)[4..4 + n]);
    let r = {
        let raw = &as_bytes(&mut buf)[4..4 + n];
        let (input, msg) = split_input(raw);
        handler(&input, msg)
    };
    let resp_len = borsh::object_length(&r).expect("borsh");
    let total = 4 + n + resp_len;
    let frame_len = u32::try_from(n + resp_len).expect("frame payload length must fit in u32");
    if total > buf.len() * 4 {
        buf.resize(total.div_ceil(4), 0);
    }
    let bytes = as_bytes(&mut buf);
    bytes[..4].copy_from_slice(&frame_len.to_le_bytes());
    borsh::to_writer(&mut &mut bytes[4 + n..total], &r).expect("borsh");
    env::commit_slice(&bytes[..total]);
    env::exit(0)
}
