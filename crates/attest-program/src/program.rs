//! Guest message handler (`attest_program::entry::run(attest_program::program::handle)`).
//!
//! Each actor only sees its own state, so cross-account effects are chained sync messages to
//! this program's own PDAs; internal messages are accepted only from the expected sender PDA.

use crate::*;
use lc_core::{apply_update, bootstrap, finish_update, prepare_update};
use lee_core::account::{AccountId, Actor};
use lee_core::program::{PdaSeed, ProgramEvent, ReceiveInput, Response, SyncMessage};
use risc0_zkvm::guest::env;

/// Exit with a docs/CONSUMER-GUIDE.md code (risc0 exit codes are u8: `code - 1000`).
fn fail(code: u16) -> ! {
    env::exit((code - 1000) as u8)
}

trait OrFail<T> {
    fn or_fail(self) -> T;
}
impl<T> OrFail<T> for Result<T, ErrorCode> {
    fn or_fail(self) -> T {
        self.unwrap_or_else(|e| fail(e as u16))
    }
}
impl<T> OrFail<T> for Result<T, inclusion::ErrorCode> {
    fn or_fail(self) -> T {
        self.unwrap_or_else(|e| fail(e as u16))
    }
}

const MALFORMED: u16 = ErrorCode::Malformed as u16;

fn pda(program: &AccountId, seed: [u8; 32]) -> AccountId {
    AccountId::for_public_pda(program, &PdaSeed::new(seed))
}

fn decode<T: BorshDeserialize>(b: &[u8]) -> T {
    borsh::from_slice(b).unwrap_or_else(|_| fail(MALFORMED))
}

fn enc<T: BorshSerialize>(v: &T) -> Vec<u8> {
    borsh::to_vec(v).expect("borsh")
}

/// The receiving actor must be this program's PDA for `seed` (state lives only at canonical PDAs).
fn require_at(input: &ReceiveInput, seed: [u8; 32]) -> AccountId {
    let program = input.receiver.program_account_id;
    if input.receiver.account_id != pda(&program, seed) {
        fail(MALFORMED);
    }
    program
}

/// Internal messages: only from this program's actor at `PDA(seed)`.
fn require_from(input: &ReceiveInput, seed: [u8; 32]) {
    let program = input.receiver.program_account_id;
    let ok = input
        .from
        .is_some_and(|f| f.program_account_id == program && f.account_id == pda(&program, seed));
    if !ok {
        fail(MALFORMED);
    }
}

fn send_own(program: AccountId, seed: [u8; 32], msg: &Msg) -> SyncMessage {
    SyncMessage::new(Actor::new(pda(&program, seed), program), msg)
        .with_pda_seeds([PdaSeed::new(seed)])
}

/// Appends `rec` to the accumulator and returns the write-once root-PDA message.
fn append_root(program: AccountId, st: &mut InstanceState, rec: &HeaderRecord) -> SyncMessage {
    let root = st
        .headers
        .append(header_leaf(rec))
        .unwrap_or_else(|| fail(MALFORMED));
    let instance_id = rec.instance_id;
    send_own(
        program,
        hroot_seed(&instance_id, &root),
        &Msg::WriteRoot { instance_id, root },
    )
}

fn write_header(program: AccountId, rec: HeaderRecord) -> SyncMessage {
    let seed = header_seed(&rec.instance_id, &rec.execution_block_hash);
    send_own(program, seed, &Msg::WriteHeader(rec))
}

/// The tx is valid only while the LEZ block timestamp is within NOW_TOLERANCE_MS of the start of
/// `now_slot` (genesis_time + 12 s/slot): binds the caller's slot to the chain clock.
fn now_window(r: Response, cfg: &InstanceConfig, now_slot: u64) -> Response {
    let t = cfg.slot_start_ms(now_slot);
    r.try_timestamp_window(t.saturating_sub(NOW_TOLERANCE_MS)..t.saturating_add(NOW_TOLERANCE_MS))
        .unwrap_or_else(|_| fail(MALFORMED))
}

/// Identical application and chained writes for the atomic and split update paths.
fn apply_verified(
    program: AccountId,
    instance_id: InstanceId,
    st: &mut InstanceState,
    verified: &VerifiedUpdate,
) -> Response {
    let old_slot = st.store.finalized_header.beacon.slot;
    apply_update(&mut st.store, verified).or_fail();
    let mut sends = vec![];
    if let Some(f) = &verified.finalized_header {
        let rec = header_record(instance_id, &st.cfg, f);
        // Accumulate only headers that advanced finality (each record once).
        if st.store.finalized_header.beacon.slot > old_slot {
            sends.push(append_root(program, st, &rec));
        }
        sends.insert(0, write_header(program, rec));
    }
    sends
        .into_iter()
        .fold(Response::set_state(enc(st)), Response::send)
}

pub fn handle(input: &ReceiveInput, message: &[u8]) -> Response {
    // Attest (the hot path) decodes borrowed: no copy of header/receipt/proof bytes (D-GAS-3).
    if let Some((&crate::view::MSG_ATTEST, req)) = message.split_first() {
        let req = AttestRequestRef::decode(req).unwrap_or_else(|| fail(MALFORMED));
        return attest(input, &req);
    }
    match decode::<Msg>(message) {
        Msg::Init {
            instance_id,
            cfg,
            trusted_block_root,
            bootstrap: b,
            now_slot,
        } => {
            let program = require_at(input, instance_seed(&instance_id));
            if !input.pre_state.is_empty() {
                fail(ErrorCode::UpdateNotNewer as u16);
            }
            // Anti-squatting: the id commits to the full config + checkpoint, and the config meets the protocol floor.
            let floor = (MIN_PARTICIPATION_FLOOR..=lc_core::SYNC_COMMITTEE_SIZE as u16)
                .contains(&cfg.chain.min_participation);
            if instance_id != crate::instance_id(&cfg, &trusted_block_root)
                || !floor
                || cfg.chain.ws_period_epochs > MAX_WS_PERIOD_EPOCHS
            {
                fail(MALFORMED);
            }
            // `now_slot` is bound to the block timestamp by the validity window below, so it is a
            // trustworthy hint for the weak-subjectivity staleness check (1105, F10).
            let store = bootstrap(&cfg.chain, &trusted_block_root, &b, now_slot).or_fail();
            let rec = header_record(instance_id, &cfg, &store.finalized_header);
            let mut st = InstanceState {
                cfg: cfg.clone(),
                store,
                headers: Frontier::default(),
            };
            let root = append_root(program, &mut st, &rec);
            now_window(Response::set_state(enc(&st)), &cfg, now_slot)
                .send(write_header(program, rec))
                .send(root)
        }
        Msg::Update {
            instance_id,
            update,
            non_signers,
            witness,
            now_slot,
        } => {
            let program = require_at(input, instance_seed(&instance_id));
            if input.pre_state.is_empty() {
                fail(ErrorCode::HeaderNotFinalised as u16);
            }
            let mut st: InstanceState = decode(&input.pre_state);
            let p = prepare_update(&st.cfg.chain, &st.store, &update, now_slot).or_fail();
            let (apk, h, sig) = crate::bls::prepare(&p.pairing, &non_signers).or_fail();
            let ok = crate::bls::pairing_check(&apk, &h, &sig, &witness);
            let verified = finish_update(p, ok).or_fail();
            let response = apply_verified(program, instance_id, &mut st, &verified);
            now_window(response, &st.cfg, now_slot)
        }
        Msg::UpdateBegin {
            instance_id,
            job_id,
            update,
            non_signers,
            now_slot,
        } => {
            let program = require_at(input, instance_seed(&instance_id));
            if input.pre_state.is_empty() {
                fail(ErrorCode::HeaderNotFinalised as u16); // no such instance
            }
            let st: InstanceState = decode(&input.pre_state);
            let p = prepare_update(&st.cfg.chain, &st.store, &update, now_slot).or_fail();
            let (apk, h, sig) = crate::bls::prepare(&p.pairing, &non_signers).or_fail();
            let job = Job {
                instance_id,
                job_id,
                verified: p.verified,
                apk,
                h,
                sig,
            };
            now_window(Response::keep_state(), &st.cfg, now_slot).send(send_own(
                program,
                job_seed(&instance_id, job_id),
                &Msg::WriteJob(job),
            ))
        }
        Msg::WriteJob(job) => {
            require_at(input, job_seed(&job.instance_id, job.job_id));
            require_from(input, instance_seed(&job.instance_id));
            if !input.pre_state.is_empty() {
                fail(ErrorCode::UpdateNotNewer as u16); // job id in use
            }
            Response::set_state(enc(&job))
        }
        Msg::UpdateVerify {
            instance_id,
            job_id,
            witness,
        } => {
            let program = require_at(input, job_seed(&instance_id, job_id));
            if input.pre_state.is_empty() {
                fail(ErrorCode::UpdateNotNewer as u16); // unknown or already finished job
            }
            let job: Job = decode(&input.pre_state);
            let ok = crate::bls::pairing_check(&job.apk, &job.h, &job.sig, &witness);
            let prepared = lc_core::PreparedUpdate {
                pairing: lc_core::PairingInputs {
                    aggregate_pubkey: [0; 48],
                    non_signer_pubkeys: vec![],
                    signing_root: [0; 32],
                    signature: [0; 96],
                },
                verified: job.verified,
            };
            let verified = finish_update(prepared, ok).or_fail();
            // Job is consumed; the PDA can be reused.
            Response::set_state(Vec::new()).send(send_own(
                program,
                instance_seed(&instance_id),
                &Msg::Apply {
                    instance_id,
                    job_id,
                    verified,
                },
            ))
        }
        Msg::Apply {
            instance_id,
            job_id,
            verified,
        } => {
            let program = require_at(input, instance_seed(&instance_id));
            require_from(input, job_seed(&instance_id, job_id));
            let mut st: InstanceState = decode(&input.pre_state);
            apply_verified(program, instance_id, &mut st, &verified)
        }
        Msg::WriteHeader(rec) => {
            require_at(
                input,
                header_seed(&rec.instance_id, &rec.execution_block_hash),
            );
            require_from(input, instance_seed(&rec.instance_id));
            let bytes = enc(&rec);
            if !input.pre_state.is_empty() && *input.pre_state != *bytes {
                fail(MALFORMED); // records are immutable (R3)
            }
            Response::set_state(bytes)
        }
        Msg::Attest(req) => attest(input, &req.view()),
        Msg::WriteRoot { instance_id, root } => {
            require_at(input, hroot_seed(&instance_id, &root));
            require_from(input, instance_seed(&instance_id));
            // Write-once; a root names a unique accumulator state, so a rewrite is identical.
            Response::set_state(root.to_vec())
        }
        Msg::CheckRoot { instance_id, root } => {
            require_at(input, hroot_seed(&instance_id, &root));
            if input.pre_state.is_empty() {
                fail(ErrorCode::HeaderNotFinalised as u16);
            }
            Response::keep_state()
        }
        Msg::CheckHeader {
            instance_id,
            chain_id,
            genesis_validators_root,
            execution_block_hash,
        } => {
            require_at(input, header_seed(&instance_id, &execution_block_hash));
            if input.pre_state.is_empty() {
                fail(ErrorCode::HeaderNotFinalised as u16);
            }
            let rec: HeaderRecord = decode(&input.pre_state);
            if rec.instance_id != instance_id || rec.execution_block_hash != execution_block_hash {
                fail(ErrorCode::HeaderNotFinalised as u16);
            }
            if rec.chain_id != chain_id || rec.genesis_validators_root != genesis_validators_root {
                fail(ErrorCode::StatementMismatch as u16);
            }
            Response::keep_state()
        }
    }
}

fn attest(input: &ReceiveInput, req: &AttestRequestRef) -> Response {
    if input.pre_state.is_empty() {
        fail(ErrorCode::HeaderNotFinalised as u16);
    }
    let rec: HeaderRecord = decode(&input.pre_state);
    require_at(
        input,
        header_seed(&req.instance_id, &rec.execution_block_hash),
    );
    let statement = verify_ref(&rec, req).unwrap_or_else(|c| fail(c));
    let reply = AttestReply {
        instance_id: req.instance_id,
        statement,
        ctx: req.ctx.to_vec(),
    };
    match input.from {
        Some(caller) => Response::keep_state().send(SyncMessage::new(caller, &reply)),
        None => Response::keep_state().event(ProgramEvent {
            selector: attested_selector(),
            data: enc(&reply),
        }),
    }
}
