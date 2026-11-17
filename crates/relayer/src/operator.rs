//! Operator loop (R4,R5,R8-R10): poll -> needed? -> jittered deferral -> re-check -> submit -> persist.
use crate::{
    beacon::{period_of, Beacon},
    material::UpdateMaterial,
};
use anyhow::{Context, Result};
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxRef(pub String);

/// What the target chain's instance currently tracks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct View {
    pub period: u64,
    pub finalized_slot: u64,
    pub next_known: bool,
}

/// Target-chain view and submission (LEZ: `crate::lez::LezChain`; tests: [`MockChain`]).
pub trait Chain {
    fn view(&self) -> Result<View>;
    fn submit_update(&self, m: UpdateMaterial) -> Result<TxRef>;
}

/// Beacon-side view: where finality is and how to build material for a job.
pub trait Source {
    fn finalized_slot(&self) -> Result<u64>;
    fn material(&self, job: &Job) -> Result<UpdateMaterial>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Job {
    /// The best update of this period: learns the next committee (period = tracked) or rotates
    /// into it (period = tracked + 1).
    Period(u64),
    /// Finality advance within the tracked period, to this slot.
    Finality(u64),
}

impl Source for Beacon {
    fn finalized_slot(&self) -> Result<u64> {
        Beacon::finalized_slot(&self.finality_update()?)
    }
    fn material(&self, job: &Job) -> Result<UpdateMaterial> {
        match job {
            Job::Period(p) => self.fetch_update(*p, None),
            Job::Finality(_) => Ok(UpdateMaterial {
                finality_update: self.finality_update()?,
                ..Default::default()
            }),
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    /// Last submissions (job, tx, unix ms); capped.
    submitted: Vec<(Job, TxRef, u64)>,
}

const KEEP: usize = 256;
/// A job we submitted is not re-submitted for this long even if the chain has not yet reflected it.
const PENDING_GRACE_MS: u64 = 300_000;

pub struct Operator<C, S> {
    chain: C,
    source: S,
    key: String,
    max_defer_ms: u64,
    state_path: PathBuf,
    state: State,
    pending: Option<(Job, u64)>,
}

fn fnv(s: &str) -> u64 {
    s.bytes().fold(0xcbf29ce484222325, |h, b| {
        (h ^ b as u64).wrapping_mul(0x100000001b3)
    })
}

impl<C: Chain, S: Source> Operator<C, S> {
    /// Loads (resumes) persisted progress from `state_path` if present.
    pub fn new(
        chain: C,
        source: S,
        key: &str,
        max_defer: Duration,
        state_path: PathBuf,
    ) -> Result<Self> {
        let state = match std::fs::read(&state_path) {
            Ok(b) => serde_json::from_slice(&b).context("corrupt state file")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            chain,
            source,
            key: key.into(),
            max_defer_ms: max_defer.as_millis() as u64,
            state_path,
            state,
            pending: None,
        })
    }

    pub fn defer_ms(&self, job: &Job) -> u64 {
        StdRng::seed_from_u64(fnv(&format!("{}|{:?}", self.key, job)))
            .gen_range(0..=self.max_defer_ms)
    }

    fn needed(&self, job: &Job) -> Result<bool> {
        let v = self.chain.view()?;
        Ok(match job {
            Job::Period(p) => (*p == v.period && !v.next_known) || *p == v.period + 1,
            Job::Finality(s) => v.finalized_slot < *s,
        })
    }

    fn recently_submitted(&self, job: &Job, now: u64) -> bool {
        self.state
            .submitted
            .iter()
            .any(|(j, _, at)| j == job && now.saturating_sub(*at) < PENDING_GRACE_MS)
    }

    fn persist(&self) -> Result<()> {
        let tmp = self.state_path.with_extension("tmp");
        let f = std::fs::File::create(&tmp)?;
        serde_json::to_writer(&f, &self.state)?;
        f.sync_all()?;
        std::fs::rename(&tmp, &self.state_path)?;
        Ok(())
    }

    /// Jobs that would be submitted now, lowest first (dry-run / planning).
    pub fn next_job(&self) -> Result<Option<Job>> {
        let head = self.source.finalized_slot()?;
        let v = self.chain.view()?;
        Ok(if !v.next_known && v.period <= period_of(head) {
            Some(Job::Period(v.period))
        } else if period_of(head) > v.period + 1 {
            Some(Job::Period(v.period + 1))
        } else if v.finalized_slot < head {
            Some(Job::Finality(head))
        } else {
            None
        })
    }

    pub fn next_due(&self) -> Option<u64> {
        self.pending.as_ref().map(|p| p.1)
    }

    /// One step at time `now_ms`. Errors leave the pending job in place so the caller can back off and retry.
    pub fn tick(&mut self, now_ms: u64) -> Result<Option<TxRef>> {
        let Some((job, due)) = self.pending.clone() else {
            if let Some(job) = self.next_job()? {
                if !self.recently_submitted(&job, now_ms) {
                    let due = now_ms + self.defer_ms(&job);
                    tracing::info!(?job, due, "scheduled after jitter");
                    self.pending = Some((job, due));
                }
            }
            return Ok(None);
        };
        if !self.needed(&job)? {
            tracing::info!(?job, "no longer needed, dropping");
            self.pending = None;
            return Ok(None);
        }
        if now_ms < due {
            return Ok(None);
        }
        let material = self.source.material(&job)?;
        // Re-check immediately before submit: someone else may have landed it while we fetched.
        if !self.needed(&job)? || self.recently_submitted(&job, now_ms) {
            tracing::info!(?job, "advanced meanwhile, skipping");
            self.pending = None;
            return Ok(None);
        }
        let tx = match self.chain.submit_update(material) {
            Ok(tx) => tx,
            Err(e) => {
                // An error after sending may have paid for an Update and its MAX_GAS_EXEC retry: record
                // the job so it is not resent on every backoff tick or after a restart (grace period).
                self.pending = None;
                self.record(job, TxRef("failed".into()), now_ms)?;
                return Err(e);
            }
        };
        tracing::info!(?job, tx = %tx.0, "submitted");
        self.pending = None;
        self.record(job, tx.clone(), now_ms)?;
        Ok(Some(tx))
    }

    fn record(&mut self, job: Job, tx: TxRef, now_ms: u64) -> Result<()> {
        self.state.submitted.push((job, tx, now_ms));
        let excess = self.state.submitted.len().saturating_sub(KEEP);
        self.state.submitted.drain(..excess);
        self.persist()
    }

    /// Blocking loop until `stop` is set. Exponential backoff (1s..60s) on errors.
    pub fn run(&mut self, poll: Duration, stop: &AtomicBool) {
        let mut backoff = Backoff::default();
        while !stop.load(Ordering::SeqCst) {
            let wait = match self.tick(now_ms()) {
                Ok(_) => {
                    backoff.reset();
                    let to_due = self
                        .next_due()
                        .map(|d| d.saturating_sub(now_ms()))
                        .unwrap_or(u64::MAX);
                    poll.min(Duration::from_millis(to_due.max(100)))
                }
                Err(e) => {
                    let d = backoff.next();
                    tracing::warn!(error = %e, retry_in_ms = d.as_millis() as u64, "tick failed");
                    d
                }
            };
            let end = std::time::Instant::now() + wait;
            while std::time::Instant::now() < end && !stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        tracing::info!("shutdown");
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub struct Backoff(Duration);
impl Default for Backoff {
    fn default() -> Self {
        Self(Duration::from_millis(500))
    }
}
impl Backoff {
    pub fn next(&mut self) -> Duration {
        self.0 = (self.0 * 2).min(Duration::from_secs(60));
        self.0
    }
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// In-memory chain: a Period update learns the next committee or rotates; a finality update
/// advances the slot (and period).
#[derive(Clone, Default)]
pub struct MockChain {
    inner: Arc<Mutex<View>>,
    pub log: Arc<Mutex<Vec<String>>>,
    pub who: String,
    /// When set, `submit_update` fails after logging the attempt (an included-but-reverted update).
    pub fail: Arc<AtomicBool>,
}
impl MockChain {
    pub fn new(period: u64, slot: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(View {
                period,
                finalized_slot: slot,
                next_known: true,
            })),
            ..Default::default()
        }
    }
    pub fn tracked_period(&self) -> u64 {
        self.inner.lock().unwrap().period
    }
    /// Same chain, different submitter label (for per-operator accounting).
    pub fn as_operator(&self, who: &str) -> Self {
        Self {
            who: who.into(),
            ..self.clone()
        }
    }
}
impl Chain for MockChain {
    fn view(&self) -> Result<View> {
        Ok(*self.inner.lock().unwrap())
    }
    fn submit_update(&self, m: UpdateMaterial) -> Result<TxRef> {
        if self.fail.load(Ordering::SeqCst) {
            self.log
                .lock()
                .unwrap()
                .push(format!("{} failed", self.who));
            anyhow::bail!("update included but expected state unconfirmed");
        }
        let mut s = self.inner.lock().unwrap();
        if !m.updates.is_empty() && !s.next_known {
            s.next_known = true;
        } else if !m.updates.is_empty() {
            s.period += 1;
        } else {
            s.finalized_slot = m.finality_update["slot"]
                .as_u64()
                .unwrap_or(s.finalized_slot);
            s.period = period_of(s.finalized_slot);
        }
        let mut log = self.log.lock().unwrap();
        log.push(self.who.clone());
        Ok(TxRef(format!("mock-{}", log.len())))
    }
}

/// Fixed-head source for the mock chain.
pub struct MockSource(pub u64);
impl Source for MockSource {
    fn finalized_slot(&self) -> Result<u64> {
        Ok(self.0)
    }
    fn material(&self, job: &Job) -> Result<UpdateMaterial> {
        Ok(match job {
            Job::Period(_) => UpdateMaterial {
                updates: vec![serde_json::json!({})],
                ..Default::default()
            },
            Job::Finality(s) => UpdateMaterial {
                finality_update: serde_json::json!({"slot": s}),
                ..Default::default()
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::SLOTS_PER_PERIOD as SPP;

    fn op(
        chain: MockChain,
        head: u64,
        key: &str,
        path: PathBuf,
    ) -> Operator<MockChain, MockSource> {
        Operator::new(chain, MockSource(head), key, Duration::from_secs(30), path).unwrap()
    }

    #[test]
    fn deferral_spreads_cost() {
        let dir = tempfile::tempdir().unwrap();
        let chain = MockChain::new(0, 0);
        let mut ops: Vec<_> = (0..3)
            .map(|i| {
                op(
                    chain.as_operator(&format!("op{i}")),
                    100 * SPP,
                    &format!("operator-{i}"),
                    dir.path().join(format!("s{i}.json")),
                )
            })
            .collect();
        let mut t = 0;
        while chain.tracked_period() < 100 && t < 100_000_000 {
            for o in ops.iter_mut() {
                o.tick(t).unwrap();
            }
            t += 1000;
        }
        assert_eq!(chain.tracked_period(), 100);
        let log = chain.log.lock().unwrap();
        assert_eq!(log.len(), 100, "no duplicate submissions");
        for i in 0..3 {
            let n = log.iter().filter(|w| **w == format!("op{i}")).count();
            assert!(n <= 60, "op{i} paid {n}/100");
        }
    }

    #[test]
    fn restart_resumes_without_resubmitting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.json");
        // Chain that ignores submissions (pending tx not yet reflected): only state can prevent a repeat.
        let chain = MockChain::new(5, 0);
        let mut a = op(chain.as_operator("a"), 6 * SPP, "k", path.clone());
        a.tick(0).unwrap();
        let due = a.next_due().unwrap();
        a.tick(due).unwrap();
        assert_eq!(chain.log.lock().unwrap().len(), 1);
        // New process, chain rolled back to look un-advanced, state file persisted.
        let stale = MockChain::new(5, 0);
        let mut b = op(stale.as_operator("b"), 6 * SPP, "k", path);
        b.tick(due + 1000).unwrap();
        assert!(
            b.next_due().is_none(),
            "completed job must not be rescheduled"
        );
        assert!(stale.log.lock().unwrap().is_empty());
    }

    /// A failed submit (each one may have paid for an Update and a MAX_GAS_EXEC retry) is recorded like a
    /// submission: no resend on every backoff tick, nor after a restart, until the grace period ends.
    #[test]
    fn failed_submit_is_not_resent_within_grace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.json");
        let chain = MockChain::new(5, 0);
        chain.fail.store(true, Ordering::SeqCst);
        let mut a = op(chain.as_operator("a"), 6 * SPP, "k", path.clone());
        a.tick(0).unwrap();
        let due = a.next_due().unwrap();
        assert!(a.tick(due).is_err());
        for t in (due..due + PENDING_GRACE_MS - 1000).step_by(5_000) {
            let _ = a.tick(t);
        }
        assert_eq!(chain.log.lock().unwrap().len(), 1, "resent within grace");
        let mut b = op(chain.as_operator("b"), 6 * SPP, "k", path);
        let _ = b.tick(due + 1000);
        assert!(b.next_due().is_none(), "restart must not reschedule it");
        // after the grace period the job is tried again
        chain.fail.store(false, Ordering::SeqCst);
        let later = due + PENDING_GRACE_MS + 1;
        b.tick(later).unwrap();
        b.tick(b.next_due().unwrap()).unwrap();
        assert_eq!(chain.log.lock().unwrap().len(), 2);
    }

    #[test]
    fn skips_when_chain_advanced_before_submit() {
        let dir = tempfile::tempdir().unwrap();
        let chain = MockChain::new(5, 0);
        let mut a = op(
            chain.as_operator("a"),
            6 * SPP,
            "k",
            dir.path().join("s.json"),
        );
        a.tick(0).unwrap();
        let due = a.next_due().unwrap();
        // Someone else lands the same update during our deferral.
        chain
            .as_operator("other")
            .submit_update(MockSource(0).material(&Job::Finality(6 * SPP)).unwrap())
            .unwrap();
        a.tick(due).unwrap();
        assert_eq!(
            chain
                .log
                .lock()
                .unwrap()
                .iter()
                .filter(|w| *w == "a")
                .count(),
            0
        );
        assert_eq!(chain.tracked_period(), 6);
    }

    #[test]
    fn unknown_next_committee_first() {
        let dir = tempfile::tempdir().unwrap();
        let chain = MockChain::new(5, 5 * SPP);
        chain.inner.lock().unwrap().next_known = false;
        let a = op(
            chain.as_operator("a"),
            5 * SPP + 64,
            "k",
            dir.path().join("s.json"),
        );
        assert_eq!(a.next_job().unwrap(), Some(Job::Period(5)));
        chain
            .submit_update(MockSource(0).material(&Job::Period(5)).unwrap())
            .unwrap();
        assert!(!a.needed(&Job::Period(5)).unwrap());
        assert_eq!(a.next_job().unwrap(), Some(Job::Finality(5 * SPP + 64)));
    }

    #[test]
    fn backoff_grows_and_caps() {
        let mut b = Backoff::default();
        let v: Vec<_> = (0..10).map(|_| b.next().as_secs()).collect();
        assert_eq!(v[0], 1);
        assert_eq!(*v.last().unwrap(), 60);
    }
}
