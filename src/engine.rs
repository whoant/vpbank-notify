//! Event-driven reconciliation: every push triggers a bounded history fetch.
//! There is no periodic polling.

use crate::{
    bank::{BankError, Transaction},
    native::PushEvent,
    state::{State, StoredTransaction},
};
use anyhow::Result;
use std::{future::Future, time::Duration};
use tokio::sync::mpsc;

/// HTTP attempts per event, including retries for transient errors or lagging history.
const ATTEMPTS: u32 = 3;

pub trait HistoryApi {
    fn snapshot(&self) -> impl Future<Output = Result<Vec<Transaction>, BankError>> + Send;
}

pub struct Engine<A> {
    api: A,
    state: State,
    /// Deduplication scope of the share pair
    scope: String,
    /// Identity of the native FCM registration
    native: String,
}

/// Rows a push event produced, and the error that ended it early, if any.
///
/// The rows are already stored, so they must be shown even when `result` is an error.
pub(crate) struct EventOutcome {
    pub(crate) rows: Vec<StoredTransaction>,
    pub(crate) result: Result<()>,
}

impl<A: HistoryApi> Engine<A> {
    pub fn new(api: A, state: State, scope: String, native: String) -> Self {
        Self {
            api,
            state,
            scope,
            native,
        }
    }

    /// Fetches the first snapshot and establishes the deduplication baseline.
    pub async fn bootstrap(&self, show: bool) -> Result<Vec<StoredTransaction>> {
        // Capture before the request so pushes arriving during HTTP stay pending.
        let pending = self.state.pending_receipts(&self.native)?;
        self.bootstrap_from_snapshot(self.fetch().await?, show, &pending)
    }

    /// Establishes the baseline from an already fetched snapshot.
    ///
    /// With an existing baseline, only rows that are new since the last run are
    /// returned, each resolving one receipt of `pending_before_fetch`. Otherwise
    /// (or with `show`) the snapshot becomes the baseline, and is returned in full
    /// only when `show` is set.
    pub fn bootstrap_from_snapshot(
        &self,
        rows: Vec<Transaction>,
        show: bool,
        pending_before_fetch: &[i64],
    ) -> Result<Vec<StoredTransaction>> {
        if self.state.has_baseline(&self.scope)? && !show {
            return self.state.commit_event_snapshot(
                &self.scope,
                &self.native,
                &rows,
                pending_before_fetch,
            );
        }
        self.state
            .commit_snapshot(&self.scope, &self.native, &rows, 0)?;
        if !show {
            return Ok(Vec::new());
        }
        let received_at = chrono::Utc::now().to_rfc3339();
        Ok(rows
            .into_iter()
            .map(|transaction| StoredTransaction {
                received_at: received_at.clone(),
                transaction,
            })
            .collect())
    }

    /// Resolves pending push receipts, one per new history row.
    pub(crate) async fn on_push(&self) -> EventOutcome {
        let mut rows = Vec::new();
        let result = self.reconcile_pending(&mut rows).await;
        EventOutcome { rows, result }
    }

    /// Runs after a reconnect: resolves pending pushes, or checks once for missed rows.
    pub(crate) async fn catch_up(&self) -> EventOutcome {
        let mut rows = Vec::new();
        let result = self.catch_up_into(&mut rows).await;
        EventOutcome { rows, result }
    }

    async fn catch_up_into(&self, output: &mut Vec<StoredTransaction>) -> Result<()> {
        if self.state.pending_watermark(&self.native)? > 0 {
            return self.reconcile_pending(output).await;
        }
        let rows = self.fetch().await?;
        output.extend(
            self.state
                .commit_event_snapshot(&self.scope, &self.native, &rows, &[])?,
        );
        Ok(())
    }

    /// Appends new rows to `output` as they are committed, so rows stored before a
    /// later failure are still reported.
    async fn reconcile_pending(&self, output: &mut Vec<StoredTransaction>) -> Result<()> {
        let mut pending = self.state.pending_receipts(&self.native)?;
        if pending.is_empty() {
            return Ok(());
        }
        // The whole event has one request budget, independent of the backlog size.
        for attempt in 0..ATTEMPTS {
            match self.api.snapshot().await {
                Ok(rows) => {
                    let new_rows = self.state.commit_event_snapshot(
                        &self.scope,
                        &self.native,
                        &rows,
                        &pending,
                    )?;
                    let resolved = new_rows.len().min(pending.len());
                    pending.drain(..resolved);
                    output.extend(new_rows);
                    if pending.is_empty() {
                        return Ok(());
                    }
                    if resolved > 0 {
                        continue;
                    }
                }
                Err(error) if error.transient() && attempt + 1 < ATTEMPTS => {}
                Err(error) => return Err(error.into()),
            }
            if attempt + 1 < ATTEMPTS {
                backoff(attempt).await;
            }
        }
        if output.is_empty() {
            eprintln!(
                "Push received, but the history has no new record yet; keeping it pending for the next event."
            );
        }
        Ok(())
    }

    /// One snapshot, retrying transient failures within the event budget.
    async fn fetch(&self) -> Result<Vec<Transaction>> {
        let mut attempt = 0;
        loop {
            match self.api.snapshot().await {
                Ok(rows) => return Ok(rows),
                Err(error) if error.transient() && attempt + 1 < ATTEMPTS => {
                    backoff(attempt).await;
                    attempt += 1;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

/// Waits 1 s, then 2 s, between attempts.
async fn backoff(attempt: u32) {
    tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
}

/// Processes push events until the channel closes, printing new rows via `output`.
pub async fn drive<A: HistoryApi>(
    engine: Engine<A>,
    mut events: mpsc::Receiver<PushEvent>,
    mut output: impl FnMut(Vec<StoredTransaction>) -> Result<()>,
) -> Result<()> {
    while let Some(event) = events.recv().await {
        let outcome = match event {
            PushEvent::Notification { .. } => {
                eprintln!("Balance change push received; fetching details...");
                engine.on_push().await
            }
            PushEvent::Connected { reconnected: true } => {
                eprintln!("Reconnected to FCM; catching up once.");
                engine.catch_up().await
            }
            PushEvent::Connected { reconnected: false } => continue,
            PushEvent::Disconnected { reason } => {
                eprintln!("Push: {reason}; reconnecting");
                continue;
            }
        };
        output(outcome.rows)?;
        match outcome.result {
            Ok(()) => {}
            Err(error)
                if error
                    .downcast_ref::<BankError>()
                    .is_some_and(BankError::transient) =>
            {
                eprintln!(
                    "{error}; no attempts left for this event, keeping it pending for the next one."
                )
            }
            Err(error) => return Err(error),
        }
    }
    anyhow::bail!("The push channel stopped")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    struct Fake {
        calls: Arc<AtomicUsize>,
        replies: Mutex<VecDeque<Result<Vec<Transaction>, BankError>>>,
    }
    impl HistoryApi for Fake {
        async fn snapshot(&self) -> Result<Vec<Transaction>, BankError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected bank request")
        }
    }
    fn row(amount: &str) -> Transaction {
        Transaction {
            bank_time: "18/10/2026 01:00".into(),
            account_group: "group".into(),
            masked_account: "XX1234".into(),
            amount: amount.into(),
            currency: "VND".into(),
            unverified_field: "00000VND".into(),
            description: "synthetic".into(),
            raw_record: format!("synthetic-{amount}"),
        }
    }
    #[tokio::test(start_paused = true)]
    async fn idle_hour_never_fetches_history_and_push_does() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path()).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let api = Fake {
            calls: calls.clone(),
            replies: Mutex::new(VecDeque::from([
                Ok(vec![row("1")]),
                Ok(vec![row("1"), row("2")]),
            ])),
        };
        let engine = Engine::new(api, state.clone(), "scope".into(), "native".into());
        assert!(engine.bootstrap(false).await.unwrap().is_empty());
        let (tx, rx) = mpsc::channel(8);
        let task = tokio::spawn(drive(engine, rx, |_| Ok(())));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(3600)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let receipt = state.record_push("native", Some("one")).unwrap().unwrap();
        tx.send(PushEvent::Notification { receipt }).await.unwrap();
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(state.history(50).unwrap().len(), 2);
        assert_eq!(state.pending_watermark("native").unwrap(), 0);
        task.abort();
    }
    #[tokio::test(start_paused = true)]
    async fn lagging_history_keeps_receipt_pending_with_bounded_retries() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path()).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let api = Fake {
            calls: calls.clone(),
            replies: Mutex::new(VecDeque::from([
                Ok(vec![row("1")]),
                Ok(vec![row("1")]),
                Ok(vec![row("1")]),
                Ok(vec![row("1")]),
            ])),
        };
        let engine = Engine::new(api, state.clone(), "scope".into(), "native".into());
        engine.bootstrap(false).await.unwrap();
        let receipt = state.record_push("native", Some("one")).unwrap().unwrap();
        let outcome = engine.on_push().await;
        outcome.result.unwrap();
        assert!(outcome.rows.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert_eq!(state.pending_watermark("native").unwrap(), receipt);
    }
    #[tokio::test(start_paused = true)]
    async fn transient_retries_are_bounded_and_auth_failure_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path()).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let api = Fake {
            calls: calls.clone(),
            replies: Mutex::new(VecDeque::from([
                Err(BankError::Network),
                Err(BankError::Network),
                Err(BankError::Network),
                Err(BankError::Unauthorized),
            ])),
        };
        let engine = Engine::new(api, state.clone(), "scope".into(), "native".into());
        let receipt = state.record_push("native", Some("one")).unwrap().unwrap();
        assert!(engine.on_push().await.result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(state.pending_watermark("native").unwrap(), receipt);
        assert!(engine.on_push().await.result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }
    #[tokio::test(start_paused = true)]
    async fn restart_recovers_pending_before_suppressing_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path()).unwrap();
        state
            .commit_snapshot("scope", "native", &[row("1")], 0)
            .unwrap();
        state.record_push("native", Some("one")).unwrap();
        let api = Fake {
            calls: Arc::new(AtomicUsize::new(0)),
            replies: Mutex::new(VecDeque::from([Ok(vec![row("1"), row("2")])])),
        };
        let engine = Engine::new(api, state.clone(), "scope".into(), "native".into());
        let recovered = engine.bootstrap(false).await.unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].transaction.amount, "2");
        assert_eq!(state.pending_watermark("native").unwrap(), 0);
    }
    #[tokio::test(start_paused = true)]
    async fn two_pushes_with_staggered_history_are_reconciled_individually() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path()).unwrap();
        state
            .commit_snapshot("scope", "native", &[row("1")], 0)
            .unwrap();
        state.record_push("native", Some("one")).unwrap();
        state.record_push("native", Some("two")).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let api = Fake {
            calls: calls.clone(),
            replies: Mutex::new(VecDeque::from([
                Ok(vec![row("1"), row("2")]),
                Ok(vec![row("1"), row("2"), row("3")]),
            ])),
        };
        let engine = Engine::new(api, state.clone(), "scope".into(), "native".into());
        let outcome = engine.on_push().await;
        outcome.result.unwrap();
        assert_eq!(outcome.rows.len(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(state.pending_watermark("native").unwrap(), 0);
    }
    #[tokio::test(start_paused = true)]
    async fn duplicate_backlog_does_not_multiply_request_budget_per_event() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path()).unwrap();
        state
            .commit_snapshot("scope", "native", &[row("1")], 0)
            .unwrap();
        for index in 0..20 {
            state
                .record_push("native", Some(&format!("push-{index}")))
                .unwrap();
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let api = Fake {
            calls: calls.clone(),
            replies: Mutex::new((0..60).map(|_| Ok(vec![row("1")])).collect()),
        };
        let engine = Engine::new(api, state.clone(), "scope".into(), "native".into());
        let outcome = engine.on_push().await;
        outcome.result.unwrap();
        assert!(outcome.rows.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(state.pending_receipts("native").unwrap().len(), 20);
    }
    #[tokio::test(start_paused = true)]
    async fn one_snapshot_with_two_new_rows_resolves_two_pushes() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path()).unwrap();
        state
            .commit_snapshot("scope", "native", &[row("1")], 0)
            .unwrap();
        state.record_push("native", Some("one")).unwrap();
        state.record_push("native", Some("two")).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let api = Fake {
            calls: calls.clone(),
            replies: Mutex::new(VecDeque::from([Ok(vec![row("1"), row("2"), row("3")])])),
        };
        let engine = Engine::new(api, state.clone(), "scope".into(), "native".into());
        let outcome = engine.on_push().await;
        outcome.result.unwrap();
        assert_eq!(outcome.rows.len(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(state.pending_watermark("native").unwrap(), 0);
    }
    #[tokio::test(start_paused = true)]
    async fn rows_found_before_an_auth_failure_are_reported_with_the_error() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path()).unwrap();
        state
            .commit_snapshot("scope", "native", &[row("1")], 0)
            .unwrap();
        state.record_push("native", Some("one")).unwrap();
        let second = state.record_push("native", Some("two")).unwrap().unwrap();
        let api = Fake {
            calls: Arc::new(AtomicUsize::new(0)),
            replies: Mutex::new(VecDeque::from([
                Ok(vec![row("1"), row("2")]),
                Err(BankError::Unauthorized),
            ])),
        };
        let engine = Engine::new(api, state.clone(), "scope".into(), "native".into());
        let outcome = engine.on_push().await;
        assert_eq!(outcome.rows.len(), 1);
        assert!(matches!(
            outcome.result.unwrap_err().downcast_ref::<BankError>(),
            Some(BankError::Unauthorized)
        ));
        assert_eq!(state.pending_receipts("native").unwrap(), [second]);
    }
    #[tokio::test]
    async fn startup_snapshot_does_not_consume_push_received_during_http() {
        struct DuringRequest {
            state: State,
        }
        impl HistoryApi for DuringRequest {
            async fn snapshot(&self) -> Result<Vec<Transaction>, BankError> {
                self.state
                    .record_push("native", Some("arrived-during-http"))
                    .unwrap();
                Ok(vec![row("1"), row("2")])
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path()).unwrap();
        state
            .commit_snapshot("scope", "native", &[row("1")], 0)
            .unwrap();
        let engine = Engine::new(
            DuringRequest {
                state: state.clone(),
            },
            state.clone(),
            "scope".into(),
            "native".into(),
        );
        assert_eq!(engine.bootstrap(false).await.unwrap().len(), 1);
        assert_eq!(state.pending_receipts("native").unwrap().len(), 1);
    }
}
