//! Authenticated native delivery shared by Flutter and the agent CLI. The SDK
//! owns record/batch lifetime; this adapter owns policy, bounded retries and I/O.
use crate::runtime::{self, Instant, Task};
use crate::{ClientError, IdentityClient, SyncRequest, observability_wire as wire};
use nddev_device_sync_telemetry::{ExportBatch, ExportFeed, FeedHealth};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

pub use crate::view::{DeliveryView, ExportPolicy};
pub struct Delivery {
    events: Arc<ExportFeed>,
    traces: Arc<ExportFeed>,
    state: Arc<Mutex<DeliveryView>>,
    active: watch::Sender<bool>,
    cancel: CancellationToken,
    task: Task,
}
impl Delivery {
    pub fn start(
        identity: Arc<IdentityClient>,
        events: ExportFeed,
        traces: ExportFeed,
        foreground: bool,
    ) -> Self {
        let events = Arc::new(events);
        let traces = Arc::new(traces);
        let state = Arc::new(Mutex::new(DeliveryView {
            initialized: true,
            paused: !foreground,
            ..Default::default()
        }));
        let (active, receiver) = watch::channel(foreground);
        let cancel = CancellationToken::new();
        let task = runtime::spawn(run(
            identity,
            events.clone(),
            traces.clone(),
            state.clone(),
            receiver,
            cancel.clone(),
        ));
        Self {
            events,
            traces,
            state,
            active,
            cancel,
            task,
        }
    }
    pub fn snapshot(&self) -> DeliveryView {
        let mut view = self
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let FeedHealth {
            pending,
            delivered,
            dropped,
            failures,
        } = self.events.health();
        view.pending = pending;
        view.delivered = delivered;
        view.dropped = dropped;
        view.failures = failures.saturating_add(view.failures);
        let health = self.traces.health();
        view.spans_pending = health.pending;
        view.spans_delivered = health.delivered;
        view.spans_dropped = health.dropped;
        view.spans_failures = health.failures;
        view
    }
    pub fn foreground(&self, active: bool) {
        self.active.send_replace(active);
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .paused = !active;
    }
    pub fn finished(&self) -> bool {
        self.task.is_finished()
    }
    /// Try to drain while the process is still running. Returns truthful counters
    /// after at most five seconds; Drop accounts for any remaining records.
    pub async fn flush(&self) -> DeliveryView {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let view = self.snapshot();
            if view.pending + view.spans_pending == 0
                || !view.initialized
                || view.paused
                || Instant::now() >= deadline
            {
                return view;
            }
            runtime::sleep(Duration::from_millis(50)).await;
        }
    }
}
impl Drop for Delivery {
    fn drop(&mut self) {
        self.events.close();
        self.traces.close();
        self.cancel.cancel();
        self.task.abort();
    }
}
struct Worker {
    events: Arc<ExportFeed>,
    traces: Arc<ExportFeed>,
    state: Arc<Mutex<DeliveryView>>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.events.close();
        self.traces.close();
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .initialized = false;
    }
}
fn terminal(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::DeviceRevoked | ClientError::RevalidationRequired | ClientError::Cancelled
    ) || matches!(error, ClientError::Server(code) if code == "authentication_failed" || code == "device_revoked")
}
async fn run(
    identity: Arc<IdentityClient>,
    events: Arc<ExportFeed>,
    traces: Arc<ExportFeed>,
    state: Arc<Mutex<DeliveryView>>,
    mut active: watch::Receiver<bool>,
    cancel: CancellationToken,
) {
    let _worker = Worker {
        events: events.clone(),
        traces: traces.clone(),
        state: state.clone(),
    };
    let mut pending: Option<(ExportBatch, bool)> = None;
    let mut attempts = 0u32;
    let mut delay = Duration::ZERO;
    let mut checked: Option<Instant> = None;
    let mut trace_turn = false;
    loop {
        if pending.as_ref().is_some_and(|(batch, _)| batch.expired()) {
            pending = None;
        }
        // Opportunistic expiry also runs while backgrounded; never send a
        // retained batch merely because policy discovery was unavailable.
        events.health();
        traces.health();
        if !*active.borrow() {
            tokio::select! { _ = cancel.cancelled() => break, changed = active.changed() => { if changed.is_err() { break; } }, _ = runtime::sleep(Duration::from_secs(30)) => {} }
            checked = None;
            delay = Duration::ZERO;
            continue;
        }
        tokio::select! {
            _ = cancel.cancelled() => break,
            changed = active.changed() => { if changed.is_err() { break; } checked = None; delay = Duration::ZERO; continue; },
            _ = runtime::sleep(delay) => {}
        }
        if checked.is_none_or(|time| time.elapsed() >= Duration::from_secs(30)) {
            let result = tokio::select! {
                _ = cancel.cancelled() => break,
                changed = active.changed() => { if changed.is_err() { break; } checked = None; continue; },
                result = identity.sync_request(SyncRequest::ObservabilityStatus) => result,
            }.and_then(|reply| serde_json::from_slice::<wire::ObservabilityStatus>(&reply.body).map_err(|_| ClientError::InvalidResponse));
            match result {
                Ok(status) => {
                    let enabled = matches!(status.export_mode, wire::ExportMode::Enabled);
                    events.set_enabled(enabled);
                    traces.set_enabled(enabled);
                    state
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .policy = if enabled {
                        ExportPolicy::Enabled
                    } else {
                        ExportPolicy::Disabled
                    };
                    if !enabled {
                        pending = None;
                    }
                    checked = Some(Instant::now());
                }
                Err(error) if terminal(&error) => break,
                Err(ClientError::Busy) => {
                    delay = Duration::from_secs(1);
                    continue;
                }
                Err(_) => {
                    let mut view = state.lock().unwrap_or_else(|error| error.into_inner());
                    view.policy = ExportPolicy::Unknown;
                    view.failures = view.failures.saturating_add(1);
                    delay = Duration::from_secs(5);
                    continue;
                }
            }
        }
        if state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .policy
            != ExportPolicy::Enabled
        {
            delay = Duration::from_secs(2);
            continue;
        }
        if pending.is_none() {
            pending = if trace_turn {
                traces
                    .take_batch()
                    .map(|batch| (batch, true))
                    .or_else(|| events.take_batch().map(|batch| (batch, false)))
            } else {
                events
                    .take_batch()
                    .map(|batch| (batch, false))
                    .or_else(|| traces.take_batch().map(|batch| (batch, true)))
            };
            attempts = 0;
        }
        let Some((batch, is_trace)) = &pending else {
            delay = Duration::from_secs(2);
            continue;
        };
        if batch.expired() || attempts >= 8 {
            pending = None;
            delay = Duration::ZERO;
            continue;
        }
        let request = if *is_trace {
            SyncRequest::NativeTraces(batch.bytes().to_vec())
        } else {
            SyncRequest::Telemetry(batch.bytes().to_vec())
        };
        let result = tokio::select! {
            _ = cancel.cancelled() => break,
            changed = active.changed() => { if changed.is_err() { break; } checked = None; continue; },
            result = identity.sync_request(request) => result,
        }.and_then(|reply| serde_json::from_slice::<wire::IngressReceipt>(&reply.body).map_err(|_| ClientError::InvalidResponse));
        match result {
            Ok(receipt) if matches!(receipt.export_mode, wire::ExportMode::Disabled) => {
                events.set_enabled(false);
                traces.set_enabled(false);
                pending = None;
                state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .policy = ExportPolicy::Disabled;
                checked = Some(Instant::now());
                delay = Duration::from_secs(2);
            }
            Ok(receipt)
                if receipt.accepted >= 0
                    && receipt.duplicates >= 0
                    && i64::from(receipt.accepted) + i64::from(receipt.duplicates)
                        == i64::from(batch.count()) =>
            {
                let (batch, trace) = pending.take().expect("owned export batch");
                batch.acknowledge();
                trace_turn = !trace;
                state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .last_success_at = time::OffsetDateTime::now_utc()
                    .unix_timestamp()
                    .try_into()
                    .unwrap_or_default();
                delay = Duration::from_millis(200);
            }
            Err(error) if terminal(&error) => break,
            Err(ClientError::Busy) => delay = Duration::from_secs(1),
            _ => {
                batch.failed();
                attempts += 1;
                delay = Duration::from_secs(1 << attempts.min(5));
            }
        }
    }
}

#[cfg(all(test, feature = "development-http"))]
mod acceptance;
