//! Admission unit tests use owned memory work, never a credential provider or
//! authentication fixture. Real native-store acceptance is a separate gate.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test]
async fn cancelled_caller_keeps_running_work_owned_and_waiters_can_cancel() {
    let store =
        SessionStore::for_endpoint(&format!("https://nds-io-{}.invalid/", uuid::Uuid::new_v4()))
            .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::sync_channel(1);
    let running = {
        let store = store.clone();
        let calls = calls.clone();
        tokio::spawn(async move {
            store
                .run_io("identity.credential.read", move |_, _| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let _ = started.send(());
                    wait.recv_timeout(Duration::from_secs(5))
                        .map_err(|_| ClientError::Timeout)?;
                    Ok(())
                })
                .await
        })
    };
    ready.await.unwrap();
    running.abort();
    assert!(running.await.unwrap_err().is_cancelled());

    // A foreground identity mutation can wait behind background I/O. Its
    // process lease is not created before dispatch, and cancellation releases
    // local mutation admission without releasing the still-running worker.
    let local = store.operation().unwrap();
    let mut identity = Box::pin(store.activate_operation(local));
    assert!(futures::poll!(identity.as_mut()).is_pending());
    assert!(matches!(store.operation(), Err(ClientError::Busy)));
    drop(identity);
    drop(store.operation().unwrap());

    let queued_calls = calls.clone();
    let mut queued = Box::pin(store.run_io("identity.credential.read", move |_, _| {
        queued_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }));
    assert!(futures::poll!(queued.as_mut()).is_pending());
    drop(queued);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let next_calls = calls.clone();
    let mut next = Box::pin(store.run_io("identity.credential.read", move |_, _| {
        Ok(next_calls.fetch_add(1, Ordering::SeqCst) + 1)
    }));
    assert!(futures::poll!(next.as_mut()).is_pending());
    release.send(()).unwrap();
    assert_eq!(next.await.unwrap(), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn io_waiting_budget_is_bounded_and_cancelled_requests_release_capacity() {
    let store = SessionStore::for_endpoint(&format!(
        "https://nds-io-budget-{}.invalid/",
        uuid::Uuid::new_v4()
    ))
    .unwrap();
    let span = tracing::Span::none();
    let active = store.admit_io(&span).await.unwrap();
    let mut waiting = Vec::new();
    for _ in 1..MAX_IO_REQUESTS {
        let mut next = Box::pin(store.admit_io(&span));
        assert!(futures::poll!(next.as_mut()).is_pending());
        waiting.push(next);
    }
    assert!(matches!(
        store.admit_io(&span).await,
        Err(ClientError::Busy)
    ));
    waiting.pop();
    let mut replacement = Box::pin(store.admit_io(&span));
    assert!(futures::poll!(replacement.as_mut()).is_pending());
    drop(waiting);
    drop(active);
    let (permit, remaining) = replacement.await.unwrap();
    assert!(!remaining.is_zero() && remaining <= IO_TIMEOUT);
    drop(permit);
    drop(store.admit_io(&span).await.unwrap());
}
