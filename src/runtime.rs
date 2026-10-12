//! Small platform scheduling adapter for the actual client/replica lifetimes.
//! No browser thread pool or unsupported Tokio timer is assumed.
#[cfg(not(target_arch = "wasm32"))]
pub use std::time::Instant;
use std::{future::Future, time::Duration};
#[cfg(target_arch = "wasm32")]
pub use web_time::Instant;

#[derive(Debug)]
pub struct Elapsed;

pub async fn sleep(duration: Duration) {
    #[cfg(not(target_arch = "wasm32"))]
    tokio::time::sleep(duration).await;
    #[cfg(target_arch = "wasm32")]
    {
        let chunk = Duration::from_millis(i32::MAX as u64);
        let mut remaining = duration;
        while remaining > chunk {
            gloo_timers::future::TimeoutFuture::new(i32::MAX as u32).await;
            remaining = remaining.saturating_sub(chunk);
        }
        gloo_timers::future::TimeoutFuture::new(remaining.as_millis() as u32).await;
    }
}

pub async fn timeout<F: Future>(duration: Duration, future: F) -> Result<F::Output, Elapsed> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        tokio::time::timeout(duration, future)
            .await
            .map_err(|_| Elapsed)
    }
    #[cfg(target_arch = "wasm32")]
    {
        match futures::future::select(Box::pin(future), Box::pin(sleep(duration))).await {
            futures::future::Either::Left((value, _)) => Ok(value),
            futures::future::Either::Right(_) => Err(Elapsed),
        }
    }
}

pub struct Task {
    #[cfg(not(target_arch = "wasm32"))]
    inner: tokio::task::JoinHandle<()>,
    #[cfg(target_arch = "wasm32")]
    cancel: futures::future::AbortHandle,
    #[cfg(target_arch = "wasm32")]
    finished: std::sync::Arc<std::sync::atomic::AtomicBool>,
    #[cfg(target_arch = "wasm32")]
    completion: tokio::sync::oneshot::Receiver<()>,
}
impl Task {
    pub fn abort(&self) {
        #[cfg(not(target_arch = "wasm32"))]
        self.inner.abort();
        #[cfg(target_arch = "wasm32")]
        self.cancel.abort();
    }
    pub fn is_finished(&self) -> bool {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.inner.is_finished()
        }
        #[cfg(target_arch = "wasm32")]
        {
            self.finished.load(std::sync::atomic::Ordering::Acquire)
        }
    }
    /// Wait for the owned future to release its operation guards after abort.
    /// Platform I/O workers retain their own admission through actual completion.
    pub async fn join(self) {
        #[cfg(not(target_arch = "wasm32"))]
        let _ = self.inner.await;
        #[cfg(target_arch = "wasm32")]
        let _ = self.completion.await;
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn spawn(future: impl Future<Output = ()> + Send + 'static) -> Task {
    Task {
        inner: tokio::spawn(future),
    }
}

#[cfg(target_arch = "wasm32")]
pub fn spawn(future: impl Future<Output = ()> + 'static) -> Task {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    struct Completed(Arc<AtomicBool>, Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for Completed {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
            if let Some(send) = self.1.take() {
                let _ = send.send(());
            }
        }
    }
    let (cancel, registration) = futures::future::AbortHandle::new_pair();
    let finished = Arc::new(AtomicBool::new(false));
    let (send, completion) = tokio::sync::oneshot::channel();
    let completed = Completed(finished.clone(), Some(send));
    wasm_bindgen_futures::spawn_local(async move {
        let _completion = completed;
        let _ = futures::future::Abortable::new(future, registration).await;
    });
    Task {
        cancel,
        finished,
        completion,
    }
}
