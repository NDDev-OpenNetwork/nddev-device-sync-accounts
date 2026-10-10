use crate::ClientError;
use keyring_core::{CredentialStore, Entry};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

const SERVICE: &str = "ai.nddev.nds.session.v2";

/// Explicit native backends. No global default store, mock or file fallback.
pub struct NativeSessionStore {
    key: String,
    owner: Arc<SessionOwner>,
}

struct SessionOwner {
    io: Arc<Semaphore>,
    operation: Arc<Semaphore>,
}
static OWNERS: OnceLock<Mutex<HashMap<String, Weak<SessionOwner>>>> = OnceLock::new();

impl NativeSessionStore {
    pub fn for_endpoint(endpoint: &str) -> Result<Self, ClientError> {
        let endpoint = crate::validate_endpoint(endpoint)?;
        let key = format!("{:x}", Sha256::digest(endpoint.as_str().as_bytes()));
        let mut owners = OWNERS
            .get_or_init(Mutex::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        owners.retain(|_, owner| owner.strong_count() > 0);
        let owner = if let Some(owner) = owners.get(&key).and_then(Weak::upgrade) {
            owner
        } else {
            if owners.len() >= 16 {
                return Err(ClientError::Busy);
            }
            let owner = Arc::new(SessionOwner {
                io: Arc::new(Semaphore::new(1)),
                operation: Arc::new(Semaphore::new(1)),
            });
            owners.insert(key.clone(), Arc::downgrade(&owner));
            owner
        };
        Ok(Self { key, owner })
    }

    pub(crate) fn operation(&self) -> Result<OwnedSemaphorePermit, ClientError> {
        let permit = self
            .owner
            .operation
            .clone()
            .try_acquire_owned()
            .map_err(|_| ClientError::Busy)?;
        if self.owner.io.available_permits() == 0 {
            return Err(ClientError::Busy);
        }
        Ok(permit)
    }

    async fn run<T: Send + 'static>(
        &self,
        event: &'static str,
        action: impl FnOnce(Entry) -> Result<T, ClientError> + Send + 'static,
    ) -> Result<T, ClientError> {
        let span = nddev_device_sync_telemetry::operation_span("accounts", "io")
            .map_err(|_| ClientError::TelemetryUnavailable)?;
        let permit = self
            .owner
            .io
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                span.in_scope(|| tracing::event!(target:"nds_accounts",tracing::Level::WARN, {
                    event.name="identity.credential.admission_rejected", error.type="busy", outcome="rejected"
                }));
                ClientError::Busy
            })?;
        let key = self.key.clone();
        let owner = self.owner.clone();
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let worker_span = span.clone();
        // The permit stays with the OS call even if its caller times out. Another
        // call cannot create an unbounded queue of non-preemptible native work.
        let work = tokio::task::spawn_blocking(move || {
            tracing::dispatcher::with_default(&dispatch, || {
                worker_span.in_scope(|| {
            let _permit = permit;
            let _owner = owner;
            let started = Instant::now();
            let result = (|| {
            let store = native_store().map_err(|_| ClientError::CredentialStore)?;
            #[cfg(target_os = "ios")]
            let modifiers = Some(HashMap::from([(
                "access-policy",
                "when-unlocked-this-device-only",
            )]));
            #[cfg(not(target_os = "ios"))]
            let modifiers = None;
            let entry = store
                .build(SERVICE, &key, modifiers.as_ref())
                .map_err(|_| ClientError::CredentialStore)?;
            action(entry)
            })();
            // This is the actual OS completion, including a late completion
            // after the waiting caller timed out or was cancelled. No key,
            // endpoint, value, presence flag or provider error text is emitted.
            match &result {
                Ok(_) => tracing::event!(target:"nds_accounts",tracing::Level::INFO, {
                    event.name=event, duration_ms=started.elapsed().as_millis() as u64, outcome="ok"
                }),
                Err(error) => tracing::event!(target:"nds_accounts",tracing::Level::WARN, {
                    event.name=event, duration_ms=started.elapsed().as_millis() as u64, error.type=error.code(), outcome="error"
                }),
            }
            result
        })
            })
        });
        match tokio::time::timeout(Duration::from_secs(15), work).await {
            Ok(Ok(result)) => result,
            failed => {
                let error = if failed.is_err() {
                    ClientError::Timeout
                } else {
                    ClientError::CredentialStore
                };
                span.in_scope(|| tracing::event!(target:"nds_accounts",tracing::Level::WARN, {
                    event.name="identity.credential.wait_failed", error.type=error.code(), outcome="error"
                }));
                Err(error)
            }
        }
    }

    pub async fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, ClientError> {
        self.run("identity.credential.read", |entry| {
            match entry.get_secret() {
                Ok(secret) => Ok(Some(Zeroizing::new(secret))),
                Err(keyring_core::Error::NoEntry) => Ok(None),
                Err(_) => Err(ClientError::CredentialStore),
            }
        })
        .await
    }
    pub async fn write(&self, value: &[u8]) -> Result<(), ClientError> {
        let value = Zeroizing::new(value.to_vec());
        self.run("identity.credential.write", move |entry| {
            entry
                .set_secret(&value)
                .map_err(|_| ClientError::CredentialStore)
        })
        .await
    }
    pub async fn delete(&self) -> Result<(), ClientError> {
        self.run("identity.credential.delete", |entry| {
            match entry.delete_credential() {
                Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
                Err(_) => Err(ClientError::CredentialStore),
            }
        })
        .await
    }
}

fn native_store() -> keyring_core::Result<Arc<CredentialStore>> {
    #[cfg(target_os = "linux")]
    {
        Ok(zbus_secret_service_keyring_store::Store::new()?)
    }
    #[cfg(target_os = "macos")]
    {
        Ok(apple_native_keyring_store::keychain::Store::new()?)
    }
    #[cfg(target_os = "ios")]
    {
        Ok(apple_native_keyring_store::protected::Store::new()?)
    }
    #[cfg(target_os = "windows")]
    {
        Ok(windows_native_keyring_store::Store::new()?)
    }
    #[cfg(target_os = "android")]
    {
        Ok(android_native_keyring_store::Store::new()?)
    }
}
