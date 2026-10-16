use crate::ClientError;
#[cfg(not(target_arch = "wasm32"))]
use keyring_core::{CredentialStore, Entry};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock, Weak},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

#[cfg(not(target_arch = "wasm32"))]
use std::time::{Duration, Instant};
#[cfg(target_arch = "wasm32")]
mod browser;
mod fence;
pub(crate) use fence::{Fence, FenceMode};
mod admission;
pub(crate) use admission::OperationPermit;
pub(crate) use admission::RdsLease;

const SERVICE: &str = "ai.nddev.nds.session.v2";

/// Explicit platform credential backends; no plaintext or metadata fallback.
#[derive(Clone)]
pub struct SessionStore {
    service: &'static str,
    key: String,
    owner: Arc<SessionOwner>,
}

struct SessionOwner {
    io: Arc<Semaphore>,
    operation: Arc<Semaphore>,
    lease: Mutex<Weak<admission::Lease>>,
    // A Linux provider owns a D-Bus connection and encryption session, not
    // cached credential values. Its lifetime follows this bounded endpoint owner.
    #[cfg(target_os = "linux")]
    backend: Mutex<Option<Arc<CredentialStore>>>,
}

#[cfg(target_os = "linux")]
impl SessionOwner {
    fn native_backend(&self) -> keyring_core::Result<Arc<CredentialStore>> {
        if let Some(store) = self
            .backend
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Ok(store);
        }
        // The existing I/O permit serializes creation. Never hold this mutex
        // across OS I/O, including when the waiting caller has timed out.
        let store = native_store()?;
        *self.backend.lock().unwrap_or_else(|e| e.into_inner()) = Some(store.clone());
        Ok(store)
    }

    fn discard_backend(&self) {
        self.backend
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
    }
}

#[cfg(target_os = "linux")]
struct BackendCall<'a>(&'a SessionOwner);

#[cfg(target_os = "linux")]
impl Drop for BackendCall<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Still under the OS I/O permit: an older panic cannot discard a
            // newer caller's connection after its own permit has been released.
            self.0.discard_backend();
        }
    }
}
static OWNERS: OnceLock<Mutex<HashMap<String, Weak<SessionOwner>>>> = OnceLock::new();

impl SessionStore {
    pub fn for_endpoint(endpoint: &str) -> Result<Self, ClientError> {
        let endpoint = crate::validate_endpoint(endpoint)?;
        let key = base16ct::lower::encode_string(&Sha256::digest(endpoint.as_str().as_bytes()));
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
                lease: Mutex::default(),
                #[cfg(target_os = "linux")]
                backend: Mutex::default(),
            });
            owners.insert(key.clone(), Arc::downgrade(&owner));
            owner
        };
        Ok(Self {
            service: SERVICE,
            key,
            owner,
        })
    }

    /// A separate credential namespace with the same endpoint admission budget.
    /// Signing keys survive logout and revocation; never delete them as compensation.
    pub(crate) fn device_store(&self, tenant: &str, user: &str) -> Self {
        let mut digest = Sha256::new();
        for value in [&self.key, tenant, user] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        Self {
            service: "ai.nddev.nds.device.v2",
            key: base16ct::lower::encode_string(&digest.finalize()),
            owner: self.owner.clone(),
        }
    }

    pub(crate) fn vault_store(&self, tenant: &str, user: &str) -> Self {
        let mut store = self.device_store(tenant, user);
        store.service = "ai.nddev.nds.vault.v1";
        store
    }

    pub(crate) fn rds_store(&self, tenant: &str, user: &str, device: &str) -> Self {
        let mut digest = Sha256::new();
        for value in ["rds.v1", &self.key, tenant, user, device] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        Self {
            service: "ai.nddev.nds.rds.v1",
            key: base16ct::lower::encode_string(&digest.finalize()),
            owner: self.owner.clone(),
        }
    }

    pub(crate) fn offline_store(&self, slot: u8) -> Self {
        let mut store = self.clone();
        store.service = "ai.nddev.nds.offline.v1";
        store.key =
            base16ct::lower::encode_string(&Sha256::digest(format!("{}:offline:{slot}", self.key)));
        store
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

    #[cfg(not(target_arch = "wasm32"))]
    async fn run_io<T: Send + 'static>(
        &self,
        event: &'static str,
        action: impl FnOnce(&'static str, &str) -> Result<T, ClientError> + Send + 'static,
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
        let service = self.service;
        let owner = self.owner.clone();
        let lease = owner
            .lease
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .upgrade();
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let worker_span = span.clone();
        // The permit stays with the OS call even if its caller times out. Another
        // call cannot create an unbounded queue of non-preemptible native work.
        let work = tokio::task::spawn_blocking(move || {
            tracing::dispatcher::with_default(&dispatch, || {
                worker_span.in_scope(|| {
            let _permit = permit;
            let _owner = owner;
            let _lease = lease;
            let started = Instant::now();
                    tracing::event!(target:"nds_accounts",tracing::Level::DEBUG, {
                        event.name=event, outcome="started"
                    });
            let result = action(service, &key);
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

    #[cfg(not(target_arch = "wasm32"))]
    async fn run<T: Send + 'static>(
        &self,
        event: &'static str,
        action: impl FnOnce(Entry) -> Result<T, ClientError> + Send + 'static,
    ) -> Result<T, ClientError> {
        #[cfg(target_os = "linux")]
        let owner = self.owner.clone();
        self.run_io(event, move |service, key| {
            #[cfg(target_os = "linux")]
            let _call = BackendCall(&owner);
            #[cfg(target_os = "linux")]
            let store = owner
                .native_backend()
                .map_err(|_| ClientError::CredentialStore)?;
            #[cfg(not(target_os = "linux"))]
            let store = native_store().map_err(|_| ClientError::CredentialStore)?;
            #[cfg(target_os = "ios")]
            let modifiers = Some(HashMap::from([(
                "access-policy",
                "when-unlocked-this-device-only",
            )]));
            #[cfg(not(target_os = "ios"))]
            let modifiers = None;
            let result = (|| {
                let entry = store
                    .build(service, key, modifiers.as_ref())
                    .map_err(|_| ClientError::CredentialStore)?;
                action(entry)
            })();
            #[cfg(target_os = "linux")]
            if result.is_err() {
                // Reconnect on the next admitted call; never retry a write
                // whose OS outcome may already have happened.
                owner.discard_backend();
            }
            result
        })
        .await
    }

    #[cfg(not(target_arch = "wasm32"))]
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
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn write(&self, value: &[u8]) -> Result<(), ClientError> {
        let value = Zeroizing::new(value.to_vec());
        self.run("identity.credential.write", move |entry| {
            entry
                .set_secret(&value)
                .map_err(|_| ClientError::CredentialStore)
        })
        .await
    }
    #[cfg(not(target_arch = "wasm32"))]
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

#[cfg(not(target_arch = "wasm32"))]
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

#[cfg(test)]
mod compatibility_tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires an actual unlocked native credential service; owns one fresh entry"]
    async fn reused_connection_reads_external_updates_and_deletion() {
        let scope = format!("https://nds-native-{}.invalid/", uuid::Uuid::new_v4());
        let store = SessionStore::for_endpoint(&scope).unwrap();
        assert!(store.read().await.unwrap().is_none());
        let first = Zeroizing::new(uuid::Uuid::new_v4().to_string());
        let second = Zeroizing::new(uuid::Uuid::new_v4().to_string());
        let service = store.service;
        let key = store.key.clone();
        let replacement = second.clone();
        let outcome = async {
            store.write(first.as_bytes()).await?;
            // A separate real provider connection changes the entry without
            // touching this SessionOwner or any client-side value cache.
            let other = tokio::task::spawn_blocking(move || {
                let other = native_store().map_err(|_| ClientError::CredentialStore)?;
                other
                    .build(service, &key, None)
                    .and_then(|entry| entry.set_secret(replacement.as_bytes()))
                    .map_err(|_| ClientError::CredentialStore)?;
                Ok::<_, ClientError>((other, key))
            })
            .await
            .map_err(|_| ClientError::CredentialStore)??;
            let updated = store
                .read()
                .await?
                .is_some_and(|value| value.as_slice() == second.as_bytes());
            tokio::task::spawn_blocking(move || {
                other
                    .0
                    .build(service, &other.1, None)
                    .and_then(|entry| entry.delete_credential())
                    .map_err(|_| ClientError::CredentialStore)
            })
            .await
            .map_err(|_| ClientError::CredentialStore)??;
            let absent = store.read().await?.is_none();
            Ok::<_, ClientError>((updated, absent))
        }
        .await;
        let cleaned = store.delete().await;
        cleaned.unwrap();
        assert_eq!(outcome.unwrap(), (true, true));
    }

    #[test]
    fn credential_names_preserve_the_existing_sha256_hex_encoding() {
        let store = SessionStore::for_endpoint("https://example.invalid/").unwrap();
        assert_eq!(
            store.key,
            "d8c0a7de34ba33bbd330fd412f87b2550e3947349c8717827335df10c0557fbd"
        );
        assert_eq!(
            store.device_store("tenant", "user").key,
            "8534cc9087ec67322196e2b2478ff5c3d7e6090947002234b5f1b9e08fee1707"
        );
        assert_eq!(
            store.rds_store("tenant", "user", "device").key,
            "cd30eea48d9f2c4ccca7c95e7877cd67f282d70be5067ebae7a50aad875e48e1"
        );
        assert_eq!(
            store.offline_store(0).key,
            "3c5cae1397461791a6dfc97fdba1adb907b627e2801fe0b43009ce080af16546"
        );
    }
}
