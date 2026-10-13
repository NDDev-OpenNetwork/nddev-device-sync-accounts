//! Protected last-known authorization. The domain owns scope/expiry; platform
//! adapters own secrets and the atomic generation pointer. Two fixed slots keep
//! the prior grant intact if a process dies while publishing its replacement.
use crate::{
    ClientError, IdentityClient, SessionCredential, View,
    store::{Fence, FenceMode},
    view::DeviceView,
    wire,
};
use nddev_device_sync_domain::{
    DeviceId, TenantId, UserId,
    identity::{CachedDeviceAuthorization, Owner},
};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cached {
    schema_version: u8,
    generation: String,
    authorization: CachedDeviceAuthorization,
    session: wire::Session,
    device: DeviceView,
    credential_fingerprint: Option<String>,
    server_version: String,
}

fn now_ms() -> Result<u64, ClientError> {
    (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .try_into()
        .map_err(|_| ClientError::RevalidationRequired)
}

impl SessionCredential {
    fn fingerprint(&self) -> Option<String> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            Self::Bearer(token) => {
                use sha2::{Digest, Sha256};
                Some(format!("{:x}", Sha256::digest(token.as_bytes())))
            }
            #[cfg(target_arch = "wasm32")]
            Self::BrowserCookie => None,
        }
    }
}

impl Cached {
    fn validate(
        &self,
        origin: &str,
        fence: &Fence,
        credential: &SessionCredential,
    ) -> Result<(), ClientError> {
        let owner = Owner {
            user_id: UserId::new(&self.session.user_id)
                .map_err(|_| ClientError::CredentialStore)?,
            tenant_id: TenantId::new(&self.session.tenant_id)
                .map_err(|_| ClientError::CredentialStore)?,
        };
        let device =
            DeviceId::new(&self.device.device_id).map_err(|_| ClientError::CredentialStore)?;
        let expires = OffsetDateTime::parse(&self.session.expires_at, &Rfc3339)
            .map_err(|_| ClientError::CredentialStore)?;
        if self.schema_version != 1
            || fence.mode != FenceMode::Ready
            || self.generation != fence.generation
            || !self.device.is_current
            || self.device.revoked
            || self.server_version.len() > 128
            || self.credential_fingerprint != credential.fingerprint()
            || expires.unix_timestamp_nanos() / 1_000_000
                < i128::from(self.authorization.expires_at_ms)
        {
            return Err(ClientError::RevalidationRequired);
        }
        self.authorization
            .authorize_offline(origin, &owner, &device, now_ms()?)
            .map_err(|_| ClientError::RevalidationRequired)
    }
}

impl IdentityClient {
    async fn cached(&self, credential: &SessionCredential) -> Result<Option<Cached>, ClientError> {
        let Some(fence) = self.store.authorization_fence(None).await? else {
            return Ok(None);
        };
        if fence.mode != FenceMode::Ready {
            if matches!(fence.mode, FenceMode::SignedOut | FenceMode::PendingLogout) {
                self.clear_session();
                self.state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .view
                    .logout_pending = fence.mode == FenceMode::PendingLogout;
            } else {
                self.require_revalidation();
            }
            return Ok(None);
        }
        let Some(secret) = self.store.offline_store(fence.slot).read().await? else {
            return Ok(None);
        };
        if secret.len() > 8192 {
            return Err(ClientError::CredentialStore);
        }
        let cached: Cached =
            serde_json::from_slice(&secret).map_err(|_| ClientError::CredentialStore)?;
        cached.validate(&self.origin(), &fence, credential)?;
        // A sign-out/revocation or slot publication may race a protected-store
        // read. Do not publish a decision from a superseded metadata generation.
        if self.store.authorization_fence(None).await? != Some(fence) {
            return Err(ClientError::Busy);
        }
        Ok(Some(cached))
    }

    pub(crate) async fn persist_offline_authorization(&self) {
        let view = self.view();
        if !view.authenticated
            || !view.session_verified
            || !view
                .devices
                .iter()
                .any(|device| device.is_current && !device.revoked)
        {
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .view
                .offline_cache_ready = false;
            return;
        }
        let result = self.persist_offline_inner().await;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .view
            .offline_cache_ready = result.is_ok();
        if let Err(error) = result {
            tracing::event!(target:"nds_accounts",tracing::Level::WARN, {event.name="identity.offline.persistence_failed",error.type=error.code(),outcome="error"});
        }
        // Device/session verification has already completed. A failure to cache
        // it is an offline-readiness failure, not a failed remote mutation.
    }

    async fn persist_offline_inner(&self) -> Result<(), ClientError> {
        let view = self.view();
        if !view.authenticated || !view.session_verified || view.credential_revalidation_required {
            return Err(ClientError::RevalidationRequired);
        }
        let device = view
            .devices
            .iter()
            .find(|d| d.is_current && !d.revoked)
            .cloned()
            .ok_or(ClientError::RevalidationRequired)?;
        let credential = self.session_credential().await?;
        let old = self.store.authorization_fence(None).await?;
        let mut next = Fence::new(FenceMode::Ready)?;
        next.slot = old.as_ref().map_or(0, |v| 1 - v.slot);
        let expires = OffsetDateTime::parse(&view.expires_at, &Rfc3339)
            .map_err(|_| ClientError::InvalidResponse)?;
        let verified_at_ms = now_ms()?;
        let remote_expiry: u64 = (expires.unix_timestamp_nanos() / 1_000_000)
            .try_into()
            .map_err(|_| ClientError::InvalidResponse)?;
        let offline_expiry = remote_expiry.min(
            verified_at_ms.saturating_add(nddev_device_sync_domain::identity::SESSION_LIFETIME_MS),
        );
        let cached = Cached {
            schema_version: 1,
            generation: next.generation.clone(),
            authorization: CachedDeviceAuthorization {
                origin: self.origin(),
                user_id: UserId::new(&view.user_id).map_err(|_| ClientError::InvalidResponse)?,
                tenant_id: TenantId::new(&view.tenant_id)
                    .map_err(|_| ClientError::InvalidResponse)?,
                device_id: DeviceId::new(&device.device_id)
                    .map_err(|_| ClientError::InvalidResponse)?,
                verified_at_ms,
                expires_at_ms: offline_expiry,
            },
            session: wire::Session {
                user_id: view.user_id,
                tenant_id: view.tenant_id,
                expires_at: view.expires_at,
                auth_method: match view.auth_method.as_str() {
                    "email_otp" => wire::AuthMethod::EmailOtp,
                    "github" => wire::AuthMethod::Github,
                    "passkey" => wire::AuthMethod::Passkey,
                    _ => return Err(ClientError::InvalidResponse),
                },
            },
            device,
            credential_fingerprint: credential.fingerprint(),
            server_version: view.server_version,
        };
        cached.validate(&self.origin(), &next, &credential)?;
        let bytes =
            Zeroizing::new(serde_json::to_vec(&cached).map_err(|_| ClientError::CredentialStore)?);
        if bytes.len() > 8192 {
            return Err(ClientError::CredentialStore);
        }
        self.store.offline_store(next.slot).write(&bytes).await?;
        self.store.authorization_fence(Some((old, next))).await?;
        tracing::event!(target:"nds_accounts",tracing::Level::INFO, {event.name="identity.offline.prepared",outcome="ok"});
        Ok(())
    }

    pub(crate) async fn restore_offline(
        &self,
        cancel: &CancellationToken,
    ) -> Result<Option<View>, ClientError> {
        let Some(credential) = self.stored_session_credential().await? else {
            return Ok(None);
        };
        let Some(cached) = self.cached(&credential).await? else {
            return Ok(None);
        };
        if cancel.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        let deadline = crate::validate_session(&cached.session)?;
        let remaining = cached
            .authorization
            .expires_at_ms
            .checked_sub(now_ms()?)
            .ok_or(ClientError::RevalidationRequired)?;
        let deadline =
            deadline.min(crate::Instant::now() + std::time::Duration::from_millis(remaining));
        let checked = i64::try_from(cached.authorization.verified_at_ms / 1000)
            .map_err(|_| ClientError::CredentialStore)?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.session_deadline = Some(deadline);
        state.view.authenticated = true;
        state.view.session_verified = false;
        state.view.offline_authorized = true;
        state.view.offline_cache_ready = true;
        state.view.credential_store_ready = true;
        state.view.credential_revalidation_required = false;
        state.view.session_checked_at = checked;
        state.view.devices_checked_at = checked;
        state.view.current_device_id = cached.device.device_id.clone();
        state.view.devices = vec![cached.device];
        state.view.server_version = cached.server_version;
        state.view.user_id = cached.session.user_id;
        state.view.tenant_id = cached.session.tenant_id;
        state.view.expires_at = cached.session.expires_at;
        state.view.auth_method = match cached.session.auth_method {
            wire::AuthMethod::EmailOtp => "email_otp",
            wire::AuthMethod::Github => "github",
            wire::AuthMethod::Passkey => "passkey",
        }
        .into();
        drop(state);
        tracing::event!(target:"nds_accounts",tracing::Level::INFO, {event.name="identity.offline.restored",outcome="ok"});
        Ok(Some(self.view()))
    }

    pub(crate) async fn invalidate_offline(&self, mode: FenceMode) -> Result<(), ClientError> {
        let old = self.store.authorization_fence(None).await?;
        self.store
            .authorization_fence(Some((old, Fence::new(mode)?)))
            .await?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.view.offline_authorized = false;
        state.view.offline_cache_ready = false;
        Ok(())
    }

    /// Local key/replica consumers must consult the durable shared decision,
    /// including a sign-out completed by another process or browser tab.
    pub async fn authorize_local(&self) -> Result<(), ClientError> {
        let credential = self.session_credential().await?;
        let cached = self
            .cached(&credential)
            .await?
            .ok_or(ClientError::RevalidationRequired)?;
        let view = self.view();
        if !view.authenticated
            || view.credential_revalidation_required
            || view.user_id != cached.session.user_id
            || view.tenant_id != cached.session.tenant_id
            || view.current_device_id != cached.device.device_id
            || !view
                .devices
                .iter()
                .any(|device| device.is_current && !device.revoked)
        {
            self.require_revalidation();
            return Err(ClientError::RevalidationRequired);
        }
        Ok(())
    }

    pub(crate) async fn finish_pending_logout(
        &self,
        cancel: &CancellationToken,
    ) -> Result<bool, ClientError> {
        let fence = self.store.authorization_fence(None).await?;
        if !fence
            .as_ref()
            .is_some_and(|f| matches!(f.mode, FenceMode::PendingLogout | FenceMode::SignedOut))
        {
            return Ok(false);
        }
        self.clear_session();
        if fence.is_some_and(|f| f.mode == FenceMode::SignedOut) {
            // The remote logout is already acknowledged. Preserve an explicit
            // new sign-in flow and never emit another DELETE/generation change.
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.view.logout_pending = false;
            state.view.credential_store_ready = true;
            return Ok(true);
        }
        self.clear_flow();
        #[cfg(target_arch = "wasm32")]
        self.store.clear_browser_access().await?;
        #[cfg(not(target_arch = "wasm32"))]
        for slot in 0..2 {
            self.store.offline_store(slot).delete().await?;
        }
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .view
            .logout_pending = true;
        if let Some(credential) = self.stored_session_credential().await? {
            match self
                .request::<()>(
                    http::Method::DELETE,
                    "/v2/session",
                    None,
                    Some(&credential),
                    "en",
                    cancel,
                )
                .await
            {
                Ok((http::StatusCode::NO_CONTENT, _)) => {}
                Err(ClientError::Server(code)) if code == "authentication_failed" => {}
                Err(error) => return Err(error),
                _ => return Err(ClientError::InvalidResponse),
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        self.store.delete().await?;
        // Keep the local signed-out decision until an explicit successful new
        // sign-in. A delayed ambient cookie must not silently restore access.
        self.invalidate_offline(FenceMode::SignedOut).await?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .view
            .logout_pending = false;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .view
            .credential_store_ready = true;
        tracing::event!(target:"nds_accounts",tracing::Level::INFO,{event.name="identity.remote_logout.completed",outcome="ok"});
        Ok(true)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod acceptance {
    use super::*;
    use futures::FutureExt;
    use nddev_device_sync_telemetry::{Config, ExportFeed, client_traces::ClientTraces};
    use opentelemetry_proto::tonic::{
        collector::trace::v1::ExportTraceServiceRequest, common::v1::any_value, trace::v1::Span,
    };
    use prost::Message;
    use serde_json::Value;
    use std::{path::PathBuf, time::Duration};
    use tracing::instrument::WithSubscriber;

    fn process_spans(feed: &ExportFeed) -> Vec<Span> {
        let mut spans = Vec::new();
        while let Some(batch) = feed.take_batch() {
            let decoded = ExportTraceServiceRequest::decode(batch.bytes()).unwrap();
            spans.extend(
                decoded
                    .resource_spans
                    .into_iter()
                    .flat_map(|resource| resource.scope_spans)
                    .flat_map(|scope| scope.spans)
                    .filter(|span| {
                        span.attributes.iter().any(|field| {
                            field.key == "scope"
                                && field.value.as_ref().and_then(|v| v.value.as_ref())
                                    == Some(&any_value::Value::StringValue("process".into()))
                        })
                    }),
            );
            batch.acknowledge();
        }
        spans
    }

    fn assert_recovered_operation(feed: &ExportFeed) {
        let spans = process_spans(feed);
        assert_eq!(spans.len(), 1);
        let status = spans[0].status.as_ref().unwrap();
        assert_eq!(
            status.code, 0,
            "handled network failure is not terminal failure"
        );
        assert!(status.message.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires an owned controllable PostgreSQL/Mailpit fixture, private state root and real unlocked keyring"]
    async fn actual_offline_recreation_preserves_authorization_and_sign_out() {
        let receipt = PathBuf::from(std::env::var("NDS_FIXTURE_RECEIPT").unwrap());
        let data: Value = serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
        let endpoint = data["base_url"].as_str().unwrap();
        let mailbox = data["mailpit_url"].as_str().unwrap();
        let owner = data["owner_email"].as_str().unwrap();
        assert!(
            (endpoint.starts_with("http://127.0.0.1:")
                || endpoint.starts_with("http://localhost:"))
                && mailbox.starts_with("http://127.0.0.1:")
        );
        assert!(owner.ends_with(".invalid"));
        let control = receipt.with_extension("control.json");
        assert_eq!(
            data["control_file"].as_str().unwrap(),
            control.to_str().unwrap()
        );
        assert!(!control.exists());
        let client = IdentityClient::new(endpoint).unwrap();
        assert!(client.store.read().await.unwrap().is_none());
        let config = Config {
            service: "nddev-device-sync-client".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            repository: "NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-desktop".into(),
            commit: "unknown".into(),
            channel: "alpha".into(),
            standards: "unreleased".into(),
            environment: "test".into(),
            target_prefixes: vec!["nds_accounts".into()],
            default_module: "accounts".into(),
            debug: None,
        };
        let traces = ClientTraces::new(&config).unwrap();
        let feed = traces.subscribe().unwrap();
        let (subscriber, _) =
            nddev_device_sync_telemetry::subscriber(config, std::io::sink(), traces.tracer())
                .unwrap();
        let mut owned_device = None;
        let result = std::panic::AssertUnwindSafe(async {
            client.refresh().await.unwrap();
            client.request_email(owner.into(), "en").await.unwrap();
            let http = reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap();
            let code = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let messages: Value = http
                        .get(format!("{mailbox}/api/v1/messages"))
                        .send()
                        .await
                        .unwrap()
                        .json()
                        .await
                        .unwrap();
                    if let Some(id) = messages["messages"]
                        .as_array()
                        .and_then(|m| m.first())
                        .and_then(|m| m["ID"].as_str())
                    {
                        let message: Value = http
                            .get(format!("{mailbox}/api/v1/message/{id}"))
                            .send()
                            .await
                            .unwrap()
                            .json()
                            .await
                            .unwrap();
                        if let Some((_, code)) =
                            message["Text"].as_str().unwrap().split_once("code: ")
                        {
                            break code.chars().take(8).collect::<String>();
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .unwrap();
            client.verify_email(code).await.unwrap();
            let device_store = client.device_store().unwrap();
            assert!(device_store.read().await.unwrap().is_none());
            owned_device = Some(device_store);
            let enrolled = client
                .prepare_device("Owned offline acceptance".into())
                .await
                .unwrap();
            assert!(
                enrolled.offline_cache_ready
                    && enrolled.session_verified
                    && !enrolled.offline_authorized
            );
            let refreshed = client.refresh().await.unwrap();
            assert_eq!(refreshed.current_device_id, enrolled.current_device_id);
            assert_eq!(refreshed.devices_checked_at, enrolled.devices_checked_at);
            client.authorize_local().await.unwrap();
            let key = client
                .device_store()
                .unwrap()
                .read()
                .await
                .unwrap()
                .unwrap();
            set_mode(&receipt, &control, "offline").await;
            let recreated = IdentityClient::new(endpoint).unwrap();
            process_spans(&feed);
            let offline = recreated.refresh().await.unwrap();
            assert_recovered_operation(&feed);
            assert!(
                offline.authenticated && offline.offline_authorized && !offline.session_verified
            );
            assert_eq!(offline.current_device_id, enrolled.current_device_id);
            assert_eq!(offline.expires_at, enrolled.expires_at);
            assert!(offline.session_checked_at <= OffsetDateTime::now_utc().unix_timestamp());
            recreated.authorize_local().await.unwrap();
            process_spans(&feed);
            let signed_out = recreated.logout().await.unwrap();
            assert_recovered_operation(&feed);
            assert!(!signed_out.authenticated && signed_out.logout_pending);
            assert!(
                client.authorize_local().await.is_err(),
                "another client retained local access after logout"
            );
            assert!(matches!(
                client
                    .sync_request(crate::SyncRequest::Page { after: 0, limit: 1 })
                    .await,
                Err(ClientError::RevalidationRequired)
            ));
            let closed = IdentityClient::new(endpoint).unwrap();
            assert!(closed.refresh().await.is_err());
            assert!(!closed.view().authenticated);
            set_mode(&receipt, &control, "online").await;
            let after = closed.refresh().await.unwrap();
            assert!(!after.authenticated && !after.logout_pending && after.credential_store_ready);
            assert!(closed.store.read().await.unwrap().is_none());
            let acknowledged = closed.store.authorization_fence(None).await.unwrap();
            closed.refresh().await.unwrap();
            assert!(
                closed.store.authorization_fence(None).await.unwrap() == acknowledged,
                "an acknowledged logout must not create another durable decision"
            );
            let device_store = client
                .store
                .device_store(&enrolled.tenant_id, &enrolled.user_id);
            assert_eq!(
                device_store.read().await.unwrap().unwrap().as_slice(),
                key.as_slice()
            );
        })
        .catch_unwind()
        .with_subscriber(tracing::Dispatch::new(subscriber))
        .await;
        // The fixture and every native entry are explicitly owned. Cleanup is
        // also attempted after assertion failure, without touching real scopes.
        client.store.delete().await.unwrap();
        if let Some(store) = owned_device {
            store.delete().await.unwrap();
        }
        set_mode(&receipt, &control, "online").await;
        for slot in 0..2 {
            client.store.offline_store(slot).delete().await.unwrap();
        }
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    async fn set_mode(receipt: &std::path::Path, control: &std::path::Path, mode: &str) {
        std::fs::write(
            control,
            serde_json::to_vec(&serde_json::json!({"mode":mode})).unwrap(),
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let state = std::fs::read(receipt)
                    .ok()
                    .and_then(|data| serde_json::from_slice::<Value>(&data).ok());
                if !control.exists()
                    && state.as_ref().is_some_and(|s| {
                        s["status"]
                            == if mode == "online" {
                                "running"
                            } else {
                                "offline"
                            }
                    })
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
    }
}
