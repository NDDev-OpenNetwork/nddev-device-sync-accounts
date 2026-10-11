use crate::{ClientError, IdentityClient, WireRequest};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signer;
use nddev_device_sync_http_signatures as signatures;
use reqwest::Method;
use ring::rand::{SecureRandom, SystemRandom};

/// A compiled-in route set, never an arbitrary URL or authenticated HTTP proxy.
pub enum SyncRequest {
    Append(Vec<u8>),
    Page {
        after: u64,
        limit: u16,
    },
    VaultKey(Vec<u8>),
    Telemetry(Vec<u8>),
    NativeTraces(Vec<u8>),
    ObservabilityStatus,
    Incidents {
        after: String,
    },
    IncidentAction {
        id: String,
        silence: bool,
        body: Vec<u8>,
    },
}
pub struct SyncReply {
    pub status: u16,
    pub body: Vec<u8>,
}
struct Key {
    key: ed25519_dalek::SigningKey,
    id: String,
}
impl signatures::SigningKey for Key {
    fn key_id(&self) -> String {
        self.id.clone()
    }
    fn alg(&self) -> signatures::AlgorithmName {
        signatures::AlgorithmName::Ed25519
    }
    fn sign(&self, data: &[u8]) -> signatures::HttpSigResult<Vec<u8>> {
        Ok(self.key.sign(data).to_bytes().to_vec())
    }
}
impl IdentityClient {
    /// Native consumers only. This namespace never appears in the FFI surface;
    /// vault keys survive sign-out and are separate from device signing keys.
    pub fn vault_credentials(&self) -> Result<crate::NativeSessionStore, ClientError> {
        self.device_store()?;
        let view = self.view();
        Ok(self.store.vault_store(&view.tenant_id, &view.user_id))
    }
    pub async fn sync_request(&self, request: SyncRequest) -> Result<SyncReply, ClientError> {
        use tracing::Instrument;
        if matches!(
            &request,
            SyncRequest::Telemetry(_)
                | SyncRequest::NativeTraces(_)
                | SyncRequest::ObservabilityStatus
                | SyncRequest::Incidents { .. }
                | SyncRequest::IncidentAction { .. }
        ) {
            self.signed_request(request)
                .instrument(nddev_device_sync_telemetry::delivery_span())
                .await
        } else {
            self.signed_request(request).await
        }
    }
    async fn signed_request(&self, request: SyncRequest) -> Result<SyncReply, ClientError> {
        let (_permit, cancel) = self.operation()?;
        let store = self.device_store()?;
        let view = self.view();
        let current = view
            .devices
            .iter()
            .find(|device| device.is_current)
            .ok_or(ClientError::RevalidationRequired)?;
        if current.revoked {
            return Err(ClientError::DeviceRevoked);
        }
        let key = Key {
            key: crate::devices::read_key(&store)
                .await?
                .ok_or(ClientError::RevalidationRequired)?,
            id: current.device_id.clone(),
        };
        let token = self.session_token().await?;
        let (method, path, body) = match request {
            SyncRequest::Telemetry(body) => {
                if body.is_empty() || body.len() > 65_536 {
                    return Err(ClientError::InvalidInput);
                }
                (Method::POST, "/v2/observability/events".into(), Some(body))
            }
            SyncRequest::NativeTraces(body) => {
                if body.is_empty() || body.len() > 65_536 {
                    return Err(ClientError::InvalidInput);
                }
                (Method::POST, "/v2/observability/traces".into(), Some(body))
            }
            SyncRequest::ObservabilityStatus => {
                (Method::GET, "/v2/observability/status".into(), None)
            }
            SyncRequest::Incidents { after } => {
                if after.len() > 128 || !after.is_empty() && !crate::valid_id(&after) {
                    return Err(ClientError::InvalidInput);
                }
                (
                    Method::GET,
                    format!("/v2/observability/incidents?after={after}"),
                    None,
                )
            }
            SyncRequest::IncidentAction { id, silence, body } => {
                if !crate::valid_id(&id) || body.len() > 1024 {
                    return Err(ClientError::InvalidInput);
                }
                let action = if silence { "silence" } else { "acknowledge" };
                (
                    Method::POST,
                    format!("/v2/observability/incidents/{id}/{action}"),
                    Some(body),
                )
            }
            SyncRequest::VaultKey(body) => {
                if body.len() > 1024 {
                    return Err(ClientError::InvalidInput);
                }
                (Method::POST, "/v2/vault/key".into(), Some(body))
            }
            SyncRequest::Append(body) => {
                if body.len() > nddev_device_sync_domain::sync::MAX_OPERATION_BYTES {
                    return Err(ClientError::InvalidInput);
                }
                (Method::POST, "/v2/sync/operations".into(), Some(body))
            }
            SyncRequest::Page { after, limit } => {
                if after > nddev_device_sync_domain::sync::MAX_REVISION
                    || !(1..=100).contains(&limit)
                {
                    return Err(ClientError::InvalidInput);
                }
                (
                    Method::GET,
                    format!("/v2/sync/operations?after_seq={after}&limit={limit}"),
                    None,
                )
            }
        };
        let target = self
            .endpoint
            .join(&path)
            .map_err(|_| ClientError::InvalidEndpoint)?;
        let mut nonce = [0; 24];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| ClientError::CredentialStore)?;
        let now = time::OffsetDateTime::now_utc()
            .unix_timestamp()
            .try_into()
            .map_err(|_| ClientError::InvalidInput)?;
        let signature = signatures::sign(
            method.as_str(),
            target.as_str(),
            body.as_deref().unwrap_or_default(),
            &key,
            &URL_SAFE_NO_PAD.encode(nonce),
            now,
        )
        .map_err(|_| ClientError::InvalidInput)?;
        let (status, body) = self
            .request_bytes(
                WireRequest {
                    method,
                    path: &path,
                    body,
                    token: Some(&token),
                    locale: "en",
                    signature: Some(signature),
                },
                &cancel,
            )
            .await?;
        Ok(SyncReply {
            status: status.as_u16(),
            body,
        })
    }

    /// Privileged native provisioning only. Root keys never enter View or FFI.
    pub async fn ensure_vault_key(
        &self,
        existing: Option<&nddev_device_sync_domain::vault::KeyMaterial>,
    ) -> Result<nddev_device_sync_domain::vault::KeyMaterial, ClientError> {
        use zeroize::{Zeroize, Zeroizing};
        let mut request = crate::vault_wire::VaultKeyRequest {
            existing_key: existing.map(|key| crate::vault_wire::VaultKey {
                key_id: key.id(),
                key_material: URL_SAFE_NO_PAD.encode(key.expose()),
            }),
        };
        let body = serde_json::to_vec(&request).map_err(|_| ClientError::InvalidInput);
        if let Some(key) = &mut request.existing_key {
            key.key_material.zeroize();
        }
        let reply = self.sync_request(SyncRequest::VaultKey(body?)).await?;
        let bytes = Zeroizing::new(reply.body);
        if bytes.len() > 1024 {
            return Err(ClientError::InvalidResponse);
        }
        let status = reply.status;
        let reply: crate::vault_wire::VaultKey =
            serde_json::from_slice(&bytes).map_err(|_| ClientError::InvalidResponse)?;
        let encoded = Zeroizing::new(reply.key_material);
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded.as_bytes())
                .map_err(|_| ClientError::InvalidResponse)?,
        );
        let key = nddev_device_sync_domain::vault::KeyMaterial::new(bytes.as_slice())
            .map_err(|_| ClientError::InvalidResponse)?;
        if status != 200
            || encoded.len() != 64
            || URL_SAFE_NO_PAD.encode(bytes.as_slice()) != encoded.as_str()
            || key.id() != reply.key_id
        {
            return Err(ClientError::InvalidResponse);
        }
        Ok(key)
    }
}
