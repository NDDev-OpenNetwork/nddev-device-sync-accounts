use crate::{ClientError, IdentityClient, WireRequest};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signer;
use nddev_device_sync_http_signatures as signatures;
use reqwest::Method;
use ring::rand::{SecureRandom, SystemRandom};

/// A compiled-in route set, never an arbitrary URL or authenticated HTTP proxy.
pub enum SyncRequest {
    Append(Vec<u8>),
    Page { after: u64, limit: u16 },
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
}
