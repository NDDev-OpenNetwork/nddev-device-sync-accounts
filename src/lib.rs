//! NDS identity HTTP client. Secrets stay in Rust and native credential stores.
pub mod device_wire;
mod sync;
pub mod sync_wire;
pub mod vault_wire;
pub use sync::{SyncReply, SyncRequest};
mod devices;
pub mod health_wire;
mod store;
pub mod wire;
pub use store::NativeSessionStore;
#[cfg(target_os = "android")]
pub mod android;

use opentelemetry::propagation::TextMapPropagator;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use reqwest::{Method, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use url::{Host, Url};
use zeroize::Zeroizing;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_BODY: usize = 65_536;

pub mod view;
pub use view::{ClientError, View};

struct WireRequest<'a> {
    method: Method,
    path: &'a str,
    body: Option<Vec<u8>>,
    token: Option<&'a str>,
    locale: &'a str,
    signature: Option<nddev_device_sync_http_signatures::Headers>,
}

enum Flow {
    Email {
        id: String,
        expires: Instant,
        resend: Instant,
    },
    Github {
        id: String,
        token: Zeroizing<String>,
        expires: Instant,
        next_poll: Instant,
    },
}

#[derive(Default)]
struct State {
    view: View,
    flow: Option<Flow>,
    session_deadline: Option<Instant>,
}

/// One bounded operation per client; concurrent calls fail instead of queuing.
pub struct IdentityClient {
    endpoint: Url,
    http: reqwest::Client,
    store: NativeSessionStore,
    state: Mutex<State>,
    cancellation: Mutex<CancellationToken>,
}

impl IdentityClient {
    pub fn origin(&self) -> String {
        self.endpoint.as_str().into()
    }
    pub fn new(endpoint: &str) -> Result<Self, ClientError> {
        let endpoint = validate_endpoint(endpoint)?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(1);
        if endpoint.scheme() == "http" {
            builder = builder.no_proxy();
        }
        let http = builder.build().map_err(|_| ClientError::Transport)?;
        Ok(Self {
            store: NativeSessionStore::for_endpoint(endpoint.as_str())?,
            endpoint,
            http,
            state: Mutex::new(State::default()),
            cancellation: Mutex::new(CancellationToken::new()),
        })
    }

    pub fn cancel(&self) {
        self.cancellation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cancel();
    }

    pub fn view(&self) -> View {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        expire_session(&mut state, now, OffsetDateTime::now_utc());
        if state.flow.as_ref().is_some_and(|flow| match flow {
            Flow::Email { expires, .. } | Flow::Github { expires, .. } => *expires <= now,
        }) {
            clear_flow_state(&mut state);
        }
        let mut view = state.view.clone();
        if let Some(flow) = &state.flow {
            let (expires, retry) = match flow {
                Flow::Email {
                    expires, resend, ..
                } => (*expires, *resend),
                Flow::Github {
                    expires, next_poll, ..
                } => (*expires, *next_poll),
            };
            view.expires_in_seconds = remaining(expires);
            view.retry_after_seconds = remaining(retry);
        }
        view
    }

    fn operation(&self) -> Result<(OwnedSemaphorePermit, CancellationToken), ClientError> {
        let permit = self.store.operation()?;
        let token = CancellationToken::new();
        *self.cancellation.lock().unwrap_or_else(|e| e.into_inner()) = token.clone();
        Ok((permit, token))
    }

    async fn observe(
        &self,
        event: &'static str,
        operation: impl std::future::Future<Output = Result<View, ClientError>>,
    ) -> Result<View, ClientError> {
        let span = nddev_device_sync_telemetry::operation_span("accounts", "process")
            .map_err(|_| ClientError::TelemetryUnavailable)?;
        async {
            let started = Instant::now();
            let result = operation.await;
            match &result {
                Ok(_) => tracing::event!(target:"nds_accounts",tracing::Level::INFO, {
                    event.name=event,duration_ms=started.elapsed().as_millis() as u64,outcome="ok"
                }),
                Err(error) => tracing::event!(target:"nds_accounts",tracing::Level::WARN, {
                    event.name=event,duration_ms=started.elapsed().as_millis() as u64,error.type=error.code(),outcome="error"
                }),
            }
            result
        }.instrument(span).await
    }

    pub async fn refresh(&self) -> Result<View, ClientError> {
        self.observe("identity.refresh", self.refresh_operation())
            .await
    }

    async fn refresh_operation(&self) -> Result<View, ClientError> {
        let (_permit, cancel) = self.operation()?;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .view
            .session_verified = false;
        let health: health_wire::HealthResponse = self.get("/v1/health", None, &cancel).await?;
        let methods: wire::AuthMethods = self.get("/v2/auth/methods", None, &cancel).await?;
        {
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            s.view.server_version = health.version;
            s.view.email_available =
                matches!(methods.email_otp, wire::MethodAvailability::Available);
            s.view.github_available = matches!(methods.github, wire::MethodAvailability::Available);
        }
        let credential = self.store.read().await;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .view
            .credential_store_ready = credential.is_ok();
        if let Some(secret) = credential? {
            let token = Zeroizing::new(
                String::from_utf8(secret.to_vec()).map_err(|_| ClientError::CredentialStore)?,
            );
            if !valid_token(&token) {
                return Err(ClientError::CredentialStore);
            }
            match self
                .get::<wire::Session>("/v2/session", Some(&token), &cancel)
                .await
            {
                Ok(session) => {
                    let deadline = validate_session(&session)?;
                    self.finish_persisted_session(session, deadline, &cancel)?;
                }
                Err(ClientError::Server(code)) if code == "authentication_failed" => {
                    self.store.delete().await?;
                    self.clear_session();
                }
                Err(error) => return Err(error),
            }
        } else {
            self.clear_session();
        }
        Ok(self.view())
    }

    pub async fn request_email(&self, email: String, locale: &str) -> Result<View, ClientError> {
        self.observe(
            "identity.email.request",
            self.request_email_operation(email, locale),
        )
        .await
    }

    async fn request_email_operation(
        &self,
        email: String,
        locale: &str,
    ) -> Result<View, ClientError> {
        if !(3..=254).contains(&email.len()) {
            return Err(ClientError::InvalidInput);
        }
        self.require_store_ready()?;
        let (_permit, cancel) = self.operation()?;
        {
            let s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if matches!(s.flow, Some(Flow::Email {resend, ..}) if resend > Instant::now()) {
                return Err(ClientError::Server("rate_limited".into()));
            }
        }
        let response: wire::EmailChallenge = self
            .post(
                "/v2/auth/email/challenges",
                &wire::EmailChallengeRequest { email },
                StatusCode::ACCEPTED,
                locale,
                &cancel,
            )
            .await?;
        let expires = lifetime(response.expires_in_seconds, 600)?;
        let resend = lifetime(response.resend_after_seconds, 600)?;
        if !valid_id(&response.challenge_id) {
            return Err(ClientError::InvalidResponse);
        }
        self.finish_flow(
            Flow::Email {
                id: response.challenge_id,
                expires,
                resend,
            },
            String::new(),
            String::new(),
            &cancel,
        )?;
        Ok(self.view())
    }

    pub async fn verify_email(&self, code: String) -> Result<View, ClientError> {
        self.observe("identity.email.verify", self.verify_email_operation(code))
            .await
    }

    async fn verify_email_operation(&self, code: String) -> Result<View, ClientError> {
        if code.len() != 8 || !code.bytes().all(|c| c.is_ascii_digit()) {
            return Err(ClientError::InvalidInput);
        }
        let (_permit, cancel) = self.operation()?;
        let id = {
            let s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            match &s.flow {
                Some(Flow::Email { id, expires, .. }) if *expires > Instant::now() => id.clone(),
                _ => return Err(ClientError::Expired),
            }
        };
        let issued = self
            .post(
                "/v2/auth/email/verify",
                &wire::EmailVerifyRequest {
                    challenge_id: id,
                    code,
                },
                StatusCode::OK,
                "en",
                &cancel,
            )
            .await?;
        self.accept_session(issued, &cancel).await?;
        Ok(self.view())
    }

    pub async fn start_github(&self, locale: &str) -> Result<View, ClientError> {
        self.observe("identity.github.start", self.start_github_operation(locale))
            .await
    }

    async fn start_github_operation(&self, locale: &str) -> Result<View, ClientError> {
        self.require_store_ready()?;
        let (_permit, cancel) = self.operation()?;
        let response: wire::GithubStart = self
            .post(
                "/v2/auth/github/start",
                &serde_json::json!({}),
                StatusCode::OK,
                locale,
                &cancel,
            )
            .await?;
        validate_github_url(&response.authorization_url, &self.endpoint)?;
        if !valid_token(&response.exchange_token)
            || !valid_id(&response.flow_id)
            || response.verification_code.len() != 8
            || !response
                .verification_code
                .bytes()
                .all(|c| c.is_ascii_digit())
        {
            return Err(ClientError::InvalidResponse);
        }
        let expires = lifetime(response.expires_in_seconds, 600)?;
        let next_poll = lifetime(response.poll_after_seconds, 30)?;
        self.finish_flow(
            Flow::Github {
                id: response.flow_id,
                token: Zeroizing::new(response.exchange_token),
                expires,
                next_poll,
            },
            response.authorization_url,
            response.verification_code,
            &cancel,
        )?;
        Ok(self.view())
    }

    pub async fn poll_github(&self) -> Result<View, ClientError> {
        self.observe("identity.github.poll", self.poll_github_operation())
            .await
    }

    async fn poll_github_operation(&self) -> Result<View, ClientError> {
        let (_permit, cancel) = self.operation()?;
        let request = {
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            match &mut s.flow {
                Some(Flow::Github {
                    id,
                    token,
                    expires,
                    next_poll,
                }) if *expires > Instant::now() => {
                    if *next_poll > Instant::now() {
                        drop(s);
                        return Ok(self.view());
                    }
                    *next_poll = Instant::now() + Duration::from_secs(2);
                    wire::GithubExchangeRequest {
                        flow_id: id.clone(),
                        exchange_token: token.to_string(),
                    }
                }
                _ => return Err(ClientError::Expired),
            }
        };
        let result = self
            .request(
                Method::POST,
                "/v2/auth/github/exchange",
                Some(&request),
                None,
                "en",
                &cancel,
            )
            .await;
        let (status, body) = match result {
            Err(error @ ClientError::Server(_)) => {
                self.clear_flow();
                return Err(error);
            }
            other => other?,
        };
        if status == StatusCode::ACCEPTED {
            let pending: wire::GithubPending = decode(&body)?;
            let next = lifetime(pending.retry_after_seconds, 30)?;
            if let Some(Flow::Github { next_poll, .. }) =
                &mut self.state.lock().unwrap_or_else(|e| e.into_inner()).flow
            {
                *next_poll = next;
            }
        } else if status == StatusCode::OK {
            self.accept_session(decode(&body)?, &cancel).await?;
        } else {
            return Err(ClientError::InvalidResponse);
        }
        Ok(self.view())
    }

    pub fn cancel_sign_in(&self) {
        let completion = self.cancellation.lock().unwrap_or_else(|e| e.into_inner());
        completion.cancel();
        self.clear_flow();
    }

    fn finish_flow(
        &self,
        flow: Flow,
        authorization_url: String,
        verification_code: String,
        cancel: &CancellationToken,
    ) -> Result<(), ClientError> {
        let _completion = self.cancellation.lock().unwrap_or_else(|e| e.into_inner());
        if cancel.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.view.flow = match &flow {
            Flow::Email { .. } => "email",
            Flow::Github { .. } => "github",
        }
        .into();
        state.flow = Some(flow);
        state.view.authorization_url = authorization_url;
        state.view.verification_code = verification_code;
        Ok(())
    }

    pub async fn logout(&self) -> Result<View, ClientError> {
        self.observe("identity.logout", self.logout_operation())
            .await
    }

    async fn logout_operation(&self) -> Result<View, ClientError> {
        let (_permit, cancel) = self.operation()?;
        let secret = self.store.read().await?;
        if let Some(secret) = secret {
            let token = Zeroizing::new(
                String::from_utf8(secret.to_vec()).map_err(|_| ClientError::CredentialStore)?,
            );
            let result = self
                .request::<()>(
                    Method::DELETE,
                    "/v2/session",
                    None,
                    Some(&token),
                    "en",
                    &cancel,
                )
                .await;
            match result {
                Ok((StatusCode::NO_CONTENT, _)) => {}
                Err(ClientError::Server(code)) if code == "authentication_failed" => {}
                Err(error) => return Err(error),
                _ => return Err(ClientError::InvalidResponse),
            }
        }
        self.store.delete().await?;
        self.clear_session();
        self.clear_flow();
        Ok(self.view())
    }

    async fn accept_session(
        &self,
        response: wire::SessionIssued,
        cancel: &CancellationToken,
    ) -> Result<(), ClientError> {
        let deadline = validate_session(&response.session)?;
        if !valid_token(&response.session_token) {
            return Err(ClientError::InvalidResponse);
        }
        if cancel.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        let token = Zeroizing::new(response.session_token);
        if let Err(error) = self.store.write(token.as_bytes()).await {
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .view
                .credential_store_ready = false;
            self.require_revalidation();
            return Err(error);
        }
        self.finish_persisted_session(response.session, deadline, cancel)
    }

    fn finish_persisted_session(
        &self,
        session: wire::Session,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), ClientError> {
        let completion = self.cancellation.lock().unwrap_or_else(|e| e.into_inner());
        if cancel.is_cancelled() || deadline <= Instant::now() {
            // The OS write can finish after cancellation. Preserve the secret,
            // expose uncertainty and require server revalidation, not a false
            // authenticated/signed-out result or destructive compensation.
            drop(completion);
            self.require_revalidation();
            return Err(ClientError::RevalidationRequired);
        }
        self.set_session(session, deadline);
        self.clear_flow();
        drop(completion);
        Ok(())
    }

    fn set_session(&self, session: wire::Session, deadline: Instant) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.session_deadline = Some(deadline);
        s.view.authenticated = true;
        s.view.session_verified = true;
        s.view.credential_revalidation_required = false;
        s.view.session_checked_at = OffsetDateTime::now_utc().unix_timestamp();
        s.view.user_id = session.user_id;
        s.view.tenant_id = session.tenant_id;
        s.view.expires_at = session.expires_at;
        s.view.auth_method = match session.auth_method {
            wire::AuthMethod::EmailOtp => "email_otp",
            wire::AuthMethod::Github => "github",
        }
        .into();
    }

    fn clear_session(&self) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.session_deadline = None;
        s.view.authenticated = false;
        s.view.session_verified = false;
        s.view.credential_revalidation_required = false;
        s.view.session_checked_at = 0;
        s.view.user_id.clear();
        s.view.tenant_id.clear();
        s.view.expires_at.clear();
        s.view.auth_method.clear();
        s.view.devices.clear();
        s.view.current_device_id.clear();
        s.view.devices_checked_at = 0;
    }

    fn require_revalidation(&self) {
        self.clear_flow();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.view.session_verified = false;
        state.view.credential_revalidation_required = true;
    }

    fn require_store_ready(&self) -> Result<(), ClientError> {
        if !self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .view
            .credential_store_ready
        {
            return Err(ClientError::CredentialStore);
        }
        Ok(())
    }

    fn clear_flow(&self) {
        clear_flow_state(&mut self.state.lock().unwrap_or_else(|e| e.into_inner()));
    }

    async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<T, ClientError> {
        let (status, body) = self
            .request::<()>(Method::GET, path, None, token, "en", cancel)
            .await?;
        if status != StatusCode::OK {
            return Err(ClientError::InvalidResponse);
        }
        decode(&body)
    }

    async fn post<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
        expected_status: StatusCode,
        locale: &str,
        cancel: &CancellationToken,
    ) -> Result<R, ClientError> {
        let (status, body) = self
            .request(Method::POST, path, Some(body), None, locale, cancel)
            .await?;
        if status != expected_status {
            return Err(ClientError::InvalidResponse);
        }
        decode(&body)
    }

    async fn request<T: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
        token: Option<&str>,
        locale: &str,
        cancel: &CancellationToken,
    ) -> Result<(StatusCode, Vec<u8>), ClientError> {
        let body = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| ClientError::InvalidInput)?;
        self.request_bytes(
            WireRequest {
                method,
                path,
                body,
                token,
                locale,
                signature: None,
            },
            cancel,
        )
        .await
    }

    async fn request_bytes(
        &self,
        options: WireRequest<'_>,
        cancel: &CancellationToken,
    ) -> Result<(StatusCode, Vec<u8>), ClientError> {
        let WireRequest {
            method,
            path,
            body,
            token,
            locale,
            signature,
        } = options;
        if body.as_ref().is_some_and(|body| body.len() > MAX_BODY) {
            return Err(ClientError::InvalidInput);
        }
        let signed = signature.is_some();
        let span = nddev_device_sync_telemetry::operation_span("accounts", "http")
            .map_err(|_| ClientError::TelemetryUnavailable)?;
        let context = nddev_device_sync_telemetry::trace_context(&span);
        // Normalize device paths before recording them; queries and IDs stay out.
        let route = if path.starts_with("/v2/devices/")
            && !matches!(path, "/v2/devices/challenges" | "/v2/devices/enrollments")
        {
            "/v2/devices/{device_id}"
        } else {
            path.split('?').next().unwrap_or("unknown")
        };
        async {
        let started = Instant::now();
        tracing::event!(target: "nds_accounts", tracing::Level::DEBUG,
            { event.name = "identity.request_started", route });
        let mut propagation = std::collections::HashMap::new();
        TraceContextPropagator::new().inject_context(&context, &mut propagation);
        let mut request = self
            .http
            .request(
                method,
                self.endpoint
                    .join(path)
                    .map_err(|_| ClientError::InvalidEndpoint)?,
            )
            .header("accept-language", if locale == "ru" { "ru" } else { "en" });
        for (key, value) in propagation {
            request = request.header(key, value);
        }
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.header("content-type","application/json").body(body);
        }
        if let Some(signature) = signature {
            request = request.header("signature",signature.signature).header("signature-input",signature.signature_input).header("content-digest",signature.content_digest);
        }
        let operation = async {
            let mut response = request.send().await.map_err(|e| {
                if e.is_timeout() {
                    ClientError::Timeout
                } else {
                    ClientError::Transport
                }
            })?;
            let status = response.status();
            if response
                .content_length()
                .is_some_and(|n| n > MAX_BODY as u64)
            {
                return Err(ClientError::InvalidResponse);
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| ClientError::Transport)? {
                if bytes.len() + chunk.len() > MAX_BODY {
                    return Err(ClientError::InvalidResponse);
                }
                bytes.extend_from_slice(&chunk);
            }
            if !status.is_success() {
                // A retained revision conflict is a sync result, not a generic
                // error. Preserve its exact bytes for the durable client inbox.
                if signed && status==StatusCode::CONFLICT && matches!(serde_json::from_slice::<sync_wire::Sync>(&bytes), Ok(sync_wire::Sync::Conflict(_))) {
                    return Ok((status,bytes));
                }
                let response: wire::Error = decode(&bytes)?;
                let code = serde_json::to_value(response.error)
                    .map_err(|_| ClientError::InvalidResponse)?;
                if token.is_some() && code.as_str() == Some("authentication_failed") {
                    self.require_revalidation();
                }
                if token.is_some() && code.as_str() == Some("device_revoked") {
                    for device in &mut self.state.lock().unwrap_or_else(|e| e.into_inner()).view.devices {
                        if device.is_current { device.revoked = true; }
                    }
                    return Err(ClientError::DeviceRevoked);
                }
                return Err(ClientError::Server(
                    code.as_str()
                        .ok_or(ClientError::InvalidResponse)?
                        .to_owned(),
                ));
            }
            Ok((status, bytes))
        };
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(ClientError::Cancelled),
            result = tokio::time::timeout(REQUEST_TIMEOUT, operation) => result.unwrap_or(Err(ClientError::Timeout)),
        };
        match &result {
            Ok((status, _)) => tracing::event!(target: "nds_accounts", tracing::Level::INFO,
                { event.name = "identity.request_completed", route, status = status.as_u16(),
                  duration_ms = started.elapsed().as_millis() as u64, outcome = "ok" }),
            Err(error) => tracing::event!(target: "nds_accounts", tracing::Level::WARN,
                { event.name = "identity.request_completed", route, error.type = error.code(),
                  duration_ms = started.elapsed().as_millis() as u64, outcome = "error" }),
        }
        result
        }.instrument(span).await
    }
}

fn clear_flow_state(state: &mut State) {
    state.flow = None;
    state.view.flow.clear();
    state.view.authorization_url.clear();
    state.view.verification_code.clear();
    state.view.expires_in_seconds = 0;
    state.view.retry_after_seconds = 0;
}

fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, ClientError> {
    serde_json::from_slice(body).map_err(|_| ClientError::InvalidResponse)
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
}
fn valid_token(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}
fn remaining(until: Instant) -> u32 {
    until
        .saturating_duration_since(Instant::now())
        .as_secs()
        .saturating_add(u64::from(until > Instant::now())) as u32
}
fn lifetime(seconds: i32, max: i32) -> Result<Instant, ClientError> {
    if !(1..=max).contains(&seconds) {
        return Err(ClientError::InvalidResponse);
    }
    Ok(Instant::now() + Duration::from_secs(seconds as u64))
}
fn validate_session(session: &wire::Session) -> Result<Instant, ClientError> {
    validate_session_at(session, OffsetDateTime::now_utc(), Instant::now())
}

fn validate_session_at(
    session: &wire::Session,
    wall: OffsetDateTime,
    now: Instant,
) -> Result<Instant, ClientError> {
    if !valid_id(&session.user_id) || !valid_id(&session.tenant_id) || session.expires_at.len() > 40
    {
        return Err(ClientError::InvalidResponse);
    }
    let expires = OffsetDateTime::parse(&session.expires_at, &Rfc3339)
        .map_err(|_| ClientError::InvalidResponse)?;
    let remaining = expires - wall;
    if remaining <= time::Duration::ZERO {
        return Err(ClientError::Expired);
    }
    let maximum = Duration::from_millis(nddev_device_sync_domain::identity::SESSION_LIFETIME_MS);
    // Client and server clocks are independent. Tolerate a small skew at this
    // response sanity boundary, but never extend the canonical local lifetime.
    if remaining.unsigned_abs() > maximum + Duration::from_secs(30) {
        return Err(ClientError::InvalidResponse);
    }
    Ok(now + remaining.unsigned_abs().min(maximum))
}

fn expire_session(state: &mut State, now: Instant, wall_time: OffsetDateTime) {
    if state.view.authenticated
        && (state
            .session_deadline
            .is_some_and(|deadline| deadline <= now)
            || OffsetDateTime::parse(&state.view.expires_at, &Rfc3339)
                .is_ok_and(|expires| expires <= wall_time))
    {
        state.view.authenticated = false;
        state.view.session_verified = false;
        state.session_deadline = None;
    }
}

pub fn validate_endpoint(input: &str) -> Result<Url, ClientError> {
    if input.len() > 2048 {
        return Err(ClientError::InvalidEndpoint);
    }
    let url = Url::parse(input).map_err(|_| ClientError::InvalidEndpoint)?;
    let loopback = matches!(url.host(), Some(Host::Ipv4(ip)) if ip.is_loopback())
        || matches!(url.host(), Some(Host::Ipv6(ip)) if ip.is_loopback())
        || url.host_str() == Some("localhost");
    let scheme_allowed = url.scheme() == "https"
        || (cfg!(feature = "development-http")
            && cfg!(debug_assertions)
            && url.scheme() == "http"
            && loopback);
    if !scheme_allowed
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(ClientError::InvalidEndpoint);
    }
    Ok(url)
}

pub fn validate_github_url(input: &str, endpoint: &Url) -> Result<(), ClientError> {
    let url = Url::parse(input).map_err(|_| ClientError::InvalidResponse)?;
    if input.len() > 2048
        || url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || url.path() != "/login/oauth/authorize"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port().is_some_and(|p| p != 443)
    {
        return Err(ClientError::InvalidResponse);
    }
    let mut query = std::collections::BTreeMap::new();
    for (key, value) in url.query_pairs() {
        if query.insert(key.into_owned(), value.into_owned()).is_some() {
            return Err(ClientError::InvalidResponse);
        }
    }
    let keys = [
        "allow_signup",
        "client_id",
        "code_challenge",
        "code_challenge_method",
        "redirect_uri",
        "scope",
        "state",
    ];
    if query.keys().map(String::as_str).ne(keys) {
        return Err(ClientError::InvalidResponse);
    }
    let client_id = &query["client_id"];
    if client_id.is_empty()
        || client_id.len() > 128
        || !client_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        || query["scope"] != "read:user"
        || query["code_challenge_method"] != "S256"
        || query["allow_signup"] != "false"
        || ["state", "code_challenge"]
            .iter()
            .any(|key| query[*key].len() != 43 || !valid_token(&query[*key]))
    {
        return Err(ClientError::InvalidResponse);
    }
    let callback = Url::parse(&query["redirect_uri"]).map_err(|_| ClientError::InvalidResponse)?;
    if callback.scheme() != "https"
        || callback.origin() != endpoint.origin()
        || callback.path() != "/v2/auth/github/callback"
        || callback.query().is_some()
        || callback.fragment().is_some()
        || !callback.username().is_empty()
        || callback.password().is_some()
    {
        return Err(ClientError::InvalidResponse);
    }
    Ok(())
}

#[cfg(test)]
mod native_completion_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires an actual unlocked native store; owns one fresh entry"]
    async fn cancellation_after_native_persistence_requires_revalidation() {
        let endpoint = format!("https://nds-completion-{}.invalid", uuid::Uuid::new_v4());
        let client = IdentityClient::new(&endpoint).unwrap();
        let (_permit, cancel) = client.operation().unwrap();
        assert!(client.store.read().await.unwrap().is_none());
        let secret = uuid::Uuid::new_v4().simple().to_string().repeat(2);
        client.store.write(secret.as_bytes()).await.unwrap();
        client.cancel();
        let result = client.finish_persisted_session(
            wire::Session {
                user_id: "ephemeral-owner".into(),
                tenant_id: "ephemeral-tenant".into(),
                auth_method: wire::AuthMethod::EmailOtp,
                expires_at: (OffsetDateTime::now_utc() + time::Duration::hours(1))
                    .format(&Rfc3339)
                    .unwrap(),
            },
            Instant::now() + Duration::from_secs(3600),
            &cancel,
        );
        let view = client.view();
        let persisted = client.store.read().await;
        client.store.delete().await.unwrap();
        assert_eq!(result, Err(ClientError::RevalidationRequired));
        assert!(
            !view.authenticated && !view.session_verified && view.credential_revalidation_required
        );
        assert!(persisted.unwrap().is_some());
    }

    #[test]
    fn cancelled_response_cannot_recreate_a_sign_in_flow() {
        let client = IdentityClient::new("https://cancelled.example").unwrap();
        let (_permit, cancel) = client.operation().unwrap();
        client.cancel_sign_in();
        let result = client.finish_flow(
            Flow::Email {
                id: "ephemeral-flow".into(),
                expires: Instant::now() + Duration::from_secs(30),
                resend: Instant::now(),
            },
            String::new(),
            String::new(),
            &cancel,
        );
        assert_eq!(result, Err(ClientError::Cancelled));
        assert!(client.view().flow.is_empty());
    }

    #[test]
    fn expired_flow_is_removed_from_owned_state_and_view() {
        let client = IdentityClient::new("https://expired.example").unwrap();
        let (_permit, cancel) = client.operation().unwrap();
        client
            .finish_flow(
                Flow::Github {
                    id: "ephemeral-flow".into(),
                    token: Zeroizing::new("ephemeral-token".into()),
                    expires: Instant::now(),
                    next_poll: Instant::now(),
                },
                "ephemeral-url".into(),
                "12345678".into(),
                &cancel,
            )
            .unwrap();
        let view = client.view();
        assert!(
            view.flow.is_empty()
                && view.authorization_url.is_empty()
                && view.verification_code.is_empty()
        );
        assert!(client.state.lock().unwrap().flow.is_none());
    }

    #[test]
    fn view_debug_never_contains_authorization_query_or_identity() {
        let view = View {
            authorization_url: "sensitive-authorization-url".into(),
            verification_code: "12345678".into(),
            user_id: "sensitive-user-id".into(),
            ..View::default()
        };
        let output = format!("{view:?}");
        assert!(!output.contains("sensitive") && !output.contains("12345678"));
    }

    #[test]
    fn expired_state_cannot_revive_when_wall_clock_moves_back() {
        let now = Instant::now();
        let wall = OffsetDateTime::now_utc();
        let mut state = State::default();
        state.view.authenticated = true;
        state.view.session_verified = true;
        state.view.expires_at = (wall + time::Duration::seconds(60))
            .format(&Rfc3339)
            .unwrap();
        state.session_deadline = Some(now + Duration::from_secs(60));
        expire_session(
            &mut state,
            now + Duration::from_secs(1),
            wall + time::Duration::seconds(61),
        );
        assert!(!state.view.authenticated);
        expire_session(
            &mut state,
            now + Duration::from_secs(2),
            wall - time::Duration::hours(1),
        );
        assert!(!state.view.authenticated && !state.view.session_verified);
    }

    #[test]
    fn small_clock_skew_is_tolerated_without_extending_session_lifetime() {
        let now = Instant::now();
        let wall = OffsetDateTime::UNIX_EPOCH;
        let maximum =
            Duration::from_millis(nddev_device_sync_domain::identity::SESSION_LIFETIME_MS);
        for (skew, accepted) in [(1, true), (30, true), (31, false)] {
            let session = wire::Session {
                user_id: "owner".into(),
                tenant_id: "tenant".into(),
                auth_method: wire::AuthMethod::EmailOtp,
                expires_at: (wall + maximum + time::Duration::seconds(skew))
                    .format(&Rfc3339)
                    .unwrap(),
            };
            let result = validate_session_at(&session, wall, now);
            if accepted {
                assert_eq!(result.unwrap(), now + maximum);
            } else {
                assert_eq!(result, Err(ClientError::InvalidResponse));
            }
        }
    }

    #[test]
    fn remote_session_cannot_exceed_the_core_lifetime_contract() {
        let session = wire::Session {
            user_id: "owner".into(),
            tenant_id: "tenant".into(),
            auth_method: wire::AuthMethod::EmailOtp,
            expires_at: (OffsetDateTime::now_utc() + time::Duration::hours(9))
                .format(&Rfc3339)
                .unwrap(),
        };
        assert_eq!(
            validate_session(&session),
            Err(ClientError::InvalidResponse)
        );
    }
}
