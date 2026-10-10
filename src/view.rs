#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    #[error("invalid_endpoint")]
    InvalidEndpoint,
    #[error("invalid_input")]
    InvalidInput,
    #[error("telemetry_unavailable")]
    TelemetryUnavailable,
    #[error("invalid_response")]
    InvalidResponse,
    #[error("transport_unavailable")]
    Transport,
    #[error("request_timeout")]
    Timeout,
    #[error("cancelled")]
    Cancelled,
    #[error("busy")]
    Busy,
    #[error("credential_store_unavailable")]
    CredentialStore,
    #[error("credential_revalidation_required")]
    RevalidationRequired,
    #[error("challenge_expired")]
    Expired,
    #[error("{0}")]
    Server(String),
}

impl ClientError {
    /// An allowlisted code for localization; never an underlying I/O message.
    pub fn code(&self) -> String {
        self.to_string()
    }
}

/// Presentation state, never a bearer credential or a wire request.
#[derive(Clone, Default)]
pub struct View {
    pub email_available: bool,
    pub github_available: bool,
    pub credential_store_ready: bool,
    pub server_version: String,
    pub authenticated: bool,
    pub session_verified: bool,
    pub credential_revalidation_required: bool,
    pub session_checked_at: i64,
    pub user_id: String,
    pub tenant_id: String,
    pub auth_method: String,
    pub expires_at: String,
    pub flow: String,
    pub authorization_url: String,
    pub verification_code: String,
    pub expires_in_seconds: u32,
    pub retry_after_seconds: u32,
}

impl std::fmt::Debug for View {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("View")
            .field("authenticated", &self.authenticated)
            .field("session_verified", &self.session_verified)
            .field(
                "credential_revalidation_required",
                &self.credential_revalidation_required,
            )
            .finish_non_exhaustive()
    }
}
