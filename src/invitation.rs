//! One pending link in Rust memory only. A link selects a verification flow;
//! it does not switch accounts or authorize membership.
use crate::{ClientError, IdentityClient, View};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use zeroize::{Zeroize, Zeroizing};

pub(crate) struct InvitationLink {
    id: String,
    token: Zeroizing<String>,
}
impl InvitationLink {
    fn parse(link: Zeroizing<String>, endpoint: &url::Url) -> Result<Self, ClientError> {
        if link.len() > 2048 {
            return Err(ClientError::InvalidInput);
        }
        let url = url::Url::parse(&link).map_err(|_| ClientError::InvalidInput)?;
        if url.origin() != endpoint.origin()
            || url.path() != "/"
            || url.query().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(ClientError::InvalidInput);
        }
        let fragment = url.fragment().ok_or(ClientError::InvalidInput)?;
        let (id, token) = fragment
            .strip_prefix("invite/")
            .and_then(|value| value.split_once('/'))
            .ok_or(ClientError::InvalidInput)?;
        if !opaque(id) || !opaque(token) {
            return Err(ClientError::InvalidInput);
        }
        Ok(Self {
            id: id.into(),
            token: Zeroizing::new(token.into()),
        })
    }
    pub(crate) fn body(&self, email: String) -> Result<Vec<u8>, ClientError> {
        let mut dto = crate::wire::InvitationEmailChallengeRequest {
            email,
            invitation_id: self.id.clone(),
            invitation_token: self.token.to_string(),
        };
        let result = serde_json::to_vec(&dto).map_err(|_| ClientError::InvalidInput);
        dto.invitation_token.zeroize();
        result
    }
}
fn opaque(value: &str) -> bool {
    value.len() == 43
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == value)
}
impl IdentityClient {
    pub async fn import_invitation(&self, link: String) -> Result<View, ClientError> {
        let link = InvitationLink::parse(Zeroizing::new(link), &self.endpoint)?;
        let (_permit, cancel) = self.operation().await?;
        // Never replace a signed-in owner's keys, pending work or browser cookie.
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if cancel.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        if state.view.authenticated || state.view.logout_pending || state.flow.is_some() {
            return Err(ClientError::Server("authorization_denied".into()));
        }
        state.invitation = Some(link);
        drop(state);
        Ok(self.view())
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use super::*;
    use std::sync::Mutex;
    static LINK: Mutex<Option<Zeroizing<String>>> = Mutex::new(None);

    /// Run before presentation routing. Clear even a malformed invitation;
    /// neither the history state object nor a presentation cache gets the URL.
    pub fn capture() -> Result<(), ClientError> {
        let Some(window) = web_sys::window() else {
            return Ok(());
        };
        let location = window.location();
        let hash = location.hash().map_err(|_| ClientError::InvalidInput)?;
        if !hash.starts_with("#invite/") {
            return Ok(());
        }
        let href = Zeroizing::new(location.href().map_err(|_| ClientError::InvalidInput)?);
        let clean = href.split('#').next().ok_or(ClientError::InvalidInput)?;
        window
            .history()
            .map_err(|_| ClientError::InvalidInput)?
            .replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(clean))
            .map_err(|_| ClientError::InvalidInput)?;
        *LINK.lock().unwrap_or_else(|e| e.into_inner()) = Some(href);
        Ok(())
    }
    pub fn take() -> Option<Zeroizing<String>> {
        LINK.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}
#[cfg(target_arch = "wasm32")]
pub use browser::{capture as capture_browser_invitation, take as take_browser_invitation};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn link_is_exact_origin_fragment_and_canonical_opaque_material() {
        let endpoint = url::Url::parse("https://example.invalid/").unwrap();
        let material = URL_SAFE_NO_PAD.encode([1; 32]);
        let link = format!("https://example.invalid/#invite/{material}/{material}");
        let parsed = InvitationLink::parse(Zeroizing::new(link.clone()), &endpoint).unwrap();
        let body: crate::wire::InvitationEmailChallengeRequest =
            serde_json::from_slice(&parsed.body("recipient@example.invalid".into()).unwrap())
                .unwrap();
        assert_eq!(body.invitation_token, material);
        for bad in [
            link.replace("example.invalid", "other.invalid"),
            link.replace("/#", "/path#"),
            link.replace("/#", "/?query#"),
            link.replace("https://", "https://user@"),
            format!("{link}/extra"),
            link.replace("#invite/", "#other/"),
            link.replace(&material, "x"),
        ] {
            assert!(InvitationLink::parse(Zeroizing::new(bad), &endpoint).is_err());
        }
    }
    #[tokio::test]
    async fn pending_link_never_appears_in_view_or_survives_sign_in_cancellation() {
        let client = IdentityClient::new("https://example.invalid").unwrap();
        let material = URL_SAFE_NO_PAD.encode([1; 32]);
        // The pure transition is exercised without writing a real credential store.
        client.state.lock().unwrap().invitation = Some(
            InvitationLink::parse(
                Zeroizing::new(format!(
                    "https://example.invalid/#invite/{material}/{material}"
                )),
                &client.endpoint,
            )
            .unwrap(),
        );
        assert!(client.view().invitation_pending);
        assert!(!format!("{:?}", client.view()).contains(&material));
        client.cancel_sign_in();
        assert!(!client.view().invitation_pending);
    }
}
