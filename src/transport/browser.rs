use crate::{ClientError, MAX_BODY, WireRequest};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::StatusCode;
use js_sys::{Array, Uint8Array};
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use wasm_bindgen::{JsCast, prelude::*};
use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen(module = "/src/browser_http.js")]
extern "C" {
    #[wasm_bindgen(js_name = currentOrigin)]
    fn current_origin() -> String;
    #[wasm_bindgen(js_name = abortRequest)]
    fn abort_request(id: &str);
    #[wasm_bindgen(catch, js_name = request)]
    fn request_js(
        id: &str,
        target: &str,
        method: &str,
        headers: &str,
        input: &[u8],
        has_body: bool,
    ) -> Result<js_sys::Promise, JsValue>;
}

struct RequestGuard(String);
impl Drop for RequestGuard {
    fn drop(&mut self) {
        abort_request(&self.0);
    }
}
fn failure(value: JsValue) -> ClientError {
    match value
        .dyn_ref::<js_sys::Error>()
        .map(|v| v.message().as_string().unwrap_or_default())
        .as_deref()
    {
        Some("invalid_response") => ClientError::InvalidResponse,
        Some("request_timeout") => ClientError::Timeout,
        Some("cancelled") => ClientError::Cancelled,
        Some("invalid_request") => ClientError::InvalidInput,
        _ => ClientError::Transport,
    }
}
pub(crate) fn validate_origin(endpoint: &url::Url) -> Result<(), ClientError> {
    if endpoint.origin().ascii_serialization() != current_origin() {
        return Err(ClientError::InvalidEndpoint);
    }
    Ok(())
}
pub(super) async fn request(
    endpoint: &url::Url,
    options: WireRequest<'_>,
    mut headers: HashMap<String, String>,
) -> Result<(StatusCode, Vec<u8>), ClientError> {
    validate_origin(endpoint)?;
    let WireRequest {
        method,
        path,
        body,
        locale,
        signature,
        ..
    } = options;
    let target = endpoint
        .join(path)
        .map_err(|_| ClientError::InvalidEndpoint)?;
    headers.insert(
        "accept-language".into(),
        if locale == "ru" { "ru" } else { "en" }.into(),
    );
    if body.is_some() {
        headers.insert(
            "content-type".into(),
            match path {
                "/v2/observability/events" => "application/x-ndjson",
                "/v2/observability/traces" => "application/x-protobuf",
                _ => "application/json",
            }
            .into(),
        );
    }
    if let Some(signature) = signature {
        headers.insert("signature".into(), signature.signature);
        headers.insert("signature-input".into(), signature.signature_input);
        headers.insert("content-digest".into(), signature.content_digest);
    }
    let mut random = [0; 24];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| ClientError::Transport)?;
    let guard = RequestGuard(URL_SAFE_NO_PAD.encode(random));
    let headers = serde_json::to_string(&headers).map_err(|_| ClientError::InvalidInput)?;
    let promise = request_js(
        &guard.0,
        target.as_str(),
        method.as_str(),
        &headers,
        body.as_deref().unwrap_or_default(),
        body.is_some(),
    )
    .map_err(failure)?;
    let result = JsFuture::from(promise)
        .await
        .map_err(failure)?
        .dyn_into::<Array>()
        .map_err(|_| ClientError::InvalidResponse)?;
    if result.length() != 2 {
        return Err(ClientError::InvalidResponse);
    }
    let status = result
        .get(0)
        .as_f64()
        .filter(|v| v.fract() == 0.0 && (100.0..=599.0).contains(v))
        .ok_or(ClientError::InvalidResponse)?;
    let bytes = result
        .get(1)
        .dyn_into::<Uint8Array>()
        .map_err(|_| ClientError::InvalidResponse)?;
    if bytes.length() > MAX_BODY as u32 {
        bytes.fill(0, 0, bytes.length());
        return Err(ClientError::InvalidResponse);
    }
    let output = bytes.to_vec();
    bytes.fill(0, 0, bytes.length());
    Ok((
        StatusCode::from_u16(status as u16).map_err(|_| ClientError::InvalidResponse)?,
        output,
    ))
}
