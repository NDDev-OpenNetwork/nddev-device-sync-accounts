//! Browser-driven acceptance against an owned PostgreSQL/Mailpit fixture.
use nddev_device_sync_accounts::{IdentityClient, NativeSessionStore};
use serde_json::Value;
use std::{path::PathBuf, time::Duration};

#[tokio::test]
#[ignore = "requires an owned localhost fixture and an actual browser authenticator"]
async fn browser_passkey_registration_login_restore_and_revocation() {
    let receipt: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("NDS_FIXTURE_RECEIPT").unwrap()).unwrap(),
    )
    .unwrap();
    let endpoint = receipt["base_url"].as_str().unwrap();
    let mailbox = receipt["mailpit_url"].as_str().unwrap();
    assert!(endpoint.starts_with("http://localhost:"));
    let handoff = PathBuf::from(std::env::var("NDS_PASSKEY_HANDOFF_FILE").unwrap());
    assert!(
        handoff.is_absolute()
            && !handoff.starts_with(env!("CARGO_MANIFEST_DIR"))
            && !handoff.exists()
    );
    let client = IdentityClient::new(endpoint).unwrap();
    assert!(!client.refresh().await.unwrap().authenticated);
    client
        .request_email(receipt["owner_email"].as_str().unwrap().into(), "en")
        .await
        .unwrap();
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let otp = tokio::time::timeout(Duration::from_secs(10), async {
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
                .unwrap()
                .first()
                .and_then(|message| message["ID"].as_str())
            {
                let message: Value = http
                    .get(format!("{mailbox}/api/v1/message/{id}"))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                if let Some((_, suffix)) = message["Text"].as_str().unwrap().split_once("code: ") {
                    break suffix.chars().take(8).collect::<String>();
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    let initial = client.verify_email(otp).await.unwrap();
    let owner = (initial.user_id, initial.tenant_id);
    for registration in [true, false] {
        let view = client.start_passkey(registration, "en").await.unwrap();
        let mut file = std::fs::OpenOptions::new();
        file.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            file.mode(0o600);
        }
        let mut file = file.open(&handoff).unwrap();
        use std::io::Write;
        file.write_all(serde_json::to_string(&serde_json::json!({"authorization_url":view.authorization_url,"verification_code":view.verification_code,"registration":registration})).unwrap().as_bytes()).unwrap();
        tokio::time::timeout(Duration::from_secs(300), async {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let view = client.poll_passkey().await.unwrap();
                if view.flow.is_empty() {
                    assert!(view.authenticated && view.session_verified);
                    assert_eq!((&view.user_id, &view.tenant_id), (&owner.0, &owner.1));
                    if !registration {
                        assert_eq!(view.auth_method, "passkey");
                    }
                    break;
                }
            }
        })
        .await
        .unwrap();
        std::fs::remove_file(&handoff).unwrap();
        if registration {
            client.logout().await.unwrap();
        }
    }
    client
        .prepare_device("Owned browser acceptance".into())
        .await
        .unwrap();
    let restored = IdentityClient::new(endpoint).unwrap();
    let view = restored.refresh().await.unwrap();
    assert!(view.authenticated && view.session_verified);
    assert_eq!(view.auth_method, "passkey");
    let native = NativeSessionStore::for_endpoint(&format!("{endpoint}/")).unwrap();
    let token = native.read().await.unwrap().unwrap();
    restored.logout().await.unwrap();
    assert!(native.read().await.unwrap().is_none());
    assert_eq!(
        http.get(format!("{endpoint}/v2/session"))
            .bearer_auth(std::str::from_utf8(&token).unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
}
