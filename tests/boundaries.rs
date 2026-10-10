use nddev_device_sync_accounts::{
    ClientError, IdentityClient, validate_endpoint, validate_github_url,
};

#[test]
fn endpoint_rejects_credentials_paths_fragments_and_cleartext() {
    for value in [
        "ftp://example.invalid",
        "https://user:pass@example.invalid",
        "https://example.invalid/api",
        "https://example.invalid/?token=x",
        "https://example.invalid/#fragment",
        "http://example.invalid",
    ] {
        assert!(validate_endpoint(value).is_err(), "{value}");
    }
    assert!(validate_endpoint("https://example.invalid:8443/").is_ok());
    #[cfg(not(feature = "development-http"))]
    assert!(validate_endpoint("http://127.0.0.1:8100/").is_err());
    #[cfg(feature = "development-http")]
    assert!(validate_endpoint("http://127.0.0.1:8100/").is_ok());
}

#[test]
fn browser_launch_is_bound_to_the_instance_scope_pkce_and_callback() {
    let endpoint = validate_endpoint("https://instance.example").unwrap();
    let mut allowed = url::Url::parse("https://github.com/login/oauth/authorize").unwrap();
    let baseline = [
        ("client_id", "test_client".to_owned()),
        (
            "redirect_uri",
            "https://instance.example/v2/auth/github/callback".to_owned(),
        ),
        ("scope", "read:user".to_owned()),
        ("state", "a".repeat(43)),
        ("code_challenge", "b".repeat(43)),
        ("code_challenge_method", "S256".to_owned()),
        ("allow_signup", "false".to_owned()),
    ];
    allowed
        .query_pairs_mut()
        .extend_pairs(baseline.iter().map(|(k, v)| (*k, v.as_str())));
    assert!(validate_github_url(allowed.as_str(), &endpoint).is_ok());
    for (key, value) in [
        ("scope", "repo"),
        (
            "redirect_uri",
            "https://foreign.example/v2/auth/github/callback",
        ),
        ("code_challenge_method", "plain"),
        ("allow_signup", "true"),
        ("state", "short"),
        ("client_id", "contains a space"),
    ] {
        let mut invalid = allowed.clone();
        invalid.set_query(None);
        invalid.query_pairs_mut().extend_pairs(
            baseline
                .iter()
                .map(|(k, v)| (*k, if *k == key { value } else { v.as_str() })),
        );
        assert_eq!(
            validate_github_url(invalid.as_str(), &endpoint),
            Err(ClientError::InvalidResponse)
        );
    }
    for extra in ["scope=read%3Auser", "unknown=field"] {
        let invalid = format!("{allowed}&{extra}");
        assert!(validate_github_url(&invalid, &endpoint).is_err());
    }
    for input in [
        "http://github.com/login/oauth/authorize",
        "https://github.com.evil.invalid/login/oauth/authorize",
        "https://github.com/login/oauth/authorize#fragment",
        "https://github.com/settings",
        "file:///etc/passwd",
    ] {
        assert!(validate_github_url(input, &endpoint).is_err());
    }
}

#[tokio::test]
async fn invalid_auth_input_never_reaches_network_or_credentials() {
    let client = IdentityClient::new("https://example.invalid").unwrap();
    assert_eq!(
        client.verify_email("1234".into()).await.unwrap_err(),
        ClientError::InvalidInput
    );
    assert_eq!(
        client.verify_email("12345678".into()).await.unwrap_err(),
        ClientError::Expired
    );
    assert_eq!(
        client.request_email("x".into(), "en").await.unwrap_err(),
        ClientError::InvalidInput
    );
    assert_eq!(
        client.poll_github().await.unwrap_err(),
        ClientError::Expired
    );
}

#[cfg(feature = "development-http")]
#[tokio::test]
async fn a_real_unresponsive_socket_is_cancelled_and_does_not_queue_calls() {
    use std::{net::TcpListener, time::Duration};
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::sync::Arc::new(
        IdentityClient::new(&format!("http://{}/", socket.local_addr().unwrap())).unwrap(),
    );
    let task_client = client.clone();
    let operation = tokio::spawn(async move { task_client.refresh().await });
    let (connection, _) = tokio::task::spawn_blocking(move || socket.accept().unwrap())
        .await
        .unwrap();
    assert_eq!(client.refresh().await.unwrap_err(), ClientError::Busy);
    let second =
        IdentityClient::new(&format!("http://{}/", connection.local_addr().unwrap())).unwrap();
    assert_eq!(second.refresh().await.unwrap_err(), ClientError::Busy);
    client.cancel();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), operation)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err(),
        ClientError::Cancelled
    );
    drop(connection);
}
