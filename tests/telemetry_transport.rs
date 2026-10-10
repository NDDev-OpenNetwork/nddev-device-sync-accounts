#![cfg(feature = "development-http")]
use nddev_device_sync_accounts::{ClientError, IdentityClient};
use nddev_device_sync_telemetry::{Config, DebugWindow};
use opentelemetry::trace::TracerProvider;
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tracing::instrument::WithSubscriber;

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        assert!(output.len() + bytes.len() < 65_536);
        output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn actual_socket_propagates_the_same_trace_as_bounded_client_events() {
    let capture = Capture(Arc::new(Mutex::new(Vec::new())));
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
    let (subscriber, control) = nddev_device_sync_telemetry::subscriber(
        Config {
            service: "nds-client-acceptance".into(),
            version: "0.0.1-alpha.9".into(),
            repository: "NDDev-OpenNetwork/nddev-device-sync-accounts".into(),
            commit: "unknown".into(),
            channel: "alpha".into(),
            standards: "v0.0.1-alpha.9".into(),
            environment: "test".into(),
            target_prefixes: vec!["nds_accounts".into()],
            default_module: "accounts".into(),
            debug: Some(DebugWindow {
                scope: "http".into(),
                duration: Duration::from_secs(30),
                events: 1,
            }),
        },
        capture.clone(),
        provider.tracer("client-acceptance"),
    )
    .unwrap();
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = Arc::new(
        IdentityClient::new(&format!("http://{}/", socket.local_addr().unwrap())).unwrap(),
    );
    let task_client = client.clone();
    let operation = tokio::spawn(
        async move { task_client.refresh().await }
            .with_subscriber(tracing::Dispatch::new(subscriber)),
    );
    // A real accepted TCP connection deliberately never responds. Inspect only
    // the transport context; there is no simulated successful server behavior.
    let (connection, context) = tokio::task::spawn_blocking(move || {
        socket.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut connection, _) = loop {
            match socket.accept() {
                Ok(connection) => break connection,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("bounded accept failed: {}", error.kind()),
            }
        };
        connection
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            assert!(bytes.len() < 8192);
            let mut byte = [0];
            connection.read_exact(&mut byte).unwrap();
            bytes.push(byte[0]);
        }
        let headers = String::from_utf8(bytes).unwrap();
        let context = headers
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("traceparent")
                    .then(|| value.trim().to_owned())
            })
            .unwrap();
        (connection, context)
    })
    .await
    .unwrap();
    client.cancel();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), operation)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err(),
        ClientError::Cancelled
    );
    drop(connection);
    let output = capture.0.lock().unwrap();
    let events: Vec<serde_json::Value> = output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    let request: Vec<_> = events
        .iter()
        .filter(|event| {
            event["event.name"]
                .as_str()
                .is_some_and(|name| name.starts_with("identity.request_"))
        })
        .collect();
    assert_eq!(request.len(), 2);
    for event in request {
        assert_eq!(event["route"], "/v1/health");
        assert_eq!(event["module"], "accounts");
        assert_eq!(event["scope"], "http");
        assert_eq!(
            context,
            format!(
                "00-{}-{}-01",
                event["trace_id"].as_str().unwrap(),
                event["span_id"].as_str().unwrap()
            )
        );
        assert!(event.get("operation").is_none());
    }
    let flow = events
        .iter()
        .find(|event| event["event.name"] == "identity.refresh")
        .unwrap();
    let parts: Vec<_> = context.split('-').collect();
    assert_eq!(flow["trace_id"], parts[1]);
    assert_ne!(flow["span_id"], parts[2]);
    assert_eq!(flow["error.type"], "cancelled");
    assert_eq!(flow["scope"], "process");
    assert_eq!(control.rejected_fields_or_events(), 0);
    assert_eq!(control.write_failures(), 0);
    assert!(!control.debug_active());
    drop(output);
    provider.shutdown().unwrap();
}
