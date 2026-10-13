#![cfg(feature = "development-http")]
use nddev_device_sync_accounts::{ClientError, IdentityClient};
use nddev_device_sync_telemetry::{
    Config, DebugWindow, ExportFeed,
    client_traces::{AuthenticatedSource, ClientTraces, authenticated_batch},
};
use opentelemetry_proto::tonic::{
    collector::trace::v1::ExportTraceServiceRequest, trace::v1::Span,
};
use prost::Message;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
    let config = config(Some(DebugWindow {
        scope: "http".into(),
        duration: Duration::from_secs(30),
        events: 1,
    }));
    let traces = ClientTraces::new(&config).unwrap();
    let feed = traces.subscribe().unwrap();
    let (subscriber, control) =
        nddev_device_sync_telemetry::subscriber(config, capture.clone(), traces.tracer()).unwrap();
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
    let (connection, context) = accept_request(socket).await;
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
    let spans = exported_spans(&feed);
    let parent = spans
        .iter()
        .find(|span| span_id(span) == flow["span_id"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        parent.status.as_ref().unwrap().code,
        0,
        "cancelled operation must not claim terminal failure"
    );
    traces.shutdown();
}

async fn accept_request(socket: TcpListener) -> (TcpStream, String) {
    tokio::task::spawn_blocking(move || {
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
        // Winsock may inherit the listener's nonblocking mode on accept.
        // This owned blocking reader has one total header deadline.
        connection.set_nonblocking(false).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            assert!(bytes.len() < 8192);
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .expect("bounded header deadline");
            connection.set_read_timeout(Some(remaining)).unwrap();
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
    .unwrap()
}

fn config(debug: Option<DebugWindow>) -> Config {
    Config {
        service: "nddev-device-sync-client".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        repository: "NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-desktop".into(),
        commit: "unknown".into(),
        channel: "alpha".into(),
        standards: "unreleased".into(),
        environment: "test".into(),
        target_prefixes: vec!["nds_accounts".into()],
        default_module: "accounts".into(),
        debug,
    }
}
fn span_id(span: &Span) -> String {
    span.span_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn exported_spans(feed: &ExportFeed) -> Vec<Span> {
    let mut spans = Vec::new();
    while let Some(batch) = feed.take_batch() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let (bytes, count) = authenticated_batch(
            batch.bytes(),
            AuthenticatedSource {
                tenant: "synthetic-tenant",
                user: "synthetic-owner",
                device: "synthetic-device",
            },
            now,
        )
        .unwrap();
        assert_eq!(count, batch.count());
        let decoded = ExportTraceServiceRequest::decode(bytes.as_slice()).unwrap();
        spans.extend(
            decoded
                .resource_spans
                .into_iter()
                .flat_map(|r| r.scope_spans)
                .flat_map(|s| s.spans),
        );
        batch.acknowledge();
    }
    assert!(
        spans
            .iter()
            .all(|span| span.status.as_ref().unwrap().message.is_empty())
    );
    spans
}

#[tokio::test]
async fn real_negative_http_outcomes_preserve_terminal_failure_and_expected_rejection() {
    for (status, body, expected, failed) in [
        (
            "200 OK",
            "SYNTHETIC_PRIVATE_INVALID_RESPONSE",
            ClientError::InvalidResponse,
            true,
        ),
        (
            "429 Too Many Requests",
            r#"{"error":"rate_limited"}"#,
            ClientError::Server("rate_limited".into()),
            false,
        ),
        (
            "503 Service Unavailable",
            r#"{"error":"dependency_unavailable"}"#,
            ClientError::Server("dependency_unavailable".into()),
            true,
        ),
    ] {
        let capture = Capture(Arc::new(Mutex::new(Vec::new())));
        let config = config(None);
        let traces = ClientTraces::new(&config).unwrap();
        let feed = traces.subscribe().unwrap();
        let (subscriber, control) =
            nddev_device_sync_telemetry::subscriber(config, capture.clone(), traces.tracer())
                .unwrap();
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let client =
            IdentityClient::new(&format!("http://{}/", socket.local_addr().unwrap())).unwrap();
        let operation = tokio::spawn(
            async move { client.refresh().await }
                .with_subscriber(tracing::Dispatch::new(subscriber)),
        );
        let (mut connection, context) = accept_request(socket).await;
        // Deliberately invalid/rejected input on a real socket; this is not a
        // substitute for successful backend/native credential acceptance.
        connection
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(
            connection,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), operation)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.unwrap_err(), expected);
        drop(connection);
        let bytes = capture.0.lock().unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("SYNTHETIC_PRIVATE"));
        let events: Vec<serde_json::Value> = bytes
            .split(|b| *b == b'\n')
            .filter(|b| !b.is_empty())
            .map(|b| serde_json::from_slice(b).unwrap())
            .collect();
        let completed = events
            .iter()
            .find(|event| event["event.name"] == "identity.refresh")
            .unwrap();
        assert_eq!(completed["error.type"], expected.code());
        assert_eq!(completed["outcome"], "error");
        assert_eq!(completed["trace_id"], context.split('-').nth(1).unwrap());
        let spans = exported_spans(&feed);
        let parent = spans
            .iter()
            .find(|span| span_id(span) == completed["span_id"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            parent.status.as_ref().unwrap().code,
            if failed { 2 } else { 0 }
        );
        assert_eq!(
            parent
                .trace_id
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            completed["trace_id"].as_str().unwrap()
        );
        assert_eq!(control.rejected_fields_or_events(), 0);
        traces.shutdown();
    }
}
