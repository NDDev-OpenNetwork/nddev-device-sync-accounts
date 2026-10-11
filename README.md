# nddev-device-sync-accounts

Rust identity client for [NDDev OpenNetwork](https://nddev.ai), AGPL-3.0-only.
Email OTP and GitHub sign-in use protocol v2. Tokens stay in native credential
stores; the client exposes only session metadata and bounded sign-in progress.
Harness profiles and vault recovery are not implemented here. Device enrollment, inventory and revocation use the same native session boundary.

Use Rust 1.99.0. `just check` runs formatting, nextest, Clippy and dependency advisory/license gates;
`just native-store` additionally exercises a fresh entry in the actual native
credential service. It requires an unlocked session and never clears a keychain.
`just generate` and `just generated-check` use the immutable `protocol.lock`
source from `NDS_PROTOCOL_SOURCE` (defaults to the adjacent protocol checkout).

HTTPS is required. The opt-in `development-http` feature permits loopback HTTP
in debug builds for isolated local acceptance only; ship without that feature.
HTTP redirects are rejected. Requests and native operations have 15-second
deadlines; overlapping calls return `busy` instead of entering an unbounded queue.
Native OS calls cannot be preempted, so their single admission permit remains
held until the OS call actually returns, including after a caller timeout.
Native read/write/delete outcomes use the same SDK and retain trace context across
the blocking OS worker. A caller wait failure and a later OS completion are distinct;
keys, endpoints, secret values and raw provider errors never enter those events.

Linux uses Secret Service, Android uses Android Keystore-encrypted preferences
with an application-context JNI initializer, Apple uses Keychain and Windows
uses Credential Manager. Platform declarations are not platform acceptance.
The Flutter bridge must never export the transport `SessionIssued` or
`GithubStart` secret fields. Use `View` only. Never log tokens, OTPs or raw bodies.

`telemetry::Delivery` owns signed event/native OTLP delivery for the desktop and
agent consumers. The SDK owns redaction and record lifetimes; the sender checks
operator export policy, pauses in the background and uses bounded backoff with
at most eight failed sends per batch and 30-minute retention. Delivery's own
credential reads and requests remain local diagnostics, outside the export feeds.
Sign-out/termination closes the feeds; transport acknowledgements are reported
separately for logs and actual spans and do not imply searchable delivery.

The ignored `actual_signed_client_delivery_and_incidents` test requires owned
server and observability fixture receipts through `NDS_FIXTURE_RECEIPT` and
`NDS_OBSERVABILITY_FIXTURE_RECEIPT`. It exercises real native credentials, signed
HTTP, PostgreSQL, Vector and searchable OpenObserve spans, incident replay and
resolution, background/resume and absence of recursive export. Fixture credentials
and generated identities remain outside public source.
