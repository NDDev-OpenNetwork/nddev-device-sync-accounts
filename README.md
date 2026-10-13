# nddev-device-sync-accounts

Rust callers may capture `local_use_fence` and call `validate_local_use` around
external awaits. The opaque handle binds this client/cancellation lifetime to
the existing durable authorization generation, protected session binding and
scope. It has no Debug/serialization/FFI and contains no raw token. Checks reuse
the current local expiry/revocation/logout policy; they do not refresh or extend
authority, or make an already sent external request atomically revocable.

Rust identity client for [NDDev OpenNetwork](https://nddev.ai), AGPL-3.0-only.
Email OTP, GitHub and passkey sign-in use protocol v2. Native tokens stay in credential
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

The WebAssembly adapter uses the same Rust identity/device rules and signed wire
protocol. It restricts fetches to the application origin, rejects redirects and
keeps the NDS session in a Secure/HttpOnly cookie. Browser credential records use
authenticated encryption under a non-extractable Web Crypto key in IndexedDB;
raw bearer tokens cannot be persisted there. This is browser-profile protection,
not an OS keychain or protection from compromised same-origin script.

After real session and active-device verification, the client can restore a
scoped offline authorization until the original session expiry. Two protected
grant slots and an atomic generation pointer preserve the previous grant across
an interrupted replacement. The metadata pointer contains no credentials.
`View` distinguishes current server verification, cached offline authorization
and a locally completed logout awaiting server revocation. A known local logout
prevents automatic reuse of a retained cookie. Browser logout removes cached
vault keys/grants while preserving device identity and encrypted unsent data.
`authorize_local` is the local secret/replica consumer gate, including changes
made by another process/tab. Offline availability does not assert server freshness.

`just wasm-check` compiles the browser adapter. Actual browser cookie, native
keyring, offline restart and later pipeline acceptance remain separate gates.

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

Owners can list passkey fingerprints/registration times and remove a credential
through the native client. Removal requires a fresh server-verified session and
returns the committed current-session revocation result directly. A subsequent
ordinary refresh removes a revoked cached bearer; vault and device keys persist.
The browser acceptance exercises two actual virtual authenticators, selective
credential/session revocation, idempotent absence, and preservation of OTP login.
Physical authenticator qualification is separate.

Browser telemetry uses the SDK's authenticated-scope IndexedDB spool. RAM ingress
staging runs independently of the common native/browser HTTP sender; a stalled
request cannot block new durable batches. Retry counters survive page restart,
and sender locks are released during backoff or backgrounding. The delivery view
reports the browser's last payload-write readiness separately from transport
policy and acknowledgements. A readable store does not prove quota recovery.
Scope changes stop the sender before old queued data can acquire another owner.
