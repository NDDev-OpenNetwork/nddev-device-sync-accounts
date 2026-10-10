# nddev-device-sync-accounts

Rust identity client for [NDDev OpenNetwork](https://nddev.ai), AGPL-3.0-only.
Email OTP and GitHub sign-in use protocol v2. Tokens stay in native credential
stores; the client exposes only session metadata and bounded sign-in progress.
Harness profiles, vault recovery and device enrollment are not implemented here.

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

Linux uses Secret Service, Android uses Android Keystore-encrypted preferences
with an application-context JNI initializer, Apple uses Keychain and Windows
uses Credential Manager. Platform declarations are not platform acceptance.
The Flutter bridge must never export the transport `SessionIssued` or
`GithubStart` secret fields. Use `View` only. Never log tokens, OTPs or raw bodies.
