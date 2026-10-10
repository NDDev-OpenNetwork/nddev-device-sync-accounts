# NDS accounts working contract

Own the Rust NDS identity client and native credential adapters. Domain and
application rules remain in core; protocol schemas own wire DTOs. Generate
consumers from the pinned protocol source, never edit generated files.

Read standarts.lock, module.yaml and the locked engineering/development
standards. Public code is AGPL-3.0-only and generic: no real addresses,
credentials, deployment topology or runtime evidence. Keep session and exchange
tokens private to Rust/native stores; no plaintext fallback, metadata database
or Flutter field may contain them. Harness accounts and vaults are separate.

Preserve live keychains and unrelated dirty work. Tests own only fresh ephemeral
entries. Use bounded requests, cancellation, typed redacted events and errors.
Run just check and real native-store/backend acceptance before claiming support.
No deployment, releases, credential rotation or backup/recovery is implicit.
