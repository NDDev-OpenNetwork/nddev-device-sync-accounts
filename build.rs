// wasm-bindgen embeds these sources; Cargo must invalidate the WASM unit
// when an adapter changes, even if no Rust source changed.
fn main() {
    println!("cargo::rerun-if-changed=src/browser_credentials.js");
    println!("cargo::rerun-if-changed=src/browser_http.js");
}
