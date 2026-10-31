//! The C multiplexer runtime is cached independently of Rust compilation, then
//! embedded in the CLI. Running hosts never invoke a compiler or download code.
use anyhow::{ensure, Result};
use std::path::Path;

static BUNDLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/terminal.bundle.tar.gz"));

pub fn install(cache: &Path) -> Result<porthub_terminal::runtime::Runtime> {
    ensure!(!BUNDLE.is_empty(), "this development build has no terminal runtime; set PORTHUB_TERMINAL_BUNDLE when compiling");
    // Both Linux Rust ABIs embed the same self-contained musl helper. The helper
    // cache follows the native compiler target, independent of the CLI linker.
    let helper_target = env!("PORTHUB_RUST_TARGET").replace("linux-musl", "linux-gnu");
    porthub_terminal::runtime::install(BUNDLE, cache, &helper_target)
}
