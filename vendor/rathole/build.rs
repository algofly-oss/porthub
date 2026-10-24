// PortHub: generate embedded Rathole metadata without a host libgit2 dependency.
// PortHub's release identity is embedded separately through PORTHUB_VERSION.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    for (output, input) in [
        ("VERGEN_BUILD_SEMVER", "CARGO_PKG_VERSION"),
        ("VERGEN_CARGO_TARGET_TRIPLE", "TARGET"),
        ("VERGEN_CARGO_PROFILE", "PROFILE"),
    ] {
        println!("cargo:rustc-env={output}={}", std::env::var(input).unwrap());
    }
    // Avoid non-reproducible wall-clock metadata or probing an enclosing repo.
    println!("cargo:rustc-env=VERGEN_BUILD_TIMESTAMP=not-recorded");
    let mut features: Vec<_> = std::env::vars()
        .filter_map(|(key, _)| key.strip_prefix("CARGO_FEATURE_").map(str::to_owned))
        .collect();
    features.sort_unstable();
    println!(
        "cargo:rustc-env=VERGEN_CARGO_FEATURES={}",
        features.join(",")
    );
}
