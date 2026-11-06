fn main() {
    println!("cargo:rerun-if-env-changed=TARGET");
    let target = std::env::var("TARGET").expect("Cargo supplies the compilation target");
    println!("cargo:rustc-env=PORTHUB_RUST_TARGET={target}");
    // Windows' default 1 MiB main stack cannot hold the debug CLI dispatch
    // future. Reserve Unix-equivalent space; pages are committed on demand.
    if target.ends_with("windows-msvc") {
        println!("cargo:rustc-link-arg-bin=porthub=/STACK:8388608");
    }
}
