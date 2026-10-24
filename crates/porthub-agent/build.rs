fn main() {
    println!("cargo:rerun-if-env-changed=TARGET");
    let target = std::env::var("TARGET").expect("Cargo supplies the compilation target");
    println!("cargo:rustc-env=PORTHUB_RUST_TARGET={target}");
}
