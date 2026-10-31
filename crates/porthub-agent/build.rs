fn main() {
    println!("cargo:rerun-if-env-changed=TARGET");
    let target = std::env::var("TARGET").expect("Cargo supplies the compilation target");
    println!("cargo:rustc-env=PORTHUB_RUST_TARGET={target}");
    println!("cargo:rerun-if-env-changed=PORTHUB_TERMINAL_BUNDLE");
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap())
        .join("terminal.bundle.tar.gz");
    let hosting = target.contains("linux") || target.contains("apple-darwin");
    if hosting {
        if let Some(bundle) = std::env::var_os("PORTHUB_TERMINAL_BUNDLE") {
            let bundle = std::path::PathBuf::from(bundle);
            println!("cargo:rerun-if-changed={}", bundle.display());
            let bytes = std::fs::read(&bundle).expect("read bundled terminal runtime");
            assert!(
                !bytes.is_empty() && bytes.len() <= 8 * 1024 * 1024,
                "invalid terminal runtime bundle size"
            );
            std::fs::write(output, bytes).expect("embed terminal runtime");
            return;
        }
        assert!(std::env::var("PROFILE").as_deref() != Ok("release"),
            "release builds require PORTHUB_TERMINAL_BUNDLE; run scripts/build-terminal-helper.py for this target first");
    }
    std::fs::write(output, []).expect("write empty development terminal bundle");
}
