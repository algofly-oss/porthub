fn main() {
    println!("cargo:rerun-if-env-changed=CUDA_PATH");
    if std::env::var_os("CARGO_FEATURE_SPEECH_CUDA").is_some() {
        let root = std::env::var("CUDA_PATH").unwrap_or_else(|_| "/usr/local/cuda".into());
        let library = if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
            "lib/x64"
        } else {
            "lib64"
        };
        println!("cargo:rustc-link-search=native={root}/{library}");
        println!("cargo:rustc-link-search=native={root}/{library}/stubs");
        // transcribe-cpp's static ggml CUDA archive needs its runtime and BLAS dependencies.
        for name in ["cudart", "cublas", "cublasLt", "cuda"] {
            println!("cargo:rustc-link-lib=dylib={name}");
            println!("cargo:rustc-link-arg-examples=-l{name}");
        }
    }
}
