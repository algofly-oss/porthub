#[path = "../build_support.rs"]
mod build_support;

fn archive(bytes: &[u8]) -> Vec<u8> {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut archive = tar::Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o400);
    header.set_cksum();
    archive
        .append_data(&mut header, "manifest.json", bytes)
        .unwrap();
    archive.into_inner().unwrap().finish().unwrap()
}
#[test]
fn embedded_runtime_requires_exact_target_without_catalog_aliases() {
    for target in [
        "arm-unknown-linux-musleabihf",
        "armv7-unknown-linux-musleabihf",
        "x86_64-unknown-linux-musl",
    ] {
        let bytes = archive(
            serde_json::to_string(&serde_json::json!({"target":target}))
                .unwrap()
                .as_bytes(),
        );
        assert!(build_support::validate_target(&bytes, target).is_ok());
        assert!(
            build_support::validate_target(&bytes, &target.replace("linux-musl", "linux-gnu"))
                .is_err()
        );
    }
}
#[test]
fn invalid_or_oversized_runtime_manifest_is_rejected() {
    assert!(build_support::validate_target(b"not gzip", "target").is_err());
    assert!(build_support::validate_target(&archive(b"not JSON"), "target").is_err());
    assert!(build_support::validate_target(&archive(&vec![b' '; 32769]), "target").is_err());
}
