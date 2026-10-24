use std::process::Command;

fn output(arguments: &[&str]) -> String {
    let result = Command::new(env!("CARGO_BIN_EXE_porthub"))
        .args(arguments)
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(result.stderr.is_empty());
    String::from_utf8(result.stdout).unwrap()
}

#[test]
fn binary_reports_numeric_release_and_separate_build_provenance() {
    let version = porthub_agent::VERSION;
    let components: Vec<_> = version.split('.').collect();
    assert_eq!(components.len(), 3, "release must use major.minor.patch");
    assert!(components.iter().all(|part| !part.is_empty()
        && part.bytes().all(|byte| byte.is_ascii_digit())
        && (part.len() == 1 || !part.starts_with('0'))));
    let expected = format!("porthub {version}\n");
    assert_eq!(output(&["version"]), expected);
    assert_eq!(output(&["--version"]), expected);
    let verbose = output(&["version", "--verbose"]);
    assert!(verbose.starts_with(&expected));
    assert!(verbose.contains(&format!("\nbuild {}\n", porthub_agent::BUILD_REVISION)));
    assert!(verbose.contains("\ntarget "));
}
