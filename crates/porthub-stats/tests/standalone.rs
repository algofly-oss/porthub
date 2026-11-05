use serde_json::Value;
use std::process::Command;
fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_porthub-stats"))
}
#[test]
fn independent_process_sampler_and_snapshot_input_need_no_core_or_gateway() {
    let output = command()
        .args(["--once", "--json", "--pid", &std::process::id().to_string()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["agents"][0]["process"]["pid"], std::process::id());
    assert!(value["agents"][0]["process"]["rss_bytes"].as_u64().unwrap() > 0);
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("snapshot.json");
    std::fs::write(&path, r#"{"agents":[{"registration":"fixture","state":"running","process":{"pid":7,"start_time":1}}]}"#).unwrap();
    let output = command()
        .args(["--once", "--json", "--input"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["agents"][0]["registration"], "fixture");
    std::fs::write(
        &path,
        r#"{"agents":[{"registration":"duplicate"},{"registration":"duplicate"}]}"#,
    )
    .unwrap();
    assert!(!command()
        .args(["--once", "--input"])
        .arg(path)
        .output()
        .unwrap()
        .status
        .success());
    let oversized = root.path().join("oversized.json");
    let rows: Vec<_> = (0..129)
        .map(|id| serde_json::json!({"registration":id.to_string()}))
        .collect();
    std::fs::write(
        &oversized,
        serde_json::to_vec(&serde_json::json!({"agents":rows})).unwrap(),
    )
    .unwrap();
    assert!(!command()
        .args(["--once", "--input"])
        .arg(&oversized)
        .output()
        .unwrap()
        .status
        .success());
    assert!(!command()
        .args(["--interval", "NaN"])
        .output()
        .unwrap()
        .status
        .success());
}
