//! Original Python/Pydantic 1.10 model fixtures.
//! Validation and normalized output are produced entirely by native Rust.
use porthub_api::domain::connections;
use serde_json::{json, Value};

#[test]
fn firewall_models_preserve_original_validation_and_normalization() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/connection-firewall.json")).unwrap();
    let mut failures = Vec::new();
    for case in fixtures["firewall"].as_array().unwrap() {
        let body: Value = serde_json::from_str(case["body"].as_str().unwrap()).unwrap();
        let result = connections::firewall(body);
        let actual = match result {
            Ok(input) => json!({"ok":serde_json::to_value(input).unwrap()}),
            Err(mut error) => {
                for item in error.detail.as_array_mut().unwrap() {
                    item["loc"].as_array_mut().unwrap().remove(0);
                }
                json!({"errors":error.detail})
            }
        };
        let expected = if case.get("errors").is_some() {
            json!({"errors":case["errors"]})
        } else {
            json!({"ok":case["ok"]})
        };
        if actual != expected {
            failures.push(format!(
                "{}\nactual: {actual}\nexpected: {expected}",
                case["body"]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures
            .iter()
            .take(15)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n\n")
    );
}

#[test]
fn snapshot_models_preserve_original_list_validation() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/connection-firewall.json")).unwrap();
    for case in fixtures["snapshot"].as_array().unwrap() {
        let actual = match connections::snapshot(
            serde_json::from_str(case["body"].as_str().unwrap()).unwrap(),
        ) {
            Ok(value) => json!({"ok":value}),
            Err(mut error) => {
                for item in error.detail.as_array_mut().unwrap() {
                    item["loc"].as_array_mut().unwrap().remove(0);
                }
                json!({"errors":error.detail})
            }
        };
        let expected = if case.get("errors").is_some() {
            json!({"errors":case["errors"]})
        } else {
            json!({"ok":case["ok"]})
        };
        assert_eq!(actual, expected, "{}", case["body"]);
    }
}
