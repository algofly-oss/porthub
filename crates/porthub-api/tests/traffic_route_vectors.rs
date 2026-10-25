//! Original Python/Pydantic 1.10 model fixtures.
//! Validation and normalized output are produced entirely by native Rust.
use porthub_api::domain::traffic_routes;
use serde_json::{json, Value};

#[test]
fn route_model_preserves_original_normalization_aliases_and_validation_order() {
    let fixtures: Value =
        serde_json::from_str(include_str!("fixtures/traffic-routes.json")).unwrap();
    let mut failures = Vec::new();
    for case in fixtures["route"].as_array().unwrap() {
        let body: Value = serde_json::from_str(case["body"].as_str().unwrap()).unwrap();
        let result = traffic_routes::parse(body);
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
