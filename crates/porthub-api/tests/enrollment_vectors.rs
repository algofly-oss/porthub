//! Original Python/Pydantic compatibility vectors, retained from the Go port's
//! policy/testdata/pydantic_vectors.json. No legacy runtime is used by this test.
use mongodb::bson::Document;
use porthub_api::domain::enrollment::{preferences, Network};
use serde_json::{json, Value};
use std::collections::HashSet;

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/enrollment-vectors.json")).unwrap()
}

#[test]
fn network_preferences_match_original_model_validation() {
    for case in vectors()["models"].as_array().unwrap() {
        let raw: Document = serde_json::from_str(case["body"].as_str().unwrap()).unwrap();
        let actual = match preferences(&raw) {
            Ok((network, suffix)) => json!({"cidr":network.cidr(),"dns_suffix":suffix}),
            Err(error) => json!({"detail":error.detail}),
        };
        assert_eq!(actual, case["response"], "input: {}", case["body"]);
    }
}

#[test]
fn stable_address_allocation_matches_original_machine_addresses() {
    let data = vectors();
    for case in data["addresses"].as_array().unwrap() {
        let occupied: HashSet<String> = case["occupied"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().into())
            .collect();
        let address = Network::parse(case["cidr"].as_str().unwrap())
            .unwrap()
            .allocate(case["machine_id"].as_str().unwrap(), &occupied)
            .unwrap_or_else(|error| panic!("allocation: {}", error.detail));
        assert_eq!(address, case["address"].as_str().unwrap());
    }
    let full = &data["full"];
    let occupied = full["occupied"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().into())
        .collect();
    let result = Network::parse(full["cidr"].as_str().unwrap())
        .unwrap()
        .allocate("overflow", &occupied);
    assert_eq!(
        result.err().unwrap().detail,
        "The private address range is full"
    );
}
