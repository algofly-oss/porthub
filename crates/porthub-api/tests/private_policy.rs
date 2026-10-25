//! Original Python/Pydantic fixtures; tests execute native Rust validation,
//! evaluation and grant compilation.
use porthub_api::domain::private_policy::{self as policy, Grant};
use serde_json::{json, Value};
use std::collections::HashMap;
fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/private-policy.json")).unwrap()
}

#[test]
fn private_rule_models_match_original_validation_and_normalization() {
    let data = vectors();
    let mut failures = Vec::new();
    for case in data["models"].as_array().unwrap() {
        let raw = serde_json::from_str(case["body"].as_str().unwrap()).unwrap();
        let result = match case["model"].as_str().unwrap() {
            "AccessRule" => policy::parse_rule(raw).map(|v| serde_json::to_value(v).unwrap()),
            "RuleBook" => policy::parse_book(raw).map(|v| serde_json::to_value(v).unwrap()),
            "DeleteBook" => policy::parse_delete(raw).map(|revision| json!({"revision":revision})),
            "ConnectionTest" => {
                policy::parse_connection(raw).map(|v| serde_json::to_value(v).unwrap())
            }
            _ => unreachable!(),
        };
        let result = result.unwrap_or_else(|error| json!({"detail":error.detail}));
        if result != case["response"] {
            failures.push(format!(
                "{}\nactual: {}\nexpected: {}",
                case["body"], result, case["response"]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

#[test]
fn private_port_ranges_match_original_syntax_unicode_and_limits() {
    for case in vectors()["ports"].as_array().unwrap() {
        let result = policy::ports(case["value"].as_str().unwrap());
        if let Some(expected) = case.get("error") {
            assert_eq!(result.unwrap_err(), expected.as_str().unwrap());
        } else {
            assert_eq!(
                json!(result
                    .unwrap()
                    .iter()
                    .map(|p| vec![p.start, p.end])
                    .collect::<Vec<_>>()),
                case["ranges"]
            );
        }
    }
}

#[test]
fn private_decisions_and_compiled_grants_match_original_and_fail_closed() {
    let data = vectors();
    let data = &data["policy"];
    let machines = data["machines"].as_array().unwrap();
    let books = data["books"].as_array().unwrap();
    let groups: HashMap<String, Value> = serde_json::from_value(data["groups"].clone()).unwrap();
    let by_id: HashMap<_, _> = machines
        .iter()
        .map(|m| (m["_id"].as_str().unwrap(), m))
        .collect();
    for case in data["decisions"].as_array().unwrap() {
        let decision = policy::evaluate(
            by_id[case["source"].as_str().unwrap()],
            by_id[case["destination"].as_str().unwrap()],
            case["protocol"].as_str().unwrap(),
            case["port"].as_i64().unwrap(),
            books,
            &groups,
        );
        assert_eq!(
            serde_json::to_value(decision).unwrap(),
            case["result"],
            "{case}"
        );
    }
    let grants = policy::compile(machines, books, &groups);
    assert_eq!(json!(grants), data["grants"]);
    for machine in machines {
        let id = machine["_id"].as_str().unwrap();
        let scoped = policy::compile_for(machines, books, &groups, id);
        let expected = grants
            .iter()
            .filter(|g| g.source == id || g.destination == id)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(scoped, expected);
    }
    assert!(policy::compile(machines, &[], &groups).is_empty());
    assert!(policy::compile(machines, books, &HashMap::new()).is_empty());
    for source in machines {
        for destination in machines {
            // Preserve the historical preview distinction for enabled:0. Actual
            // compilation excludes every falsy machine, including this fixture.
            if source["_id"] == destination["_id"]
                || source["_id"] == "h"
                || destination["_id"] == "h"
            {
                continue;
            }
            for protocol in ["tcp", "udp", "icmp"] {
                for port in [22, 23, 53, 8000, 8002, 8003] {
                    let expected =
                        policy::evaluate(source, destination, protocol, port, books, &groups)
                            .allowed;
                    let actual = grants.iter().any(|g| {
                        g.source == source["_id"].as_str().unwrap()
                            && g.destination == destination["_id"].as_str().unwrap()
                            && (g.protocol == protocol || g.protocol == "any")
                            && (g.ports.is_empty()
                                || g.ports.iter().any(|p| {
                                    i64::from(p.start) <= port && port <= i64::from(p.end)
                                }))
                    });
                    assert_eq!(
                        actual, expected,
                        "{} -> {} {protocol}/{port}",
                        source["_id"], destination["_id"]
                    );
                }
            }
        }
    }
    let invalid = vec![
        json!({"user_id":"ws","group_id":"dev","rules":[{"id":"broken","name":"Broken","sources":[],"destinations":[{"kind":"all","id":"machines"}]}]}),
    ];
    assert!(policy::compile(machines, &invalid, &groups).is_empty());
    let _: Vec<Grant> = grants;
}
