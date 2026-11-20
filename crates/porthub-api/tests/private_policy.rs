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

#[test]
fn exact_pair_compilation_matches_legacy_selectors_without_unrelated_grants() {
    let data=vectors();let data=&data["policy"];
    let machines=data["machines"].as_array().unwrap();let books=data["books"].as_array().unwrap();
    let groups:HashMap<String,Value>=serde_json::from_value(data["groups"].clone()).unwrap();
    for source in machines { for destination in machines {
        let a=source["_id"].as_str().unwrap();let b=destination["_id"].as_str().unwrap();
        let expected:Vec<_>=policy::compile_for(machines,books,&groups,a).into_iter()
            .filter(|g| (g.source==a&&g.destination==b)||(g.source==b&&g.destination==a)).collect();
        assert_eq!(serde_json::to_value(policy::compile_pair(machines,books,&groups,a,b)).unwrap(),
            serde_json::to_value(expected).unwrap(),"pair {a} -> {b}");
    }}
    assert!(policy::compile_pair(machines,books,&groups,"missing","other").is_empty());
}

#[test]
fn compiled_selector_index_matches_pair_rules_with_current_group_and_machine_memberships(){
    let data=vectors();let data=&data["policy"];let machines=data["machines"].as_array().unwrap();let books=data["books"].as_array().unwrap();
    let groups:HashMap<String,Value>=serde_json::from_value(data["groups"].clone()).unwrap();let index=porthub_api::domain::private_rule_index::Index::compile(books).unwrap_or_else(|_|panic!("valid indexed rule fixture"));
    assert!(index.weight_bytes()<16*1024*1024);
    let normalized=|grants:Vec<Grant>|{let mut values=grants.into_iter().map(|g|serde_json::to_string(&g).unwrap()).collect::<Vec<_>>();values.sort();values};
    for a in machines{for b in machines{let expected=policy::compile_pair(machines,books,&groups,a["_id"].as_str().unwrap(),b["_id"].as_str().unwrap());assert_eq!(normalized(index.pair(a,b,&groups)),normalized(expected));}}
    assert!(index.pair(&machines[0],&machines[1],&HashMap::new()).is_empty());
}

#[test]
fn a_wildcard_bidirectional_rule_only_opens_tcp_and_udp_toward_a_virtual_host() {
    let source = json!({"_id": "condor", "user_id": "owner"});
    let target = json!({"_id": "via-luna", "user_id": "owner", "kind": "virtual_host"});
    let machines = vec![source.clone(), target.clone()];
    let all = json!([{"kind": "all", "id": "machines"}]);
    let books = vec![json!({"_id":"book","user_id":"owner","group_id":"test",
        "rules":[{"id":"all","name":"Allow both directions","sources":all,"destinations":all,
            "protocol":"any","ports":"","bidirectional":true}]})];
    let groups = HashMap::from([("test".to_owned(), json!({"_id":"test"}))]);
    let index = porthub_api::domain::private_rule_index::Index::compile(&books).unwrap_or_else(|_| panic!("valid virtual host policy"));
    for grants in [
        policy::compile_for(&machines, &books, &groups, "condor"),
        index.pair(&source, &target, &groups),
        index.pair(&target, &source, &groups),
    ] {
        assert!(grants.iter().all(|g| g.source == "condor" && g.destination == "via-luna"));
        let mut protocols: Vec<_> = grants.iter().map(|g| g.protocol.as_str()).collect();
        protocols.sort_unstable();
        assert_eq!(protocols, ["tcp", "udp"]);
    }
    assert!(!policy::evaluate(&target, &source, "tcp", 443, &books, &groups).allowed);
    assert!(!policy::evaluate(&source, &target, "icmp", 0, &books, &groups).allowed);
    assert!(policy::evaluate(&source, &target, "udp", 53, &books, &groups).allowed);
}
