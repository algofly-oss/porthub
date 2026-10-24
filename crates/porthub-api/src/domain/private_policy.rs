//! Allow-only private-network policies. Groups label machines and users; they
//! never grant access without an enabled rule. Public forwarding is separate.
use crate::{
    error::ApiResult,
    input::Model,
    input_compat::{self, strip, text, truthy},
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    sync::LazyLock,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Selector {
    pub kind: String,
    pub id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub sources: Vec<Selector>,
    pub destinations: Vec<Selector>,
    pub protocol: String,
    pub ports: String,
    pub bidirectional: bool,
    pub enabled: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Book {
    pub name: String,
    pub group_id: String,
    pub enabled: bool,
    pub rules: Vec<Rule>,
    pub revision: i64,
}
#[derive(Debug, Serialize)]
pub struct ConnectionInput {
    pub source_id: String,
    pub destination_id: String,
    pub protocol: String,
    pub port: i64,
}
pub fn parse_connection(raw: Value) -> ApiResult<ConnectionInput> {
    let mut model = model(raw)?;
    let source_id = model.required_string("source_id");
    let destination_id = model.required_string("destination_id");
    let protocol = model.literal("protocol", "tcp", &["tcp", "udp", "icmp"]);
    let port = if model.field(&["port"]).is_some() {
        model.required_integer("port", 1, 65535)
    } else {
        443
    };
    model.finish()?;
    Ok(ConnectionInput {
        source_id,
        destination_id,
        protocol,
        port,
    })
}
pub fn parse_delete(raw: Value) -> ApiResult<i64> {
    let mut model = model(raw)?;
    let revision = model.required_integer("revision", 1, i64::MAX);
    model.finish()?;
    Ok(revision)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Port {
    pub start: u16,
    pub end: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Grant {
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub ports: Vec<Port>,
}
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub rule_id: Option<String>,
    pub book_id: Option<String>,
    pub reason: String,
}

static DECIMAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A\p{Nd}\z").unwrap());
fn decimal(c: char) -> Option<u32> {
    if c.is_ascii_digit() {
        return Some(c as u32 - '0' as u32);
    }
    if !DECIMAL.is_match(&c.to_string()) {
        return None;
    }
    let mut n = 0;
    while char::from_u32(c as u32 - n - 1).is_some_and(|p| DECIMAL.is_match(&p.to_string())) {
        n += 1;
    }
    Some(n % 10)
}
pub fn ports(value: &str) -> Result<Vec<Port>, &'static str> {
    let value = strip(value);
    if ["", "any", "all", "*"].contains(&value.to_lowercase().as_str()) {
        return Ok(Vec::new());
    }
    let number = |part: &str| -> Option<u32> {
        let part = strip(part);
        if !(1..=5).contains(&part.chars().count()) {
            return None;
        }
        part.chars()
            .try_fold(0, |n, c| decimal(c).map(|d| n * 10 + d))
    };
    let syntax = "Use ports such as 22, 443, 8000-8090";
    let mut result = Vec::new();
    for item in value.split(',') {
        let mut parts = item.split('-');
        let start = number(parts.next().unwrap()).ok_or(syntax)?;
        let end = parts
            .next()
            .map(number)
            .unwrap_or(Some(start))
            .ok_or(syntax)?;
        if parts.next().is_some() {
            return Err(syntax);
        }
        if start == 0 || start > end || end > 65535 {
            return Err("Ports must be between 1 and 65535, with ranges in ascending order");
        }
        result.push(Port {
            start: start as u16,
            end: end as u16,
        });
    }
    if result.len() > 64 {
        return Err("Use no more than 64 port entries");
    }
    result.sort_by_key(|p| (p.start, p.end));
    result.dedup();
    Ok(result)
}
pub fn format_ports(ports: &[Port]) -> String {
    ports
        .iter()
        .map(|p| {
            if p.start == p.end {
                p.start.to_string()
            } else {
                format!("{}-{}", p.start, p.end)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}
fn model(raw: Value) -> ApiResult<Model> {
    let raw = input_compat::dictionary(raw.clone())
        .map(Value::Object)
        .unwrap_or(raw);
    Model::new(raw)
}
fn string(model: &mut Model, key: &str, min: usize, max: usize) -> String {
    let value = model.required_string(key);
    model.string_length(key, &value, min, Some(max));
    value
}
fn boolean(model: &mut Model, key: &str, default: bool) -> bool {
    if model.field(&[key]).is_some() {
        model.required_bool(key)
    } else {
        default
    }
}
fn selectors(model: &mut Model, key: &str) -> Vec<Selector> {
    let mut result = Vec::new();
    for mut child in model.objects(key, true, 1, 32) {
        if !child.is_valid() {
            model.merge(child);
            continue;
        }
        let kind = if child.field(&["kind"]).is_none() {
            child.required_string("kind")
        } else {
            child.literal("kind", "", &["machine", "user", "group", "all"])
        };
        let id = string(&mut child, "id", 1, 64);
        if child.field_valid("id") && kind == "all" && id != "machines" {
            child.add("id", "Use id \"machines\" for all machines", "value_error");
        }
        if child.is_valid() {
            result.push(Selector { kind, id });
        }
        model.merge(child);
    }
    result
}
fn rule(model: &mut Model) -> Rule {
    let id = string(model, "id", 1, 64);
    let name = string(model, "name", 1, 80);
    if model.field_valid("name") && strip(&name).is_empty() {
        model.add("name", "A rule name is required", "value_error");
    }
    let sources = selectors(model, "sources");
    let destinations = selectors(model, "destinations");
    let protocol = model.literal("protocol", "tcp", &["any", "tcp", "udp", "icmp"]);
    let raw_ports = if model.field(&["ports"]).is_some() {
        string(model, "ports", 0, 512)
    } else {
        String::new()
    };
    let raw_ports = if model.field_valid("ports") {
        raw_ports
    } else {
        String::new()
    };
    let bidirectional = boolean(model, "bidirectional", false);
    let enabled = boolean(model, "enabled", true);
    let normalized = match ports(&raw_ports) {
        Ok(ranges) if !ranges.is_empty() && protocol != "tcp" && protocol != "udp" => {
            model.add(
                "__root__",
                "Port restrictions require TCP or UDP",
                "value_error",
            );
            String::new()
        }
        Ok(ranges) => format_ports(&ranges),
        Err(message) => {
            model.add("__root__", message, "value_error");
            String::new()
        }
    };
    Rule {
        id,
        name: strip(&name).into(),
        sources,
        destinations,
        protocol,
        ports: normalized,
        bidirectional,
        enabled,
    }
}
pub fn parse_rule(raw: Value) -> ApiResult<Rule> {
    let mut model = model(raw)?;
    let result = rule(&mut model);
    model.finish()?;
    Ok(result)
}
pub fn parse_book(raw: Value) -> ApiResult<Book> {
    let mut model = model(raw)?;
    let name = string(&mut model, "name", 1, 80);
    if model.field_valid("name") && strip(&name).is_empty() {
        model.add("name", "A rule-book name is required", "value_error");
    }
    let group_id = string(&mut model, "group_id", 1, 64);
    let enabled = boolean(&mut model, "enabled", true);
    let mut rules = Vec::new();
    for mut child in model.objects("rules", false, 0, 100) {
        if child.is_valid() {
            rules.push(rule(&mut child));
        }
        model.merge(child);
    }
    if model.field_valid("rules") {
        let mut seen = HashSet::new();
        if rules.iter().any(|r| !seen.insert(&r.id)) {
            model.add(
                "rules",
                "Rule identifiers must be unique inside a rule book",
                "value_error",
            );
        }
    }
    let revision = if model.field(&["revision"]).is_some() {
        model.required_integer("revision", 0, i64::MAX)
    } else {
        0
    };
    model.finish()?;
    Ok(Book {
        name: strip(&name).into(),
        group_id,
        enabled,
        rules,
        revision,
    })
}

fn field(value: &Value, key: &str) -> String {
    text(&value[key])
}
fn enabled(value: &Value) -> bool {
    value.get("enabled").is_none_or(truthy)
}
fn revoked(value: &Value) -> bool {
    truthy(&value["private_owner_revoked"])
}
pub fn entity_matches(
    selector: &Selector,
    machine: &Value,
    groups: &HashMap<String, Value>,
) -> bool {
    if selector.kind == "all" {
        return true;
    }
    if selector.kind == "machine" {
        return field(machine, "_id") == selector.id;
    }
    let owner = if truthy(&machine["private_owner_id"]) {
        field(machine, "private_owner_id")
    } else {
        field(machine, "user_id")
    };
    if selector.kind == "user" {
        return owner == selector.id;
    }
    let Some(group) = groups
        .get(&selector.id)
        .filter(|_| selector.kind == "group")
    else {
        return false;
    };
    let ids = if truthy(&machine["group_ids"]) {
        machine["group_ids"].as_array().cloned().unwrap_or_default()
    } else if truthy(&machine["group_id"]) {
        vec![machine["group_id"].clone()]
    } else {
        Vec::new()
    };
    ids.iter().any(|id| text(id) == selector.id)
        || group["user_ids"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|id| text(id) == owner)
}
fn matched(selectors: &[Selector], machine: &Value, groups: &HashMap<String, Value>) -> bool {
    selectors.iter().any(|s| entity_matches(s, machine, groups))
}
fn rules(book: &Value) -> impl Iterator<Item = Rule> + '_ {
    book["rules"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|raw| parse_rule(raw.clone()).ok())
}
pub fn evaluate(
    source: &Value,
    destination: &Value,
    protocol: &str,
    port: i64,
    books: &[Value],
    groups: &HashMap<String, Value>,
) -> Decision {
    let deny = |reason: &str| Decision {
        allowed: false,
        rule_id: None,
        book_id: None,
        reason: reason.into(),
    };
    if source.is_null()
        || destination.is_null()
        || source["enabled"] == false
        || destination["enabled"] == false
        || revoked(source)
        || revoked(destination)
    {
        return deny("Both machines must be enabled");
    }
    if field(source, "user_id") != field(destination, "user_id") {
        return deny("Machines belong to different workspaces");
    }
    if !["tcp", "udp", "icmp"].contains(&protocol) {
        return deny("Unsupported protocol or invalid port");
    }
    if protocol != "icmp" && !(1..=65535).contains(&port) {
        return deny("Port is outside the supported range");
    }
    for book in books.iter().filter(|b| {
        enabled(b)
            && groups.contains_key(&field(b, "group_id"))
            && field(b, "user_id") == field(source, "user_id")
    }) {
        for rule in
            rules(book).filter(|r| r.enabled && (r.protocol == "any" || r.protocol == protocol))
        {
            let ranges = ports(&rule.ports).expect("validated ports");
            if !ranges.is_empty()
                && !ranges
                    .iter()
                    .any(|p| i64::from(p.start) <= port && port <= i64::from(p.end))
            {
                continue;
            }
            let pair =
                |a, b| matched(&rule.sources, a, groups) && matched(&rule.destinations, b, groups);
            if pair(source, destination) || rule.bidirectional && pair(destination, source) {
                return Decision {
                    allowed: true,
                    rule_id: Some(rule.id),
                    book_id: Some(field(book, "_id")),
                    reason: rule.name,
                };
            }
        }
    }
    deny("No enabled rule allows this connection")
}
pub fn compile(machines: &[Value], books: &[Value], groups: &HashMap<String, Value>) -> Vec<Grant> {
    compile_inner(machines, books, groups, None)
}
/// Per-client snapshots need only incident grants. Restrict pairs before
/// expansion instead of constructing and filtering the full workspace mesh.
pub fn compile_for(
    machines: &[Value],
    books: &[Value],
    groups: &HashMap<String, Value>,
    machine: &str,
) -> Vec<Grant> {
    compile_inner(machines, books, groups, Some(machine))
}
fn compile_inner(
    machines: &[Value],
    books: &[Value],
    groups: &HashMap<String, Value>,
    scope: Option<&str>,
) -> Vec<Grant> {
    let active: Vec<_> = machines
        .iter()
        .filter(|m| enabled(m) && !revoked(m))
        .collect();
    let mut grants = Vec::new();
    let mut seen = HashSet::new();
    for book in books
        .iter()
        .filter(|b| enabled(b) && groups.contains_key(&field(b, "group_id")))
    {
        for rule in rules(book).filter(|r| r.enabled) {
            let select = |selectors: &[Selector]| {
                active
                    .iter()
                    .copied()
                    .filter(|m| {
                        field(m, "user_id") == field(book, "user_id")
                            && matched(selectors, m, groups)
                    })
                    .collect::<Vec<_>>()
            };
            let sources = select(&rule.sources);
            let destinations = select(&rule.destinations);
            let scoped_destinations: Vec<_> = destinations
                .iter()
                .copied()
                .filter(|m| scope.is_some_and(|id| field(m, "_id") == id))
                .collect();
            let ranges = ports(&rule.ports).expect("validated ports");
            for source in &sources {
                let destinations = if scope.is_none_or(|id| field(source, "_id") == id) {
                    &destinations
                } else {
                    &scoped_destinations
                };
                for destination in destinations {
                    let pairs = if rule.bidirectional {
                        vec![(*source, *destination), (*destination, *source)]
                    } else {
                        vec![(*source, *destination)]
                    };
                    for (left, right) in pairs {
                        if left["_id"] == right["_id"] {
                            continue;
                        }
                        let source = field(left, "_id");
                        let destination = field(right, "_id");
                        if seen.insert((
                            source.clone(),
                            destination.clone(),
                            rule.protocol.clone(),
                            rule.ports.clone(),
                        )) {
                            grants.push(Grant {
                                source,
                                destination,
                                protocol: rule.protocol.clone(),
                                ports: ranges.clone(),
                            });
                        }
                    }
                }
            }
        }
    }
    grants
}
