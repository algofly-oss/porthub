//! Immutable selector index. This contains rules, NEVER cached identity/member/IP decisions.
//! Callers must validate the current book revision manifest and fresh pair/group memberships.
use super::private_policy::{self, Grant, Rule, Selector};
use crate::{
    error::{ApiError, ApiResult},
    input_compat::{text, truthy},
};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap, HashSet};
const MAX_INDEX_BYTES: usize = 16 * 1024 * 1024;
#[derive(Clone, Hash, PartialEq, Eq)]
struct Key {
    kind: String,
    id: String,
}
struct Entry {
    workspace: String,
    book_group: String,
    rule: Rule,
}
pub struct Index {
    entries: Vec<Entry>,
    sources: HashMap<Key, BTreeSet<usize>>,
    destinations: HashMap<Key, BTreeSet<usize>>,
    bytes: usize,
    groups: BTreeSet<String>,
}
fn field(value: &Value, key: &str) -> String {
    text(&value[key])
}
impl Index {
    pub fn compile(books: &[Value]) -> ApiResult<Self> {
        let mut index = Self {
            entries: vec![],
            sources: HashMap::new(),
            destinations: HashMap::new(),
            bytes: 0,
            groups: BTreeSet::new(),
        };
        for book in books.iter().filter(|b| b.get("enabled").is_none_or(truthy)) {
            let group = field(book, "group_id");
            if index.groups.insert(group.clone()) {
                index.bytes += 64 + group.len();
            }
            for raw in book["rules"].as_array().into_iter().flatten() {
                let Ok(rule) = private_policy::parse_rule(raw.clone()) else {
                    continue;
                };
                if !rule.enabled {
                    continue;
                }
                let id = index.entries.len();
                index.bytes += std::mem::size_of::<Entry>()
                    + group.len()
                    + field(book, "user_id").len()
                    + serde_json::to_vec(&rule).expect("typed rule").len();
                for (selectors, map) in [
                    (&rule.sources, &mut index.sources),
                    (&rule.destinations, &mut index.destinations),
                ] {
                    for selector in selectors {
                        if selector.kind == "group" && index.groups.insert(selector.id.clone()) {
                            index.bytes += 64 + selector.id.len();
                        }
                        let key = Key {
                            kind: selector.kind.clone(),
                            id: selector.id.clone(),
                        };
                        index.bytes += 128 + key.kind.len() + key.id.len() + 32;
                        map.entry(key).or_default().insert(id);
                    }
                }
                if index.bytes > MAX_INDEX_BYTES {
                    return Err(ApiError::bad_request(
                        "Private compiled rule index exceeds resource budget",
                    ));
                }
                index.entries.push(Entry {
                    workspace: field(book, "user_id"),
                    book_group: group.clone(),
                    rule,
                });
            }
        }
        Ok(index)
    }
    pub fn weight_bytes(&self) -> usize {
        self.bytes
    }
    pub fn referenced_groups(&self) -> impl Iterator<Item = &str> {
        self.groups.iter().map(String::as_str)
    }
    fn matches(
        &self,
        machine: &Value,
        groups: &HashMap<String, Value>,
        map: &HashMap<Key, BTreeSet<usize>>,
    ) -> BTreeSet<usize> {
        let mut output = BTreeSet::new();
        let owner = if truthy(&machine["private_owner_id"]) {
            field(machine, "private_owner_id")
        } else {
            field(machine, "user_id")
        };
        let mut keys = vec![
            Key {
                kind: "all".into(),
                id: "machines".into(),
            },
            Key {
                kind: "machine".into(),
                id: field(machine, "_id"),
            },
            Key {
                kind: "user".into(),
                id: owner,
            },
        ];
        for id in &self.groups {
            if private_policy::entity_matches(
                &Selector {
                    kind: "group".into(),
                    id: id.clone(),
                },
                machine,
                groups,
            ) {
                keys.push(Key {
                    kind: "group".into(),
                    id: id.clone(),
                });
            }
        }
        for key in keys {
            if let Some(ids) = map.get(&key) {
                output.extend(ids);
            }
        }
        output
    }
    pub fn pair(
        &self,
        source: &Value,
        destination: &Value,
        groups: &HashMap<String, Value>,
    ) -> Vec<Grant> {
        if source.is_null()
            || destination.is_null()
            || source.get("enabled").is_some_and(|v| !truthy(v))
            || destination.get("enabled").is_some_and(|v| !truthy(v))
            || truthy(&source["private_owner_revoked"])
            || truthy(&destination["private_owner_revoked"])
            || source["_id"] == destination["_id"]
            || source["user_id"] != destination["user_id"]
        {
            return vec![];
        }
        let forward = self
            .matches(source, groups, &self.sources)
            .intersection(&self.matches(destination, groups, &self.destinations))
            .copied()
            .collect::<BTreeSet<_>>();
        let reverse = self
            .matches(destination, groups, &self.sources)
            .intersection(&self.matches(source, groups, &self.destinations))
            .copied()
            .collect::<BTreeSet<_>>();
        let mut seen = HashSet::new();
        let mut output = Vec::new();
        for id in forward.union(&reverse) {
            let entry = &self.entries[*id];
            if entry.workspace != field(source, "user_id")
                || !groups.contains_key(&entry.book_group)
            {
                continue;
            }
            let mut emit = |left: &Value, right: &Value| {
                for protocol in private_policy::grant_protocols(left, right, &entry.rule.protocol) {
                    let key = (
                        field(left, "_id"),
                        field(right, "_id"),
                        protocol.to_owned(),
                        entry.rule.ports.clone(),
                    );
                    if seen.insert(key.clone()) {
                        output.push(Grant {
                            source: key.0,
                            destination: key.1,
                            protocol: key.2,
                            ports: private_policy::ports(&entry.rule.ports).expect("validated ports"),
                        });
                    }
                }
            };
            if forward.contains(id) {
                emit(source, destination);
                if entry.rule.bidirectional {
                    emit(destination, source);
                }
            }
            if reverse.contains(id) {
                emit(destination, source);
                if entry.rule.bidirectional {
                    emit(source, destination);
                }
            }
        }
        output
    }
}
