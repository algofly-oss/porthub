//! Stable private DNS names. Address/name hints never replace enrolled peer IDs.
use crate::store;
use mongodb::bson::{Bson, Document};
use std::collections::{HashMap, HashSet};

fn key(value: Option<&Bson>) -> String {
    match value {
        Some(Bson::ObjectId(id)) => format!("oid:{id}"),
        Some(Bson::String(id)) => format!("str:{id}"),
        other => format!("other:{other:?}"),
    }
}
pub fn label(value: Option<&Bson>) -> String {
    let text = match value {
        Some(Bson::String(value)) => value.clone(),
        Some(Bson::Null) | None => String::new(),
        Some(value) => store::json(value).to_string(),
    };
    let mut output = String::new();
    for c in text.to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            output.push(c);
        } else if !output.is_empty() && !output.ends_with('-') {
            output.push('-');
        }
    }
    output.truncate(output.len().min(48)); // The output contains ASCII only.
    let output = output.trim_end_matches('-');
    if output.is_empty() {
        "machine".into()
    } else {
        output.into()
    }
}

pub struct Names {
    pub primary: HashMap<String, String>,
    pub aliases: HashMap<String, Vec<String>>,
}

pub fn assign(machines: &[Document], peers: &[Document]) -> Names {
    let by_id: HashMap<_, _> = machines.iter().map(|m| (key(m.get("_id")), m)).collect();
    let mut primary = HashMap::new();
    let mut taken = HashSet::new();
    for peer in peers {
        let name = store::string(peer, "hostname");
        if !name.is_empty() {
            primary.insert(store::id(peer.get("_id")), name.to_owned());
            taken.insert(name.to_owned());
        }
    }
    let mut ordered: Vec<_> = peers.iter().collect();
    ordered.sort_by_key(|p| {
        (
            p.get("created_at")
                .map(store::json)
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default(),
            store::id(p.get("_id")),
        )
    });
    for peer in &ordered {
        let id = store::id(peer.get("_id"));
        if primary.contains_key(&id) {
            continue;
        }
        let mut name = label(
            by_id
                .get(&key(peer.get("machine_id")))
                .and_then(|m| m.get("name")),
        );
        if taken.contains(&name) {
            let machine_id = store::id(peer.get("machine_id"));
            let suffix: String = machine_id
                .chars()
                .rev()
                .take(4)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            name = format!(
                "{}-{suffix}",
                name[..name.len().min(43)].trim_end_matches('-')
            );
            // Legacy four-character ID suffixes can also collide. Preserve
            // existing unambiguous names and disambiguate only the extra peer.
            let stem = name.clone();
            let mut serial = 2usize;
            while taken.contains(&name) {
                let suffix = format!("-{serial}");
                name = format!(
                    "{}{}",
                    stem[..stem.len().min(48 - suffix.len())].trim_end_matches('-'),
                    suffix
                );
                serial += 1;
            }
        }
        taken.insert(name.clone());
        primary.insert(id, name);
    }
    for machine in machines {
        taken.insert(label(machine.get("name")));
    }
    let mut aliases = HashMap::new();
    for peer in ordered {
        let mut names = Vec::new();
        if let Some(machine) = by_id.get(&key(peer.get("machine_id"))) {
            if let Ok(values) = machine.get_array("aliases") {
                for value in values {
                    let name = label(Some(value));
                    if taken.insert(name.clone()) {
                        names.push(name);
                    }
                }
            }
        }
        aliases.insert(store::id(peer.get("_id")), names);
    }
    Names { primary, aliases }
}
