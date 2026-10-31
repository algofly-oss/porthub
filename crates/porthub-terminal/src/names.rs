//! Friendly names are deliberately one lowercase word so terminal double-click
//! selection copies the whole name. Names are labels, never authorization.
use anyhow::{bail, Result};
use rand::seq::SliceRandom;

const ADJECTIVES: &[&str] = &[
    "amber", "brave", "bright", "calm", "clear", "clever", "coral", "crisp", "daring", "eager",
    "gentle", "golden", "happy", "indigo", "jolly", "kind", "lively", "lucky", "mellow", "merry",
    "nimble", "noble", "quiet", "rapid", "silver", "steady", "sunny", "swift", "tidy", "vivid",
    "warm", "wise",
];
const ANIMALS: &[&str] = &[
    "badger", "bear", "bison", "crane", "deer", "dolphin", "dove", "eagle", "falcon", "finch",
    "fox", "gecko", "heron", "ibis", "koala", "lark", "lemur", "lion", "lynx", "marten", "otter",
    "owl", "panda", "puffin", "quail", "raven", "robin", "seal", "swift", "tiger", "whale", "wren",
];

/// Check the owner's persisted session names, including detached workspaces.
/// The caller must hold its session registry lock through creation.
pub fn generate(mut exists: impl FnMut(&str) -> bool) -> Result<String> {
    let mut rng = rand::thread_rng();
    let mut candidates: Vec<_> = ADJECTIVES
        .iter()
        .flat_map(|adjective| {
            ANIMALS
                .iter()
                .map(move |animal| format!("{adjective}{animal}"))
        })
        .collect();
    candidates.shuffle(&mut rng);
    for name in candidates {
        if !exists(&name) {
            return Ok(name);
        }
    }
    bail!("all generated session names are in use; choose a name with --name")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_whole_word_and_checks_existing_names() {
        let available = "quietfalcon";
        assert_eq!(generate(|name| name != available).unwrap(), available);
        let name = generate(|_| false).unwrap();
        assert!(name.bytes().all(|byte| byte.is_ascii_lowercase()));
    }

    #[test]
    fn exhausted_namespace_returns_actionable_error() {
        assert!(generate(|_| true)
            .unwrap_err()
            .to_string()
            .contains("--name"));
    }
}
