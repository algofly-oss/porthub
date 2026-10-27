//! Domain policy shared by the management server and local DNS responder.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::IpAddr};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub domain: String,
    pub action: Action,
    #[serde(default = "yes")]
    pub include_subdomains: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Block,
}

fn yes() -> bool {
    true
}

pub fn domain(raw: &str) -> Result<String> {
    let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    ensure!(
        name.len() <= 253 && name.contains('.') && name.parse::<IpAddr>().is_err(),
        "Enter a DNS domain, not an IP address or URL"
    );
    ensure!(
        name.split('.').all(|label| !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')),
        "Invalid DNS domain"
    );
    Ok(name)
}

/// The resolver route covers the base domain even for a subdomains-only rule.
pub fn zone(rule: &Rule) -> &str {
    rule.domain.strip_prefix("*.").unwrap_or(&rule.domain)
}

/// Validate the complete replacement before publishing it to the responder.
/// A more specific domain wins; duplicate domains are rejected, never reordered.
pub fn prepare(rules: &[Rule]) -> Result<Vec<Rule>> {
    ensure!(
        rules.len() <= 256,
        "At most 256 DNS rules may apply to a machine"
    );
    let mut result = Vec::with_capacity(rules.len());
    let mut seen = HashSet::new();
    for rule in rules {
        let mut rule = rule.clone();
        rule.domain = if let Some(base) = rule.domain.trim().strip_prefix("*.") {
            format!("*.{}", domain(base)?)
        } else {
            domain(&rule.domain)?
        };
        if rule.domain.starts_with("*.") {
            rule.include_subdomains = true;
        }
        ensure!(
            seen.insert(rule.domain.clone()),
            "Conflicting DNS rules for the same domain"
        );
        result.push(rule);
    }
    result.sort_by(|a, b| {
        zone(b)
            .len()
            .cmp(&zone(a).len())
            // A wildcard specializes the children; its apex remains eligible
            // for the plain-domain rule at the same depth.
            .then(b.domain.starts_with("*.").cmp(&a.domain.starts_with("*.")))
            .then(a.domain.cmp(&b.domain))
    });
    Ok(result)
}

pub fn matching<'a>(rules: &'a [Rule], query: &str) -> Option<&'a Rule> {
    let name = query.trim_end_matches('.');
    rules.iter().find(|rule| {
        let base = zone(rule);
        (!rule.domain.starts_with("*.") && name == base)
            || rule.include_subdomains
                && name
                    .strip_suffix(base)
                    .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_matching_respects_label_boundaries_and_specific_rules() {
        let rules = prepare(&[
            Rule {
                domain: "Example.COM.".into(),
                action: Action::Block,
                include_subdomains: true,
            },
            Rule {
                domain: "allowed.example.com".into(),
                action: Action::Block,
                include_subdomains: false,
            },
        ])
        .unwrap();
        assert!(matches!(
            matching(&rules, "example.com.").unwrap().action,
            Action::Block
        ));
        assert!(matches!(
            matching(&rules, "a.example.com.").unwrap().action,
            Action::Block
        ));
        assert!(matches!(
            matching(&rules, "allowed.example.com.").unwrap().action,
            Action::Block
        ));
        assert!(matching(&rules, "notexample.com.").is_none());
        assert!(matching(&rules, "example.com.evil.test.").is_none());
        assert!(matches!(
            matching(&rules, "a.allowed.example.com.").unwrap().action,
            Action::Block
        ));
    }

    #[test]
    fn address_replacement_actions_are_rejected() {
        assert!(serde_json::from_str::<Rule>(
            r#"{"domain":"example.com","action":{"type":"override","addresses":["192.0.2.1"]}}"#
        )
        .is_err());
    }

    #[test]
    fn rejects_urls_root_zone_and_ambiguous_rules() {
        for invalid in [
            ".",
            "com",
            "*.example.com",
            "https://example.com",
            "example.com/path",
            "example.com:443",
            "127.0.0.1",
        ] {
            assert!(domain(invalid).is_err(), "{invalid}");
        }
        let rule = Rule {
            domain: "example.com".into(),
            action: Action::Block,
            include_subdomains: true,
        };
        assert!(prepare(&[rule.clone(), rule]).is_err());
    }

    #[test]
    fn exact_and_wildcard_rules_have_distinct_scopes() {
        let rule = |domain: &str, include_subdomains| Rule {
            domain: domain.into(),
            include_subdomains,
            action: Action::Block,
        };
        let wildcard = prepare(&[rule("*.Example.COM.", false)]).unwrap();
        assert_eq!(zone(&wildcard[0]), "example.com");
        assert!(matching(&wildcard, "example.com.").is_none());
        assert!(matching(&wildcard, "one.two.example.com.").is_some());
        assert!(matching(&wildcard, "notexample.com.").is_none());
        let exact = prepare(&[rule("www.example.com", false)]).unwrap();
        assert!(matching(&exact, "www.example.com.").is_some());
        assert!(matching(&exact, "child.www.example.com.").is_none());
        assert!(matching(&exact, "example.com.").is_none());
        for invalid in [
            "*example.com",
            "a.*.example.com",
            "*.*.example.com",
            "*.com",
        ] {
            assert!(prepare(&[rule(invalid, true)]).is_err());
        }
    }
}
