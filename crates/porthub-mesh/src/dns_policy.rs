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
    Override { addresses: Vec<IpAddr> },
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
        rule.domain = domain(&rule.domain)?;
        ensure!(
            seen.insert(rule.domain.clone()),
            "Conflicting DNS rules for the same domain"
        );
        if let Action::Override { addresses } = &mut rule.action {
            ensure!(
                !addresses.is_empty() && addresses.len() <= 8,
                "DNS overrides require between one and eight addresses"
            );
            ensure!(
                addresses
                    .iter()
                    .all(|ip| !ip.is_unspecified() && !ip.is_multicast()),
                "Invalid DNS override address"
            );
            addresses.sort_unstable();
            addresses.dedup();
        }
        result.push(rule);
    }
    result.sort_by(|a, b| {
        b.domain
            .len()
            .cmp(&a.domain.len())
            .then(a.domain.cmp(&b.domain))
    });
    Ok(result)
}

pub fn matching<'a>(rules: &'a [Rule], query: &str) -> Option<&'a Rule> {
    let name = query.trim_end_matches('.');
    rules.iter().find(|rule| {
        name == rule.domain
            || rule.include_subdomains
                && name
                    .strip_suffix(&rule.domain)
                    .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_matching_respects_label_boundaries_and_specific_exceptions() {
        let rules = prepare(&[
            Rule {
                domain: "Example.COM.".into(),
                action: Action::Block,
                include_subdomains: true,
            },
            Rule {
                domain: "allowed.example.com".into(),
                action: Action::Override {
                    addresses: vec!["192.0.2.1".parse().unwrap()],
                },
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
            Action::Override { .. }
        ));
        assert!(matching(&rules, "notexample.com.").is_none());
        assert!(matching(&rules, "example.com.evil.test.").is_none());
        assert!(matches!(
            matching(&rules, "a.allowed.example.com.").unwrap().action,
            Action::Block
        ));
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
}
