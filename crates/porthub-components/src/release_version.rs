//! Release precedence shared by update publishers and native clients.
use std::cmp::Ordering;
pub fn compare(left: &str, right: &str) -> Option<Ordering> {
    let left = left.trim();
    let right = right.trim();
    let left = semver::Version::parse(left.strip_prefix('v').unwrap_or(left)).ok()?;
    let right = semver::Version::parse(right.strip_prefix('v').unwrap_or(right)).ok()?;
    Some(left.cmp_precedence(&right))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prereleases_never_downgrade_to_an_older_stable_release() {
        assert_eq!(compare("1.11.16-dev.1", "1.11.13"), Some(Ordering::Greater));
        assert_eq!(compare("1.11.16-dev.1", "1.11.16"), Some(Ordering::Less));
        assert_eq!(compare("1.11.16", "1.11.16-dev.1"), Some(Ordering::Greater));
        assert_eq!(
            compare("1.11.16+local", "v1.11.16+published"),
            Some(Ordering::Equal)
        );
        assert_eq!(compare("unknown-build", "1.11.16"), None);
    }
}
