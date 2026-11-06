//! Explicit local endpoint consent. Gateway messages never supply these URLs.
use anyhow::{ensure, Result};
pub fn server(value: &str) -> Result<String, String> {
    #[cfg(feature = "direct")]
    return porthub_mesh::stun::normalize_server(value).ok_or_else(|| {
        "expected a credential-free UDP STUN URI, for example stun:your-server.example:3478".into()
    });
    #[cfg(not(feature = "direct"))]
    {
        let _ = value;
        Err("terminal direct transport support is disabled".into())
    }
}
pub fn checked(values: &[String]) -> Result<Vec<String>> {
    ensure!(
        values.len() <= 2,
        "at most two terminal STUN endpoints are allowed"
    );
    let mut servers = Vec::new();
    for value in values {
        let value = server(value).map_err(|_| anyhow::anyhow!("invalid terminal STUN endpoint"))?;
        if !servers.contains(&value) {
            servers.push(value);
        }
    }
    Ok(servers)
}
#[cfg(all(test, feature = "direct"))]
mod tests {
    use super::*;
    #[test]
    fn terminal_endpoints_are_explicit_canonical_and_bounded() {
        assert!(checked(&[]).unwrap().is_empty());
        assert_eq!(
            checked(&[
                "stun:example.com".into(),
                "stun:example.com:3478?transport=udp".into()
            ])
            .unwrap(),
            ["stun:example.com:3478"]
        );
        for invalid in [
            "https://example.com",
            "turn:example.com",
            "stun:user:secret@example.com",
            "stun:example.com/path",
            "stun:example.com:0",
            "stun:0.0.0.0",
            "stun:[ff02::1]",
            "stun:exa\nmple.com",
        ] {
            assert!(server(invalid).is_err());
        }
        assert!(checked(&vec!["stun:example.com".into(); 3]).is_err());
    }
}
