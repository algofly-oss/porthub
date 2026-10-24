//! Interface name and index utilities.

/// Maximum interface name length (including null terminator).
pub const IFNAMSIZ: usize = 16;

/// Error type for interface operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IfError {
    #[error("interface not found: {0}")]
    NotFound(String),

    #[error("invalid interface name: {0}")]
    InvalidName(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, IfError>;

/// Validate an interface name the way the kernel's `dev_valid_name` does.
///
/// Refused: an empty name, 16 bytes or more, `.` and `..`, and any `/`,
/// `:`, NUL or byte the kernel's `isspace` takes: tab, newline, vertical
/// tab, form feed, carriage return, space, and 0xA0. The check is on
/// bytes, as the kernel's is, so a character whose UTF-8 encoding holds
/// 0xA0 (`à` is `C3 A0`) is refused, and a Unicode space without one
/// (U+2003 is `E2 80 83`) is a valid name, as it is to `ip link` (#598).
pub fn validate(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(IfError::InvalidName("empty name".to_string()));
    }

    if name.len() >= IFNAMSIZ {
        return Err(IfError::InvalidName(format!(
            "name too long (max {} bytes)",
            IFNAMSIZ - 1
        )));
    }

    if name == "." || name == ".." {
        return Err(IfError::InvalidName(format!("{name:?} is not a name")));
    }

    if name.bytes().any(|b| matches!(b, b'/' | b':' | b'\0')) {
        return Err(IfError::InvalidName(format!(
            "{name:?} contains `/`, `:` or NUL"
        )));
    }

    if name
        .bytes()
        .any(|b| matches!(b, b'\t'..=b'\r' | b' ' | 0xa0))
    {
        return Err(IfError::InvalidName(format!(
            "{name:?} contains whitespace"
        )));
    }

    Ok(())
}

/// Convert an interface index to name.
pub fn index_to_name(index: u32) -> Result<String> {
    if index == 0 {
        return Err(IfError::NotFound("index 0".to_string()));
    }

    // Read from /sys/class/net
    let entries = std::fs::read_dir("/sys/class/net")?;

    for entry in entries.flatten() {
        let path = entry.path().join("ifindex");
        if let Ok(content) = std::fs::read_to_string(&path)
            && let Ok(idx) = content.trim().parse::<u32>()
            && idx == index
        {
            return Ok(entry.file_name().to_string_lossy().to_string());
        }
    }

    Err(IfError::NotFound(format!("index {}", index)))
}

/// Convert an interface name to index.
pub fn name_to_index(name: &str) -> Result<u32> {
    validate(name)?;

    let path = format!("/sys/class/net/{}/ifindex", name);
    let content =
        std::fs::read_to_string(&path).map_err(|_| IfError::NotFound(name.to_string()))?;

    content
        .trim()
        .parse()
        .map_err(|_| IfError::NotFound(name.to_string()))
}

/// Get all interface names.
pub fn list_interfaces() -> Result<Vec<String>> {
    let entries = std::fs::read_dir("/sys/class/net")?;

    let mut names = Vec::new();
    for entry in entries.flatten() {
        names.push(entry.file_name().to_string_lossy().to_string());
    }

    names.sort();
    Ok(names)
}

/// Parse an interface name or index.
/// If the string is numeric, treat it as an index and resolve to name.
/// Otherwise, treat it as a name.
pub fn resolve(s: &str) -> Result<(String, u32)> {
    if let Ok(index) = s.parse::<u32>() {
        let name = index_to_name(index)?;
        Ok((name, index))
    } else {
        let index = name_to_index(s)?;
        Ok((s.to_string(), index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate() {
        assert!(validate("eth0").is_ok());
        assert!(validate("lo").is_ok());
        assert!(validate("veth123").is_ok());

        assert!(validate("").is_err());
        assert!(validate("this_name_is_way_too_long_for_an_interface").is_err());
        assert!(validate("eth/0").is_err());
        assert!(validate("eth 0").is_err());
    }

    /// The kernel's `dev_valid_name`, byte for byte, as checked against
    /// 6.12: `.`, `..`, `:`, and every byte its `isspace` takes, which
    /// includes 0xA0 inside a UTF-8 character (`à` is `C3 A0`). A Unicode
    /// space that has no such byte is a valid name (#598).
    #[test]
    fn validate_matches_dev_valid_name() {
        for bad in [
            ".", "..", "a:b", "à0", "a\tb", "a\x0bb", "a\x0cb", "a\rb", "a\nb",
        ] {
            assert!(validate(bad).is_err(), "{bad:?} should be refused");
        }
        for good in ["...", ".a", "a.b", "été", "a\u{2003}b", "fifteen-bytes-x"] {
            assert!(validate(good).is_ok(), "{good:?} should be accepted");
        }
        assert!(validate("sixteen-bytes-xx").is_err());
    }

    #[test]
    fn test_list_interfaces() {
        // This should at least find "lo"
        let interfaces = list_interfaces().unwrap();
        assert!(interfaces.contains(&"lo".to_string()));
    }
}
