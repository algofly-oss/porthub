//! Display-only OS metadata, read once without invoking a shell.
use std::sync::OnceLock;

#[derive(Default, Debug, PartialEq)]
pub struct OsInfo {
    pub id: String,
    pub name: String,
}

pub fn current() -> &'static OsInfo {
    static INFO: OnceLock<OsInfo> = OnceLock::new();
    INFO.get_or_init(detect)
}

fn detect() -> OsInfo {
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;
        // os-release explicitly gives /etc precedence over the vendor file.
        let path = if std::path::Path::new("/etc/os-release").exists() {
            "/etc/os-release"
        } else {
            "/usr/lib/os-release"
        };
        if !std::fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() <= 16384) { return OsInfo::default(); }
        if let Ok(file) = std::fs::File::open(path) {
            if file.metadata().is_ok_and(|meta| meta.is_file() && meta.len() <= 16384) {
                let mut text = String::new();
                if file.take(16385).read_to_string(&mut text).is_ok() && text.len() <= 16384 {
                    return parse(&text);
                }
            }
        }
    }
    OsInfo::default()
}

fn value(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let (text, double) = if raw.starts_with('"') {
        (raw.strip_prefix('"')?.strip_suffix('"')?, true)
    } else if raw.starts_with('\'') {
        (raw.strip_prefix('\'')?.strip_suffix('\'')?, false)
    } else {
        (raw, true)
    };
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if double && c == '\\' && chars.peek().is_some_and(|c| ['$', '`', '"', '\\'].contains(c)) {
            out.push(chars.next()?);
        } else { out.push(c); }
    }
    (!out.chars().any(char::is_control) && out.chars().count() <= 160).then_some(out)
}

fn parse(text: &str) -> OsInfo {
    let mut info = OsInfo::default();
    let mut name = String::new();
    let mut version = String::new();
    for line in text.lines() {
        let Some((key, raw)) = line.trim().split_once('=') else { continue; };
        let Some(value) = value(raw) else { continue; };
        match key {
            "ID" if !value.is_empty() && value.len() <= 64 && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)) => info.id = value,
            "PRETTY_NAME" => info.name = value,
            "NAME" => name = value,
            "VERSION_ID" => version = value,
            _ => (),
        }
    }
    if info.name.is_empty() && !name.is_empty() {
        info.name = if version.is_empty() { name } else { format!("{name} {version}") };
        info.name = info.name.chars().take(160).collect();
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reports_distribution_and_release_without_expanding_shell_values() {
        assert_eq!(parse("ID=ubuntu\nPRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\n"), OsInfo { id: "ubuntu".into(), name: "Ubuntu 24.04.3 LTS".into() });
        assert_eq!(parse("ID='rhel'\nNAME=\"Red Hat Enterprise Linux\"\nVERSION_ID=9.5").name, "Red Hat Enterprise Linux 9.5");
        assert_eq!(parse("ID=raspbian\nPRETTY_NAME='Raspbian GNU/Linux 12 (bookworm)'").id, "raspbian");
        assert_eq!(parse("PRETTY_NAME=\"Literal \\$HOME\"").name, "Literal $HOME");
        assert_eq!(parse("ID=ubuntu\nID=debian").id, "debian");
    }
    #[test]
    fn rejects_unbounded_or_control_character_metadata() {
        assert_eq!(parse("ID=../../other\nPRETTY_NAME=\"bad\tname\""), OsInfo::default());
        assert!(parse(&format!("PRETTY_NAME=\"{}\"", "a".repeat(161))).name.is_empty());
        assert!(parse("PRETTY_NAME=\"unterminated").name.is_empty());
    }
}
