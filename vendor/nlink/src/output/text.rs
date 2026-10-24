//! Text output formatting.

use std::io::Write;

/// Text output helper.
pub struct TextOutput<W: Write> {
    writer: W,
}

impl<W: Write> TextOutput<W> {
    /// Create a new text output.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Write a string.
    pub fn write(&mut self, s: &str) -> std::io::Result<()> {
        write!(self.writer, "{}", s)
    }

    /// Write a line.
    pub fn writeln(&mut self, s: &str) -> std::io::Result<()> {
        writeln!(self.writer, "{}", s)
    }

    /// Write a formatted string.
    pub fn write_fmt(&mut self, args: std::fmt::Arguments<'_>) -> std::io::Result<()> {
        self.writer.write_fmt(args)
    }

    /// Get the underlying writer.
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Get a mutable reference to the writer.
    pub fn writer_mut(&mut self) -> &mut W {
        &mut self.writer
    }
}

/// Format bytes as a human-readable string.
#[allow(dead_code)]
pub fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    const TIB: u64 = 1024 * 1024 * 1024 * 1024;

    if bytes >= TIB {
        format!("{:.2}TiB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.2}GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2}MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2}KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{}B", bytes)
    }
}

/// Format a rate (bits per second) as a human-readable string.
#[allow(dead_code)]
pub fn format_rate(bps: u64) -> String {
    const KBIT: u64 = 1000;
    const MBIT: u64 = 1_000_000;
    const GBIT: u64 = 1_000_000_000;
    const TBIT: u64 = 1_000_000_000_000;

    if bps >= TBIT {
        format!("{:.2}Tbit", bps as f64 / TBIT as f64)
    } else if bps >= GBIT {
        format!("{:.2}Gbit", bps as f64 / GBIT as f64)
    } else if bps >= MBIT {
        format!("{:.2}Mbit", bps as f64 / MBIT as f64)
    } else if bps >= KBIT {
        format!("{:.2}Kbit", bps as f64 / KBIT as f64)
    } else {
        format!("{}bit", bps)
    }
}

/// Format a duration in seconds as a human-readable string.
#[allow(dead_code)]
pub fn format_duration(secs: u64) -> String {
    if secs == 0 {
        return "0s".to_string();
    }

    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let secs = secs % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{}d", days));
    }
    if hours > 0 {
        parts.push(format!("{}h", hours));
    }
    if mins > 0 {
        parts.push(format!("{}m", mins));
    }
    if secs > 0 {
        parts.push(format!("{}s", secs));
    }

    parts.join("")
}

/// Format a number with thousands separators.
#[allow(dead_code)]
pub fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0B");
        assert_eq!(format_bytes(512), "512B");
        assert_eq!(format_bytes(1024), "1.00KiB");
        assert_eq!(format_bytes(1536), "1.50KiB");
        assert_eq!(format_bytes(1048576), "1.00MiB");
    }

    #[test]
    fn test_format_rate() {
        assert_eq!(format_rate(1000), "1.00Kbit");
        assert_eq!(format_rate(1_000_000), "1.00Mbit");
        assert_eq!(format_rate(1_000_000_000), "1.00Gbit");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(59), "59s");
        assert_eq!(format_duration(60), "1m");
        assert_eq!(format_duration(3661), "1h1m1s");
        assert_eq!(format_duration(86400), "1d");
    }
}
