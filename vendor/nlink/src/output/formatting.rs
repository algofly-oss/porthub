//! Shared formatting utilities for CLI output.
//!
//! This module provides common formatting functions used across multiple binaries
//! for displaying bytes, rates, durations, and other values in human-readable format.
//!
//! # Example
//!
//! ```
//! use nlink::output::formatting::{format_bytes, format_rate_bps, format_duration};
//! use std::time::Duration;
//!
//! assert_eq!(format_bytes(1024), "1.00 KiB");
//! assert_eq!(format_bytes(1_048_576), "1.00 MiB");
//!
//! assert_eq!(format_rate_bps(1_000_000), "1.0Mbps");
//! assert_eq!(format_rate_bps(1_000_000_000), "1.0Gbps");
//!
//! assert_eq!(format_duration(Duration::from_secs(90)), "1 minute, 30 seconds");
//! ```

use std::time::{Duration, SystemTime};

/// Format a byte count in human-readable format (KiB, MiB, GiB).
///
/// Uses binary units (1 KiB = 1024 bytes).
///
/// # Example
///
/// ```
/// use nlink::output::formatting::format_bytes;
///
/// assert_eq!(format_bytes(0), "0 B");
/// assert_eq!(format_bytes(512), "512 B");
/// assert_eq!(format_bytes(1024), "1.00 KiB");
/// assert_eq!(format_bytes(1_048_576), "1.00 MiB");
/// assert_eq!(format_bytes(1_073_741_824), "1.00 GiB");
/// assert_eq!(format_bytes(1_099_511_627_776), "1.00 TiB");
/// ```
pub fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const TIB: f64 = 1024.0 * 1024.0 * 1024.0 * 1024.0;

    let bytes_f = bytes as f64;

    if bytes_f >= TIB {
        format!("{:.2} TiB", bytes_f / TIB)
    } else if bytes_f >= GIB {
        format!("{:.2} GiB", bytes_f / GIB)
    } else if bytes_f >= MIB {
        format!("{:.2} MiB", bytes_f / MIB)
    } else if bytes_f >= KIB {
        format!("{:.2} KiB", bytes_f / KIB)
    } else {
        format!("{} B", bytes)
    }
}

/// Format a bit rate in human-readable format (Kbps, Mbps, Gbps).
///
/// # Example
///
/// ```
/// use nlink::output::formatting::format_rate_bps;
///
/// assert_eq!(format_rate_bps(0), "0bps");
/// assert_eq!(format_rate_bps(1_000), "1.0Kbps");
/// assert_eq!(format_rate_bps(1_000_000), "1.0Mbps");
/// assert_eq!(format_rate_bps(1_000_000_000), "1.0Gbps");
/// assert_eq!(format_rate_bps(10_000_000_000), "10.0Gbps");
/// ```
pub fn format_rate_bps(bits_per_sec: u64) -> String {
    const KBPS: f64 = 1_000.0;
    const MBPS: f64 = 1_000_000.0;
    const GBPS: f64 = 1_000_000_000.0;
    const TBPS: f64 = 1_000_000_000_000.0;

    let rate = bits_per_sec as f64;

    if rate >= TBPS {
        format!("{:.1}Tbps", rate / TBPS)
    } else if rate >= GBPS {
        format!("{:.1}Gbps", rate / GBPS)
    } else if rate >= MBPS {
        format!("{:.1}Mbps", rate / MBPS)
    } else if rate >= KBPS {
        format!("{:.1}Kbps", rate / KBPS)
    } else {
        format!("{}bps", bits_per_sec)
    }
}

/// Format a byte rate in human-readable format (KB/s, MB/s, GB/s).
///
/// Converts bytes/sec to a readable string.
///
/// # Example
///
/// ```
/// use nlink::output::formatting::format_rate_bytes;
///
/// assert_eq!(format_rate_bytes(0), "0 B/s");
/// assert_eq!(format_rate_bytes(1024), "1.00 KiB/s");
/// assert_eq!(format_rate_bytes(1_048_576), "1.00 MiB/s");
/// ```
pub fn format_rate_bytes(bytes_per_sec: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

    let rate = bytes_per_sec as f64;

    if rate >= GIB {
        format!("{:.2} GiB/s", rate / GIB)
    } else if rate >= MIB {
        format!("{:.2} MiB/s", rate / MIB)
    } else if rate >= KIB {
        format!("{:.2} KiB/s", rate / KIB)
    } else {
        format!("{} B/s", bytes_per_sec)
    }
}

/// Format a duration in human-readable format.
///
/// # Example
///
/// ```
/// use nlink::output::formatting::format_duration;
/// use std::time::Duration;
///
/// assert_eq!(format_duration(Duration::from_secs(0)), "0 seconds");
/// assert_eq!(format_duration(Duration::from_secs(1)), "1 second");
/// assert_eq!(format_duration(Duration::from_secs(45)), "45 seconds");
/// assert_eq!(format_duration(Duration::from_secs(60)), "1 minute");
/// assert_eq!(format_duration(Duration::from_secs(90)), "1 minute, 30 seconds");
/// assert_eq!(format_duration(Duration::from_secs(3600)), "1 hour");
/// assert_eq!(format_duration(Duration::from_secs(3661)), "1 hour, 1 minute, 1 second");
/// assert_eq!(format_duration(Duration::from_secs(86400)), "1 day");
/// assert_eq!(format_duration(Duration::from_secs(90061)), "1 day, 1 hour, 1 minute, 1 second");
/// ```
pub fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();

    if total_secs == 0 {
        return "0 seconds".to_string();
    }

    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    let mut parts = Vec::new();

    if days > 0 {
        parts.push(if days == 1 {
            "1 day".to_string()
        } else {
            format!("{} days", days)
        });
    }

    if hours > 0 {
        parts.push(if hours == 1 {
            "1 hour".to_string()
        } else {
            format!("{} hours", hours)
        });
    }

    if minutes > 0 {
        parts.push(if minutes == 1 {
            "1 minute".to_string()
        } else {
            format!("{} minutes", minutes)
        });
    }

    if seconds > 0 {
        parts.push(if seconds == 1 {
            "1 second".to_string()
        } else {
            format!("{} seconds", seconds)
        });
    }

    parts.join(", ")
}

/// Format a duration in compact format (e.g., "1d 2h 3m 4s").
///
/// # Example
///
/// ```
/// use nlink::output::formatting::format_duration_compact;
/// use std::time::Duration;
///
/// assert_eq!(format_duration_compact(Duration::from_secs(0)), "0s");
/// assert_eq!(format_duration_compact(Duration::from_secs(45)), "45s");
/// assert_eq!(format_duration_compact(Duration::from_secs(90)), "1m 30s");
/// assert_eq!(format_duration_compact(Duration::from_secs(3661)), "1h 1m 1s");
/// assert_eq!(format_duration_compact(Duration::from_secs(90061)), "1d 1h 1m 1s");
/// ```
pub fn format_duration_compact(duration: Duration) -> String {
    let total_secs = duration.as_secs();

    if total_secs == 0 {
        return "0s".to_string();
    }

    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    let mut parts = Vec::new();

    if days > 0 {
        parts.push(format!("{}d", days));
    }
    if hours > 0 {
        parts.push(format!("{}h", hours));
    }
    if minutes > 0 {
        parts.push(format!("{}m", minutes));
    }
    if seconds > 0 || parts.is_empty() {
        parts.push(format!("{}s", seconds));
    }

    parts.join(" ")
}

/// Format time elapsed since a given time point.
///
/// # Example
///
/// ```
/// use nlink::output::formatting::format_time_ago;
/// use std::time::{SystemTime, Duration};
///
/// let now = SystemTime::now();
/// let one_hour_ago = now - Duration::from_secs(3600);
/// let result = format_time_ago(one_hour_ago);
/// assert!(result.contains("hour") || result.contains("minute"));
/// ```
pub fn format_time_ago(time: SystemTime) -> String {
    match SystemTime::now().duration_since(time) {
        Ok(duration) => {
            let secs = duration.as_secs();
            if secs < 60 {
                format!("{} seconds ago", secs)
            } else if secs < 3600 {
                let mins = secs / 60;
                let secs_rem = secs % 60;
                if secs_rem == 0 {
                    format!("{} minute{} ago", mins, if mins == 1 { "" } else { "s" })
                } else {
                    format!(
                        "{} minute{}, {} second{} ago",
                        mins,
                        if mins == 1 { "" } else { "s" },
                        secs_rem,
                        if secs_rem == 1 { "" } else { "s" }
                    )
                }
            } else if secs < 86400 {
                let hours = secs / 3600;
                let mins = (secs % 3600) / 60;
                if mins == 0 {
                    format!("{} hour{} ago", hours, if hours == 1 { "" } else { "s" })
                } else {
                    format!(
                        "{} hour{}, {} minute{} ago",
                        hours,
                        if hours == 1 { "" } else { "s" },
                        mins,
                        if mins == 1 { "" } else { "s" }
                    )
                }
            } else {
                let days = secs / 86400;
                let hours = (secs % 86400) / 3600;
                if hours == 0 {
                    format!("{} day{} ago", days, if days == 1 { "" } else { "s" })
                } else {
                    format!(
                        "{} day{}, {} hour{} ago",
                        days,
                        if days == 1 { "" } else { "s" },
                        hours,
                        if hours == 1 { "" } else { "s" }
                    )
                }
            }
        }
        Err(_) => "in the future".to_string(),
    }
}

/// Format a percentage value.
///
/// # Example
///
/// ```
/// use nlink::output::formatting::format_percent;
///
/// assert_eq!(format_percent(0.0), "0.00%");
/// assert_eq!(format_percent(50.5), "50.50%");
/// assert_eq!(format_percent(100.0), "100.00%");
/// ```
pub fn format_percent(value: f64) -> String {
    format!("{:.2}%", value)
}

/// Format a MAC address from bytes.
///
/// # Example
///
/// ```
/// use nlink::output::formatting::format_mac;
///
/// assert_eq!(format_mac(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]), "00:11:22:33:44:55");
/// ```
pub fn format_mac(bytes: &[u8]) -> String {
    if bytes.len() >= 6 {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    } else {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// Format an IPv4 address from bytes (network byte order).
///
/// # Example
///
/// ```
/// use nlink::output::formatting::format_ipv4;
///
/// assert_eq!(format_ipv4(&[192, 168, 1, 1]), "192.168.1.1");
/// ```
pub fn format_ipv4(bytes: &[u8]) -> String {
    if bytes.len() >= 4 {
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    } else {
        "0.0.0.0".to_string()
    }
}

/// Format a hex string from bytes.
///
/// # Example
///
/// ```
/// use nlink::output::formatting::format_hex;
///
/// assert_eq!(format_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
/// ```
pub fn format_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Format a TC handle (major:minor).
///
/// # Example
///
/// ```
/// use nlink::output::formatting::format_tc_handle;
///
/// assert_eq!(format_tc_handle(0x10010), "1:10");
/// assert_eq!(format_tc_handle(0xFFFFFFFF), "ffff:ffff");
/// assert_eq!(format_tc_handle(0), "0:");
/// ```
pub fn format_tc_handle(handle: u32) -> String {
    let major = (handle >> 16) & 0xFFFF;
    let minor = handle & 0xFFFF;
    if minor == 0 {
        format!("{:x}:", major)
    } else {
        format!("{:x}:{:x}", major, minor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(100), "100 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.00 KiB");
        assert_eq!(format_bytes(1536), "1.50 KiB");
        assert_eq!(format_bytes(1_048_576), "1.00 MiB");
        assert_eq!(format_bytes(1_073_741_824), "1.00 GiB");
        assert_eq!(format_bytes(1_099_511_627_776), "1.00 TiB");
    }

    #[test]
    fn test_format_rate_bps() {
        assert_eq!(format_rate_bps(0), "0bps");
        assert_eq!(format_rate_bps(500), "500bps");
        assert_eq!(format_rate_bps(1_000), "1.0Kbps");
        assert_eq!(format_rate_bps(1_500_000), "1.5Mbps");
        assert_eq!(format_rate_bps(1_000_000_000), "1.0Gbps");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0 seconds");
        assert_eq!(format_duration(Duration::from_secs(1)), "1 second");
        assert_eq!(format_duration(Duration::from_secs(2)), "2 seconds");
        assert_eq!(format_duration(Duration::from_secs(60)), "1 minute");
        assert_eq!(
            format_duration(Duration::from_secs(61)),
            "1 minute, 1 second"
        );
        assert_eq!(format_duration(Duration::from_secs(3600)), "1 hour");
        assert_eq!(format_duration(Duration::from_secs(86400)), "1 day");
    }

    #[test]
    fn test_format_duration_compact() {
        assert_eq!(format_duration_compact(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration_compact(Duration::from_secs(45)), "45s");
        assert_eq!(format_duration_compact(Duration::from_secs(60)), "1m");
        assert_eq!(format_duration_compact(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration_compact(Duration::from_secs(3600)), "1h");
        assert_eq!(
            format_duration_compact(Duration::from_secs(3661)),
            "1h 1m 1s"
        );
    }

    #[test]
    fn test_format_mac() {
        assert_eq!(
            format_mac(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            "00:11:22:33:44:55"
        );
        assert_eq!(
            format_mac(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            "ff:ff:ff:ff:ff:ff"
        );
    }

    #[test]
    fn test_format_tc_handle() {
        assert_eq!(format_tc_handle(0x10010), "1:10");
        assert_eq!(format_tc_handle(0x10000), "1:");
        assert_eq!(format_tc_handle(0), "0:");
    }
}
