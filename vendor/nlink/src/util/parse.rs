//! Argument parsing utilities.

use std::time::Duration;

/// Error type for parsing.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    #[error("invalid number: {0}")]
    InvalidNumber(String),

    #[error("number out of range: {0}")]
    OutOfRange(String),

    #[error("invalid format: {0}")]
    InvalidFormat(String),

    #[error("unknown unit: {0}")]
    UnknownUnit(String),
}

pub type Result<T> = std::result::Result<T, ParseError>;

/// Parse a u8 from string.
pub fn get_u8(s: &str) -> Result<u8> {
    parse_int(s)
}

/// Parse a u16 from string.
pub fn get_u16(s: &str) -> Result<u16> {
    parse_int(s)
}

/// Parse a u32 from string.
pub fn get_u32(s: &str) -> Result<u32> {
    parse_int(s)
}

/// Parse a u64 from string.
pub fn get_u64(s: &str) -> Result<u64> {
    parse_int(s)
}

/// Parse an i32 from string.
pub fn get_i32(s: &str) -> Result<i32> {
    parse_int(s)
}

/// Generic integer parsing with hex support.
fn parse_int<T: std::str::FromStr + TryFrom<u64>>(s: &str) -> Result<T>
where
    <T as std::str::FromStr>::Err: std::fmt::Display,
    <T as TryFrom<u64>>::Error: std::fmt::Display,
{
    let s = s.trim();

    // Handle hex
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        let val =
            u64::from_str_radix(hex, 16).map_err(|e| ParseError::InvalidNumber(e.to_string()))?;
        return T::try_from(val).map_err(|e| ParseError::OutOfRange(e.to_string()));
    }

    // Handle octal. The second-byte access is safe: the `len() > 1`
    // guard above ensures at least 2 bytes; ASCII '0' is one byte
    // wide, so `as_bytes()[1]` cannot panic. Prefer byte indexing
    // over `chars().nth(1).unwrap()` to avoid the implicit UTF-8
    // walk + Option unwrap.
    if s.starts_with('0') && s.len() > 1 && (s.as_bytes()[1] as char).is_ascii_digit() {
        let val = u64::from_str_radix(&s[1..], 8)
            .map_err(|e| ParseError::InvalidNumber(e.to_string()))?;
        return T::try_from(val).map_err(|e| ParseError::OutOfRange(e.to_string()));
    }

    s.parse()
        .map_err(|e| ParseError::InvalidNumber(format!("{}", e)))
}

/// Parse a rate string and return the value in **bits per second**.
///
/// Follows the `tc(8)` grammar, which matches suffixes **case-insensitively**
/// and splits them into two families:
///
/// | family | meaning | examples |
/// |---|---|---|
/// | `bit` | **bits** per second | `bit`, `kbit`, `mbit`, `gbit`, `tbit` |
/// | `bps` | **bytes** per second (×8) | `bps`, `kbps`, `mbps`, `gbps`, `tbps` |
///
/// The `ibit`/`ibps` spellings (`kibit`, `mibps`, …) are the binary-prefix
/// variants; `k`/`m`/`g`/`t` alone are decimal bit shortcuts. A bare number
/// is bits per second.
///
/// # `mbps` means megaBYTES
///
/// This is the part that surprises people, and nlink got it wrong until
/// 0.25 (#203): iproute2's suffix table is matched with `strcasecmp`, so
/// the lowercase `mbps` hits the `MBps = 8_000_000` entry — mega**bytes**.
/// nlink used to map it to megabits, so every `mbps` string shaped **8x
/// too slow**. If you want megabits, spell it `mbit`.
///
/// # New code: prefer [`crate::util::Rate`]
///
/// This function returns an unchecked `u64` in bits/sec. Use
/// [`Rate::parse`](crate::util::Rate::parse) (or `"100mbit".parse::<Rate>()?`)
/// instead — it returns a typed `Rate` that makes the bits-vs-bytes mistake
/// impossible downstream. This remains the primitive that powers it.
pub fn get_rate(s: &str) -> Result<u64> {
    let s = s.trim().to_lowercase();

    // Try to find where the number ends
    let (num_str, unit) = split_number_unit(&s);
    let num = parse_non_negative(num_str, &s)?;

    // Bit-valued suffixes. The byte-valued family is the same table x8 —
    // see the `bps` note above.
    let multiplier: u64 = match unit {
        // No bare "b": iproute2's rate table has no such suffix, and in a
        // size slot "b" means bytes — silently accepting it as bits here
        // would recreate the confusion this fix exists to remove.
        "" | "bit" => 1,
        "kbit" | "k" => 1000,
        "mbit" | "m" => 1_000_000,
        "gbit" | "g" => 1_000_000_000,
        "tbit" | "t" => 1_000_000_000_000,
        "kibit" => 1024,
        "mibit" => 1024 * 1024,
        "gibit" => 1024 * 1024 * 1024,
        "tibit" => 1024u64 * 1024 * 1024 * 1024,

        "bps" => 8,
        "kbps" => 8 * 1000,
        "mbps" => 8 * 1_000_000,
        "gbps" => 8 * 1_000_000_000,
        "tbps" => 8 * 1_000_000_000_000,
        "kibps" => 8 * 1024,
        "mibps" => 8 * 1024 * 1024,
        "gibps" => 8 * 1024 * 1024 * 1024,
        "tibps" => 8u64 * 1024 * 1024 * 1024 * 1024,

        _ => return Err(ParseError::UnknownUnit(unit.to_string())),
    };

    Ok((num * multiplier as f64) as u64)
}

/// Parse a size string and return the value in **bytes**.
///
/// Supports tc-style suffixes (binary base for `k`/`m`/`g`/`t`): `b`,
/// `k`, `kb`, `m`, `mb`, `g`, `gb`, `t`, `tb`. Bit-suffixes (`kbit`/
/// `mbit`/`gbit`) are accepted and divided by 8 to yield bytes.
///
/// # New code: prefer [`crate::util::Bytes`]
///
/// Use [`Bytes::parse`](crate::util::Bytes::parse) (or
/// `"32kib".parse::<Bytes>()?`) instead — it returns a typed `Bytes`
/// value with explicit decimal/binary constructors and a `Display`
/// that round-trips.
pub fn get_size(s: &str) -> Result<u64> {
    let s = s.trim().to_lowercase();

    let (num_str, unit) = split_number_unit(&s);
    let num = parse_non_negative(num_str, &s)?;

    let multiplier: u64 = match unit {
        "" | "b" => 1,
        // tc's size suffixes are binary, and the explicit `ib` spellings are
        // accepted as synonyms (the `Bytes` rustdoc has always advertised
        // "32kib", which used to be rejected outright).
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        "t" | "tb" | "tib" => 1024u64 * 1024 * 1024 * 1024,
        "kbit" => 1000 / 8,
        "mbit" => 1_000_000 / 8,
        "gbit" => 1_000_000_000 / 8,
        "tbit" => 1_000_000_000_000 / 8,
        _ => return Err(ParseError::UnknownUnit(unit.to_string())),
    };

    Ok((num * multiplier as f64) as u64)
}

/// Parse a time duration, following the `tc(8)` grammar.
///
/// Supported suffixes: `s`/`sec`/`secs`, `ms`/`msec`/`msecs`,
/// `us`/`usec`/`usecs`, `ns`/`nsec`/`nsecs`.
///
/// # A bare number is MICROseconds
///
/// This matches `tc(8)`, whose internal time unit is `TIME_UNITS_PER_SEC`
/// = 1e6. `tc qdisc add ... netem delay 100` means **100 µs**, not 100
/// seconds. nlink read a bare number as seconds until 0.25 (#216) — a
/// 1,000,000x error that effectively stopped the interface passing traffic.
///
/// `m` is **not** accepted: `tc(8)` has no minute suffix, and mapping it to
/// minutes (as nlink used to) made a mistyped `ms` silently 60,000x too long.
pub fn get_time(s: &str) -> Result<Duration> {
    let s = s.trim().to_lowercase();

    let (num_str, unit) = split_number_unit(&s);
    // A negative duration is not merely wrong, it panics:
    // Duration::from_secs_f64(-1.0) aborts with "value is negative".
    let num = parse_non_negative(num_str, &s)?;

    let duration = match unit {
        // Bare == microseconds. See the doc note above.
        "" | "us" | "usec" | "usecs" => Duration::from_secs_f64(num / 1_000_000.0),
        "s" | "sec" | "secs" => Duration::from_secs_f64(num),
        "ms" | "msec" | "msecs" => Duration::from_secs_f64(num / 1000.0),
        "ns" | "nsec" | "nsecs" => Duration::from_nanos(num as u64),
        _ => return Err(ParseError::UnknownUnit(unit.to_string())),
    };

    Ok(duration)
}

/// A time as tc(8) writes it, which [`get_time`] reads back as exactly
/// `d`: the largest of s, ms and µs that divides it, then µs with a
/// fraction, else nanoseconds. The fraction comes before `ns` because
/// iproute2 before 6.3 reads netem's delay in 64 ns ticks and takes no
/// `ns` (`1499.968us`, not `1499968ns`).
pub fn format_time(d: Duration) -> String {
    let ns = d.as_nanos();
    let mut candidates = Vec::new();
    for (unit, name) in [(1_000_000_000, "s"), (1_000_000, "ms"), (1_000, "us")] {
        if ns.is_multiple_of(unit) {
            candidates.push(format!("{}{name}", ns / unit));
        }
    }
    let fraction = format!("{:03}", ns % 1000);
    candidates.push(format!(
        "{}.{}us",
        ns / 1000,
        fraction.trim_end_matches('0')
    ));
    candidates
        .into_iter()
        .find(|text| get_time(text).ok() == Some(d))
        .unwrap_or_else(|| format!("{ns}ns"))
}

/// Parse the numeric span of a value, rejecting negatives.
///
/// `f64 as u64` **saturates to 0** for negative values, so `get_rate("-5mbit")`
/// used to return `Ok(0)` — which HTB then rejected with a bare EINVAL rather
/// than the contract-mandated `"htb: invalid rate ..."` (#217). `Duration`'s
/// constructors are worse: a negative value panics outright.
fn parse_non_negative(num_str: &str, full: &str) -> Result<f64> {
    let num: f64 = num_str
        .parse()
        .map_err(|_| ParseError::InvalidNumber(num_str.to_string()))?;

    if !num.is_finite() || num < 0.0 {
        return Err(ParseError::OutOfRange(format!(
            "`{full}` is negative or not finite (expected a non-negative value)"
        )));
    }

    Ok(num)
}

/// Parse a percentage (0-100) to a fraction (0.0-1.0).
pub fn get_percent(s: &str) -> Result<f64> {
    let s = s.trim();
    let s = s.strip_suffix('%').unwrap_or(s);
    let val: f64 = s
        .parse()
        .map_err(|_| ParseError::InvalidNumber(s.to_string()))?;
    if !(0.0..=100.0).contains(&val) {
        return Err(ParseError::OutOfRange(format!(
            "{} not in range 0-100",
            val
        )));
    }
    Ok(val / 100.0)
}

/// Split a string into number and unit parts.
fn split_number_unit(s: &str) -> (&str, &str) {
    let idx = s
        .find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-')
        .unwrap_or(s.len());
    (&s[..idx], &s[idx..])
}

/// Parse a boolean value.
pub fn get_bool(s: &str) -> Result<bool> {
    match s.to_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(ParseError::InvalidFormat(format!(
            "expected boolean, got '{}'",
            s
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_u32() {
        assert_eq!(get_u32("123").unwrap(), 123);
        assert_eq!(get_u32("0x1a").unwrap(), 26);
        assert_eq!(get_u32("0777").unwrap(), 511);
    }

    #[test]
    fn test_get_rate() {
        assert_eq!(get_rate("1000").unwrap(), 1000);
        assert_eq!(get_rate("1kbit").unwrap(), 1000);
        assert_eq!(get_rate("1mbit").unwrap(), 1_000_000);
        assert_eq!(get_rate("1.5mbit").unwrap(), 1_500_000);
    }

    #[test]
    fn test_get_size() {
        assert_eq!(get_size("1024").unwrap(), 1024);
        assert_eq!(get_size("1k").unwrap(), 1024);
        assert_eq!(get_size("1kb").unwrap(), 1024);
        assert_eq!(get_size("1m").unwrap(), 1024 * 1024);
    }

    #[test]
    fn test_get_time() {
        assert_eq!(get_time("1s").unwrap(), Duration::from_secs(1));
        assert_eq!(get_time("100ms").unwrap(), Duration::from_millis(100));
        assert_eq!(get_time("1000us").unwrap(), Duration::from_micros(1000));
    }

    // ========================================================================
    // tc(8) grammar conformance (#203, #216, #217)
    // ========================================================================

    /// iproute2 matches its suffix table with strcasecmp, so lowercase `mbps`
    /// hits the `MBps = 8_000_000` entry — mega**bytes** per second. nlink
    /// mapped the whole bps family to bits, so every such string was 8x too
    /// small. `tc qdisc add ... tbf rate 10mbps` means 80 mbit.
    #[test]
    fn the_bps_family_is_bytes_per_second() {
        assert_eq!(get_rate("1bps").unwrap(), 8);
        assert_eq!(get_rate("1kbps").unwrap(), 8_000);
        assert_eq!(get_rate("10mbps").unwrap(), 80_000_000);
        assert_eq!(get_rate("1gbps").unwrap(), 8_000_000_000);
        assert_eq!(get_rate("1kibps").unwrap(), 8 * 1024);

        // The bit family is unchanged, and is exactly 1/8 of its bps twin.
        assert_eq!(get_rate("10mbit").unwrap(), 10_000_000);
        assert_eq!(
            get_rate("1mbps").unwrap(),
            8 * get_rate("1mbit").unwrap(),
            "mbps must be exactly 8x mbit",
        );
    }

    #[test]
    fn rate_suffixes_are_case_insensitive() {
        assert_eq!(get_rate("10MBps").unwrap(), get_rate("10mbps").unwrap());
        assert_eq!(get_rate("10MBit").unwrap(), get_rate("10mbit").unwrap());
        assert_eq!(get_rate("1GBit").unwrap(), 1_000_000_000);
    }

    /// tc(8)'s internal time unit is TIME_UNITS_PER_SEC = 1e6, so a bare
    /// number in a time slot is microseconds. nlink read it as seconds — so
    /// `netem delay 100` meant 100 SECONDS, a 1,000,000x error that
    /// effectively stopped the interface passing traffic.
    #[test]
    fn a_bare_time_is_microseconds() {
        assert_eq!(get_time("100").unwrap(), Duration::from_micros(100));
        assert_eq!(get_time("1000").unwrap(), Duration::from_millis(1));
        // The explicit suffix still means what it says.
        assert_eq!(get_time("100s").unwrap(), Duration::from_secs(100));
    }

    /// tc(8) has no minute suffix. Accepting `m` as minutes made a mistyped
    /// `ms` silently 60,000x too long.
    #[test]
    fn minutes_and_hours_are_not_time_suffixes() {
        assert!(get_time("5m").is_err());
        assert!(get_time("5min").is_err());
        assert!(get_time("1h").is_err());
    }

    /// `f64 as u64` saturates to 0 for negatives, so a negative rate used to
    /// return Ok(0) — which the kernel then rejected with a bare EINVAL
    /// instead of nlink's contract-mandated "kind: invalid ..." message.
    #[test]
    fn negative_values_are_rejected_not_silently_zeroed() {
        assert!(get_rate("-5mbit").is_err());
        assert!(get_size("-1k").is_err());
        // This one used to PANIC: Duration::from_secs_f64(-1.0) aborts.
        assert!(get_time("-1s").is_err());
    }

    /// The `Bytes` rustdoc has always advertised "32kib"; get_size rejected it.
    #[test]
    fn get_size_accepts_the_binary_ib_spellings() {
        assert_eq!(get_size("32kib").unwrap(), 32 * 1024);
        assert_eq!(get_size("1mib").unwrap(), 1024 * 1024);
        assert_eq!(get_size("1gib").unwrap(), 1024 * 1024 * 1024);
    }
}
