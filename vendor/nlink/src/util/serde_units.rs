//! Serde for the unit types, in the units tc(8) writes (#515).
//!
//! - A [`Rate`] is `"100mbit"`. A bare number is refused: tc(8) reads one as
//!   bits per second, and the declarative `rate_bps` nlink had before 0.32
//!   meant bytes, so there is no number both would agree on.
//! - A [`Bytes`] is `"32kib"`, or on input a bare number of bytes.
//! - A [`Packets`] is a bare number of packets, or on input `"1000p"`, as
//!   tc(8) writes it (#643). The documents that had packet limits before
//!   0.32 wrote numbers, so they still read.
//! - A [`Percent`] is `"1.5%"`, or on input a bare number of percent. A
//!   value outside `0..=100`, or not a number, is refused rather than
//!   clamped: a document that says 150 % is wrong, not 100 %.
//! - A duration, through [`duration`] and [`option_duration`], is `"10ms"`,
//!   or on input a bare number of microseconds, which is how tc(8) reads a
//!   bare time.
//!
//! What is written always reads back as the same value.

use std::{fmt, time::Duration};

use serde::{Deserializer, Serializer, de};

use super::{bytes::Bytes, packets::Packets, parse, percent::Percent, rate::Rate};

impl serde::Serialize for Rate {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Rate {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl de::Visitor<'_> for V {
            type Value = Rate;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a rate with its unit, such as \"100mbit\"")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Rate, E> {
                Rate::parse(v).map_err(E::custom)
            }
        }
        d.deserialize_str(V)
    }
}

impl serde::Serialize for Packets {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(self.as_u32())
    }
}

impl<'de> serde::Deserialize<'de> for Packets {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl de::Visitor<'_> for V {
            type Value = Packets;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a number of packets, or a count such as \"1000p\"")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Packets, E> {
                Packets::parse(v).map_err(E::custom)
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Packets, E> {
                u32::try_from(v)
                    .map(Packets::new)
                    .map_err(|_| E::custom(format!("a packet count is at most {}: {v}", u32::MAX)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Packets, E> {
                u32::try_from(v)
                    .map(Packets::new)
                    .map_err(|_| E::custom(format!("not a packet count: {v}")))
            }
        }
        d.deserialize_any(V)
    }
}

impl serde::Serialize for Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl de::Visitor<'_> for V {
            type Value = Bytes;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a size such as \"32kib\", or a number of bytes")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Bytes, E> {
                Bytes::parse(v).map_err(E::custom)
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Bytes, E> {
                Ok(Bytes::new(v))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Bytes, E> {
                u64::try_from(v)
                    .map(Bytes::new)
                    .map_err(|_| E::custom(format!("a size cannot be negative: {v}")))
            }
        }
        d.deserialize_any(V)
    }
}

impl serde::Serialize for Percent {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// A percentage in `0..=100`, or an error naming the value.
fn checked_percent<E: de::Error>(v: f64) -> Result<Percent, E> {
    if v.is_finite() && (0.0..=100.0).contains(&v) {
        Ok(Percent::new(v))
    } else {
        Err(E::custom(format!("a percentage is 0 to 100, not {v}")))
    }
}

impl<'de> serde::Deserialize<'de> for Percent {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl de::Visitor<'_> for V {
            type Value = Percent;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a percentage such as \"1.5%\", or a number of percent")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Percent, E> {
                let n: f64 = v
                    .trim()
                    .trim_end_matches('%')
                    .trim()
                    .parse()
                    .map_err(|_| E::custom(format!("not a percentage: `{v}`")))?;
                checked_percent(n)
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Percent, E> {
                checked_percent(v)
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Percent, E> {
                checked_percent(v as f64)
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Percent, E> {
                checked_percent(v as f64)
            }
        }
        d.deserialize_any(V)
    }
}

/// A duration from text (`"10ms"`) or a number of microseconds.
struct DurationVisitor;

impl de::Visitor<'_> for DurationVisitor {
    type Value = Duration;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a time such as \"10ms\", or a number of microseconds")
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Duration, E> {
        parse::get_time(v).map_err(|e| E::custom(format!("not a time: `{v}`: {e}")))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Duration, E> {
        Ok(Duration::from_micros(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Duration, E> {
        u64::try_from(v)
            .map(Duration::from_micros)
            .map_err(|_| E::custom(format!("a time cannot be negative: {v}")))
    }
}

/// `#[serde(with = "…::duration")]` for a `Duration`, as `"10ms"`.
pub mod duration {
    use super::*;

    /// Write `d` as tc(8) does.
    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&parse::format_time(*d))
    }

    /// Read text or a number of microseconds.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        d.deserialize_any(DurationVisitor)
    }
}

/// `#[serde(with = "…::option_duration")]` for an `Option<Duration>`.
pub mod option_duration {
    use super::*;

    /// Write `d` as tc(8) does, or nothing.
    pub fn serialize<S: Serializer>(d: &Option<Duration>, s: S) -> Result<S::Ok, S::Error> {
        match d {
            Some(d) => s.serialize_some(&parse::format_time(*d)),
            None => s.serialize_none(),
        }
    }

    /// Read text, a number of microseconds, or nothing.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
        struct Wrapper(Duration);
        impl<'de> serde::Deserialize<'de> for Wrapper {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                d.deserialize_any(DurationVisitor).map(Wrapper)
            }
        }
        Ok(<Option<Wrapper> as serde::Deserialize>::deserialize(d)?.map(|w| w.0))
    }
}

/// The JSON Schema of the unit types and of a duration: a string in
/// tc(8)'s syntax, or a number where the type takes one.
#[cfg(feature = "schemars")]
mod schema {
    use std::borrow::Cow;

    use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};

    use super::{Bytes, Packets, Percent, Rate};

    impl JsonSchema for Rate {
        fn schema_name() -> Cow<'static, str> {
            "Rate".into()
        }
        fn json_schema(_: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": "string",
                "description": "A rate with its unit, as tc(8) writes it: \"100mbit\", \"1gbit\", \"64kbit\".",
            })
        }
    }

    impl JsonSchema for Bytes {
        fn schema_name() -> Cow<'static, str> {
            "Bytes".into()
        }
        fn json_schema(_: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": ["string", "integer"],
                "description": "A size, as tc(8) writes it (\"32kib\", \"1mb\"), or a number of bytes.",
            })
        }
    }

    impl JsonSchema for Packets {
        fn schema_name() -> Cow<'static, str> {
            "Packets".into()
        }
        fn json_schema(_: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": ["integer", "string"],
                "description": "A number of packets, or a count as tc(8) writes it (\"1000p\").",
            })
        }
    }

    impl JsonSchema for Percent {
        fn schema_name() -> Cow<'static, str> {
            "Percent".into()
        }
        fn json_schema(_: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": ["string", "number"],
                "description": "A percentage from 0 to 100: \"1.5%\", or a number of percent.",
            })
        }
    }

    /// The schema of a duration: `#[schemars(with = "HumanDuration")]`.
    pub struct HumanDuration;

    impl JsonSchema for HumanDuration {
        fn schema_name() -> Cow<'static, str> {
            "Duration".into()
        }
        fn json_schema(_: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": ["string", "integer"],
                "description": "A time, as tc(8) writes it (\"10ms\", \"1.5s\", \"250us\"), or a number of microseconds.",
            })
        }
    }
}

#[cfg(feature = "schemars")]
pub use schema::HumanDuration;

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Units {
        rate: Rate,
        size: Bytes,
        loss: Percent,
        #[serde(with = "duration")]
        delay: Duration,
        #[serde(with = "option_duration", default)]
        jitter: Option<Duration>,
    }

    #[test]
    fn units_write_as_tc_does_and_read_back() {
        let u = Units {
            rate: Rate::mbit(100),
            size: Bytes::kib(32),
            loss: Percent::new(1.5),
            delay: Duration::from_millis(10),
            jitter: Some(Duration::from_nanos(1_499_968)),
        };
        let json = serde_json::to_string(&u).unwrap();
        assert_eq!(
            json,
            r#"{"rate":"100mbit","size":"32kib","loss":"1.5%","delay":"10ms","jitter":"1499.968us"}"#
        );
        assert_eq!(serde_json::from_str::<Units>(&json).unwrap(), u);
    }

    /// #643: a packet count is a number, as the documents before 0.32 wrote
    /// it, and reads tc(8)'s `1000p` too.
    #[test]
    fn packets_are_numbers_and_read_tc_text() {
        assert_eq!(serde_json::to_string(&Packets::new(1000)).unwrap(), "1000");
        for doc in ["1000", r#""1000p""#, r#""1000""#] {
            assert_eq!(serde_json::from_str::<Packets>(doc).unwrap(), Packets::new(1000), "{doc}");
        }
        for doc in ["-1", "4294967296", r#""1000kb""#, "1.5"] {
            assert!(serde_json::from_str::<Packets>(doc).is_err(), "{doc}");
        }
    }

    #[test]
    fn numbers_read_in_the_documented_units() {
        let u: Units =
            serde_json::from_str(r#"{"rate":"1gbit","size":2048,"loss":25,"delay":1500}"#).unwrap();
        assert_eq!(u.size, Bytes::new(2048));
        assert_eq!(u.loss, Percent::new(25.0));
        assert_eq!(u.delay, Duration::from_micros(1500));
        assert_eq!(u.jitter, None);
    }

    #[test]
    fn what_cannot_be_meant_is_refused() {
        for bad in [
            r#"{"rate":1000,"size":1,"loss":1,"delay":1}"#,
            r#"{"rate":"1mbit","size":-1,"loss":1,"delay":1}"#,
            r#"{"rate":"1mbit","size":1,"loss":150,"delay":1}"#,
            r#"{"rate":"1mbit","size":1,"loss":"NaN%","delay":1}"#,
            r#"{"rate":"1mbit","size":1,"loss":1,"delay":"10 parsecs"}"#,
            r#"{"rate":"1mbit","size":1,"loss":1,"delay":-5}"#,
        ] {
            assert!(serde_json::from_str::<Units>(bad).is_err(), "{bad}");
        }
    }
}
