//! JSON output formatting.

use std::io::Write;

use serde::Serialize;
use serde_json::{Map, Value};

/// JSON output helper.
pub struct JsonOutput<W: Write> {
    writer: W,
    pretty: bool,
}

impl<W: Write> JsonOutput<W> {
    /// Create a new JSON output.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            pretty: false,
        }
    }

    /// Enable pretty printing.
    pub fn pretty(mut self) -> Self {
        self.pretty = true;
        self
    }

    /// Write a JSON value.
    pub fn write_value(&mut self, value: &Value) -> std::io::Result<()> {
        if self.pretty {
            serde_json::to_writer_pretty(&mut self.writer, value)?;
        } else {
            serde_json::to_writer(&mut self.writer, value)?;
        }
        writeln!(self.writer)
    }

    /// Write a serializable value.
    pub fn write<T: Serialize>(&mut self, value: &T) -> std::io::Result<()> {
        if self.pretty {
            serde_json::to_writer_pretty(&mut self.writer, value)?;
        } else {
            serde_json::to_writer(&mut self.writer, value)?;
        }
        writeln!(self.writer)
    }

    /// Get the underlying writer.
    pub fn into_inner(self) -> W {
        self.writer
    }
}

/// Helper for building JSON objects.
#[allow(dead_code)]
pub struct JsonBuilder {
    map: Map<String, Value>,
}

#[allow(dead_code)]
impl JsonBuilder {
    /// Create a new JSON builder.
    pub fn new() -> Self {
        Self { map: Map::new() }
    }

    /// Add a string field.
    pub fn string(mut self, key: &str, value: impl Into<String>) -> Self {
        self.map
            .insert(key.to_string(), Value::String(value.into()));
        self
    }

    /// Add a string field if the value is Some.
    pub fn string_opt(mut self, key: &str, value: Option<impl Into<String>>) -> Self {
        if let Some(v) = value {
            self.map.insert(key.to_string(), Value::String(v.into()));
        }
        self
    }

    /// Add a number field.
    pub fn number(mut self, key: &str, value: impl Into<serde_json::Number>) -> Self {
        self.map
            .insert(key.to_string(), Value::Number(value.into()));
        self
    }

    /// Add a u64 field.
    pub fn u64(mut self, key: &str, value: u64) -> Self {
        self.map
            .insert(key.to_string(), Value::Number(value.into()));
        self
    }

    /// Add an i64 field.
    pub fn i64(mut self, key: &str, value: i64) -> Self {
        self.map
            .insert(key.to_string(), Value::Number(value.into()));
        self
    }

    /// Add a boolean field.
    pub fn bool(mut self, key: &str, value: bool) -> Self {
        self.map.insert(key.to_string(), Value::Bool(value));
        self
    }

    /// Add a null field.
    pub fn null(mut self, key: &str) -> Self {
        self.map.insert(key.to_string(), Value::Null);
        self
    }

    /// Add an array field.
    pub fn array(mut self, key: &str, value: Vec<Value>) -> Self {
        self.map.insert(key.to_string(), Value::Array(value));
        self
    }

    /// Add an object field.
    pub fn object(mut self, key: &str, value: Value) -> Self {
        self.map.insert(key.to_string(), value);
        self
    }

    /// Add a field with any JSON value.
    pub fn field(mut self, key: &str, value: Value) -> Self {
        self.map.insert(key.to_string(), value);
        self
    }

    /// Build the JSON value.
    pub fn build(self) -> Value {
        Value::Object(self.map)
    }
}

impl Default for JsonBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_builder() {
        let json = JsonBuilder::new()
            .string("name", "eth0")
            .u64("index", 1)
            .bool("up", true)
            .build();

        assert_eq!(json["name"], "eth0");
        assert_eq!(json["index"], 1);
        assert_eq!(json["up"], true);
    }
}
