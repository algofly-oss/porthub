//! Legacy JSON pre-validator semantics, implemented natively. These helpers
//! retain existing request contracts while the old runtime is removed.
use serde_json::Value;
use std::fmt::Write;

pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(n) => n.as_f64() != Some(0.),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}
/// Pydantic's dictionary coercion accepts lists of key/value pairs.
pub fn dictionary(value: Value) -> Option<serde_json::Map<String, Value>> {
    match value {
        Value::Object(object) => Some(object),
        Value::Array(values) => {
            let mut object = serde_json::Map::new();
            for value in values {
                match value {
                    Value::Array(pair) if pair.len() == 2 && pair[0].is_string() => {
                        object.insert(pair[0].as_str()?.into(), pair[1].clone());
                    }
                    Value::String(pair) if pair.chars().count() == 2 => {
                        let mut chars = pair.chars();
                        object.insert(
                            chars.next()?.to_string(),
                            Value::String(chars.next()?.to_string()),
                        );
                    }
                    _ => return None,
                }
            }
            Some(object)
        }
        _ => None,
    }
}
pub fn strip(value: &str) -> &str {
    value.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}
pub fn text(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(number) if number.is_f64() => {
            let value = number.as_f64().unwrap();
            if value.abs() >= 1e16 || (value != 0. && value.abs() < 1e-4) {
                let value = format!("{value:e}");
                let (mantissa, exponent) = value.split_once('e').unwrap();
                let exponent = exponent.parse::<i32>().unwrap();
                format!("{mantissa}e{exponent:+03}")
            } else {
                let mut value = value.to_string();
                if !value.contains('.') {
                    value.push_str(".0");
                }
                value
            }
        }
        Value::Number(number) => number.to_string(),
        other => repr(other),
    }
}
fn repr(value: &Value) -> String {
    match value {
        Value::String(value) => {
            let quote = if value.contains('\'') && !value.contains('"') {
                '"'
            } else {
                '\''
            };
            let mut result = String::new();
            result.push(quote);
            for c in value.chars() {
                match c {
                    '\n' => result.push_str("\\n"),
                    '\r' => result.push_str("\\r"),
                    '\t' => result.push_str("\\t"),
                    c if c == quote || c == '\\' => {
                        result.push('\\');
                        result.push(c);
                    }
                    c if c.is_control() => {
                        let code = c as u32;
                        if code <= 255 {
                            write!(result, "\\x{code:02x}").unwrap();
                        } else {
                            write!(result, "\\u{code:04x}").unwrap();
                        }
                    }
                    c => result.push(c),
                }
            }
            result.push(quote);
            result
        }
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(repr).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .map(|(k, v)| format!("{}: {}", repr(&Value::String(k.clone())), repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => text(other),
    }
}
pub fn items(value: Value) -> Result<Vec<Value>, String> {
    match value {
        Value::Array(values) => Ok(values),
        Value::Object(values) => Ok(values
            .into_iter()
            .map(|(key, _)| Value::String(key))
            .collect()),
        Value::String(value) => Ok(value
            .chars()
            .map(|c| Value::String(c.to_string()))
            .collect()),
        Value::Bool(_) => Err("'bool' object is not iterable".into()),
        Value::Number(n) => Err(format!(
            "'{}' object is not iterable",
            if n.is_f64() { "float" } else { "int" }
        )),
        Value::Null => Err("'NoneType' object is not iterable".into()),
    }
}
pub fn hostname(value: &str) -> bool {
    (1..=253).contains(&value.chars().count())
        && value.split('.').all(|part| {
            (1..=63).contains(&part.chars().count())
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | 'İ' | 'ı' | 'ſ' | 'K'))
        })
}

/// Legacy bounded-integer coercion; large magnitudes saturate outside API bounds.
pub fn integer(value: &Value) -> Option<i128> {
    match value {
        Value::Bool(value) => Some(i128::from(*value)),
        Value::Number(number) => number
            .as_i64()
            .map(i128::from)
            .or_else(|| number.as_u64().map(i128::from))
            .or_else(|| {
                number
                    .as_f64()
                    .filter(|n| n.is_finite())
                    .map(|n| n.trunc() as i128)
            }),
        Value::String(value) => {
            let value = value.trim();
            let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
            if !digits.is_empty()
                && !digits.starts_with('_')
                && !digits.ends_with('_')
                && !digits.contains("__")
                && digits.bytes().all(|c| c.is_ascii_digit() || c == b'_')
            {
                let normalized = value.replace('_', "");
                Some(
                    normalized
                        .parse::<i128>()
                        .unwrap_or(if value.starts_with('-') {
                            i128::MIN
                        } else {
                            i128::MAX
                        }),
                )
            } else {
                None
            }
        }
        _ => None,
    }
}
