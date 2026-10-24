use mongodb::bson::{Bson, Document};
use serde_json::{Map, Value};

pub fn datetime(millis: i64) -> String {
    let Some(time) = chrono::DateTime::from_timestamp_millis(millis) else {
        return String::new();
    };
    let base = time.format("%Y-%m-%dT%H:%M:%S").to_string();
    let micros = time.timestamp_subsec_micros();
    if micros == 0 {
        base
    } else {
        format!("{base}.{micros:06}")
    }
}

// Preserve PortHub's existing JSON contract instead of returning MongoDB's
// extended JSON wrappers for ObjectIds and dates.
pub fn json(value: &Bson) -> Value {
    match value {
        Bson::ObjectId(id) => Value::String(id.to_hex()),
        Bson::DateTime(date) => Value::String(datetime(date.timestamp_millis())),
        Bson::Document(doc) => document(doc),
        Bson::Array(values) => Value::Array(values.iter().map(json).collect()),
        Bson::String(value) => Value::String(value.clone()),
        Bson::Boolean(value) => Value::Bool(*value),
        Bson::Int32(value) => (*value).into(),
        Bson::Int64(value) => (*value).into(),
        Bson::Double(value) => serde_json::Number::from_f64(*value)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Bson::Null => Value::Null,
        Bson::Decimal128(value) => Value::String(value.to_string()),
        _ => serde_json::to_value(value).unwrap_or(Value::Null),
    }
}

pub fn id(value: Option<&Bson>) -> String {
    match value {
        Some(Bson::ObjectId(id)) => id.to_hex(),
        Some(Bson::String(value)) => value.clone(),
        _ => String::new(),
    }
}

pub fn string<'a>(doc: &'a Document, key: &str) -> &'a str {
    doc.get_str(key).unwrap_or("")
}

pub fn duplicate(error: &mongodb::error::Error) -> bool {
    use mongodb::error::{ErrorKind, WriteFailure};
    match error.kind.as_ref() {
        ErrorKind::Write(WriteFailure::WriteError(error)) => error.code == 11000,
        ErrorKind::Command(error) => error.code == 11000,
        _ => false,
    }
}

pub fn field(doc: &Document, key: &str) -> Value {
    doc.get(key).map(json).unwrap_or(Value::Null)
}

pub fn document(doc: &Document) -> Value {
    Value::Object(
        doc.iter()
            .map(|(key, value)| (key.clone(), json(value)))
            .collect::<Map<_, _>>(),
    )
}
