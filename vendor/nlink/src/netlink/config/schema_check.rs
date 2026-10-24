//! A JSON Schema check for the tests: does a value's JSON match the schema
//! its type publishes (#876)?
//!
//! A field with a custom `serialize_with` and no matching `schemars(with)`
//! gets a schema of its Rust type, not of its JSON: a public key described
//! as 32 integers, written as a base64 string. Nothing compared the two,
//! so a consumer validating real output against `json_schema_value()` was
//! the first to notice.
//!
//! This validates draft-07 as `schemars` writes it, and nothing more, which
//! is why it is not a dependency: both validators on crates.io pull in
//! 30-odd crates for one test. It is strict about what it does not know: a
//! keyword it cannot check panics rather than pass, so a schema that grows
//! a `pattern` makes the test learn it instead of skipping it. It sees only
//! the parts of a schema the JSON reaches, which is why the tests fill in
//! every root field.

use serde_json::{Map, Value};

/// Keywords that only describe; nothing to check.
const ANNOTATIONS: &[&str] = &[
    "$schema",
    "$comment",
    "$id",
    "title",
    "description",
    "default",
    "examples",
    "deprecated",
    "readOnly",
    "writeOnly",
    // An annotation in draft 7 unless a validator opts in; schemars's
    // integer formats (`uint8`, …) come with `minimum`/`maximum`.
    "format",
    "definitions",
];

/// Panics unless `value`'s JSON matches `schema`, listing every mismatch by
/// its JSON path.
pub(crate) fn assert_matches_schema<T: serde::Serialize>(value: &T, schema: schemars::Schema) {
    let instance = serde_json::to_value(value).expect("the value serializes");
    let schema = serde_json::to_value(schema).expect("the schema serializes");
    let errors = violations(&schema, &instance);
    assert!(
        errors.is_empty(),
        "the JSON does not match its own schema:\n  {}\nJSON: {instance:#}",
        errors.join("\n  ")
    );
}

/// Panics unless every property the schema's root lists is in `value`'s
/// JSON and not empty, so a test cannot validate a diff whose new field it
/// never filled in.
pub(crate) fn assert_every_root_property_populated<T: serde::Serialize>(
    value: &T,
    schema: schemars::Schema,
) {
    let instance = serde_json::to_value(value).expect("the value serializes");
    let schema = serde_json::to_value(schema).expect("the schema serializes");
    let properties = schema["properties"]
        .as_object()
        .expect("the root lists its properties");
    let missing: Vec<&String> = properties
        .keys()
        .filter(|key| match instance.get(key.as_str()) {
            None | Some(Value::Null) => true,
            Some(Value::Array(a)) => a.is_empty(),
            Some(Value::Object(o)) => o.is_empty(),
            Some(_) => false,
        })
        .collect();
    assert!(
        missing.is_empty(),
        "the test leaves these empty, so their schema is unchecked: {missing:?}"
    );
}

/// Every way `instance` fails `schema`, by JSON path.
pub(crate) fn violations(schema: &Value, instance: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    check(schema, schema, instance, "$", &mut errors);
    errors
}

fn check(root: &Value, schema: &Value, instance: &Value, path: &str, errors: &mut Vec<String>) {
    let schema = match schema {
        Value::Bool(true) => return,
        Value::Bool(false) => {
            errors.push(format!("{path}: the schema allows nothing here"));
            return;
        }
        Value::Object(schema) => schema,
        other => panic!("{path}: not a schema: {other}"),
    };
    for (keyword, value) in schema {
        let keyword = keyword.as_str();
        if ANNOTATIONS.contains(&keyword) {
            continue;
        }
        match keyword {
            "$ref" => {
                let target = value.as_str().expect("$ref is a string");
                let pointer = target
                    .strip_prefix('#')
                    .unwrap_or_else(|| panic!("{path}: external $ref {target}"));
                let resolved = root
                    .pointer(pointer)
                    .unwrap_or_else(|| panic!("{path}: dangling $ref {target}"));
                check(root, resolved, instance, path, errors);
            }
            "type" => {
                let types: Vec<&str> = match value {
                    Value::String(t) => vec![t.as_str()],
                    Value::Array(ts) => ts
                        .iter()
                        .map(|t| t.as_str().expect("a type name"))
                        .collect(),
                    other => panic!("{path}: bad type {other}"),
                };
                if !types.iter().any(|t| is_type(instance, t)) {
                    errors.push(format!(
                        "{path}: {} is not of type {}",
                        short(instance),
                        types.join(" or ")
                    ));
                }
            }
            "enum" => {
                let options = value.as_array().expect("enum is an array");
                if !options.contains(instance) {
                    errors.push(format!("{path}: {} is not one of {value}", short(instance)));
                }
            }
            "const" => {
                if instance != value {
                    errors.push(format!("{path}: {} is not {value}", short(instance)));
                }
            }
            "properties"
            | "required"
            | "additionalProperties"
            | "minProperties"
            | "maxProperties" => {
                if let Value::Object(object) = instance {
                    check_object_keyword(root, schema, keyword, value, object, path, errors);
                }
            }
            "items" | "additionalItems" | "minItems" | "maxItems" | "uniqueItems" => {
                if let Value::Array(items) = instance {
                    check_array_keyword(root, schema, keyword, value, items, path, errors);
                }
            }
            "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" => {
                if let Some(n) = instance.as_f64() {
                    let bound = value.as_f64().expect("a numeric bound");
                    let ok = match keyword {
                        "minimum" => n >= bound,
                        "maximum" => n <= bound,
                        "exclusiveMinimum" => n > bound,
                        _ => n < bound,
                    };
                    if !ok {
                        errors.push(format!("{path}: {n} breaks {keyword} {bound}"));
                    }
                }
            }
            "minLength" | "maxLength" => {
                if let Some(s) = instance.as_str() {
                    let len = s.chars().count() as u64;
                    let bound = value.as_u64().expect("a length");
                    if (keyword == "minLength" && len < bound)
                        || (keyword == "maxLength" && len > bound)
                    {
                        errors.push(format!("{path}: length {len} breaks {keyword} {bound}"));
                    }
                }
            }
            "allOf" => {
                for sub in value.as_array().expect("allOf is an array") {
                    check(root, sub, instance, path, errors);
                }
            }
            "anyOf" | "oneOf" => {
                let subs = value.as_array().expect("anyOf/oneOf is an array");
                let mut failures = Vec::new();
                let matching = subs
                    .iter()
                    .filter(|sub| {
                        let mut e = Vec::new();
                        check(root, sub, instance, path, &mut e);
                        let ok = e.is_empty();
                        failures.extend(e);
                        ok
                    })
                    .count();
                if matching == 0 {
                    errors.push(format!(
                        "{path}: {} matches none of its {keyword}: {}",
                        short(instance),
                        failures.join("; ")
                    ));
                } else if keyword == "oneOf" && matching > 1 {
                    errors.push(format!(
                        "{path}: {} matches {matching} branches of a oneOf",
                        short(instance)
                    ));
                }
            }
            "not" => {
                let mut e = Vec::new();
                check(root, value, instance, path, &mut e);
                if e.is_empty() {
                    errors.push(format!("{path}: {} matches a `not`", short(instance)));
                }
            }
            other => panic!(
                "{path}: schema_check does not know the keyword `{other}`; teach it before trusting it"
            ),
        }
    }
}

fn check_object_keyword(
    root: &Value,
    schema: &Map<String, Value>,
    keyword: &str,
    value: &Value,
    object: &Map<String, Value>,
    path: &str,
    errors: &mut Vec<String>,
) {
    match keyword {
        "properties" => {
            for (name, sub) in value.as_object().expect("properties is an object") {
                if let Some(v) = object.get(name) {
                    check(root, sub, v, &format!("{path}.{name}"), errors);
                }
            }
        }
        "required" => {
            for name in value.as_array().expect("required is an array") {
                let name = name.as_str().expect("a property name");
                if !object.contains_key(name) {
                    errors.push(format!("{path}: missing required `{name}`"));
                }
            }
        }
        "additionalProperties" => {
            let known = schema.get("properties").and_then(Value::as_object);
            if schema.contains_key("patternProperties") {
                panic!("{path}: schema_check does not know `patternProperties`");
            }
            for (name, v) in object {
                if known.is_some_and(|k| k.contains_key(name)) {
                    continue;
                }
                check(root, value, v, &format!("{path}.{name}"), errors);
            }
        }
        _ => {
            let bound = value.as_u64().expect("a count") as usize;
            if (keyword == "minProperties" && object.len() < bound)
                || (keyword == "maxProperties" && object.len() > bound)
            {
                errors.push(format!(
                    "{path}: {} properties break {keyword} {bound}",
                    object.len()
                ));
            }
        }
    }
}

fn check_array_keyword(
    root: &Value,
    schema: &Map<String, Value>,
    keyword: &str,
    value: &Value,
    items: &[Value],
    path: &str,
    errors: &mut Vec<String>,
) {
    match keyword {
        "items" => match value {
            // Draft 7's tuple form: one schema per position.
            Value::Array(positions) => {
                for (i, (sub, item)) in positions.iter().zip(items).enumerate() {
                    check(root, sub, item, &format!("{path}[{i}]"), errors);
                }
            }
            sub => {
                for (i, item) in items.iter().enumerate() {
                    check(root, sub, item, &format!("{path}[{i}]"), errors);
                }
            }
        },
        "additionalItems" => {
            if let Some(Value::Array(positions)) = schema.get("items") {
                for (i, item) in items.iter().enumerate().skip(positions.len()) {
                    check(root, value, item, &format!("{path}[{i}]"), errors);
                }
            }
        }
        "uniqueItems" => {
            if value == &Value::Bool(true) {
                for (i, item) in items.iter().enumerate() {
                    if items[..i].contains(item) {
                        errors.push(format!(
                            "{path}[{i}]: a repeated item in a uniqueItems array"
                        ));
                    }
                }
            }
        }
        _ => {
            let bound = value.as_u64().expect("a count") as usize;
            if (keyword == "minItems" && items.len() < bound)
                || (keyword == "maxItems" && items.len() > bound)
            {
                errors.push(format!(
                    "{path}: {} items break {keyword} {bound}",
                    items.len()
                ));
            }
        }
    }
}

fn is_type(instance: &Value, ty: &str) -> bool {
    match ty {
        "null" => instance.is_null(),
        "boolean" => instance.is_boolean(),
        "string" => instance.is_string(),
        "array" => instance.is_array(),
        "object" => instance.is_object(),
        "number" => instance.is_number(),
        "integer" => {
            instance.is_i64()
                || instance.is_u64()
                || instance.as_f64().is_some_and(|f| f.fract() == 0.0)
        }
        other => panic!("unknown JSON type `{other}`"),
    }
}

/// An instance, cut short for an error message.
fn short(instance: &Value) -> String {
    let s = instance.to_string();
    if s.chars().count() > 60 {
        format!("{}…", s.chars().take(60).collect::<String>())
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::violations;

    /// The check itself, where it must fail: each keyword it implements
    /// rejects an instance that breaks it.
    #[test]
    fn each_keyword_rejects_what_breaks_it() {
        let schema = json!({
            "type": "object",
            "required": ["key"],
            "properties": {
                "key": { "type": "string" },
                "port": { "type": "integer", "minimum": 0, "maximum": 65535 },
                "keys": { "type": "array", "items": { "$ref": "#/definitions/Key" } },
                "pair": { "type": "array", "items": [{ "type": "string" }, { "type": "boolean" }], "maxItems": 2 },
                "kind": { "oneOf": [{ "const": "a" }, { "enum": ["b", "c"] }] },
            },
            "additionalProperties": false,
            "definitions": { "Key": { "type": "string", "minLength": 44, "maxLength": 44 } },
        });
        let good = json!({ "key": "k", "port": 22, "keys": ["x".repeat(44)], "pair": ["a", true], "kind": "c" });
        assert_eq!(violations(&schema, &good), Vec::<String>::new());

        for (bad, why) in [
            (json!({ "port": 1 }), "missing required"),
            (json!({ "key": [1, 2] }), "is not of type string"),
            (json!({ "key": "k", "port": 70000 }), "breaks maximum"),
            (json!({ "key": "k", "port": 1.5 }), "is not of type integer"),
            (
                json!({ "key": "k", "keys": [[1, 2]] }),
                "$.keys[0]: [1,2] is not of type string",
            ),
            (json!({ "key": "k", "keys": ["short"] }), "breaks minLength"),
            (json!({ "key": "k", "pair": ["a", "b"] }), "$.pair[1]"),
            (
                json!({ "key": "k", "pair": ["a", true, 1] }),
                "break maxItems",
            ),
            (
                json!({ "key": "k", "kind": "d" }),
                "matches none of its oneOf",
            ),
            (
                json!({ "key": "k", "extra": 1 }),
                "$.extra: the schema allows nothing here",
            ),
        ] {
            let errors = violations(&schema, &bad);
            assert!(
                errors.iter().any(|e| e.contains(why)),
                "{bad} should fail with `{why}`: {errors:?}"
            );
        }
    }

    #[test]
    #[should_panic(expected = "does not know the keyword `pattern`")]
    fn an_unknown_keyword_panics_rather_than_passes() {
        violations(&json!({ "type": "string", "pattern": "^a" }), &json!("b"));
    }
}
