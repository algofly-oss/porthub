//! Existing clients expect FastAPI-shaped validation errors. Validate request
//! objects in declared field order, including the legacy numeric/bool coercions.
use crate::error::{ApiError, ApiResult};
use axum::{
    body::Bytes,
    extract::{FromRequest, Request},
};
use serde_json::{json, Map, Value};

pub struct ApiBody(pub Value);

impl<S: Send + Sync> FromRequest<S> for ApiBody {
    type Rejection = ApiError;
    async fn from_request(request: Request, state: &S) -> ApiResult<Self> {
        let body = Bytes::from_request(request, state).await.map_err(|_| {
            ApiError::new(
                axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                "Request body is too large",
            )
        })?;
        if body.is_empty() {
            return Err(ApiError::validation(vec![
                json!({"loc":["body"],"msg":"field required","type":"value_error.missing"}),
            ]));
        }
        serde_json::from_slice(&body).map(Self).map_err(|error| {
            ApiError::validation(vec![
                json!({"loc":["body",0],"msg":error.to_string(),"type":"value_error.jsondecode"}),
            ])
        })
    }
}

pub struct Model {
    object: Map<String, Value>,
    location: Vec<Value>,
    errors: Vec<Value>,
}

impl Model {
    pub fn alias(&mut self, primary: &str, secondary: &str) {
        if !self.object.contains_key(primary) {
            if let Some(value) = self.object.get(secondary).cloned() {
                self.object.insert(primary.into(), value);
            }
        }
    }
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
    pub fn query(values: std::collections::HashMap<String, String>) -> Self {
        Self {
            object: values
                .into_iter()
                .map(|(k, v)| (k, Value::String(v)))
                .collect(),
            location: vec![json!("query")],
            errors: Vec::new(),
        }
    }
    pub fn field_valid(&self, key: &str) -> bool {
        !self.errors.iter().any(|error| {
            error["loc"]
                .as_array()
                .is_some_and(|location| location.get(self.location.len()) == Some(&json!(key)))
        })
    }
    pub fn new(value: Value) -> ApiResult<Self> {
        let object = match value {
            Value::Object(object) => object,
            Value::Null => {
                return Err(ApiError::validation(vec![
                    json!({"loc":["body"],"msg":"field required","type":"value_error.missing"}),
                ]))
            }
            _ => {
                return Err(ApiError::validation(vec![
                    json!({"loc":["body"],"msg":"value is not a valid dict","type":"type_error.dict"}),
                ]))
            }
        };
        Ok(Self {
            object,
            location: vec![json!("body")],
            errors: Vec::new(),
        })
    }

    pub fn field(&self, keys: &[&str]) -> Option<Value> {
        keys.iter().find_map(|key| self.object.get(*key)).cloned()
    }

    fn add_at(
        &mut self,
        key: &str,
        index: Option<usize>,
        message: &str,
        kind: &str,
        context: Option<Value>,
    ) {
        let mut location = self.location.clone();
        location.push(json!(key));
        if let Some(index) = index {
            location.push(json!(index));
        }
        let mut error = json!({"loc":location,"msg":message,"type":kind});
        if let Some(context) = context {
            error["ctx"] = context;
        }
        self.errors.push(error);
    }

    pub fn add(&mut self, key: &str, message: &str, kind: &str) {
        self.add_at(key, None, message, kind, None);
    }

    fn missing(&mut self, key: &str) {
        self.add(key, "field required", "value_error.missing");
    }
    fn null(&mut self, key: &str) {
        self.add(
            key,
            "none is not an allowed value",
            "type_error.none.not_allowed",
        );
    }

    pub fn required_string(&mut self, key: &str) -> String {
        match self.field(&[key]) {
            None => {
                self.missing(key);
                String::new()
            }
            Some(Value::Null) => {
                self.null(key);
                String::new()
            }
            Some(value) => self.string_value(key, None, value).unwrap_or_default(),
        }
    }

    fn string_value(&mut self, key: &str, index: Option<usize>, value: Value) -> Option<String> {
        match value {
            Value::String(s) => Some(s),
            Value::Number(n) => Some(crate::input_compat::text(&Value::Number(n))),
            Value::Bool(true) => Some("True".into()),
            Value::Bool(false) => Some("False".into()),
            Value::Null => {
                self.add_at(
                    key,
                    index,
                    "none is not an allowed value",
                    "type_error.none.not_allowed",
                    None,
                );
                None
            }
            _ => {
                self.add_at(key, index, "str type expected", "type_error.str", None);
                None
            }
        }
    }

    pub fn optional_string(&mut self, key: &str) -> Option<String> {
        match self.field(&[key]) {
            None | Some(Value::Null) => None,
            Some(value) => self.string_value(key, None, value),
        }
    }

    pub fn string_length(
        &mut self,
        key: &str,
        value: &str,
        minimum: usize,
        maximum: Option<usize>,
    ) {
        if self.errors.iter().any(|error| {
            error["loc"]
                .as_array()
                .is_some_and(|loc| loc.get(self.location.len()) == Some(&json!(key)))
        }) {
            return;
        }
        let size = value.chars().count();
        if size < minimum {
            self.add_at(
                key,
                None,
                &format!("ensure this value has at least {minimum} characters"),
                "value_error.any_str.min_length",
                Some(json!({"limit_value":minimum})),
            );
        } else if let Some(maximum) = maximum.filter(|max| size > *max) {
            self.add_at(
                key,
                None,
                &format!("ensure this value has at most {maximum} characters"),
                "value_error.any_str.max_length",
                Some(json!({"limit_value":maximum})),
            );
        }
    }

    pub fn optional_bool(&mut self, key: &str) -> Option<bool> {
        let value = match self.field(&[key]) {
            None | Some(Value::Null) => return None,
            Some(value) => value,
        };
        let parsed = match value {
            Value::Bool(value) => Some(value),
            Value::Number(value) if value.as_f64() == Some(0.0) => Some(false),
            Value::Number(value) if value.as_f64() == Some(1.0) => Some(true),
            Value::String(value) => match value.to_ascii_lowercase().as_str() {
                "1" | "true" | "t" | "on" | "yes" | "y" => Some(true),
                "0" | "false" | "f" | "off" | "no" | "n" => Some(false),
                _ => None,
            },
            _ => None,
        };
        if parsed.is_none() {
            self.add(
                key,
                "value could not be parsed to a boolean",
                "type_error.bool",
            );
        }
        parsed
    }

    pub fn required_bool(&mut self, key: &str) -> bool {
        match self.field(&[key]) {
            None => {
                self.missing(key);
                false
            }
            Some(Value::Null) => {
                self.null(key);
                false
            }
            _ => self.optional_bool(key).unwrap_or(false),
        }
    }

    pub fn required_integer(&mut self, key: &str, minimum: i64, maximum: i64) -> i64 {
        match self.field(&[key]) {
            None => {
                self.missing(key);
                0
            }
            Some(Value::Null) => {
                self.null(key);
                0
            }
            _ => self.optional_integer(key, minimum, maximum).unwrap_or(0),
        }
    }
    pub fn list(&mut self, key: &str) -> Vec<Value> {
        match self.field(&[key]) {
            None => Vec::new(),
            Some(Value::Array(values)) => values,
            Some(Value::Null) => {
                self.null(key);
                Vec::new()
            }
            _ => {
                self.add(key, "value is not a valid list", "type_error.list");
                Vec::new()
            }
        }
    }
    pub fn add_index(&mut self, key: &str, index: usize, message: &str, kind: &str) {
        self.add_at(key, Some(index), message, kind, None);
    }
    /// Nested bounded models retain the full error path and field order.
    pub fn bounded_list(
        &mut self,
        key: &str,
        required: bool,
        minimum: usize,
        maximum: usize,
    ) -> Vec<Value> {
        if self.field(&[key]).is_none() && required {
            self.missing(key);
            return Vec::new();
        }
        let values = self.list(key);
        if !self.field_valid(key) {
            return Vec::new();
        }
        let constraint = if values.len() < minimum {
            Some(("at least", "min_items", minimum))
        } else if values.len() > maximum {
            Some(("at most", "max_items", maximum))
        } else {
            None
        };
        if let Some((words, kind, limit)) = constraint {
            self.add_at(
                key,
                None,
                &format!("ensure this value has {words} {limit} items"),
                &format!("value_error.list.{kind}"),
                Some(json!({"limit_value":limit})),
            );
            return Vec::new();
        }
        values
    }
    pub fn objects(
        &mut self,
        key: &str,
        required: bool,
        minimum: usize,
        maximum: usize,
    ) -> Vec<Self> {
        self.bounded_list(key, required, minimum, maximum)
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                let null = value.is_null();
                let object = crate::input_compat::dictionary(value);
                let mut location = self.location.clone();
                location.extend([json!(key), json!(index)]);
                match object {
                    Some(object) => Self {
                        object,
                        location,
                        errors: Vec::new(),
                    },
                    None => {
                        let msg = if null {
                            "none is not an allowed value"
                        } else {
                            "value is not a valid dict"
                        };
                        let kind = if null {
                            "type_error.none.not_allowed"
                        } else {
                            "type_error.dict"
                        };
                        Self {
                            object: Map::new(),
                            errors: vec![json!({"loc":location,"msg":msg,"type":kind})],
                            location,
                        }
                    }
                }
            })
            .collect()
    }
    pub fn string_list(&mut self, key: &str, maximum: usize) -> Vec<String> {
        self.bounded_list(key, false, 0, maximum)
            .into_iter()
            .enumerate()
            .filter_map(|(index, value)| self.string_value(key, Some(index), value))
            .collect()
    }
    pub fn required_object(&mut self, key: &str) -> Option<Self> {
        let value = match self.field(&[key]) {
            Some(value) => value,
            None => {
                self.missing(key);
                return None;
            }
        };
        if value.is_null() {
            self.null(key);
            return None;
        }
        let Some(object) = crate::input_compat::dictionary(value) else {
            self.add(key, "value is not a valid dict", "type_error.dict");
            return None;
        };
        let mut location = self.location.clone();
        location.push(json!(key));
        Some(Self {
            object,
            location,
            errors: Vec::new(),
        })
    }
    pub fn keys(&self) -> Vec<String> {
        self.object.keys().cloned().collect()
    }
    pub fn regex(&mut self, key: &str, pattern: &str, matches: bool) {
        if self.field_valid(key) && !matches {
            self.add_at(
                key,
                None,
                &format!("string does not match regex \"{pattern}\""),
                "value_error.str.regex",
                Some(json!({"pattern":pattern})),
            );
        }
    }
    pub fn optional_integer(&mut self, key: &str, minimum: i64, maximum: i64) -> Option<i64> {
        let value = match self.field(&[key]) {
            None | Some(Value::Null) => return None,
            Some(value) => value,
        };
        let integer = crate::input_compat::integer(&value);
        match integer {
            None => self.add(key, "value is not a valid integer", "type_error.integer"),
            Some(value) if value < minimum as i128 => self.add_at(
                key,
                None,
                &format!("ensure this value is greater than or equal to {minimum}"),
                "value_error.number.not_ge",
                Some(json!({"limit_value":minimum})),
            ),
            Some(value) if value > maximum as i128 => self.add_at(
                key,
                None,
                &format!("ensure this value is less than or equal to {maximum}"),
                "value_error.number.not_le",
                Some(json!({"limit_value":maximum})),
            ),
            Some(value) => return Some(value as i64),
        }
        None
    }

    pub fn optional_strings(&mut self, key: &str) -> Option<Vec<String>> {
        let values = match self.field(&[key]) {
            None | Some(Value::Null) => return None,
            Some(Value::Array(values)) => values,
            _ => {
                self.add(key, "value is not a valid list", "type_error.list");
                return None;
            }
        };
        Some(
            values
                .into_iter()
                .enumerate()
                .filter_map(|(index, value)| self.string_value(key, Some(index), value))
                .collect(),
        )
    }

    pub fn optional_object(&mut self, key: &str) -> Option<Self> {
        match self.field(&[key]) {
            None | Some(Value::Null) => None,
            Some(Value::Object(object)) => {
                let mut location = self.location.clone();
                location.push(json!(key));
                Some(Self {
                    object,
                    location,
                    errors: Vec::new(),
                })
            }
            _ => {
                self.add(key, "value is not a valid dict", "type_error.dict");
                None
            }
        }
    }

    pub fn merge(&mut self, child: Self) {
        self.errors.extend(child.errors);
    }

    pub fn literal(&mut self, key: &str, default: &str, permitted: &[&str]) -> String {
        let Some(value) = self.field(&[key]) else {
            return default.into();
        };
        if value.is_null() {
            self.null(key);
            return String::new();
        }
        if let Some(value) = value.as_str().filter(|value| permitted.contains(value)) {
            return value.into();
        }
        let names = permitted
            .iter()
            .map(|name| format!("'{name}'"))
            .collect::<Vec<_>>()
            .join(", ");
        self.add_at(
            key,
            None,
            &format!("unexpected value; permitted: {names}"),
            "value_error.const",
            Some(json!({"given":value,"permitted":permitted})),
        );
        String::new()
    }

    pub fn finish(self) -> ApiResult<()> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(ApiError::validation(self.errors))
        }
    }
}
