use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

pub struct ApiError {
    pub status: StatusCode,
    pub detail: Value,
    pub headers: Option<Box<axum::http::HeaderMap>>,
}

impl ApiError {
    pub fn bad_request(detail: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, detail)
    }

    pub fn validation(items: Vec<Value>) -> Self {
        Self {
            headers: None,
            status: StatusCode::UNPROCESSABLE_ENTITY,
            detail: Value::Array(items),
        }
    }
    pub fn new(status: StatusCode, detail: &str) -> Self {
        Self {
            headers: None,
            status,
            detail: json!(detail),
        }
    }
    pub fn unauthenticated() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "User not logged in")
    }
    pub fn header(mut self, key: &'static str, value: &'static str) -> Self {
        self.headers
            .get_or_insert_with(Default::default)
            .insert(key, axum::http::HeaderValue::from_static(value));
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (self.status, Json(json!({"detail": self.detail}))).into_response();
        if let Some(headers) = self.headers {
            response.headers_mut().extend(*headers);
        }
        response
    }
}

impl From<mongodb::error::Error> for ApiError {
    fn from(error: mongodb::error::Error) -> Self {
        tracing::error!(%error, "database operation failed");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
