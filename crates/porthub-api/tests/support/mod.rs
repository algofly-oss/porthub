use anyhow::{ensure, Context, Result};
use axum::{
    body::{to_bytes, Body},
    http::{HeaderMap, Request, StatusCode},
    Router,
};
use mongodb::{
    bson::{doc, oid::ObjectId, spec::BinarySubtype, Binary, Bson, DateTime},
    Client, Database,
};
use porthub_api::{config::Config, App};
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

pub struct Case {
    pub app: Arc<App>,
    pub router: Router,
    pub db: Database,
}
impl Case {
    pub async fn new(mut config: Config) -> Result<Self> {
        let uri = std::env::var("PORTHUB_TEST_MONGO_URI").context("isolated MongoDB required")?;
        let client = Client::with_uri_str(&uri).await?;
        let db = client.database(&format!(
            "porthub_rust_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        config.mongo_uri = uri;
        config.mongo_database = db.name().into();
        let app = Arc::new(App::new(config, db.clone()));
        let router = porthub_api::router(app.clone());
        Ok(Self { app, router, db })
    }
    pub async fn user(&self, email: &str, role: &str) -> Result<(ObjectId, String)> {
        let id = ObjectId::new();
        let hash = bcrypt::hash("Original-Password1!", 4)?;
        self.app.collection("users").insert_one(doc! {"_id":id,"name":email,"username":email,"role":role,"created_at":DateTime::now(),
            "password":Bson::Binary(Binary{subtype:BinarySubtype::Generic,bytes:hash.into_bytes()})}).await?;
        let token = uuid::Uuid::new_v4().to_string();
        let now = DateTime::now();
        self.app.collection("user_sessions").insert_one(doc! {"_id":&token,"user_id":id.to_hex(),"revoked_at":Bson::Null,"renewed_at":now,"expires_at":DateTime::from_millis(now.timestamp_millis()+86_400_000)}).await?;
        Ok((id, format!("porthub_session={token}")))
    }
    pub async fn call(
        &self,
        method: &str,
        path: &str,
        cookie: &str,
        body: Value,
        extra: &[(&str, &str)],
    ) -> Result<(StatusCode, HeaderMap, Value)> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "porthub.test")
            .header("content-type", "application/json")
            .header("cookie", cookie)
            .header("x-forwarded-proto", "https");
        for (key, value) in extra {
            request = request.header(*key, *value);
        }
        let response = self
            .router
            .clone()
            .oneshot(request.body(Body::from(body.to_string()))?)
            .await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024).await?;
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        };
        Ok((status, headers, value))
    }
    pub async fn status(
        &self,
        method: &str,
        path: &str,
        cookie: &str,
        body: Value,
        expected: StatusCode,
    ) -> Result<Value> {
        let (status, _, body) = self.call(method, path, cookie, body, &[]).await?;
        ensure!(
            status == expected,
            "{method} {path}: expected {expected}, got {status}: {body}"
        );
        Ok(body)
    }
}
