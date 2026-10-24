use anyhow::Result;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use mongodb::{
    bson::{doc, oid::ObjectId, spec::BinarySubtype, Binary, Bson, DateTime},
    Client,
};
use porthub_api::{config::Config, App};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

async fn call(
    router: &Router,
    method: &str,
    path: &str,
    cookie: &str,
    body: Value,
) -> Result<(StatusCode, axum::http::HeaderMap, Value)> {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("cookie", cookie)
        .header("x-forwarded-proto", "https")
        .body(Body::from(body.to_string()))?;
    let response = router.clone().oneshot(request).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await?)?;
    Ok((status, headers, body))
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn preserves_go_accounts_sessions_and_bcrypt_passwords() -> Result<()> {
    let uri = std::env::var("PORTHUB_TEST_MONGO_URI")?;
    let client = Client::with_uri_str(&uri).await?;
    let name = format!("porthub_rust_test_{}", uuid::Uuid::new_v4().simple());
    let db = client.database(&name);
    let result = async {
        let config = Config {
            listen:"127.0.0.1:0".into(),mongo_uri:uri,mongo_database:name,
            session_cookie:"porthub_session".into(), signup_disabled:true,
            service_domain:"test.invalid".into(),proxy_domain_suffix:"test.invalid".into(),
            telegram_base_url:"https://api.telegram.org".into(),
            ..Config::default()
        };
        let app = Arc::new(App::new(config, db.clone()));
        let user_id = ObjectId::new();
        let hash = bcrypt::hash("Existing-Password1!", 4)?;
        app.collection("users").insert_one(doc! {
            "_id":user_id,"name":"Existing user","username":"existing@example.invalid","role":"admin",
            "password":Bson::Binary(Binary {subtype:BinarySubtype::Generic,bytes:hash.into_bytes()}),
            "created_at":DateTime::from_millis(1_700_000_000_123_i64),"preferences":{"nav_collapsed":true}
        }).await?;
        let now = DateTime::now();
        app.collection("user_sessions").insert_many([
            doc! {"_id":"existing-valid","user_id":user_id.to_hex(),"expires_at":DateTime::from_millis(now.timestamp_millis()+60_000),"renewed_at":DateTime::from_millis(now.timestamp_millis()-90_000_000),"revoked_at":Bson::Null},
            doc! {"_id":"expired","user_id":user_id.to_hex(),"expires_at":DateTime::from_millis(1),"revoked_at":Bson::Null},
            doc! {"_id":"revoked","user_id":user_id.to_hex(),"revoked_at":now},
            doc! {"_id":"another-account","user_id":ObjectId::new().to_hex(),"revoked_at":Bson::Null}
        ]).await?;
        let router = porthub_api::router(app.clone());
        for cookie in ["", "porthub_session=expired", "porthub_session=revoked"] {
            let (status, _, body) = call(&router,"GET","/api/auth/me",cookie,json!(null)).await?;
            assert_eq!(status,StatusCode::BAD_REQUEST);
            assert_eq!(body,json!({"detail":"User not logged in"}));
        }
        let (status, headers, body) = call(&router,"GET","/api/auth/me","porthub_session=existing-valid",json!(null)).await?;
        assert_eq!(status,StatusCode::OK);
        assert_eq!(body["username"],"existing@example.invalid");
        assert_eq!(body["created_at"],"2023-11-14T22:13:20.123000");
        assert_eq!(body["preferences"]["nav_collapsed"],true);
        assert_eq!(body["has_password"],true);
        assert!(headers["set-cookie"].to_str()?.contains("Secure"));
        let (_, headers, _) = call(&router,"GET","/api/auth/me","porthub_session=existing-valid",json!(null)).await?;
        assert!(!headers.contains_key("set-cookie"),"session renewed more than once per day");
        let (status,_,body) = call(&router,"POST","/api/auth/signin","",json!({"username":"existing@example.invalid","password":"wrong"})).await?;
        assert_eq!(status,StatusCode::BAD_REQUEST);assert_eq!(body["detail"],"incorrect password");
        let (status,headers,_) = call(&router,"POST","/api/auth/signin","",json!({"username":"existing@example.invalid","password":"Existing-Password1!"})).await?;
        assert_eq!(status,StatusCode::OK);
        let cookie = headers["set-cookie"].to_str()?.split(';').next().unwrap();
        let (_,_,body) = call(&router,"GET","/api/auth/sessions",cookie,json!(null)).await?;
        assert!(body["data"].as_array().unwrap().iter().all(|s|s["id"]!="another-account"));
        let (status,_,_) = call(&router,"POST","/api/auth/signout",cookie,json!(null)).await?;
        assert_eq!(status,StatusCode::OK);
        let (status,_,_) = call(&router,"GET","/api/auth/me",cookie,json!(null)).await?;
        assert_eq!(status,StatusCode::BAD_REQUEST);
        let (status,_,body) = call(&router,"GET","/api/unknown","",json!(null)).await?;
        assert_eq!(status,StatusCode::NOT_FOUND);assert_eq!(body,json!({"detail":"Not Found"}));
        Ok::<_,anyhow::Error>(())
    }.await;
    db.drop().await?;
    result
}
