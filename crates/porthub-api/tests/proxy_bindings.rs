//! Isolated API → Mongo → published routing snapshot → real upstream requests.
use anyhow::{ensure, Result};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::{config::Config, domain::traffic_routes};
use porthub_runtime::web_routes::{Selection, WebRoutes};
use serde_json::json;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::{net::TcpListener, task::JoinSet};
mod support;
use support::Case;

#[test]
fn model_rejects_invalid_pools_and_keeps_two_modes_distinct() {
    let request = json!({"name":"app","hosts":["app.example"],"bindings":[{"id":"a","target_mode":"manual","target_url":"https://a.example"}],"routing":{"mode":"balance","strategy":"weighted_round_robin"}});
    let parsed = traffic_routes::parse(request.clone()).unwrap_or_else(|e| panic!("{}", e.detail));
    assert_eq!(parsed.bindings.unwrap().len(), 1);
    for patch in [
        json!([]),
        json!([{"id":"a","target_mode":"manual","target_url":"file:///etc/passwd"}]),
        json!([{"id":"a","target_mode":"connection","connection_data_id":"invalid"}]),
        json!([{"id":"a","target_mode":"manual","target_url":"https://a.example","weight":0}]),
        json!([{"id":"a","target_mode":"manual","target_url":"https://a.example"},{"id":"a","target_mode":"manual","target_url":"https://b.example"}]),
        json!([{"id":"a","target_mode":"manual","target_url":"https://a.example"},{"id":"b","target_mode":"manual","target_url":"https://a.example/"}]),
    ] {
        let mut invalid = request.clone();
        invalid["bindings"] = patch;
        assert!(traffic_routes::parse(invalid).is_err());
    }
    let mut health = request.clone();
    health["routing"] = json!({"mode":"priority","priority_policy":"health"});
    assert!(traffic_routes::parse(health).is_ok());
    let mut invalid = request;
    invalid["routing"] = json!({"mode":"something_else"});
    assert!(traffic_routes::parse(invalid).is_err());
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn mixed_bindings_publish_and_route_then_disable_deleted_references() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("web-routes.json");
    let case = Case::new(Config {
        web_routes_config_path: Some(path.clone()),
        public_base_url: "https://gateway.example".into(),
        web_activity_log_path: Some(temp.path().join("web-activity.log")),
        ..Config::default()
    })
    .await?;
    let result=async{
        let(owner,cookie)=case.user("bindings@example.invalid","user").await?;let(other,other_cookie)=case.user("other-bindings@example.invalid","user").await?;
        let machine=ObjectId::new();let connection=ObjectId::new();let foreign=ObjectId::new();let mut workers=JoinSet::new();
        let primary=TcpListener::bind("127.0.0.1:0").await?;let primary_port=primary.local_addr()?.port();let healthy=Arc::new(AtomicBool::new(true));let flag=healthy.clone();
        workers.spawn(async move{axum::serve(primary,Router::new().fallback(move||{let flag=flag.clone();async move{(if flag.load(Ordering::SeqCst){StatusCode::OK}else{StatusCode::SERVICE_UNAVAILABLE},"machine")}})).await.unwrap();});
        let backup=TcpListener::bind("127.0.0.1:0").await?;let backup_url=format!("http://{}",backup.local_addr()?);
        workers.spawn(async move{axum::serve(backup,Router::new().fallback(||async{"standalone"})).await.unwrap();});
        case.app.collection("machines").insert_one(doc!{"_id":machine,"user_id":owner,"enabled":true,"token":"test-only","name":"Local test"}).await?;
        case.app.collection("connections").insert_many([doc!{"_id":connection,"user_id":owner,"machine_id":machine,"enabled":true,"external_port":primary_port as i64,"internal_port":8000_i64},doc!{"_id":foreign,"user_id":other,"machine_id":machine,"external_port":primary_port as i64}]).await?;
        let mut request=json!({"name":"unified","hosts":["unified.example"],"bindings":[{"id":"primary","label":"Machine route","target_mode":"connection","connection_data_id":connection.to_hex(),"target_url":"http://attacker.invalid","priority":1},{"id":"backup","label":"URL route","target_mode":"manual","target_url":backup_url,"priority":2}],"routing":{"mode":"priority","priority_policy":"manual"}});
        let saved=case.status("POST","/api/traffic-routes/add",&cookie,request.clone(),StatusCode::OK).await?;
        let id=saved["data"]["_id"].as_str().unwrap();ensure!(saved["data"]["bindings"][0]["target_url"]==format!("http://127.0.0.1:{primary_port}"));
        let config:porthub_runtime::web_routes::Config=serde_json::from_slice(&std::fs::read(&path)?)?;let routes=WebRoutes::new(None);routes.reload(config)?;
        let send=||Request::builder().uri("/").header("host","unified.example").body(Body::empty()).unwrap();
        let Selection::Proxy(pool)=routes.select(&send(),true)else{panic!()};
        ensure!(to_bytes(pool.forward(send()).await.into_body(),4096).await?.as_ref()==b"machine");healthy.store(false,Ordering::SeqCst);
        ensure!(to_bytes(pool.forward(send()).await.into_body(),4096).await?.as_ref()==b"standalone");
        // Browser health responses are fresh and owner-scoped.
        std::fs::write(temp.path().join("web-health.json"),serde_json::to_vec(&json!({"updated_at":chrono::Utc::now().timestamp_millis(),"routes":{(id):pool.status(),"foreign-route":[{"id":"secret"}]}}))?)?;
        let health=case.status("GET","/api/traffic-routes/health",&cookie,json!(null),StatusCode::OK).await?;ensure!(health["available"]==true && health["data"].as_object().unwrap().len()==1);
        let hidden=case.status("GET","/api/traffic-routes/health",&other_cookie,json!(null),StatusCode::OK).await?;ensure!(hidden["data"]==json!({}));
        // A foreign mapping cannot be added even with a URL that appears valid.
        request["hosts"]=json!(["foreign.example"]);request["bindings"][0]["connection_data_id"]=json!(foreign.to_hex());
        case.status("POST","/api/traffic-routes/add",&cookie,request,StatusCode::BAD_REQUEST).await?;
        case.app.collection("connections").delete_one(doc!{"_id":connection}).await?;porthub_api::generated::rebuild_web(&case.app).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        let config:porthub_runtime::web_routes::Config=serde_json::from_slice(&std::fs::read(path)?)?;ensure!(!config.routes[0].bindings[0].enabled && config.routes[0].bindings[1].enabled);
        // An old single-target editor must not erase bindings.
        case.status("PUT","/api/traffic-routes/update",&cookie,json!({"data_id":id,"name":"legacy","hosts":["unified.example"],"targetUrl":"http://old.example"}),StatusCode::BAD_REQUEST).await?;
        let listed=case.status("GET","/api/traffic-routes/list",&cookie,json!(null),StatusCode::OK).await?;ensure!(listed["data"][0]["bindings"].as_array().unwrap().len()==2);
        workers.shutdown().await;Ok(())
    }.await;
    case.db.drop().await?;
    result
}

#[test]
fn managed_targets_use_authoritative_specific_and_ipv6_binds() -> Result<()> {
    for (bind, expected) in [
        ("0.0.0.0", "http://127.0.0.1:8000"),
        ("192.0.2.10", "http://192.0.2.10:8000"),
        ("::", "http://[::1]:8000"),
        ("2001:db8::1", "http://[2001:db8::1]:8000"),
    ] {
        ensure!(
            porthub_api::generated::connection_web_target(
                &doc! {"external_bind_ip":bind,"external_port":8000_i64}
            )? == expected
        );
    }
    ensure!(porthub_api::generated::connection_web_target(&doc! {"external_port":0_i64}).is_err());
    Ok(())
}
