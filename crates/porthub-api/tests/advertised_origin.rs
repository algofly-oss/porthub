use anyhow::{ensure, Result};
use axum::http::StatusCode;
use porthub_api::config::Config;
use serde_json::{json, Value};
mod support;
use support::Case;
#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn advertised_external_scheme_and_port_override_internal_listener_and_ip_discovery(
) -> Result<()> {
    for endpoint in ["http://192.0.2.5:18445", "https://masked.example:23456"] {
        let directory = tempfile::tempdir()?;
        let socket = directory.path().join("edge.sock");
        std::fs::write(
            directory.path().join("origin.json"),
            json!({"tls_port":8346,"spki_sha256":"AB".repeat(32)}).to_string(),
        )?;
        let case = Case::new(Config {
            gateway_advertised_url: Some(endpoint.into()),
            gateway_public_ip: Some("93.184.216.34".into()),
            gateway_ip_sources: vec!["http://127.0.0.1:1/never-contact".into()],
            edge_socket: Some(socket),
            public_base_url: "https://porthub.example".into(),
            ..Default::default()
        })
        .await?;
        let result = async {
            let (owner,_)=case.user("advertised-owner@test.invalid","user").await?;
            let id=mongodb::bson::oid::ObjectId::new();
            let token="advertised-origin-fixture-token-0123456789";
            case.app.collection("machines").insert_one(mongodb::bson::doc!{"_id":id,"user_id":owner,"name":"Advertised origin","token":token,"enabled":true}).await?;
            let machine=json!({"_id":id.to_hex(),"token":token});
            let credentials = json!({"machine_id":machine["_id"],"token":machine["token"]});
            case.status(
                "POST",
                "/api/gateway/origin",
                "",
                json!({"machine_id":machine["_id"],"token":"wrong"}),
                StatusCode::UNAUTHORIZED,
            )
            .await?;
            let origin = case
                .status(
                    "POST",
                    "/api/gateway/origin",
                    "",
                    credentials,
                    StatusCode::OK,
                )
                .await?["data"]
                .clone();
            let url = url::Url::parse(endpoint)?;
            ensure!(
                origin["origin_url"] == endpoint
                    && origin["public_port"] == url.port_or_known_default().unwrap()
                    && origin["scheme"] == url.scheme()
            );
            ensure!(origin["public_port"] != 8346 && case.app.gateway_origin.cached().is_none());
            let path=format!("/api/machines/client/config?machine_id={}&token={}",machine["_id"].as_str().unwrap(),machine["token"].as_str().unwrap());
            let legacy=case.status("GET",&path,"",Value::Null,StatusCode::OK).await?;
            let old:toml::Value=toml::from_str(legacy["data"]["files"]["client.toml"].as_str().unwrap())?;
            if url.scheme()=="http" {ensure!(old["client"].get("direct_addr").is_none());}
            ensure!(old["client"].get("direct_proxy_fallback").is_none());
            let (status,_,config)=case.call("GET",&path,"",Value::Null,&[("x-porthub-agent-protocol","rust-v1")]).await?;
            ensure!(status==StatusCode::OK);
            let text = config["data"]["files"]["client.toml"].as_str().unwrap();
            let parsed: toml::Value = toml::from_str(text)?;
            ensure!(
                parsed["client"]["direct_addr"].as_str()
                    == Some(format!("{endpoint}/api/tunnel").as_str())
            );
            if url.scheme() == "http" {
                ensure!(
                    parsed["client"].get("direct_spki_sha256").is_none()
                        && origin.get("spki_sha256").is_none()
                );
            } else {
                ensure!(
                    origin["tls_port"] == 23456
                        && parsed["client"]["direct_proxy_fallback"].as_bool() == Some(true)
                );
            }
            Ok(())
        }
        .await;
        case.db.drop().await?;
        result?;
    }
    Ok(())
}
