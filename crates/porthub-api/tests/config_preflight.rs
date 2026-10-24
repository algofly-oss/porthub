use anyhow::{ensure, Result};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::{config::Config, generated};
use std::time::Duration;
#[allow(dead_code)]
mod support;
use support::Case;

fn settings() -> Config {
    Config {
        public_base_url: "https://gateway.example".into(),
        gateway_advertised_url: Some("http://192.0.2.10:8345".into()),
        ..Default::default()
    }
}
fn route(host: &str, target: &str) -> mongodb::bson::Document {
    doc! {"_id":ObjectId::new(),"hosts":[host],"target_url":target,"target_mode":"manual","enabled":true}
}

#[test]
fn existing_whole_gateway_proxies_become_builtin_aliases_without_rewriting_records() -> Result<()> {
    let routes = vec![
        route("gateway.example", "http://192.0.2.10:8345"),
        route("previous-gateway.example", "http://192.0.2.10:8345/"),
        route("application.example", "http://192.0.2.10:9000/"),
    ];
    let original = routes.clone();
    let config = generated::render_web_for_gateway(&routes, &settings())?;
    ensure!(config.routes.len() == 1 && config.routes[0].hosts == ["application.example"]);
    ensure!(routes == original);
    porthub_runtime::web_routes::WebRoutes::with_gateway_hosts(["gateway.example".into()])
        .reload(config)?;
    Ok(())
}

#[test]
fn another_upstream_or_non_root_url_cannot_take_over_the_gateway_hostname() -> Result<()> {
    for target in [
        "http://192.0.2.11:8345/",
        "http://192.0.2.10:9000/",
        "http://192.0.2.10:8345/application",
        "http://192.0.2.10:8345/?token=not-an-origin",
        "http://user:password@192.0.2.10:8345/",
    ] {
        let config =
            generated::render_web_for_gateway(&[route("gateway.example", target)], &settings())?;
        ensure!(config.routes.len() == 1);
        ensure!(porthub_runtime::web_routes::WebRoutes::with_gateway_hosts([
            "gateway.example".into()
        ])
        .reload(config)
        .is_err());
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn actual_preflight_binary_validates_legacy_records_without_startup_writes_or_ipc(
) -> Result<()> {
    let case = Case::new(settings()).await?;
    let directory = tempfile::tempdir()?;
    let result = async {
        let machine = ObjectId::new();
        case.app.collection("machines").insert_one(doc!{"_id":machine,"enabled":true,"token":"preflight-fixture"}).await?;
        case.app.collection("connections").insert_one(doc!{"_id":ObjectId::new(),"machine_id":machine,"external_port":31001,"enabled":true}).await?;
        case.app.collection("traffic_routes").insert_many([
            route("gateway.example", "http://192.0.2.10:8345/"),
            route("previous-gateway.example", "http://192.0.2.10:8345/"),
            route("application.example", "http://192.0.2.10:9000/"),
        ]).await?;
        let before: Vec<_> = case.app.collection("traffic_routes").find(doc!{}).sort(doc!{"_id":1}).await?.try_collect().await?;
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_porthub-api"));
        command.kill_on_drop(true).arg("--check-config")
            .env("MONGO_DATABASE_URI", &case.app.config.mongo_uri)
            .env("MONGO_DATABASE_NAME", case.db.name())
            // Even with normal bootstrap enabled, this mode must not run it.
            .env("PORTHUB_DB_INITIALIZE", "true")
            .env("PORT_HUB_PUBLIC_BASE_URL", "https://gateway.example")
            .env("PORTHUB_GATEWAY_ADVERTISED_URL", "http://192.0.2.10:8345")
            .env("PORTHUB_GATEWAY_CONFIG_PATH", directory.path().join("gateway.toml"))
            .env("PORTHUB_WEB_ROUTES_CONFIG_PATH", directory.path().join("web-routes.json"))
            .env("PORTHUB_API_SOCKET", directory.path().join("api.sock"))
            .env("PORTHUB_EDGE_SOCKET", directory.path().join("edge.sock"))
            .env("FIREWALL_SOCKET", directory.path().join("firewall.sock"))
            .env("FW_API_KEY", "unused-preflight-fixture-key");
        let output = tokio::time::timeout(Duration::from_secs(15), command.output()).await??;
        ensure!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        ensure!(report["active_machines"] == 1 && report["public_services"] == 1);
        ensure!(report["web_routes"] == 3 && report["proxy_routes"] == 1 && report["gateway_alias_routes"] == 2);
        ensure!(directory.path().read_dir()?.next().is_none());
        let after: Vec<_> = case.app.collection("traffic_routes").find(doc!{}).sort(doc!{"_id":1}).await?.try_collect().await?;
        ensure!(before == after);
        ensure!(case.db.list_collection_names().await?.len() == 3, "preflight created startup collections");
        Ok::<_, anyhow::Error>(())
    }.await;
    case.db.drop().await?;
    result
}
