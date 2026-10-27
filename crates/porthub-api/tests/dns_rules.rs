use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::config::Config;
use serde_json::{json, Value};
mod support;
use support::Case;

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn dns_policies_are_owned_scoped_validated_and_removable() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let (owner, cookie) = case.user("dns-owner@example.invalid", "user").await?;
        let (other, other_cookie) = case.user("dns-other@example.invalid", "user").await?;
        let machine = ObjectId::new(); let foreign = ObjectId::new();
        case.app.collection("machines").insert_many([
            doc! {"_id":machine,"user_id":owner,"name":"miro"},
            doc! {"_id":foreign,"user_id":other,"name":"foreign"},
        ]).await?;
        let route = format!("/api/access/dns-rules/{machine}");
        let rules = json!({"rules":[{"domain":"Blocked.Example.COM.","action":{"type":"block"}}]});
        case.status("PUT", &route, "", rules.clone(), StatusCode::BAD_REQUEST).await?;
        case.status("PUT", &route, &other_cookie, rules.clone(), StatusCode::NOT_FOUND).await?;
        case.status("PUT", &format!("/api/access/dns-rules/{foreign}"), &cookie, rules.clone(), StatusCode::NOT_FOUND).await?;
        let saved = case.status("PUT", &route, &cookie, rules.clone(), StatusCode::OK).await?;
        ensure!(saved["data"]["rules"][0]["domain"] == "blocked.example.com");
        let loaded = case.status("GET", &route, &cookie, Value::Null, StatusCode::OK).await?;
        ensure!(loaded["data"]["rules"] == saved["data"]["rules"]);
        ensure!(loaded["data"]["can_manage"] == true);
        case.status("GET", &route, &other_cookie, Value::Null, StatusCode::NOT_FOUND).await?;
        case.status("GET", &route, "", Value::Null, StatusCode::BAD_REQUEST).await?;
        for suffix in ["blocked.example.com", "example.com", "child.blocked.example.com"] {
            case.status("PUT", "/api/access/network", &cookie,
                json!({"cidr":"10.239.1.0/24","dns_suffix":suffix}), StatusCode::BAD_REQUEST).await?;
            case.status("PUT", "/api/machines/update", &cookie,
                json!({"data_id":machine.to_hex(),"name":"miro","private_domains":[{"default":true},{"host":"miro","suffix":suffix}]}), StatusCode::BAD_REQUEST).await?;
        }
        ensure!(case.app.collection("private_networks").count_documents(doc! {"_id":owner.to_hex()}).await? == 0);
        ensure!(!case.app.collection("machines").find_one(doc! {"_id":machine}).await?.unwrap().contains_key("private_domains"));
        for invalid in ["https://blocked.example.com/path", "miro.phub", "127.0.0.1"] {
            case.status("PUT", &route, &cookie, json!({"rules":[{"domain":invalid,"action":{"type":"block"}}]}), StatusCode::BAD_REQUEST).await?;
        }
        case.status("PUT", &route, &cookie, json!({"rules":[{"domain":"mapped.example","action":{"type":"override","addresses":["not-an-ip"]}}]}), StatusCode::BAD_REQUEST).await?;
        case.status("PUT", &route, &cookie, json!({"rules":[{"domain":"mapped.example","action":{"type":"override","addresses":["192.0.2.30","2001:db8::30"]}}]}), StatusCode::OK).await?;
        let own = case.status("GET", "/api/access/snapshot", &cookie, Value::Null, StatusCode::OK).await?;
        ensure!(own["dns_rules"].as_array().unwrap().len() == 1);
        let others = case.status("GET", "/api/access/snapshot", &other_cookie, Value::Null, StatusCode::OK).await?;
        ensure!(others["dns_rules"].as_array().unwrap().is_empty());
        for (name, include) in [("*.example.test", true), ("www.example.test", false)] {
            let saved = case.status("PUT", &route, &cookie,
                json!({"rules":[{"domain":name,"include_subdomains":include,"action":{"type":"block"}}]}), StatusCode::OK).await?;
            ensure!(saved["data"]["rules"][0]["domain"] == name);
            ensure!(saved["data"]["rules"][0]["include_subdomains"] == include);
            let loaded = case.status("GET", &route, &cookie, Value::Null, StatusCode::OK).await?;
            ensure!(loaded["data"]["rules"] == saved["data"]["rules"]);
        }
        for invalid in ["*.phub", "*.miro.phub", "a.*.example.test"] {
            case.status("PUT", &route, &cookie,
                json!({"rules":[{"domain":invalid,"action":{"type":"block"}}]}), StatusCode::BAD_REQUEST).await?;
        }
        case.status("PUT", &route, &cookie, json!({"rules":[]}), StatusCode::OK).await?;
        ensure!(case.app.collection("private_dns_rules").count_documents(doc! {}).await? == 0);
        Ok::<_,anyhow::Error>(())
    }.await;
    case.db.drop().await?;
    result
}
