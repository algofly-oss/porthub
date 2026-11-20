use anyhow::{Result, ensure};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::{config::Config, domain::workspaces::token_digest};
use serde_json::{Value, json};
#[allow(dead_code)]
mod support;
use support::Case;

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn virtual_host_has_a_separate_acl_identity_and_requires_its_enrolled_parent() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result=async{
        let (owner,cookie)=case.user("virtual-hosts-owner@test.invalid","user").await?;
        let (_,outsider)=case.user("virtual-hosts-other@test.invalid","user").await?;
        let provider=ObjectId::new();let consumer=ObjectId::new();
        let parent=format!("{owner}:{provider}");let condor=format!("{owner}:{consumer}");
        let parent_token="virtual-host-fixture-parent-01234567890123456";
        let consumer_token="virtual-host-fixture-condor-01234567890123456";
        for (mid,pid,name,token,ip) in [(provider,&parent,"luna",parent_token,"10.203.0.1"),(consumer,&condor,"condor",consumer_token,"10.203.0.2")]{
            case.app.collection("machines").insert_one(doc!{"_id":mid,"user_id":owner,"name":name,"enabled":true}).await?;
            case.app.collection("private_peers").insert_one(doc!{"_id":pid,"workspace_id":owner,"machine_id":mid,"owner_id":owner,"enabled":true,"ip":ip,"credential_hash":token_digest(token),"enrollment_generation":"fixture-generation"}).await?;
        }
        let endpoint=format!("/api/machines/{provider}/virtual-hosts");
        let create=json!({"name":"miro-via-luna","target_ip":"192.168.0.166"});
        case.status("GET",&endpoint,&outsider,json!({}),StatusCode::NOT_FOUND).await?;
        for target in ["127.0.0.1","169.254.169.254","8.8.8.8","10.203.0.2"]{
            case.status("POST",&endpoint,&cookie,json!({"name":"wrong","target_ip":target}),StatusCode::BAD_REQUEST).await?;
        }
        let added=case.status("POST",&endpoint,&cookie,create.clone(),StatusCode::OK).await?["virtual_host"].clone();
        let id=added["id"].as_str().unwrap();let peer=format!("{owner}:{id}");
        ensure!(added["hostname"]=="miro-via-luna.phub" && added["private_ip"]!="192.168.0.166" && added["via"]["id"]==provider.to_hex());
        ensure!(case.status("POST",&endpoint,&cookie,create,StatusCode::OK).await?["virtual_host"]==added);
        ensure!(case.status("GET",&endpoint,&cookie,json!({}),StatusCode::OK).await?["virtual_hosts"]==json!([added]));
        let sync="/api/access/private/sync";
        let message=|id:&str,token:&str|json!({"peer_id":id,"token":token,"fingerprint":vec!["AB";32].join(":"),"instance":"native-virtual-fixture-12345"});
        let mut request=message(&parent,parent_token);request["virtual_host_provider"]=json!(1);
        let response=case.status("POST",sync,"",request.clone(),StatusCode::OK).await?;
        let assignment=&response["virtual_hosts"][0];
        ensure!(assignment["peer_id"]==peer && assignment["target_ip"]=="192.168.0.166");
        let token=assignment["token"].as_str().unwrap();
        let child=message(&peer,token);
        case.status("POST",sync,"",child.clone(),StatusCode::OK).await?;
        let mut nested=child.clone();nested["virtual_host_provider"]=json!(1);
        case.status("POST",sync,"",nested,StatusCode::FORBIDDEN).await?;
        case.status("POST","/api/access/private/peers",&cookie,json!({"machine_id":id}),StatusCode::FORBIDDEN).await?;
        let check=message(&condor,consumer_token);
        let granted=|r:&Value|r["snapshot"]["grants"].as_array().unwrap().iter().any(|g|g["source"]==condor && g["destination"]==peer);
        ensure!(!granted(&case.status("POST",sync,"",check.clone(),StatusCode::OK).await?));
        let book=ObjectId::new();let group=ObjectId::new();
        case.app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner}).await?;
        case.app.collection("access_rulebooks").insert_one(doc!{"_id":book,"user_id":owner,"group_id":group.to_hex(),"rules":[{"id":"miro-only","name":"Virtual target only","bidirectional":true,"sources":[{"kind":"machine","id":consumer.to_hex()}],"destinations":[{"kind":"machine","id":id}],"ports":"8000"}]}).await?;
        let permitted=case.status("POST",sync,"",check.clone(),StatusCode::OK).await?;
        ensure!(granted(&permitted),"virtual host is missing its ACL grant");
        ensure!(added["peer_id"] == peer);
        let rename = format!("/api/access/private/peers/{peer}/hostname");
        case.status("PUT", &rename, &outsider, json!({"hostname":"foreign"}), StatusCode::NOT_FOUND).await?;
        for (label, expected) in [("miro-renamed", "miro-renamed.phub"), ("miro-via-luna", "miro-via-luna.phub")] {
            case.status("PUT", &rename, &cookie, json!({"hostname":label}), StatusCode::OK).await?;
            let listed = case.status("GET",&endpoint,&cookie,json!({}),StatusCode::OK).await?;
            let host = &listed["virtual_hosts"][0];
            ensure!(host["hostname"] == expected && host["id"] == added["id"] && host["target_ip"] == added["target_ip"] && host["private_ip"] == added["private_ip"]);
            ensure!(granted(&case.status("POST",sync,"",check.clone(),StatusCode::OK).await?));
        }
        ensure!(!permitted["snapshot"]["grants"].as_array().unwrap().iter().any(|g|g["source"]==condor && g["destination"]==parent));
        let grants = permitted["snapshot"]["grants"].as_array().unwrap();
        ensure!(!grants.iter().any(|g|g["source"]==peer || (g["destination"]==peer && g["protocol"]!="tcp" && g["protocol"]!="udp")));
        #[cfg(feature="private-sparse")]
        let lookup = {
            let mut target = child.clone();
            target["sparse"] = json!({"protocol":1,"sequence":1,"wanted":[]});
            let base = case.status("POST",sync,"",target,StatusCode::OK).await?;
            ensure!(base["snapshot"]["sparse"]["protocol"] == 1 && base["snapshot"]["exit_routes"] == json!([]));
            let mut source = check.clone();
            source["sparse"] = json!({"protocol":1,"sequence":1,"wanted":[{"kind":"name","value":"miro-via-luna.phub"}]});
            let reply = case.status("POST",sync,"",source.clone(),StatusCode::OK).await?;
            let answer = &reply["pair_responses"][0];
            ensure!(answer["status"]=="allowed" && answer["lease"]["peer"]["id"]==peer && answer["lease"]["peer"]["ip"]==added["private_ip"], "virtual DNS lookup returned status {}",answer["status"]);
            let acl:porthub_network::policy::pair_acl::PairAcl=serde_json::from_value(answer["lease"]["acl"].clone())?;
            let acl=acl.compile()?;
            ensure!(acl.allows(false,6,8000) && !acl.allows(false,17,8000) && !acl.allows(false,6,8001) && !acl.allows(false,1,0) && !acl.allows(true,6,8000));
            source
        };
        case.app.collection("access_rulebooks").delete_one(doc!{"_id":book}).await?;
        ensure!(!granted(&case.status("POST",sync,"",check,StatusCode::OK).await?));
        #[cfg(feature="private-sparse")]
        {
            let reply = case.status("POST",sync,"",lookup,StatusCode::OK).await?;
            ensure!(reply["pair_responses"][0]["status"]=="unavailable","revoked virtual host remained reachable");
        }
        let replacement = "new-provider-enrollment-fixture-0123456789";
        case.app.collection("private_peers").update_one(doc!{"_id":&parent},doc!{"$set":{"credential_hash":token_digest(replacement),"enrollment_generation":"second-generation"}}).await?;
        case.status("POST",sync,"",child.clone(),StatusCode::FORBIDDEN).await?;
        request["token"]=json!(replacement);
        let renewed=case.status("POST",sync,"",request,StatusCode::OK).await?;
        let delegated=&renewed["virtual_hosts"][0];
        ensure!(delegated["peer_id"]==peer && delegated["token"]!=token);
        let rebound=message(&peer,delegated["token"].as_str().unwrap());
        case.status("POST",sync,"",rebound.clone(),StatusCode::OK).await?;
        case.status("POST",sync,"",child.clone(),StatusCode::FORBIDDEN).await?;
        let child=rebound;
        case.app.collection("private_peers").update_one(doc!{"_id":&parent},doc!{"$set":{"enabled":false}}).await?;
        case.status("POST",sync,"",child.clone(),StatusCode::FORBIDDEN).await?;
        case.status("DELETE",&format!("{endpoint}/{id}"),&cookie,json!({}),StatusCode::OK).await?;
        case.status("POST",sync,"",child,StatusCode::FORBIDDEN).await?;
        ensure!(case.app.collection("machines").find_one(doc!{"_id":consumer}).await?.is_some());
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}
