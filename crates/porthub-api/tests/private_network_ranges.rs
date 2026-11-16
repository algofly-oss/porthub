use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::{
    config::Config,
    domain::{enrollment::Network, private_networks},
};
use serde_json::json;
mod support;
use support::Case;

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn tenants_receive_distinct_ranges_and_cannot_claim_overlaps() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let (a, cookie_a) = case.user("range-a@test.invalid", "user").await?;
        let (b, cookie_b) = case.user("range-b@test.invalid", "user").await?;
        let a_id = a.to_hex();
        let b_id = b.to_hex();
        let (first, second) = tokio::join!(
            private_networks::ensure(&case.app, &a_id),
            private_networks::ensure(&case.app, &b_id)
        );
        let first = first.map_err(|e| anyhow::anyhow!("{}", e.detail))?;
        let second = second.map_err(|e| anyhow::anyhow!("{}", e.detail))?;
        let first_range = Network::parse(first.get_str("cidr")?).unwrap();
        let second_range = Network::parse(second.get_str("cidr")?).unwrap();
        ensure!(!first_range.overlaps(second_range));
        ensure!(
            private_networks::ensure(&case.app, &a_id)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e.detail))?
                == first
        );
        let path = format!("/api/access/network?workspace={b}");
        case.status(
            "PUT",
            &path,
            &cookie_b,
            json!({"cidr":first_range.cidr(),"dns_suffix":"phub"}),
            StatusCode::CONFLICT,
        )
        .await?;
        case.status(
            "PUT",
            &path,
            &cookie_b,
            json!({"cidr":"10.203.0.0/16","dns_suffix":"phub"}),
            StatusCode::CONFLICT,
        )
        .await?;
        case.status(
            "PUT",
            &path,
            &cookie_b,
            json!({"cidr":"192.168.77.0/24","dns_suffix":"phub"}),
            StatusCode::OK,
        )
        .await?;
        // A foreign account cannot use the network endpoint to change the owner.
        case.status(
            "PUT",
            &format!("/api/access/network?workspace={a}"),
            &cookie_b,
            json!({"cidr":"192.168.78.0/24","dns_suffix":"phub"}),
            StatusCode::FORBIDDEN,
        )
        .await?;
        // Existing peer addresses stay reserved even after preferences change.
        case.app
            .collection("private_peers")
            .insert_one(doc! {"_id":"retained", "workspace_id":b, "ip":"192.168.79.12"})
            .await?;
        case.status(
            "PUT",
            &format!("/api/access/network?workspace={a}"),
            &cookie_a,
            json!({"cidr":"192.168.79.0/24","dns_suffix":"phub"}),
            StatusCode::CONFLICT,
        )
        .await?;
        Ok(())
    }
    .await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn legacy_addresses_are_preserved_and_reserved_for_new_tenants() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let legacy = ObjectId::new();
        case.app
            .collection("private_peers")
            .insert_one(doc! {"_id":"legacy", "workspace_id":legacy, "ip":"10.203.0.10"})
            .await?;
        let fresh = private_networks::ensure(&case.app, &ObjectId::new().to_hex())
            .await
            .map_err(|e| anyhow::anyhow!("{}", e.detail))?;
        ensure!(fresh.get_str("cidr")? != "10.203.0.0/24");
        let retained = private_networks::ensure(&case.app, &legacy.to_hex())
            .await
            .map_err(|e| anyhow::anyhow!("{}", e.detail))?;
        ensure!(retained.get_str("cidr")? == "10.203.0.0/24");
        Ok(())
    }
    .await;
    case.db.drop().await?;
    result
}

async fn full_small_pool(case: &Case, owner: ObjectId, cidr: &str) -> Result<Vec<mongodb::bson::Document>> {
    let base: std::net::Ipv4Addr = cidr.split('/').next().unwrap().parse()?;
    case.app.collection("private_networks").insert_one(doc! {"_id":owner.to_hex(),"cidr":cidr,"dns_suffix":"phub"}).await?;
    let mut peers=Vec::new();
    for host in 1..=14u32 {
        let id=ObjectId::new();
        let peer=doc! {"_id":format!("{owner}:{id}"),"workspace_id":owner,"owner_id":owner,"machine_id":id,
            "ip":std::net::Ipv4Addr::from(u32::from(base)+host).to_string(),"enabled":host!=1,"revision":17,"credential_hash":"preserved-test-credential"};
        case.app.collection("private_peers").insert_one(peer.clone()).await?;peers.push(peer);
    }
    Ok(peers)
}
async fn enroll_growth(case: &Case, owner:ObjectId) -> Result<mongodb::bson::Document> {
    let id=ObjectId::new();
    porthub_api::domain::enrollment::ensure(&case.app,&doc! {"_id":id,"user_id":owner}).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
    Ok(case.app.collection("private_peers").find_one(doc! {"machine_id":id}).await?.unwrap())
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn exhausted_small_pool_grows_parent_without_renumbering_or_changing_acl_identity() -> Result<()> {
    let case=Case::new(Config::default()).await?;
    let result=async {
        let (owner,_)=case.user("grow-parent@test.invalid","user").await?;
        let before=full_small_pool(&case,owner,"10.222.0.0/28").await?;
        let group=doc! {"_id":ObjectId::new(),"user_id":owner,"name":"retained-group","machine_ids":[before[0].get_object_id("machine_id")?]};
        let book=doc! {"_id":ObjectId::new(),"user_id":owner,"group_id":group.get_object_id("_id")?.to_hex(),"rules":[{"id":"retained-rule","sources":[{"kind":"machine","id":before[0].get_object_id("machine_id")?.to_hex()}],"destinations":[{"kind":"machine","id":before[1].get_object_id("machine_id")?.to_hex()}],"ports":"443"}]};
        case.app.collection("machine_groups").insert_one(group.clone()).await?;
        case.app.collection("access_rulebooks").insert_one(book.clone()).await?;
        let added=enroll_growth(&case,owner).await?;
        let prefs=private_networks::ensure(&case.app,&owner.to_hex()).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        ensure!(prefs.get_str("cidr")?=="10.222.0.0/27");
        ensure!(before.iter().all(|peer|peer.get_str("ip").ok()!=added.get_str("ip").ok()));
        ensure!(Network::parse("10.222.0.0/27").unwrap().contains(added.get_str("ip")?.parse()?));
        ensure!(!["10.222.0.0","10.222.0.31"].contains(&added.get_str("ip")?));
        for peer in before {ensure!(case.app.collection("private_peers").find_one(doc! {"_id":peer.get("_id")}).await?==Some(peer));}
        ensure!(case.app.collection("machine_groups").find_one(doc! {"_id":group.get("_id")}).await?==Some(group));
        ensure!(case.app.collection("access_rulebooks").find_one(doc! {"_id":book.get("_id")}).await?==Some(book));
        Ok(())
    }.await;case.db.drop().await?;result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn blocked_parent_allocates_additional_pool_and_preserves_foreign_reservations() -> Result<()> {
    let case=Case::new(Config::default()).await?;
    let result=async {
        let (owner,_)=case.user("grow-overflow@test.invalid","user").await?;
        let (foreign,_)=case.user("grow-neighbor@test.invalid","user").await?;
        let before=full_small_pool(&case,owner,"10.222.0.0/28").await?;
        let neighbor=doc! {"_id":foreign.to_hex(),"cidr":"10.222.0.16/28"};
        case.app.collection("private_networks").insert_one(neighbor.clone()).await?;
        let added=enroll_growth(&case,owner).await?;
        let prefs=private_networks::ensure(&case.app,&owner.to_hex()).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        ensure!(prefs.get_str("cidr")?=="10.222.0.0/28");
        let pools=private_networks::pools(&prefs).map_err(|e|anyhow::anyhow!("{}",e.detail))?;ensure!(pools.len()==2);
        ensure!(pools[1].contains(added.get_str("ip")?.parse()?) && !pools[1].overlaps(Network::parse("10.222.0.16/28").unwrap()));
        for peer in before {ensure!(case.app.collection("private_peers").find_one(doc! {"_id":peer.get("_id")}).await?==Some(peer));}
        ensure!(case.app.collection("private_networks").find_one(doc! {"_id":foreign.to_hex()}).await?==Some(neighbor));
        Ok(())
    }.await;case.db.drop().await?;result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn concurrent_tenants_expand_into_distinct_durable_pools() -> Result<()> {
    let case=Case::new(Config::default()).await?;
    let result=async {
        let (a,_)=case.user("grow-concurrent-a@test.invalid","user").await?;
        let (b,_)=case.user("grow-concurrent-b@test.invalid","user").await?;
        full_small_pool(&case,a,"10.222.0.0/28").await?;full_small_pool(&case,b,"10.222.0.16/28").await?;
        let owners=[a,b,a,b,a,b,a,b];
        let peers=futures_util::future::join_all(owners.into_iter().map(|owner|enroll_growth(&case,owner))).await;
        let mut ips=std::collections::HashSet::new();for peer in peers {ensure!(ips.insert(peer?.get_str("ip")?.to_owned()));}
        let left=private_networks::ensure(&case.app,&a.to_hex()).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        let right=private_networks::ensure(&case.app,&b.to_hex()).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        let aa=private_networks::pools(&left).map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        let bb=private_networks::pools(&right).map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        ensure!(aa.len()==2 && bb.len()==2);for x in aa {for y in &bb {ensure!(!x.overlaps(*y));}}
        let restarted=porthub_api::App::new(Config::default(),case.db.clone());
        ensure!(private_networks::ensure(&restarted,&a.to_hex()).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?==left);
        ensure!(private_networks::ensure(&restarted,&b.to_hex()).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?==right);
        Ok(())
    }.await;case.db.drop().await?;result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn explicit_private_enrollment_ticket_path_grows_full_pool_without_reassigning_peers() -> Result<()> {
    let case=Case::new(Config::default()).await?;
    let result=async {
        let (owner,cookie)=case.user("grow-ticket@test.invalid","user").await?;
        let before=full_small_pool(&case,owner,"10.222.0.0/28").await?;
        let machine=ObjectId::new();
        case.app.collection("machines").insert_one(doc! {"_id":machine,"user_id":owner,"name":"Ticket growth","enabled":true}).await?;
        let issued=case.status("POST","/api/access/private/peers",&cookie,json!({"machine_id":machine.to_hex(),"hostname":"grown-ticket"}),StatusCode::OK).await?;
        let peer_id=format!("{owner}:{machine}");
        ensure!(issued["peer_id"]==peer_id);
        let ip=issued["ip"].as_str().unwrap();
        ensure!(before.iter().all(|peer|peer.get_str("ip").ok()!=Some(ip)));
        ensure!(Network::parse("10.222.0.0/27").unwrap().contains(ip.parse()?));
        ensure!(!["10.222.0.0","10.222.0.31"].contains(&ip));
        let prefs=private_networks::ensure(&case.app,&owner.to_hex()).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        ensure!(prefs.get_str("cidr")?=="10.222.0.0/27");
        let redeemed=case.status("POST","/api/access/private/bootstrap","",json!({"ticket":issued["ticket"]}),StatusCode::OK).await?;
        ensure!(redeemed["peer_id"]==peer_id && redeemed["workspace"]==owner.to_hex());
        ensure!(case.app.collection("private_peers").find_one(doc! {"_id":&peer_id}).await?.unwrap().get_str("ip")?==ip);
        case.status("POST","/api/access/private/bootstrap","",json!({"ticket":issued["ticket"]}),StatusCode::FORBIDDEN).await?;
        for peer in before {ensure!(case.app.collection("private_peers").find_one(doc! {"_id":peer.get("_id")}).await?==Some(peer));}
        Ok(())
    }.await;case.db.drop().await?;result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn expansion_avoids_own_lan_without_reserving_foreign_lans_globally() -> Result<()> {
    let case=Case::new(Config::default()).await?;
    let result=async {
        let (owner,_)=case.user("grow-own-lan@test.invalid","user").await?;
        let (foreign,_)=case.user("grow-foreign-lan@test.invalid","user").await?;
        let before=full_small_pool(&case,owner,"10.222.0.0/28").await?;
        case.app.collection("private_peers").update_one(doc! {"_id":before[1].get("_id")},doc! {"$set":{"lan_networks":["10.203.0.0/24"]}}).await?;
        case.app.collection("private_networks").insert_one(doc! {"_id":foreign.to_hex(),"cidr":"10.222.0.16/28"}).await?;
        case.app.collection("private_peers").insert_one(doc! {"_id":"foreign-lan-declaration","workspace_id":foreign,"ip":"10.222.0.17","lan_networks":["10.0.0.0/8"]}).await?;
        let added=enroll_growth(&case,owner).await?;
        let prefs=private_networks::ensure(&case.app,&owner.to_hex()).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        let pools=private_networks::pools(&prefs).map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        ensure!(prefs.get_str("cidr")?=="10.222.0.0/28" && pools.len()==2);
        ensure!(!pools[1].overlaps(Network::parse("10.203.0.0/24").unwrap()));
        ensure!("10.0.0.0/8".parse::<porthub_mesh::lan_routes::Network>().unwrap().contains(added.get_str("ip")?.parse()?),"Foreign LAN declaration must not globally reserve all 10/8");
        ensure!(pools[1].contains(added.get_str("ip")?.parse()?));
        for peer in before {ensure!(case.app.collection("private_peers").find_one(doc! {"_id":peer.get("_id")}).await?.unwrap().get_str("ip")?==peer.get_str("ip")?);}
        Ok(())
    }.await;case.db.drop().await?;result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn available_pool_conflicting_with_own_lan_is_retained_but_not_used_for_new_peers() -> Result<()> {
    let case=Case::new(Config::default()).await?;
    let result=async {
        let (owner,_)=case.user("grow-existing-lan@test.invalid","user").await?;
        let before=full_small_pool(&case,owner,"10.222.0.0/28").await?;
        let retained=&before[1];
        case.app.collection("private_peers").delete_many(doc! {"workspace_id":owner,"_id":{"$ne":retained.get("_id")}}).await?;
        case.app.collection("private_peers").update_one(doc! {"_id":retained.get("_id")},doc! {"$set":{"lan_networks":["10.222.0.0/24"]}}).await?;
        let snapshot=case.app.collection("private_peers").find_one(doc! {"_id":retained.get("_id")}).await?.unwrap();
        let added=enroll_growth(&case,owner).await?;
        let prefs=private_networks::ensure(&case.app,&owner.to_hex()).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        let pools=private_networks::pools(&prefs).map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        ensure!(prefs.get_str("cidr")?=="10.222.0.0/28" && pools.len()==2);
        ensure!(!Network::parse("10.222.0.0/24").unwrap().contains(added.get_str("ip")?.parse()?));
        ensure!(case.app.collection("private_peers").find_one(doc! {"_id":retained.get("_id")}).await?==Some(snapshot));
        Ok(())
    }.await;case.db.drop().await?;result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn revoked_peer_broad_lan_is_ignored_but_its_assigned_address_stays_reserved() -> Result<()> {
    let case=Case::new(Config::default()).await?;
    let result=async {
        let (owner,_)=case.user("grow-revoked-lan@test.invalid","user").await?;
        let before=full_small_pool(&case,owner,"10.222.0.0/28").await?;
        let revoked=&before[0];ensure!(revoked.get_bool("enabled")==Ok(false));
        case.app.collection("private_peers").update_one(doc! {"_id":revoked.get("_id")},doc! {"$set":{"lan_networks":["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"]}}).await?;
        let snapshot=case.app.collection("private_peers").find_one(doc! {"_id":revoked.get("_id")}).await?.unwrap();
        let added=enroll_growth(&case,owner).await?;
        let prefs=private_networks::ensure(&case.app,&owner.to_hex()).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        ensure!(prefs.get_str("cidr")?=="10.222.0.0/27");
        ensure!(private_networks::pools(&prefs).map_err(|e|anyhow::anyhow!("{}",e.detail))?.len()==1);
        ensure!(before.iter().all(|peer|peer.get_str("ip").ok()!=added.get_str("ip").ok()));
        ensure!(case.app.collection("private_peers").find_one(doc! {"_id":revoked.get("_id")}).await?==Some(snapshot));
        Ok(())
    }.await;case.db.drop().await?;result
}
