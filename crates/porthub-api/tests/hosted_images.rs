use anyhow::{ensure, Result};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::config::Config;
use serde_json::{json, Value};
use tower::ServiceExt;
mod support;
use support::Case;

fn png() -> Vec<u8> {
    let mut out = std::io::Cursor::new(Vec::new());
    image::DynamicImage::new_rgb8(4, 3)
        .write_to(&mut out, image::ImageFormat::Png)
        .unwrap();
    out.into_inner()
}
#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn browser_and_agent_images_are_owned_public_and_revocable() -> Result<()> {
    let case = Case::new(Config {
        public_base_url: "https://images.example.invalid".into(),
        ..Config::default()
    })
    .await?;
    let result = async {
        let (owner,cookie) = case.user("images@example.invalid","user").await?;
        let (_,outsider) = case.user("outsider@example.invalid","user").await?;
        let payload = json!({"image":STANDARD.encode(png()),"name":"Screenshot.png"});
        case.status("POST","/api/images","",payload.clone(),StatusCode::BAD_REQUEST).await?;
        let row = case.status("POST","/api/images",&cookie,payload,StatusCode::OK).await?;
        ensure!(row["width"]==4 && row["height"]==3 && row["url"].as_str().unwrap().starts_with("https://images.example.invalid/i/"));
        let path = row["path"].as_str().unwrap();
        ensure!(path.len()==12 && path.ends_with(".png"));
        let response = case.router.clone().oneshot(Request::builder().uri(path).body(Body::empty())?).await?;
        ensure!(response.status()==StatusCode::OK && response.headers()["content-type"]=="image/png" && response.headers()["cache-control"]=="no-store");
        let bytes = to_bytes(response.into_body(),1024*1024).await?;
        ensure!(image::load_from_memory(&bytes)?.width()==4);
        // The database rejects duplicate short codes, even across API processes.
        let stored=case.app.collection("hosted_images").find_one(doc!{"_id":row["id"].as_str().unwrap()}).await?.unwrap();
        let mut collision=stored.clone(); collision.insert("_id","collision-fixture");
        let duplicate=case.app.collection("hosted_images").insert_one(collision.clone()).await.unwrap_err();
        ensure!(porthub_api::store::duplicate(&duplicate));
        let delete = format!("/api/images/{}",row["id"].as_str().unwrap());
        case.status("DELETE",&delete,&outsider,Value::Null,StatusCode::NOT_FOUND).await?;
        let other = case.status("GET","/api/images",&outsider,Value::Null,StatusCode::OK).await?;
        ensure!(other["images"].as_array().unwrap().is_empty());
        let listed = case.status("GET","/api/images",&cookie,Value::Null,StatusCode::OK).await?;
        ensure!(listed["images"].as_array().unwrap().len()==1 && !listed.to_string().contains("owner_id") && !listed.to_string().contains("data:"));
        case.status("POST","/api/images",&cookie,json!({"image":STANDARD.encode(b"<svg/>" )}),StatusCode::BAD_REQUEST).await?;
        // The image route must override the portal's usual 4 MiB body limit.
        use rand::{RngCore, SeedableRng};
        let mut pixels = vec![0u8; 1152 * 1152 * 4];
        rand::rngs::StdRng::seed_from_u64(42).fill_bytes(&mut pixels);
        let large = image::RgbaImage::from_raw(1152,1152,pixels).unwrap();
        let mut encoded = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(large).write_to(&mut encoded,image::ImageFormat::Png)?;
        ensure!(encoded.get_ref().len() > 4 * 1024 * 1024);
        case.status("POST","/api/images",&cookie,json!({"image":STANDARD.encode(encoded.into_inner()),"name":"Large screenshot"}),StatusCode::OK).await?;
        let machine_id = ObjectId::new();
        case.app.collection("machines").insert_one(doc!{"_id":machine_id,"user_id":owner,"name":"Luna","token":"image-test-token"}).await?;
        let request_id = uuid::Uuid::new_v4().simple().to_string();
        let agent = json!({"machine_id":machine_id.to_hex(),"token":"image-test-token","image":STANDARD.encode(png()),"request_id":request_id});
        let one = case.status("POST","/api/machines/client/images","",agent.clone(),StatusCode::OK).await?;
        let two = case.status("POST","/api/machines/client/images","",agent.clone(),StatusCode::OK).await?;
        ensure!(one["id"]==two["id"]);
        ensure!(one["machine_name"]=="Luna" && one["source"]=="machine");
        ensure!(row["source"]=="browser" && row["machine_name"].is_null());
        // Completed retries do not evict images, even when storage is full.
        case.app.collection("hosted_images").insert_one(doc!{"_id":"quota-fixture","owner_id":owner,"size":512_i64*1024*1024}).await?;
        let retry = case.status("POST","/api/machines/client/images","",agent.clone(),StatusCode::OK).await?;
        ensure!(retry["id"]==one["id"]);
        ensure!(case.app.collection("hosted_images").find_one(doc!{"_id":"quota-fixture"}).await?.is_some());
        case.app.collection("hosted_images").delete_one(doc!{"_id":"quota-fixture"}).await?;
        // Storage pressure removes only enough oldest images from this account.
        let (temporary,temp_cookie)=case.user("temporary@example.invalid","user").await?;
        for (id,code,created) in [("oldest","AbC23",1_i64),("newer","Def45",2_i64)] {
            let mut fixture=stored.clone();
            fixture.insert("_id",id); fixture.insert("public_id",code);
            fixture.insert("owner_id",temporary); fixture.insert("size",256_i64*1024*1024);
            fixture.insert("created_at",mongodb::bson::DateTime::from_millis(created));
            case.app.collection("hosted_images").insert_one(fixture).await?;
        }
        case.status("POST","/api/images",&temp_cookie,json!({"image":STANDARD.encode(b"invalid")}),StatusCode::BAD_REQUEST).await?;
        ensure!(case.app.collection("hosted_images").count_documents(doc!{"owner_id":temporary}).await?==2);
        let fresh=case.status("POST","/api/images",&temp_cookie,json!({"image":STANDARD.encode(png())}),StatusCode::OK).await?;
        case.status("GET","/i/AbC23.png","",Value::Null,StatusCode::NOT_FOUND).await?;
        ensure!(case.app.collection("hosted_images").find_one(doc!{"_id":"newer"}).await?.is_some());
        ensure!(case.app.collection("hosted_images").find_one(doc!{"_id":fresh["id"].as_str().unwrap()}).await?.is_some());
        ensure!(case.app.collection("hosted_images").count_documents(doc!{"owner_id":temporary}).await?==2);
        // Other accounts' images and links survive eviction.
        let original=case.router.clone().oneshot(Request::builder().uri(path).body(Body::empty())?).await?;
        ensure!(original.status()==StatusCode::OK);
        let mut wrong = agent.clone(); wrong["token"] = json!("invalid");
        case.status("POST","/api/machines/client/images","",wrong,StatusCode::GONE).await?;
        case.app.collection("machines").update_one(doc!{"_id":machine_id},doc!{"$set":{"enabled":false}}).await?;
        case.status("POST","/api/machines/client/images","",agent,StatusCode::FORBIDDEN).await?;
        case.status("DELETE",&delete,&cookie,Value::Null,StatusCode::NO_CONTENT).await?;
        case.status("GET",path,"",Value::Null,StatusCode::NOT_FOUND).await?;
        // Once deleted, the same code can be allocated to a new image.
        case.app.collection("hosted_images").insert_one(collision).await?;
        let reused=case.router.clone().oneshot(Request::builder().uri(path).body(Body::empty())?).await?;
        ensure!(reused.status()==StatusCode::OK);
        case.app.collection("hosted_images").delete_one(doc!{"_id":"collision-fixture"}).await?;
        // Account removal cleans up public image content as well.
        {
            let _lifecycle = case.app.account_lifecycle.write().await;
            porthub_api::account_delete::delete_locked(&case.app,owner).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?;
        }
        ensure!(case.app.collection("hosted_images").count_documents(doc!{"owner_id":owner}).await?==0);
        case.status("GET",one["path"].as_str().unwrap(),"",Value::Null,StatusCode::NOT_FOUND).await?;
        Ok::<_,anyhow::Error>(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn bulk_image_deletion_is_explicit_and_owner_scoped() -> Result<()> {
    let case=Case::new(Config::default()).await?;
    let result=async {
        let (_,owner)=case.user("bulk-owner@example.invalid","user").await?;
        let (_,other)=case.user("bulk-other@example.invalid","user").await?;
        let payload=json!({"image":STANDARD.encode(png())});
        let a=case.status("POST","/api/images",&owner,payload.clone(),StatusCode::OK).await?;
        case.status("POST","/api/images",&owner,payload.clone(),StatusCode::OK).await?;
        let b=case.status("POST","/api/images",&other,payload,StatusCode::OK).await?;
        case.status("DELETE","/api/images","",json!({"all":true}),StatusCode::BAD_REQUEST).await?;
        case.status("DELETE","/api/images",&owner,json!({}),StatusCode::BAD_REQUEST).await?;
        case.status("DELETE","/api/images",&owner,json!({"all":true,"ids":[a["id"]]}),StatusCode::BAD_REQUEST).await?;
        let selected=case.status("DELETE","/api/images",&owner,json!({"ids":[a["id"],b["id"]]}),StatusCode::OK).await?;
        ensure!(selected["deleted_count"]==1);
        let own=case.status("GET","/api/images",&owner,Value::Null,StatusCode::OK).await?;
        ensure!(own["images"].as_array().unwrap().len()==1);
        let all=case.status("DELETE","/api/images",&owner,json!({"all":true}),StatusCode::OK).await?;
        ensure!(all["deleted_count"]==1);
        let foreign=case.status("GET","/api/images",&other,Value::Null,StatusCode::OK).await?;
        ensure!(foreign["images"].as_array().unwrap().len()==1 && foreign["images"][0]["id"]==b["id"]);
        Ok::<_,anyhow::Error>(())
    }.await;
    case.db.drop().await?;result
}
