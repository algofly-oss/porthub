use anyhow::{ensure, Result};
use axum::http::StatusCode;
use base64::{engine::general_purpose::STANDARD, Engine};
use mongodb::bson::doc;
use serde_json::{json, Value};
mod support;
use support::Case;

async fn request(
    case: &Case,
    method: &str,
    path: &str,
    cookie: &str,
    share: &str,
    body: Value,
    expected: StatusCode,
) -> Result<Value> {
    let (status, headers, value) = case
        .call(
            method,
            path,
            cookie,
            body,
            &[("x-board-share", share)]
                .into_iter()
                .filter(|(_, v)| !v.is_empty())
                .collect::<Vec<_>>(),
        )
        .await?;
    ensure!(
        status == expected,
        "{method} {path}: expected {expected}, got {status}: {value}"
    );
    ensure!(headers["cache-control"] == "no-store");
    Ok(value)
}
fn shape(id: &str, version: u64, nonce: u32, deleted: bool) -> Value {
    json!({"id":id,"type":"rectangle","version":version,"versionNonce":nonce,"isDeleted":deleted,"index":format!("a{id}"),"x":10,"y":20,"width":100,"height":50})
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn board_ownership_guest_permissions_conflicts_and_durable_assets() -> Result<()> {
    let case = Case::new(Default::default()).await?;
    let result: Result<()> = async {
        let (_, owner) = case.user("boards-owner@example.invalid", "user").await?;
        let (_, foreign) = case.user("boards-foreign@example.invalid", "user").await?;
        let board = request(
            &case,
            "POST",
            "/api/boards",
            &owner,
            "",
            json!({"name":"Planning"}),
            StatusCode::OK,
        )
        .await?;
        let id = board["id"].as_str().unwrap();
        let path = format!("/api/boards/{id}");
        request(
            &case,
            "GET",
            &path,
            &foreign,
            "",
            Value::Null,
            StatusCode::NOT_FOUND,
        )
        .await?;
        request(
            &case,
            "GET",
            &path,
            "",
            "",
            Value::Null,
            StatusCode::BAD_REQUEST,
        )
        .await?;
        let shared = request(
            &case,
            "PATCH",
            &format!("{path}/sharing"),
            &owner,
            "",
            json!({"enabled":true}),
            StatusCode::OK,
        )
        .await?;
        let edit = shared["sharing"]["edit_token"].as_str().unwrap();
        let view = shared["sharing"]["view_token"].as_str().unwrap();
        ensure!(edit.len() == 43 && view.len() == 43 && edit != view);
        let public = request(&case, "GET", &path, "", edit, Value::Null, StatusCode::OK).await?;
        ensure!(
            public["editable"] == true
                && public["owner"] == false
                && public.get("sharing").is_none()
        );
        request(
            &case,
            "PATCH",
            &path,
            "",
            edit,
            json!({"name":"Unauthorized"}),
            StatusCode::NOT_FOUND,
        )
        .await?;
        request(
            &case,
            "PATCH",
            &format!("{path}/scene"),
            "",
            view,
            json!({"elements":[shape("a",1,100,false)]}),
            StatusCode::FORBIDDEN,
        )
        .await?;
        let first = request(
            &case,
            "PATCH",
            &format!("{path}/scene"),
            "",
            edit,
            json!({"elements":[shape("a",1,100,false)],"app_state":{"viewBackgroundColor":"#eff6ff"}}),
            StatusCode::OK,
        )
        .await?;
        ensure!(first["revision"] == 1 && first["elements"].as_array().unwrap().len() == 1);
        let stored = request(&case, "GET", &path, "", edit, Value::Null, StatusCode::OK).await?;
        ensure!(stored["elements"][0]["x"] == 10 && stored["elements"][0]["width"] == 100);
        ensure!(stored["appState"]["viewBackgroundColor"] == "#eff6ff");
        // Concurrently added elements are merged, not whole-scene replacements.
        let scene_path = format!("{path}/scene");
        let (a, b) = tokio::join!(
            request(
                &case,
                "PATCH",
                &scene_path,
                &owner,
                "",
                json!({"elements":[shape("b",1,100,false)]}),
                StatusCode::OK
            ),
            request(
                &case,
                "PATCH",
                &scene_path,
                "",
                edit,
                json!({"elements":[shape("c",1,100,false)]}),
                StatusCode::OK
            )
        );
        a?;
        b?;
        request(
            &case,
            "PATCH",
            &format!("{path}/scene"),
            "",
            edit,
            json!({"elements":[shape("a",2,30,true)]}),
            StatusCode::OK,
        )
        .await?;
        let stale = request(
            &case,
            "PATCH",
            &format!("{path}/scene"),
            "",
            edit,
            json!({"elements":[shape("a",1,1,false)]}),
            StatusCode::OK,
        )
        .await?;
        ensure!(
            stale["elements"][0]["isDeleted"] == true,
            "A delayed edit must not resurrect a deleted shape"
        );
        request(
            &case,
            "PATCH",
            &format!("{path}/scene"),
            "",
            edit,
            json!({"elements":[shape("b",2,50,false)]}),
            StatusCode::OK,
        )
        .await?;
        request(
            &case,
            "PATCH",
            &format!("{path}/scene"),
            &owner,
            "",
            json!({"elements":[shape("b",2,20,false)]}),
            StatusCode::OK,
        )
        .await?;
        let read = request(&case, "GET", &path, "", view, Value::Null, StatusCode::OK).await?;
        ensure!(read["elements"].as_array().unwrap().len() == 3 && read["editable"] == false);
        ensure!(
            read["elements"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["id"] == "b")
                .unwrap()["versionNonce"]
                == 20
        );
        let image = STANDARD.encode([137, 80, 78, 71, 13, 10, 26, 10]);
        request(
            &case,
            "PUT",
            &format!("{path}/assets/test-file"),
            "",
            view,
            json!({"image":image}),
            StatusCode::FORBIDDEN,
        )
        .await?;
        let mut bytes = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            20,
            10,
            image::Rgba([1, 2, 3, 255]),
        ))
        .write_to(&mut bytes, image::ImageFormat::Png)?;
        request(
            &case,
            "PUT",
            &format!("{path}/assets/test-file"),
            "",
            edit,
            json!({"image":STANDARD.encode(bytes.into_inner())}),
            StatusCode::OK,
        )
        .await?;
        let asset = request(
            &case,
            "GET",
            &format!("{path}/assets/test-file"),
            "",
            view,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
        ensure!(asset["dataURL"]
            .as_str()
            .unwrap()
            .starts_with("data:image/png;base64,"));
        request(
            &case,
            "GET",
            &format!("{path}/assets/test-file"),
            &foreign,
            "",
            Value::Null,
            StatusCode::NOT_FOUND,
        )
        .await?;
        // A fresh App has no in-memory room state and still restores the board.
        let restarted = Case {
            app: std::sync::Arc::new(porthub_api::App::new(Default::default(), case.db.clone())),
            router: axum::Router::new(),
            db: case.db.clone(),
        };
        let restored = porthub_api::router(restarted.app.clone());
        let restarted = Case {
            router: restored,
            ..restarted
        };
        let persisted = request(
            &restarted,
            "GET",
            &path,
            "",
            view,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
        ensure!(persisted["elements"] == read["elements"]);
        request(
            &restarted,
            "GET",
            &format!("{path}/assets/test-file"),
            "",
            view,
            Value::Null,
            StatusCode::OK,
        )
        .await?;
        request(
            &case,
            "PATCH",
            &format!("{path}/sharing"),
            &owner,
            "",
            json!({"enabled":true,"rotate":true}),
            StatusCode::OK,
        )
        .await?;
        request(
            &case,
            "GET",
            &path,
            "",
            edit,
            Value::Null,
            StatusCode::NOT_FOUND,
        )
        .await?;
        request(
            &case,
            "GET",
            &format!("{path}/assets/test-file"),
            "",
            view,
            Value::Null,
            StatusCode::NOT_FOUND,
        )
        .await?;
        request(
            &case,
            "DELETE",
            &path,
            &owner,
            "",
            Value::Null,
            StatusCode::OK,
        )
        .await?;
        ensure!(
            case.app
                .collection(porthub_api::boards::ASSETS)
                .count_documents(doc! {"board_id":id})
                .await?
                == 0
        );
        request(
            &case,
            "GET",
            &path,
            &owner,
            "",
            Value::Null,
            StatusCode::NOT_FOUND,
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
async fn board_search_and_private_previews() -> Result<()> {
    use axum::{body::{to_bytes,Body},http::Request};
    use tower::ServiceExt;
    let case=Case::new(Default::default()).await?;
    let result: Result<()> = async {
        let (_,cookie)=case.user("search@example.invalid","user").await?;
        let (_,foreign)=case.user("other-search@example.invalid","user").await?;
        let created=request(&case,"POST","/api/boards",&cookie,"",json!({"name":"Sprint [2026]"}),StatusCode::OK).await?;
        let id=created["id"].as_str().unwrap();
        let path=format!("/api/boards/{id}");
        request(&case,"PATCH",&format!("{path}/scene"),&cookie,"",json!({"elements":[
            {"id":"note","type":"text","text":"Architecture <script>alert(1)</script>","originalText":"Architecture <script>alert(1)</script>","version":1,"versionNonce":1,"x":0,"y":0,"width":200,"height":30,"fontSize":20},
            {"id":"deleted","type":"text","text":"obsolete unique","isDeleted":true,"version":1,"versionNonce":1,"x":0,"y":0,"width":20,"height":10}
        ]}),StatusCode::OK).await?;
        for (search, count, user) in [("sprint",1,&cookie),("%5B2026%5D",1,&cookie),("architecture",1,&cookie),("obsolete",0,&cookie),(".*",0,&cookie),("architecture",0,&foreign)] {
            let found=request(&case,"GET",&format!("/api/boards?search={search}"),user,"",Value::Null,StatusCode::OK).await?;
            ensure!(found["boards"].as_array().unwrap().len()==count,"search {search}");
            ensure!(found["boards"].as_array().unwrap().iter().all(|b|b.get("elements").is_none()&&b.get("preview").is_none()));
        }
        let raw=|cookie:String| {
            let router=case.router.clone(); let url=format!("{path}/preview");
            async move { Ok::<_,anyhow::Error>(router.oneshot(Request::builder().uri(url).header("cookie",cookie).body(Body::empty())?).await?) }
        };
        ensure!(raw(foreign).await?.status()==StatusCode::NOT_FOUND);
        ensure!(raw(String::new()).await?.status()==StatusCode::BAD_REQUEST);
        let response=raw(cookie.clone()).await?;
        ensure!(response.status()==StatusCode::OK&&response.headers()["content-type"]=="image/svg+xml");
        let svg=String::from_utf8(to_bytes(response.into_body(),1024*1024).await?.to_vec())?;
        ensure!(svg.contains("&lt;script&gt;")&&!svg.contains("<script>"));
        let mut png=std::io::Cursor::new(Vec::new());
        image::DynamicImage::new_rgba8(80,50).write_to(&mut png,image::ImageFormat::Png)?;
        let rev=request(&case,"GET",&path,&cookie,"",Value::Null,StatusCode::OK).await?["revision"].as_i64().unwrap();
        request(&case,"PUT",&format!("{path}/preview"),&cookie,"",json!({"revision":rev-1,"image":STANDARD.encode(png.get_ref())}),StatusCode::CONFLICT).await?;
        request(&case,"PUT",&format!("{path}/preview"),&cookie,"",json!({"revision":rev,"image":STANDARD.encode(png.get_ref())}),StatusCode::NO_CONTENT).await?;
        let response=raw(cookie.clone()).await?;
        ensure!(response.headers()["content-type"]=="image/png");
        let png=to_bytes(response.into_body(),1024*1024).await?;
        ensure!(png.starts_with(b"\x89PNG"));
        let mut bad=png.to_vec(); bad[16..20].copy_from_slice(&9999_u32.to_be_bytes());
        request(&case,"PUT",&format!("{path}/preview"),&cookie,"",json!({"revision":rev,"image":STANDARD.encode(bad)}),StatusCode::BAD_REQUEST).await?;
        Ok(())
    }.await;
    case.db.drop().await?;
    result
}
