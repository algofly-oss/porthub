#![cfg(target_os = "linux")]
//! Isolated browser -> real Rust broker -> existing CLI -> Xvfb desktop.
use anyhow::{ensure, Context, Result};
use mongodb::bson::{doc, oid::ObjectId};
use serde_json::json;
use std::{path::PathBuf, sync::Arc, time::Duration};
mod support;
use support::Case;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires built static UI, Xvfb, Playwright and isolated MongoDB"]
async fn native_keyboard_clipboard_mouse_and_local_disable_from_embedded_portal() -> Result<()> {
    let root = tempfile::tempdir()?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    let config = root.path().join("config");
    let data = root.path().join("data");
    let state = config.join("porthub/native");
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&state)?;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
    let case = Case::new(porthub_api::config::Config {
        ui_root: std::env::var("PORTHUB_TEST_BOARD_UI_ROOT")?,
        ..Default::default()
    })
    .await?;
    let result:Result<()>=async{
        let(owner,cookie)=case.user("keyboard-browser@example.invalid","admin").await?;let machine=ObjectId::new();let token="isolated-keyboard-native-test-token";
        case.app.collection("machines").insert_one(doc!{"_id":machine,"user_id":owner,"name":"Isolated desktop","token":token,"enabled":true}).await?;
        let metric_sample=json!({"cpu":20,"cores":8,"ram":{"used":4_000_000_000_u64,"total":8_000_000_000_u64},"disk":{"used":50_000_000_000_u64,"total":100_000_000_000_u64},"gpus":[{"name":"Fixture GPU","utilization":80,"memory":{"used":1_000_000_000_u64,"total":4_000_000_000_u64}}]});
        case.status("POST","/api/machines/client/metrics","",json!({"machine_id":machine.to_hex(),"token":token,"sample":metric_sample}),axum::http::StatusCode::OK).await?;
        let busy=ObjectId::new();
        case.app.collection("machines").insert_one(doc!{"_id":busy,"user_id":owner,"name":"Busy CPU host","token":"fixture-busy","enabled":true}).await?;
        let mut busy_sample=metric_sample.clone();busy_sample["cpu"]=json!(90);busy_sample["gpus"][0]["utilization"]=json!(0);
        case.status("POST","/api/machines/client/metrics","",json!({"machine_id":busy.to_hex(),"token":"fixture-busy","sample":busy_sample}),axum::http::StatusCode::OK).await?;
        let now=mongodb::bson::DateTime::now().timestamp_millis();
        for minute in 1..60_i64 {
            let mut sample=metric_sample.clone();sample["cpu"]=json!(20+(minute%50));
            case.app.collection("machine_metrics_history").insert_one(doc!{"_id":format!("browser-{}-{minute}",machine.to_hex()),"machine_id":machine,"owner_id":owner,"at":mongodb::bson::DateTime::from_millis(now-minute*60000),"expires_at":mongodb::bson::DateTime::from_millis(now+86400000),"sample":mongodb::bson::to_document(&serde_json::from_value::<porthub_components::metrics::Sample>(sample)?)?}).await?;
        }
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let base=format!("http://{}",listener.local_addr()?);let router=case.router.clone();let _server=tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move{axum::serve(listener,router).await}));
        let profile:porthub_agent::profile::Profile=serde_json::from_value(json!({"server":base,"machine_id":machine.to_hex(),"token":token,"allow_insecure_http_for_tests":true}))?;
        let id=porthub_agent::service::identity(&profile);let layout=porthub_agent::service::Layout{user:true,state:state.clone(),releases:data.join("releases"),units:config.join("systemd/user")};let profile_path=state.join(format!("{id}.json"));
        let spec=porthub_agent::service::Spec{user:true,identity:id.clone(),service:format!("porthub-{}",&id[..24]),profile:profile_path.clone(),executable:layout.releases.join("a".repeat(64)).join("porthub"),unit:layout.units.join(format!("porthub-{}.service",&id[..24])),cli:None};
        porthub_agent::profile::write_private(&profile_path,&serde_json::to_vec(&profile)?,false)?;porthub_agent::profile::write_private(&state.join(format!("{id}.service.json")),&serde_json::to_vec(&spec)?,false)?;
        let control=Arc::new(porthub_agent::control::Control::new(profile)?);let _broker=porthub_agent::exposure_broker::start_registered(&profile_path,control,tokio_util::sync::CancellationToken::new(),&layout)?;
        let record=porthub_agent::service::readable::Record{format_version:1,id:id.clone(),machine_id:machine.to_hex(),email:String::new(),gateway:base.clone(),private:false,enabled:true,active:Some(true),state:"running".into(),agent_version:"test".into(),ports:0,route:String::new(),updated_at:1,strategy:Default::default(),strategy_override:false,private_status:None};
        porthub_agent::profile::write_private(&state.with_file_name("status").join(format!("{id}.json")),&serde_json::to_vec(&record)?,false)?;
        let display=std::env::var("PORTHUB_TEST_KEYBOARD_DISPLAY").unwrap_or_else(|_|":199".into());
        let mut xvfb=tokio::process::Command::new("Xvfb").args([&display,"-screen","0","1440x900x24","-nolisten","tcp"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).kill_on_drop(true).spawn()?;
        tokio::time::sleep(Duration::from_millis(300)).await;
        ensure!(xvfb.try_wait()?.is_none(),"Xvfb did not start");
        let executable=PathBuf::from(std::env::var("PORTHUB_TEST_AGENT_EXECUTABLE").context("Set the test CLI binary")?);
        let mut module=tokio::process::Command::new(&executable).args(["keyboard","run","--user","--registration",&id]).env("XDG_CONFIG_HOME",&config).env("XDG_DATA_HOME",&data).env("DISPLAY",&display).env("RUST_BACKTRACE","1").env("RUST_LOG","warn,porthub_agent::keyboard=debug").env_remove("WAYLAND_DISPLAY").kill_on_drop(true).spawn()?;
        tokio::time::timeout(Duration::from_secs(15),async {
            loop {
                ensure!(module.try_wait()?.is_none(),"VKeyboard module exited before connecting");
                let rows=case.status("GET","/api/keyboard/targets",&cookie,serde_json::Value::Null,axum::http::StatusCode::OK).await?;
                if rows["targets"].as_array().unwrap().iter().any(|t|t["online"]==true){break;}
                tokio::time::sleep(Duration::from_millis(50)).await;
            }Ok::<_,anyhow::Error>(())
        }).await??;
        let project=PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_owned();
        let output=tokio::time::timeout(Duration::from_secs(180),tokio::process::Command::new("node").arg(project.join("ui/tests/keyboard-browser.cjs")).env("PORTHUB_TEST_UI_URL",&base).env("PORTHUB_TEST_BOARD_COOKIE",&cookie).env("PORTHUB_TEST_KEYBOARD_CONFIG",&config).env("PORTHUB_TEST_KEYBOARD_DATA",&data).env("PORTHUB_TEST_KEYBOARD_ID",&id).env("PORTHUB_TEST_AGENT_EXECUTABLE",&executable).env("DISPLAY",&display).kill_on_drop(true).output()).await??;
        print!("{}",String::from_utf8_lossy(&output.stdout));let _=module.kill().await;let _=xvfb.kill().await;ensure!(output.status.success(),"Browser verification failed: {}",String::from_utf8_lossy(&output.stderr));Ok(())
    }.await;
    case.db.drop().await?;
    result
}
