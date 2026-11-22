#![cfg(target_os = "linux")]
//! Isolated browser -> real Rust broker -> existing CLI -> Xvfb desktop.
use anyhow::{ensure, Context, Result};
use mongodb::bson::{doc, oid::ObjectId};
use serde_json::json;
use std::{path::PathBuf, sync::Arc, time::Duration};
mod support;
use support::Case;
// SIGTERM lets Xvfb remove its own socket/lock. Never unlink a replacement
// display's paths: report leftovers after the bounded kill/reap fallback.
async fn stop_xvfb(child: &mut tokio::process::Child, display: &str) -> Result<()> {
    let mut fallback = false;
    if child.try_wait()?.is_none() {
        let pid = child.id().context("Xvfb PID absent before shutdown")?;
        // The unreaped Child owns this PID; do not signal by process name.
        let sent = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) } == 0;
        let stopped = if sent {
            match tokio::time::timeout(Duration::from_secs(3), child.wait()).await {
                Ok(status) => {
                    status?;
                    true
                }
                Err(_) => false,
            }
        } else {
            false
        };
        if !stopped {
            fallback = true;
            child.start_kill()?;
            tokio::time::timeout(Duration::from_secs(3), child.wait()).await??;
        }
    }
    let number = display
        .strip_prefix(':')
        .context("Invalid fixture display")?
        .parse::<u16>()?;
    for path in [
        format!("/tmp/.X11-unix/X{number}"),
        format!("/tmp/.X{number}-lock"),
    ] {
        ensure!(
            matches!(std::fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
            "Owned Xvfb path remains after shutdown"
        );
    }
    println!("native_xvfb_cleanup reaped=true socket_absent=true lock_absent=true kill_fallback={fallback}");
    Ok(())
}
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
    let mut xvfb: Option<(tokio::process::Child, String)> = None;
    let result:Result<()>=async{
        let(owner,cookie)=case.user("keyboard-browser@example.invalid","admin").await?;let machine=ObjectId::new();let token="isolated-keyboard-native-test-token";
        case.app.collection("machines").insert_one(doc!{"_id":machine,"user_id":owner,"name":"Isolated desktop","token":token,"enabled":true}).await?;
        let mut metric_sample=json!({"cpu":20,"cores":8,"ram":{"used":4_000_000_000_u64,"total":8_000_000_000_u64},"disk":{"used":50_000_000_000_u64,"total":100_000_000_000_u64},"gpus":[{"id":"fixture-integrated","name":"Fixture GPU","integrated":true,"utilization":96,"memory":null,"shared_memory_capacity":8_589_934_592_u64,"shared_memory":{"used":268_435_456_u64,"total":8_589_934_592_u64}},{"id":"fixture-discrete","name":"Fixture discrete GPU","utilization":null,"memory":{"used":1_000_000_000_u64,"total":4_000_000_000_u64}}]});
        let smart_at=mongodb::bson::DateTime::now().timestamp_millis();
        metric_sample["drive_health"]=json!([{"id":"a".repeat(64),"name":"Fixture physical SSD","protocol":"nvme","capacity":1_000_000_000_000_u64,"present":true,"status":"healthy","observed_at":smart_at,"checked_at":smart_at,"temperature":42,"percentage_used":12,"available_spare":100,"spare_threshold":10,"power_on_hours":1200,"power_cycles":300,"unsafe_shutdowns":0,"media_errors":0,"reallocated_sectors":null,"pending_sectors":null,"uncorrectable_sectors":null,"short_test_supported":true,"self_test":"passed","last_test_started":null,"next_test_at":null,"reasons":[]}]);
        case.status("POST","/api/machines/client/metrics","",json!({"machine_id":machine.to_hex(),"token":token,"sample":metric_sample}),axum::http::StatusCode::OK).await?;
        let busy=ObjectId::new();
        case.app.collection("machines").insert_one(doc!{"_id":busy,"user_id":owner,"name":"Busy CPU host","token":"fixture-busy","enabled":true}).await?;
        let mut busy_sample=metric_sample.clone();busy_sample["cpu"]=json!(90);busy_sample["gpus"][0]["utilization"]=json!(0);
        busy_sample["drive_health"][0]["status"]=json!("critical");busy_sample["drive_health"][0]["media_errors"]=json!(10);busy_sample["drive_health"][0]["reasons"]=json!(["Media or data-integrity errors recorded"]);
        case.status("POST","/api/machines/client/metrics","",json!({"machine_id":busy.to_hex(),"token":"fixture-busy","sample":busy_sample}),axum::http::StatusCode::OK).await?;
        let third=ObjectId::new();
        case.app.collection("machines").insert_one(doc!{"_id":third,"user_id":owner,"name":"Third host","token":"fixture-third","enabled":true}).await?;
        let mut third_sample=metric_sample.clone();third_sample["cpu"]=json!(60);third_sample["gpus"][0]["utilization"]=json!(50);
        third_sample["drive_health"][0]["status"]=json!("warning");third_sample["drive_health"][0]["percentage_used"]=json!(92);third_sample["drive_health"][0]["reasons"]=json!(["SSD is nearing its rated endurance"]);
        case.status("POST","/api/machines/client/metrics","",json!({"machine_id":third.to_hex(),"token":"fixture-third","sample":third_sample}),axum::http::StatusCode::OK).await?;
        let usb_device=json!({"busid":"1-2","vendor":"1377","product":"1100","serial":"fixture-microphone","name":"Fixture USB microphone","busnum":1,"devnum":2,"speed":2,"blocked":null});
        case.status("POST","/api/usb/client/report","",json!({"machine_id":machine.to_hex(),"token":token,"enabled":true,"supported":true,"devices":[usb_device],"states":[]}),axum::http::StatusCode::OK).await?;
        case.status("POST","/api/usb/client/report","",json!({"machine_id":busy.to_hex(),"token":"fixture-busy","enabled":true,"supported":true,"devices":[],"states":[]}),axum::http::StatusCode::OK).await?;
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
        let number=display.strip_prefix(':').context("Invalid fixture display")?.parse::<u16>()?;
        for path in [format!("/tmp/.X11-unix/X{number}"),format!("/tmp/.X{number}-lock")] {
            ensure!(matches!(std::fs::symlink_metadata(path),Err(error) if error.kind()==std::io::ErrorKind::NotFound),"Fixture display is already occupied");
        }
        let child=tokio::process::Command::new("Xvfb").args([&display,"-screen","0","1440x900x24","-nolisten","tcp"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).kill_on_drop(true).spawn()?;
        xvfb=Some((child,display.clone()));
        tokio::time::sleep(Duration::from_millis(300)).await;
        ensure!(xvfb.as_mut().unwrap().0.try_wait()?.is_none(),"Xvfb did not start");
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
        print!("{}",String::from_utf8_lossy(&output.stdout));let _=module.kill().await;ensure!(output.status.success(),"Browser verification failed: {}",String::from_utf8_lossy(&output.stderr));Ok(())
    }.await;
    let cleanup = if let Some((child,display)) = &mut xvfb { stop_xvfb(child,display).await } else { Ok(()) };
    if let Err(error) = &cleanup { eprintln!("native_xvfb_cleanup failed: {error}"); }
    let database_cleanup = case.db.drop().await;
    result?;
    cleanup?;
    database_cleanup?;
    Ok(())
}
