//! Local actual-App + actual agent unit-carrier proof, with no TUN/host changes.
//! Run after building the exact agent unit binary containing the ignored sibling.
use anyhow::{ensure, Context, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::{config::Config, domain::workspaces::token_digest};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;
#[allow(dead_code)]
mod support;
use support::Case;
const SELECTOR:&str="private_network::runtime::traffic_transport_tests::actual_direct_and_gateway_carriers_upload_observed_tx";
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
#[tokio::test]
#[ignore = "requires isolated Mongo and exact built agent unit executable; local sockets only"]
async fn actual_agent_direct_and_gateway_tx_are_automatically_uploaded_to_owner_history(
) -> Result<()> {
    let executable = PathBuf::from(std::env::var("PORTHUB_TEST_AGENT_UNIT_EXECUTABLE")?);
    let meta = std::fs::symlink_metadata(&executable)?;
    ensure!(
        meta.is_file()
            && !meta.file_type().is_symlink()
            && executable
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("porthub_agent-")),
        "exact actual agent unit binary required"
    );
    let case = Case::new(Config {
        private_transport: porthub_api::private_transport::Settings::parse(
            "[]",
            "",
            "native-controller-relay-secret-0123456789abcdef",
        ),
        ..Default::default()
    })
    .await?;
    let cancel = CancellationToken::new();
    let mut server = None;
    let mut child = None;
    let result=async {
        let(owner,cookie)=case.user("carrier-traffic-owner@test.invalid","user").await?;
        let ids=[ObjectId::new(),ObjectId::new()];let peers:Vec<_>=ids.iter().map(|id|format!("{owner}:{id}")).collect();
        let token="carrier-fixture-token-0123456789abcdef0123456789";
        for(index,id)in ids.iter().enumerate(){
            case.app.collection("machines").insert_one(doc!{"_id":id,"user_id":owner,"enabled":true,"name":format!("Carrier node {index}"),"token":"fixture-unused-public-token"}).await?;
            case.app.collection("private_peers").insert_one(doc!{"_id":&peers[index],"workspace_id":owner,"machine_id":id,"owner_id":owner,"ip":format!("10.203.0.{}",index+10),"enabled":true,"credential_hash":token_digest(token)}).await?;
        }
        let group=ObjectId::new();case.app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner}).await?;
        case.app.collection("access_rulebooks").insert_one(doc!{"_id":ObjectId::new(),"user_id":owner,"group_id":group.to_hex(),"rules":[{"id":"carrier","name":"Carrier fixture","sources":[{"kind":"machine","id":ids[0].to_hex()},{"kind":"machine","id":ids[1].to_hex()}],"destinations":[{"kind":"machine","id":ids[0].to_hex()},{"kind":"machine","id":ids[1].to_hex()}],"ports":"8000"}]}).await?;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let base=format!("http://{}",listener.local_addr()?);let router=case.router.clone();let stop=cancel.clone();server=Some(tokio::spawn(async move{axum::serve(listener,router).with_graceful_shutdown(stop.cancelled_owned()).await}));
        let mut builder=tempfile::Builder::new();
        #[cfg(unix)]
        let builder={use std::os::unix::fs::PermissionsExt;builder.permissions(std::fs::Permissions::from_mode(0o700))};
        let own=builder.tempdir()?;let input=own.path().join("input.json");let complete=own.path().join("complete.json");let nonce=uuid::Uuid::new_v4().simple().to_string();
        let config=json!({"nonce":nonce,"base":base,"workspace":owner.to_hex(),"peers":peers,"token":token,"complete":complete,"fixture_sha256":digest(include_bytes!("../../porthub-agent/src/private_network/traffic_transport_tests.rs")),"runtime_sha256":digest(include_bytes!("../../porthub-agent/src/private_network/runtime.rs"))});
        porthub_agent::profile::write_private(&input,&serde_json::to_vec(&config)?,false)?;
        child=Some(tokio::process::Command::new(&executable).args([SELECTOR,"--ignored","--exact","--nocapture"]).env("PORTHUB_PRIVATE_TRAFFIC_CARRIER_INPUT",&input).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true).spawn()?);
        let process=child.as_mut().unwrap();let stdout=process.stdout.take().context("carrier stdout missing")?;let stderr=process.stderr.take().context("carrier stderr missing")?;
        let mut out=tokio::spawn(async move{let mut bytes=Vec::new();stdout.take(65_537).read_to_end(&mut bytes).await?;Ok::<_,std::io::Error>(bytes)});
        let mut err=tokio::spawn(async move{let mut bytes=Vec::new();stderr.take(65_537).read_to_end(&mut bytes).await?;Ok::<_,std::io::Error>(bytes)});
        tokio::time::timeout(Duration::from_secs(90),async {
            loop {
                if let Some(status)=child.as_mut().unwrap().try_wait()? {let output=tokio::time::timeout(Duration::from_secs(2),&mut out).await???;
 let errors=tokio::time::timeout(Duration::from_secs(2),&mut err).await???;
 let text=String::from_utf8_lossy(&errors);
 let guard=["carrier compiled source guard","carrier actual transports ready deadline","carrier receive deadline","carrier path/peer mismatch","carrier byte identity mismatch","carrier snapshot owner closed","carrier expected observed byte counts","carrier automatic controller upload deadline","machine state directory must be owned","carrier owned completion guard","carrier peer binding"].into_iter().find(|guard|text.contains(guard)).unwrap_or("unclassified-child-error");
 eprintln!("PRIVATE_TRAFFIC_CARRIER_CHILD_FAILURE code={:?} guard={} stdout_bytes={} stderr_bytes={} stdout_sha256={} stderr_sha256={}",status.code(),guard,output.len(),errors.len(),digest(&output),digest(&errors));anyhow::bail!("carrier child exited before API confirmation: {guard}");}
                let(status,_,page)=case.call("GET","/api/private/traffic?range=1h",&cookie,Value::Null,&[]).await?;
                if status==StatusCode::OK && page["flows"].as_array().is_some_and(|flows|flows.len()==2) {
                    ensure!(page["totals"]["direct_bytes"]==168&&page["totals"]["relay_bytes"]==168&&page["totals"]["total_bytes"]==336,"actual carrier aggregate mismatch");
                    for flow in page["flows"].as_array().unwrap(){ensure!(flow["direct_bytes"]==84&&flow["relay_bytes"]==84&&flow["total_bytes"]==168&&flow["coverage"]=="sender_reported","actual directed carrier report mismatch");}
                    porthub_agent::profile::write_private(&complete,&serde_json::to_vec(&json!({"nonce":nonce,"uploaded":true}))?,false)?;break Ok::<_,anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }).await.context("actual carrier API upload deadline")??;
        let status=tokio::time::timeout(Duration::from_secs(15),child.as_mut().unwrap().wait()).await.context("carrier child cleanup deadline")??;
        let stdout=tokio::time::timeout(Duration::from_secs(2),out).await???;let stderr=tokio::time::timeout(Duration::from_secs(2),err).await???;
        ensure!(stdout.len()<=65_536&&stderr.len()<=65_536,"carrier output bound");
        ensure!(status.success(),"carrier child cleanup failed");
        let text=String::from_utf8(stdout)?;ensure!(text.contains("PRIVATE_TRAFFIC_CARRIER_PROOF direct_tx_bytes=168 relay_tx_bytes=168 actual_rx_bytes=336 controller_upload=true runtime_rx_owner_exercised=false")&&text.contains("1 passed"),"actual carrier child proof missing");
        println!("PRIVATE_TRAFFIC_ACTUAL_API_PROOF directions=2 direct_tx_bytes=168 relay_tx_bytes=168 carrier_rx_observed_bytes=336 automatic_controller_upload=true runtime_rx_owner_exercised=false");
        Ok::<_,anyhow::Error>(())
    }.await;
    let child_reaped = if let Some(mut process) = child {
        if process.try_wait().ok().flatten().is_some() {
            true
        } else {
            tokio::time::timeout(Duration::from_secs(5), process.kill())
                .await
                .is_ok_and(|value| value.is_ok())
        }
    } else {
        true
    };
    cancel.cancel();
    let listener_stopped = if let Some(mut task) = server {
        match tokio::time::timeout(Duration::from_secs(5), &mut task).await {
            Ok(Ok(Ok(()))) => true,
            Ok(_) => false,
            Err(_) => {
                task.abort();
                let _ = task.await;
                false
            }
        }
    } else {
        true
    };
    let case_database_dropped = tokio::time::timeout(Duration::from_secs(10), case.db.drop())
        .await
        .is_ok_and(|value| value.is_ok());
    println!("PRIVATE_TRAFFIC_CARRIER_CLEANUP child_reaped={child_reaped} listener_stopped={listener_stopped} case_database_dropped={case_database_dropped}");
    result?;
    ensure!(
        child_reaped && listener_stopped && case_database_dropped,
        "owned carrier fixture cleanup unproven"
    );
    Ok(())
}
