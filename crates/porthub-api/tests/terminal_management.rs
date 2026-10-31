use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::{config::Config, terminal_grants};
use porthub_terminal::protocol::*;
use serde_json::json;
mod support;
use support::Case;
fn api<T>(value: porthub_api::error::ApiResult<T>) -> Result<T> {
    value.map_err(|e| anyhow::anyhow!("{}", e.detail))
}
#[tokio::test]
#[ignore = "requires isolated MongoDB"]
async fn browser_management_requires_current_machine_workspace_admin_and_no_guest_capability_bypass(
) -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let (owner, owner_cookie) = case.user("terminal-owner@example.test", "user").await?;
    let (admin, admin_cookie) = case.user("terminal-admin@example.test", "user").await?;
    let (member, member_cookie) = case.user("terminal-member@example.test", "user").await?;
    let (_, foreign_cookie) = case.user("terminal-foreign@example.test", "admin").await?;
    for (user, role) in [(admin, "admin"), (member, "member")] {
        case.app.collection("workspace_members").insert_one(doc!{"_id":format!("{}:{}",owner.to_hex(),user.to_hex()),"workspace_id":owner,"user_id":user,"role":role}).await?;
    }
    let machine = ObjectId::new();
    case.app
        .collection("machines")
        .insert_one(doc! {"_id":machine,"user_id":owner,"enabled":true})
        .await?;
    let hello = HostHello {
        id: random_token(16),
        secret: random_token(32),
        write_token: random_token(32),
        read_token: random_token(32),
        options: Options {
            name: "amberotter".into(),
            expires_at: 0,
            session_expires_at: None,
            idle_timeout: 0,
            reconnect_timeout: 60,
            history_limit: 100000,
            mouse: true,
            read_only: false,
            size_policy: SizePolicy::Smallest,
            access: Access::Both,
            max_viewers: 16,
        },
    };
    case.app
        .collection("terminal_sessions")
        .insert_one(doc! {"_id":&hello.id,"state":"active","machine_id":machine.to_hex()})
        .await?;
    let host = case
        .app
        .terminals
        .register(&machine.to_hex(), &hello, now())?;
    let (grant, recovery) = api(terminal_grants::create(&case.app, &hello.id, true, 60).await)?;
    let reader = case.app.terminals.attach_authorized(
        &hello.id,
        Some(grant.identity),
        true,
        80,
        24,
        "xterm-256color",
    )?;
    let writer = case
        .app
        .terminals
        .attach(&hello.write_token, 80, 24, "xterm-256color")?;
    let endpoint = format!("/api/terminal/{}/participants", hello.id);
    let kick = format!("/api/terminal/{}/kick", hello.id);
    let revoke = format!("/api/terminal/{}/invitations/revoke", hello.id);
    for cookie in ["", &foreign_cookie, &member_cookie] {
        let (status, _, _) = case
            .call("GET", &endpoint, cookie, json!(null), &[])
            .await?;
        ensure!(
            !status.is_success(),
            "unprivileged user must not receive management access"
        );
        let (status, _, _) = case
            .call("POST", &kick, cookie, json!({"client":grant.identity}), &[])
            .await?;
        ensure!(
            !status.is_success(),
            "login or invitation alone must not authorize guest removal"
        );
        let (status, _, _) = case.call("POST", &revoke, cookie, json!({}), &[]).await?;
        ensure!(!status.is_success() && !host.session.invitations_revoked());
        ensure!(host.session.participants() == 2);
    }
    for cookie in [&owner_cookie, &admin_cookie] {
        let result = case
            .status("GET", &endpoint, cookie, json!(null), StatusCode::OK)
            .await?;
        ensure!(result["can_manage"] == true && result["members"].as_array().unwrap().len() == 2);
    }
    case.status("POST", &revoke, &owner_cookie, json!({}), StatusCode::OK)
        .await?;
    ensure!(host.session.invitations_revoked() && host.session.participants() == 2);
    ensure!(
        case.app.terminals.resolve(&hello.write_token).is_err()
            && case.app.terminals.resolve(&hello.read_token).is_err()
    );
    ensure!(case
        .app
        .collection("terminal_sessions")
        .find_one(doc! {"_id":&hello.id,"invitations_revoked":true})
        .await?
        .is_some());
    let status = case
        .status("GET", &endpoint, &owner_cookie, json!(null), StatusCode::OK)
        .await?;
    ensure!(status["invitations_revoked"] == true);
    let (status, _, _) = case
        .call(
            "POST",
            &kick,
            &owner_cookie,
            json!({"client":grant.identity}),
            &[("origin", "https://unrelated.example")],
        )
        .await?;
    ensure!(status == StatusCode::FORBIDDEN && host.session.participants() == 2);
    let (status, _, _) = case
        .call(
            "POST",
            &kick,
            &admin_cookie,
            json!({"client":grant.identity}),
            &[("origin", "https://porthub.test")],
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "same-origin administrator removal must succeed"
    );
    ensure!(
        host.session.participants() == 1
            && terminal_grants::resume(&case.app, &recovery).await.is_err()
    );
    writer.session.input(
        writer.id,
        ViewerInput::Input {
            data: encode_data(b"echo still-running\r"),
        },
    )?;
    case.app
        .collection("workspace_members")
        .delete_one(doc! {"_id":format!("{}:{}",owner.to_hex(),admin.to_hex())})
        .await?;
    let (status, _, _) = case
        .call("GET", &endpoint, &admin_cookie, json!(null), &[])
        .await?;
    ensure!(
        status == StatusCode::FORBIDDEN,
        "revoked administrator must lose access immediately"
    );
    let (status, _, _) = case
        .call(
            "POST",
            &kick,
            &admin_cookie,
            json!({"client":writer.id}),
            &[],
        )
        .await?;
    ensure!(status == StatusCode::FORBIDDEN && host.session.participants() == 1);
    // An administrator can revoke persisted invitations while the machine's
    // terminal host is offline; no live in-memory session is needed.
    let offline = random_token(16);
    case.app
        .collection("terminal_sessions")
        .insert_one(doc! {"_id":&offline,"machine_id":machine.to_hex(),"state":"active"})
        .await?;
    let offline_revoke = format!("/api/terminal/{offline}/invitations/revoke");
    let (status, _, _) = case
        .call("POST", &offline_revoke, &foreign_cookie, json!({}), &[])
        .await?;
    ensure!(status == StatusCode::FORBIDDEN);
    case.status(
        "POST",
        &offline_revoke,
        &owner_cookie,
        json!({}),
        StatusCode::OK,
    )
    .await?;
    ensure!(case
        .app
        .collection("terminal_sessions")
        .find_one(doc! {"_id":&offline,"invitations_revoked":true})
        .await?
        .is_some());
    drop(reader);
    drop(writer);
    case.app.terminals.end(&hello.id, "fixture ended");
    case.db.drop().await?;
    Ok(())
}
