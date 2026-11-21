//! Grant a loopback-only listener on an enrolled consumer access to one bound
//! SSH export. Each WebSocket uses the current private-sync lease and an actual
//! workspace machine record. An IP address never identifies a caller.
use super::*;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    http::HeaderMap,
    response::Response,
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/port-forwards/agent/config", get(config))
        .route("/api/port-forwards/agent/{id}/{port}/connect", get(connect))
}
fn denied() -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, "Private forward is unavailable")
}
struct Peer {
    id: String,
    instance: String,
    hash: String,
    owner: ObjectId,
    machine: ObjectId,
    groups: Vec<ObjectId>,
}
impl Peer {
    async fn authenticate(app: &App, headers: &HeaderMap) -> ApiResult<Self> {
        fn header<'a>(h: &'a HeaderMap, key: &str, max: usize) -> ApiResult<&'a str> {
            h.get(key)
                .and_then(|v| v.to_str().ok())
                .filter(|s| !s.is_empty() && s.len() <= max)
                .ok_or_else(denied)
        }
        let id = header(headers, "x-porthub-peer", 128)?;
        let instance = header(headers, "x-porthub-instance", 128)?;
        let token = header(headers, "authorization", 263)?
            .strip_prefix("Bearer ")
            .ok_or_else(denied)?;
        let hash = crate::domain::workspaces::token_digest(token);
        Self::enrolled(app, id, instance, hash).await
    }
    async fn enrolled(app: &App, id: &str, instance: &str, hash: String) -> ApiResult<Self> {
        let owner = app
            .private_relay
            .change_workspace(id, &hash, instance)
            .ok_or_else(denied)?;
        let peer = app
            .collection("private_peers")
            .find_one(doc! {"_id":id,"workspace_id":owner,"owner_id":owner,
            "credential_hash":&hash,"enabled":true,"virtual_parent":{"$exists":false}})
            .projection(doc! {"machine_id":1})
            .await?
            .ok_or_else(denied)?;
        let machine = peer.get_object_id("machine_id").map_err(|_| denied())?;
        let machine_row=app.collection("machines").find_one(doc!{"_id":machine,"user_id":owner,"enabled":{"$ne":false},
            "deletion_pending":{"$ne":true},"private_owner_revoked":{"$ne":true},"kind":{"$ne":"virtual_host"}})
            .projection(doc!{"group_ids":1,"group_id":1}).await?.ok_or_else(denied)?;
        let ids = crate::domain::inventory::group_ids(&machine_row);
        let groups = if ids.is_empty() {
            Vec::new()
        } else {
            app.collection("machine_groups")
                .find(doc! {"_id":{"$in":ids},"user_id":owner})
                .projection(doc! {"_id":1})
                .await?
                .try_collect::<Vec<Document>>()
                .await?
                .into_iter()
                .filter_map(|d| d.get_object_id("_id").ok())
                .collect()
        };
        if app
            .collection("users")
            .count_documents(doc! {"_id":owner,"account_deletion":{"$exists":false}})
            .await?
            != 1
        {
            return Err(denied());
        }
        let this = Self {
            id: id.into(),
            instance: instance.into(),
            hash,
            owner,
            machine,
            groups,
        };
        if !this.current(app) {
            return Err(denied());
        }
        Ok(this)
    }
    fn current(&self, app: &App) -> bool {
        app.private_relay
            .change_workspace(&self.id, &self.hash, &self.instance)
            == Some(self.owner)
    }
    fn filter(&self) -> Document {
        doc! {"workspace_id":self.owner,"state":"active","public":false,
        "$or":[{"machine_ids":self.machine},{"group_ids":{"$in":&self.groups}}]}
    }
}
pub(super) async fn suffix(app: &App, owner: ObjectId) -> ApiResult<String> {
    let network = app
        .collection("private_networks")
        .find_one(doc! {"_id":owner.to_hex()})
        .await?;
    crate::domain::enrollment::preferences(&network.unwrap_or_default()).map(|(_, suffix)| suffix)
}
async fn config(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<impl axum::response::IntoResponse> {
    let peer = Peer::authenticate(&app, &headers).await?;
    let suffix = suffix(&app, peer.owner).await?;
    let rows = app
        .collection(COLLECTION)
        .find(peer.filter())
        .projection(doc! {"_id":1,"mappings":1})
        .sort(doc! {"_id":1})
        .await?;
    let mut rows = rows;
    let mut descriptors = Vec::<Value>::new();
    while let Some(row) = rows.try_next().await? {
        let Ok(id) = row.get_object_id("_id") else {
            continue;
        };
        for item in mappings(&row).unwrap_or_default() {
            if item.get_str("direction") == Ok("remote") {
                if let Ok(port) = number(item, "gatewayPort") {
                    descriptors.push(json!({"entryId":id.to_hex(),"host":format!("{id}.forwards.{suffix}"),"port":port}));
                }
            }
        }
    }
    if !peer.current(&app) {
        return Err(denied());
    }
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"forwards":descriptors})),
    ))
}
pub(super) fn signal(app: &App, owner: ObjectId) {
    app.private_changes.changed(owner);
}
async fn connect(
    State(app): State<Arc<App>>,
    Path((id, port)): Path<(String, u16)>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    let id = ObjectId::parse_str(id).map_err(|_| denied())?;
    let peer = Peer::authenticate(&app, &headers).await?;
    let mut changes = app
        .private_changes
        .subscribe(peer.owner)
        .ok_or_else(denied)?;
    changes.borrow_and_update();
    // Read current inventory after subscribing so a change during lookup
    // cannot leave the former membership usable.
    let peer = Peer::authenticate(&app, &headers).await?;
    if !selected(&app, &peer, id, port).await?
        || !peer.current(&app)
        || changes.has_changed().unwrap_or(true)
    {
        return Err(denied());
    }
    let grant = app
        .forward_registry
        .get(&id.to_hex())
        .filter(|g| g.is_listening(port))
        .ok_or_else(denied)?;
    Ok(ws
        .max_message_size(65536)
        .max_frame_size(65536)
        .on_upgrade(move |ws| serve(app, peer, grant, id, port, changes, ws)))
}
async fn selected(app: &App, peer: &Peer, id: ObjectId, port: u16) -> ApiResult<bool> {
    let mut filter = peer.filter();
    filter.extend(doc!{"_id":id,"mappings":{"$elemMatch":{"direction":"remote","gatewayPort":i32::from(port)}}});
    Ok(app.collection(COLLECTION).count_documents(filter).await? == 1)
}
struct StreamScope<'a> {
    app: &'a App,
    peer: &'a Peer,
    id: ObjectId,
    port: u16,
    changes: watch::Receiver<uuid::Uuid>,
    confirmed: Mutex<uuid::Uuid>,
}
impl StreamScope<'_> {
    async fn permit(&self) -> std::result::Result<(), ()> {
        let mut confirmed = self.confirmed.lock().await;
        // Both directions consult the current workspace cursor before forwarding
        // fresh bytes. A notification triggers one membership query per stream.
        loop {
            if !self.peer.current(self.app) {
                return Err(());
            }
            let revision = *self.changes.borrow();
            if revision == *confirmed {
                return Ok(());
            }
            let peer = Peer::enrolled(
                self.app,
                &self.peer.id,
                &self.peer.instance,
                self.peer.hash.clone(),
            )
            .await
            .map_err(|_| ())?;
            if peer.machine != self.peer.machine
                || peer.owner != self.peer.owner
                || !selected(self.app, &peer, self.id, self.port)
                    .await
                    .map_err(|_| ())?
            {
                return Err(());
            }
            if revision == *self.changes.borrow() {
                *confirmed = revision;
            }
        }
    }
}
async fn serve(
    app: Arc<App>,
    peer: Peer,
    grant: Arc<porthub_forward_ssh::Grant>,
    id: ObjectId,
    port: u16,
    mut changes: watch::Receiver<uuid::Uuid>,
    ws: WebSocket,
) {
    use futures_util::{SinkExt, StreamExt};
    changes.borrow_and_update();
    // The HTTP upgrade may complete after membership has changed. Recheck once
    // with the original identity before letting the SSH server see a channel.
    let scope = StreamScope {
        app: &app,
        peer: &peer,
        id,
        port,
        changes: changes.clone(),
        confirmed: Mutex::new(uuid::Uuid::nil()),
    };
    if scope.permit().await.is_err() {
        return;
    }
    let (mut tx, mut rx) = ws.split();
    let (local, wire) = tokio::io::duplex(32 * 1024);
    let (mut reader, mut writer) = tokio::io::split(wire);
    let upload = async {
        while let Some(Ok(frame)) = rx.next().await {
            scope.permit().await?;
            match frame {
                Message::Binary(bytes) => writer.write_all(&bytes).await.map_err(|_| ())?,
                Message::Text(text) if text == "eof" => {
                    writer.shutdown().await.map_err(|_| ())?;
                    return Ok::<(), ()>(());
                }
                Message::Ping(_) | Message::Pong(_) => {}
                _ => break,
            }
        }
        Err(())
    };
    let download = async {
        let mut bytes = [0u8; 16384];
        loop {
            let n = reader.read(&mut bytes).await.map_err(|_| ())?;
            scope.permit().await?;
            if n == 0 {
                tx.send(Message::Text("eof".into())).await.map_err(|_| ())?;
                return Ok::<(), ()>(());
            }
            tx.send(Message::Binary(bytes[..n].to_vec().into()))
                .await
                .map_err(|_| ())?;
        }
    };
    let review = async {
        loop {
            tokio::select! {r=changes.changed()=>if r.is_err(){break;},_=tokio::time::sleep(Duration::from_secs(2))=>{}}
            if scope.permit().await.is_err() {
                break;
            }
        }
    };
    let transfer = async {
        let _ = tokio::try_join!(upload, download);
    };
    let bridge = async {
        let ssh = grant.forward(port, local);
        tokio::pin!(ssh, transfer);
        tokio::select! {
            _=&mut ssh=>{let _=tokio::time::timeout(Duration::from_secs(5), transfer).await;},
            _=&mut transfer=>{let _=tokio::time::timeout(Duration::from_secs(5), ssh).await;},
        }
    };
    tokio::select! {biased;_=grant.cancel.cancelled()=>{},_=review=>{},_=bridge=>{}}
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::bson::Bson;
    #[tokio::test]
    #[ignore = "needs isolated MongoDB"]
    async fn current_enrollment_selects_owned_groups_and_rechecks_without_losing_unrelated_streams(
    ) -> Result<()> {
        let client =
            mongodb::Client::with_uri_str(std::env::var("PORTHUB_TEST_MONGO_URI")?).await?;
        let db = client.database(&format!(
            "porthub_forward_scope_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let app = App::new(Default::default(), db.clone());
        let result=async {
            let (owner,machine,group,id)=(ObjectId::new(),ObjectId::new(),ObjectId::new(),ObjectId::new());
            let peer_id=format!("{owner}:{machine}");let token="test-only-private-credential";let instance="unit-private-owner";
            let hash=crate::domain::workspaces::token_digest(token);
            app.collection("users").insert_one(doc!{"_id":owner}).await?;
            app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner}).await?;
            app.collection("machines").insert_one(doc!{"_id":machine,"user_id":owner,"group_ids":[group]}).await?;
            app.collection("private_peers").insert_one(doc!{"_id":&peer_id,"workspace_id":owner,"owner_id":owner,"machine_id":machine,"enabled":true,"credential_hash":&hash}).await?;
            app.collection(COLLECTION).insert_one(doc!{"_id":id,"workspace_id":owner,"public":false,"state":"active","group_ids":[group],"mappings":[{"direction":"remote","gatewayPort":13456}]}).await?;
            assert!(app.private_relay.workspace_generation(&owner.to_hex(),1,false));
            let admitted=app.private_relay.begin_workspace_admission(&peer_id,&hash,instance,&owner.to_hex());
            assert!(admitted.is_some());
            assert!(!app.private_relay.publish_admitted(&peer_id,&hash,instance,"10.203.0.4".parse()?,Default::default(),admitted).is_empty());
            let mut headers=HeaderMap::new();
            headers.insert("authorization",format!("Bearer {token}").parse()?);
            headers.insert("x-porthub-peer",peer_id.parse()?);
            headers.insert("x-porthub-instance",instance.parse()?);
            let peer=Peer::authenticate(&app,&headers).await.map_err(api)?;
            assert!(selected(&app,&peer,id,13456).await.map_err(api)?);
            assert!(!selected(&app,&peer,id,13455).await.map_err(api)?);
            let changes=app.private_changes.subscribe(owner).unwrap();
            let scope=StreamScope{app:&app,peer:&peer,id,port:13456,changes,confirmed:Mutex::new(uuid::Uuid::nil())};
            assert!(scope.permit().await.is_ok());
            signal(&app,owner);assert!(scope.permit().await.is_ok());
            app.collection("machines").update_one(doc!{"_id":machine},doc!{"$set":{"group_ids":Bson::Array(Vec::new())}}).await?;
            signal(&app,owner);assert!(scope.permit().await.is_err());
            app.collection(COLLECTION).update_one(doc!{"_id":id},doc!{"$set":{"machine_ids":[machine]}}).await?;
            signal(&app,owner);assert!(scope.permit().await.is_ok());
            let mut replay=headers.clone();replay.insert("x-porthub-instance","stale-instance".parse()?);
            assert!(Peer::authenticate(&app,&replay).await.is_err());
            app.private_relay.revoke(&[peer_id]);assert!(scope.permit().await.is_err());
            Ok::<_,anyhow::Error>(())
        }.await;
        db.drop().await?;
        result
    }
}
