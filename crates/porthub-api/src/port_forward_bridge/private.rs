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
        .route(
            "/api/port-forwards/agent/{id}/{port}/host-connect",
            get(connect_host),
        )
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
fn choose_label(row: &Document, id: ObjectId, used: &HashSet<String>) -> String {
    let base = crate::domain::private_names::label(row.get("name"));
    if !porthub_forward_ssh::valid_id(&base) && !used.contains(&base) {
        return base;
    }
    // The account is bounded to 64 profiles. A stable ID suffix avoids
    // exposing creation order and grows if the short fragment collides.
    let hex = id.to_hex();
    for len in 4..=24 {
        let candidate = format!(
            "{}-{}",
            base[..base.len().min(62 - len)].trim_end_matches('-'),
            &hex[24 - len..]
        );
        if !used.contains(&candidate) {
            return candidate;
        }
    }
    for serial in 2.. {
        let candidate = format!("forward-{hex}-{serial}");
        if !used.contains(&candidate) {
            return candidate;
        }
    }
    unreachable!()
}

// New profiles reserve these fields before they become active. Catalog reads
// also backfill legacy records and replace addresses retired by pool migration.
pub(crate) async fn ensure_identity(
    app: &App,
    owner: ObjectId,
    row: &Document,
    ranges: &[crate::domain::enrollment::Network],
) -> ApiResult<(String, String)> {
    fn current(
        row: &Document,
        ranges: &[crate::domain::enrollment::Network],
    ) -> Option<(String, String)> {
        let label = row.get_str("dns_label").ok()?;
        let ip = row.get_str("private_ip").ok()?.parse().ok()?;
        ranges
            .iter()
            .any(|r| r.contains(ip))
            .then(|| (label.to_owned(), ip.to_string()))
    }
    if let Some(identity) = current(row, ranges) {
        return Ok(identity);
    }
    let id = row.get_object_id("_id").map_err(|_| denied())?;
    let filter = doc! {"_id":id,"workspace_id":owner,"state":{"$in":["active","provisioning"]}};
    let _guard = app.private_network_lock.lock().await;
    #[cfg(feature = "private-sparse")]
    let _workspace = crate::private_renumber::fence::stable_with_allocation(app, owner).await?;
    let refreshed = app
        .collection(COLLECTION)
        .find_one(filter.clone())
        .projection(doc! {"private_ip":1,"dns_label":1,"name":1})
        .await?
        .ok_or_else(denied)?;
    let network = crate::domain::private_networks::ensure_locked(app, &owner.to_hex()).await?;
    if let Some(identity) = current(
        &refreshed,
        &crate::domain::private_networks::pools(&network)?,
    ) {
        return Ok(identity);
    }
    let label = if let Ok(label) = refreshed.get_str("dns_label") {
        label.to_owned()
    } else {
        let used = app
            .collection(COLLECTION)
            .distinct("dns_label", doc! {"workspace_id":owner})
            .await?
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        choose_label(&refreshed, id, &used)
    };
    let occupied = app
        .collection("private_peers")
        .distinct("ip", doc! {"workspace_id":owner})
        .await?
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect();
    let ip = crate::domain::private_networks::allocate_locked(
        app,
        &owner.to_hex(),
        &format!("forward-{id}"),
        &occupied,
    )
    .await?;
    if app
        .collection(COLLECTION)
        .update_one(filter, doc! {"$set":{"private_ip":&ip,"dns_label":&label}})
        .await?
        .matched_count
        != 1
    {
        return Err(denied());
    }
    Ok((label, ip))
}

async fn config(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<impl axum::response::IntoResponse> {
    let peer = Peer::authenticate(&app, &headers).await?;
    let network = app
        .collection("private_networks")
        .find_one(doc! {"_id":peer.owner.to_hex()})
        .await?
        .unwrap_or_default();
    let (_, suffix) = crate::domain::enrollment::preferences(&network)?;
    let network_ranges = crate::domain::private_networks::pools(&network)?;
    let host_capable = headers
        .get("x-porthub-host-forwards")
        .and_then(|v| v.to_str().ok())
        == Some("1");
    let rows = app
        .collection(COLLECTION)
        .find(peer.filter())
        .projection(doc! {"_id":1,"mappings":1,"private_ip":1,"dns_label":1,"name":1})
        .sort(doc! {"_id":1})
        .await?;
    let mut rows = rows;
    let mut descriptors = Vec::<Value>::new();
    let mut hosts = Vec::new();
    while let Some(row) = rows.try_next().await? {
        let Ok(id) = row.get_object_id("_id") else {
            continue;
        };
        let host = format!("{id}.forwards.{suffix}");
        let mut ports = Vec::new();
        let mut dynamic = false;
        for item in mappings(&row).map_err(|_| denied())? {
            match item.get_str("direction") {
                Ok("remote") => {
                    let port = number(item, "gatewayPort").map_err(|_| denied())?;
                    ports.push(port);
                    descriptors.push(json!({"entryId":id.to_hex(),"host":host,"port":port}));
                }
                Ok("host") => dynamic = true,
                _ => {}
            }
        }
        if host_capable && (dynamic || !ports.is_empty()) {
            let (label, ip) = ensure_identity(&app, peer.owner, &row, &network_ranges).await?;
            let host = format!("{label}.forwards.{suffix}");
            hosts.push(json!({"entryId":id.to_hex(),"host":host,"address":ip,"ports":ports}));
        }
    }
    if !peer.current(&app) {
        return Err(denied());
    }
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(if host_capable {
            json!({"forwards":descriptors,"hosts":hosts})
        } else {
            json!({"forwards":descriptors})
        }),
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
    connect_selected(app, id, port, false, headers, ws).await
}
async fn connect_host(
    State(app): State<Arc<App>>,
    Path((id, port)): Path<(String, u16)>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    connect_selected(app, id, port, true, headers, ws).await
}
async fn connect_selected(
    app: Arc<App>,
    id: String,
    port: u16,
    host_mode: bool,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    if port == 0 {
        return Err(denied());
    }
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
    let gateway = selected_gateway(&app, &peer, id, port, host_mode)
        .await?
        .ok_or_else(denied)?;
    if !peer.current(&app) || changes.has_changed().unwrap_or(true) {
        return Err(denied());
    }
    let grant = app
        .forward_registry
        .get(&id.to_hex())
        .filter(|g| g.is_listening(gateway))
        .ok_or_else(denied)?;
    Ok(ws
        .max_message_size(65536)
        .max_frame_size(65536)
        .on_upgrade(move |ws| serve(app, peer, grant, id, port, gateway, host_mode, changes, ws)))
}
async fn selected_gateway(
    app: &App,
    peer: &Peer,
    id: ObjectId,
    port: u16,
    host_mode: bool,
) -> ApiResult<Option<u16>> {
    let mut filter = peer.filter();
    let mapping = if host_mode {
        doc! {"direction":"host"}
    } else {
        doc! {"direction":"remote","gatewayPort":i32::from(port)}
    };
    filter.extend(doc! {"_id":id,"mappings":{"$elemMatch":mapping}});
    let Some(row) = app
        .collection(COLLECTION)
        .find_one(filter)
        .projection(doc! {"mappings":1})
        .await?
    else {
        return Ok(None);
    };
    if !host_mode {
        return Ok(Some(port));
    }
    let maps = mappings(&row).map_err(|_| denied())?;
    match maps.as_slice() {
        [m] if m.get_str("direction") == Ok("host") => {
            Ok(Some(number(m, "gatewayPort").map_err(|_| denied())?))
        }
        _ => Err(denied()),
    }
}
struct StreamScope<'a> {
    app: &'a App,
    peer: &'a Peer,
    id: ObjectId,
    port: u16,
    gateway: u16,
    host_mode: bool,
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
                || selected_gateway(self.app, &peer, self.id, self.port, self.host_mode)
                    .await
                    .map_err(|_| ())?
                    != Some(self.gateway)
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
    gateway: u16,
    host_mode: bool,
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
        gateway,
        host_mode,
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
        let ssh = async {
            if host_mode {
                grant.forward_host(gateway, port, local).await
            } else {
                grant.forward(port, local).await
            }
        };
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
    #[test]
    fn profile_dns_labels_are_stable_and_leave_identity_aliases_reserved() {
        let id = ObjectId::parse_str("0123456789abcdef12345678").unwrap();
        let profile = doc! {"name":"Lab notebook"};
        let mut used = HashSet::new();
        assert_eq!(choose_label(&profile, id, &used), "lab-notebook");
        used.insert("lab-notebook".to_string());
        assert_eq!(choose_label(&profile, id, &used), "lab-notebook-5678");
        used.insert("lab-notebook-5678".to_string());
        assert_eq!(choose_label(&profile, id, &used), "lab-notebook-45678");
        let ambiguous = doc! {"name":id.to_hex()};
        assert_ne!(choose_label(&ambiguous, id, &used), id.to_hex());
    }

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
        let app = Arc::new(App::new(Default::default(), db.clone()));
        let result=async {
            let (owner,machine,group,id)=(ObjectId::new(),ObjectId::new(),ObjectId::new(),ObjectId::new());
            let peer_id=format!("{owner}:{machine}");let token="test-only-private-credential";let instance="unit-private-owner";
            let hash=crate::domain::workspaces::token_digest(token);
            app.collection("users").insert_one(doc!{"_id":owner}).await?;
            app.collection("machine_groups").insert_one(doc!{"_id":group,"user_id":owner}).await?;
            app.collection("machines").insert_one(doc!{"_id":machine,"user_id":owner,"group_ids":[group]}).await?;
            app.collection("private_peers").insert_one(doc!{"_id":&peer_id,"workspace_id":owner,"owner_id":owner,"machine_id":machine,"enabled":true,"credential_hash":&hash}).await?;
            app.collection(COLLECTION).insert_one(doc!{"_id":id,"workspace_id":owner,"public":false,"state":"active","group_ids":[group],"mappings":[{"direction":"remote","gatewayPort":13456}]}).await?;
            assert!(app.private_relay.workspace_generation(&owner.to_hex(),0,false));
            let admitted=app.private_relay.begin_workspace_admission(&peer_id,&hash,instance,&owner.to_hex());
            assert!(admitted.is_some());
            assert!(!app.private_relay.publish_admitted(&peer_id,&hash,instance,"10.203.0.4".parse()?,Default::default(),admitted).is_empty());
            let mut headers=HeaderMap::new();
            headers.insert("authorization",format!("Bearer {token}").parse()?);
            headers.insert("x-porthub-peer",peer_id.parse()?);
            headers.insert("x-porthub-instance",instance.parse()?);
            let peer=Peer::authenticate(&app,&headers).await.map_err(api)?;
            assert_eq!(selected_gateway(&app,&peer,id,13456,false).await.map_err(api)?,Some(13456));
            assert_eq!(selected_gateway(&app,&peer,id,13455,false).await.map_err(api)?,None);
            // An old agent may see explicit mappings only. The host endpoint
            // resolves every requested port to the one authorized SSH listener.
            let dynamic = ObjectId::new();
            app.collection(COLLECTION).insert_one(doc!{"_id":dynamic,"name":"Lab notebook","workspace_id":owner,"public":false,"state":"active","group_ids":[group],"mappings":[{"direction":"host","gatewayPort":24000}]}).await?;
            assert_eq!(selected_gateway(&app,&peer,id,8888,true).await.map_err(api)?,None);
            assert_eq!(selected_gateway(&app,&peer,dynamic,8888,true).await.map_err(api)?,Some(24000));
            assert_eq!(selected_gateway(&app,&peer,dynamic,24000,false).await.map_err(api)?,None);
            use axum::response::IntoResponse;
            async fn catalog(app:&Arc<App>,headers:HeaderMap) -> Result<Value> {
                let response=config(State(app.clone()),headers).await.map_err(api)?.into_response();
                Ok(serde_json::from_slice(&axum::body::to_bytes(response.into_body(),65536).await?)?)
            }
            let legacy=catalog(&app,headers.clone()).await?;
            assert!(legacy.get("hosts").is_none());
            assert_eq!(legacy["forwards"].as_array().unwrap().len(),1);
            let mut v2=headers.clone();
            v2.insert("x-porthub-host-forwards","1".parse()?);
            let first=catalog(&app,v2.clone()).await?;
            let descriptors=first["hosts"].as_array().unwrap();
            assert_eq!(descriptors.len(),2);
            let host=descriptors.iter().find(|h|h["entryId"]==dynamic.to_hex()).unwrap();
            assert_eq!(host["host"],"lab-notebook.forwards.phub");
            assert_eq!(host["ports"],json!([]));
            let fixed=descriptors.iter().find(|h|h["entryId"]==id.to_hex()).unwrap();
            assert_eq!(fixed["ports"],json!([13456]));
            assert_ne!(host["address"],fixed["address"]);
            // Reusing the identical allocation seed cannot hand a reserved
            // profile address to a regular enrolled machine.
            let candidate=crate::domain::private_networks::allocate_locked(&app,&owner.to_hex(),&format!("forward-{dynamic}"),&HashSet::new()).await.map_err(api)?;
            assert_ne!(host["address"],candidate);
            app.collection(COLLECTION).update_one(doc!{"_id":dynamic},doc!{"$set":{"name":"Renamed"}}).await?;
            assert_eq!(catalog(&app,v2.clone()).await?["hosts"],first["hosts"]);
            let changes=app.private_changes.subscribe(owner).unwrap();
            let scope=StreamScope{app:&app,peer:&peer,id,port:13456,gateway:13456,host_mode:false,changes,confirmed:Mutex::new(uuid::Uuid::nil())};
            assert!(scope.permit().await.is_ok());
            signal(&app,owner);assert!(scope.permit().await.is_ok());
            app.collection("machines").update_one(doc!{"_id":machine},doc!{"$set":{"group_ids":Bson::Array(Vec::new())}}).await?;
            signal(&app,owner);assert!(scope.permit().await.is_err());
            assert_eq!(catalog(&app,v2).await?["hosts"],json!([]));
            let withdrawn=Peer::authenticate(&app,&headers).await.map_err(api)?;
            assert_eq!(selected_gateway(&app,&withdrawn,dynamic,8888,true).await.map_err(api)?,None);

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

#[cfg(all(test, unix))]
#[path = "private_host_test.rs"]
mod private_host_test;
