//! Verify signed per-entry access against the current owner and saved service mappings.
use crate::App;
use anyhow::{ensure, Context, Result};
use mongodb::bson::{doc, oid::ObjectId, Document};
use porthub_forward_ssh::{Authority, Dial, Grant, Master};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

impl App {
    pub async fn forward_keys(&self) -> Result<&Master> {
        self.forward_keys
            .get_or_try_init(|| async {
                let path = std::env::var_os("PORTHUB_FORWARD_SSH_MASTER")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("/data/port-forwards/master.seed"));
                tokio::task::spawn_blocking(move || Master::open(&path)).await?
            })
            .await
    }
}

/// Forwarding clients need a raw, publicly routable TCP endpoint. A TLS origin
/// explicitly configured by the operator can also carry SSH on this listener.
pub fn endpoint(app: &App) -> Result<(String, u16)> {
    let explicit = std::env::var("PORTHUB_FORWARD_SSH_ENDPOINT")
        .ok()
        .filter(|s| !s.is_empty());
    let address = if let Some(value) = explicit {
        let u = url::Url::parse(&format!("ssh://{value}"))?;
        ensure!(
            u.username().is_empty()
                && u.password().is_none()
                && u.query().is_none()
                && u.fragment().is_none()
                && (u.path().is_empty() || u.path() == "/"),
            "invalid SSH forwarding endpoint"
        );
        let port = u
            .port()
            .context("forwarding endpoint requires an explicit TCP port")?;
        (
            u.host_str()
                .context("missing forwarding endpoint host")?
                .trim_matches(['[', ']'])
                .to_owned(),
            port,
        )
    } else {
        let origin=app.config.private_relay_tls_origin.as_ref().context("forwarding SSH requires an advertised direct TLS origin or PORTHUB_FORWARD_SSH_ENDPOINT")?;
        let u = url::Url::parse(origin)?;
        (
            u.host_str()
                .context("missing direct gateway host")?
                .trim_matches(['[', ']'])
                .to_owned(),
            u.port_or_known_default()
                .context("missing direct gateway port")?,
        )
    };
    ensure!(address.1 != 0, "invalid public forwarding port");
    Ok(address)
}
fn port(d: &Document, key: &str) -> Result<u16> {
    let value = d.get_i32(key).map(i64::from).or_else(|_| d.get_i64(key))?;
    let n = u16::try_from(value)?;
    ensure!(n != 0, "zero mapping port");
    Ok(n)
}
struct Backend(Arc<App>);

async fn active(app: &App, id: ObjectId, key: &str) -> Result<Option<Document>> {
    let Some(entry) = app
        .collection("ssh_port_forwards")
        .find_one(doc! {"_id":id,"public_key":key,"state":"active"})
        .await?
    else {
        return Ok(None);
    };
    let owner = entry.get_object_id("workspace_id")?;
    if app
        .collection("users")
        .find_one(doc! {"_id":owner,"account_deletion":{"$exists":false}})
        .projection(doc! {"_id":1})
        .await?
        .is_none()
    {
        return Ok(None);
    }
    Ok(Some(entry))
}

type ImportRoutes = HashMap<(String, u16), String>;
fn saved_routes(entry: &Document) -> Result<(ImportRoutes, HashSet<u16>)> {
    let mut local = HashMap::new();
    let mut remote = HashSet::new();
    for (index, mapping) in entry.get_array("mappings")?.iter().enumerate() {
        let d = mapping
            .as_document()
            .context("invalid forwarding mapping")?;
        match d.get_str("direction")? {
            "remote" => {
                ensure!(
                    remote.insert(port(d, "gatewayPort")?),
                    "duplicate remote binding"
                );
            }
            "local" => {
                let machine = d.get_str("machineId")?;
                ensure!(
                    porthub_forward_ssh::valid_id(machine),
                    "invalid registered machine reference"
                );
                let alias = format!("host-{machine}");
                ensure!(
                    alias == d.get_str("target")?,
                    "stored target differs from registered machine"
                );
                local
                    .entry((alias, port(d, "servicePort")?))
                    .or_insert_with(|| index.to_string());
            }
            _ => anyhow::bail!("invalid forwarding direction"),
        }
    }
    Ok((local, remote))
}
#[cfg(test)]
#[test]
fn two_client_ports_can_import_one_pinned_service() -> Result<()> {
    let machine = "1234567890abcdef12345678";
    let target = format!("host-{machine}");
    let route = |local_port| doc! {"direction":"local","machineId":machine,"target":&target,"servicePort":22,"clientPort":local_port};
    let (imports, exports) = saved_routes(&doc! {"mappings":[route(12001i32),route(12002i32)]})?;
    assert_eq!(imports, HashMap::from([((target, 22), "0".into())]));
    assert!(exports.is_empty());
    Ok(())
}

#[porthub_forward_ssh::async_trait]
impl Authority for Backend {
    async fn authorize(&self, id: &str, key: &str) -> Result<Option<Arc<Grant>>> {
        let oid = ObjectId::parse_str(id)?;
        let Some(entry) = active(&self.0, oid, key).await? else {
            return Ok(None);
        };
        let owner = entry.get_object_id("workspace_id")?.to_hex();
        let (local, remote) = saved_routes(&entry)?;
        let (tx, mut requests) = mpsc::channel::<Dial>(32);
        let grant = Grant::new(local, remote, tx)?;
        // A write may have retired the entry while the initial read was in flight.
        let current = active(&self.0, oid, key).await?;
        if !current.is_some_and(|d| {
            d.get("workspace_id") == entry.get("workspace_id")
                && d.get("mappings") == entry.get("mappings")
        }) {
            return Ok(None);
        }
        let app = self.0.clone();
        let saved_owner = entry.get_object_id("workspace_id")?;
        let saved_mappings = entry.get_array("mappings")?.clone();
        let entry = id.to_owned();
        let stop = grant.cancel.clone();
        let signed = key.to_owned();
        tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            // Local removal cancels immediately. This bound also retires credentials
            // removed on another writer or with a disconnected control channel.
            let mut review = tokio::time::interval_at(
                tokio::time::Instant::now() + Duration::from_secs(5),
                Duration::from_secs(5),
            );
            review.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {biased;
                   _=stop.cancelled()=>break,
                   _=review.tick()=>{
                     if !matches!(tokio::time::timeout(Duration::from_secs(3),active(&app,oid,&signed)).await,Ok(Ok(Some(d))) if d.get_object_id("workspace_id").ok()==Some(saved_owner) && d.get_array("mappings").ok()==Some(&saved_mappings)){stop.cancel();break;}
                   }
                   Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
                   request=requests.recv()=>{
                     let Some(request)=request else{break};
                     let (app,owner,entry)=(app.clone(),owner.clone(),entry.clone());
                     tasks.spawn(async move{if let Ok(Ok(stream))=tokio::time::timeout(Duration::from_secs(8),crate::port_forward_bridge::open_import(&app,&owner,&entry,&request.service)).await {let _=request.stream.send(stream);}});
                   }
                }
            }
        });
        Ok(Some(grant))
    }
}

#[cfg(unix)]
pub async fn listen(
    app: Arc<App>,
    socket: &Path,
    mut stopping: watch::Receiver<bool>,
) -> Result<()> {
    let master = app.forward_keys().await?;
    let (listener, _lease) = porthub_runtime::socket::bind(socket).await?;
    let stop = CancellationToken::new();
    let _shutdown = stop.clone().drop_guard();
    let mut sessions = tokio::task::JoinSet::new();
    let backend = Arc::new(Backend(app.clone()));
    loop {
        tokio::select! {biased;
          _=stopping.changed()=>break,
          Some(_)=sessions.join_next(),if !sessions.is_empty()=>{},
          accepted=listener.accept()=>{
           let(stream,_)=accepted?;
           if sessions.len()>=128{drop(stream);continue;}
           let (app,registry,auth,stop)=(app.clone(),app.forward_registry.clone(),backend.clone(),stop.clone());
           sessions.spawn(async move{if let Ok(master)=app.forward_keys().await{let _=porthub_forward_ssh::serve(stream,master,registry,auth,stop).await;}});
          }
        }
    }
    let _ = master;
    stop.cancel();
    while sessions.join_next().await.is_some() {}
    Ok(())
}
