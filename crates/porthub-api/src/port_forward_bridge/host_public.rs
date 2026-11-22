//! One public listener per explicitly published destination. Its edge owner is
//! the reservation ID, so removing one port leaves the other listeners intact.
use super::*;

#[derive(Clone, Copy)]
pub(super) struct Publication {
    owner: ObjectId,
    host: ObjectId,
    reservation: ObjectId,
    port: u16,
    destination: u16,
}
impl Publication {
    fn parse(row: &Document) -> Result<Self> {
        Ok(Self {
            owner: row.get_object_id("forward_owner")?,
            host: row.get_object_id("forward_reservation")?,
            reservation: row.get_object_id("_id")?,
            port: number(row, "external_port")?,
            destination: number(row, "host_client_port")?,
        })
    }
    pub(super) async fn authorized_listener(self, app: &App) -> Result<u16> {
        let profile = entry(app, self.owner, self.host).await?;
        let mapping = mappings(&profile)?
            .into_iter()
            .find(|m| m.get_str("direction") == Ok("host"))
            .context("Temporary host withdrawn")?;
        let active=app.collection("connections").count_documents(doc!{"_id":self.reservation,"forward_reservation":self.host,"forward_owner":self.owner,"external_port":i32::from(self.port),"host_client_port":i32::from(self.destination),"host_public_state":"active"}).await?>0;
        ensure!(active, "Public port withdrawn");
        number(mapping, "gatewayPort")
    }
    pub(super) async fn serve(self, app: &App, stream: reqwest::Upgraded) -> Result<()> {
        let listener = self.authorized_listener(app).await?;
        let grant = app
            .forward_registry
            .get(&self.host.to_hex())
            .context("Host disconnected")?;
        grant.forward_host(listener, self.destination, stream).await
    }
}

pub(crate) async fn activate(app: &Arc<App>, row: &Document) -> Result<()> {
    let p = Publication::parse(row)?;
    p.authorized_listener(app).await?;
    policy(app, p.port, true).await?;
    edge(app)
        .await?
        .post(format!("{BASE}/public/{}/{}", p.reservation, p.port))
        .timeout(Duration::from_secs(3))
        .send()
        .await?
        .error_for_status()?;
    app.forward_bridge
        .workers()
        .entry((p.reservation, p.port))
        .or_insert_with(|| {
            let stop = CancellationToken::new();
            let ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
            tokio::spawn(public_worker(
                app.clone(),
                p.owner,
                p.reservation,
                p.port,
                stop.clone(),
                ready.clone(),
                Some(p),
            ));
            Worker { stop, ready }
        });
    Ok(())
}

pub(crate) async fn withdraw(app: &App, row: &Document) -> Result<()> {
    let p = Publication::parse(row)?;
    let filter = doc! {"_id":p.reservation,"forward_owner":p.owner,"forward_reservation":p.host};
    app.collection("connections")
        .update_one(
            filter.clone(),
            doc! {"$set":{"host_public_state":"deleting"}},
        )
        .await?;
    if let Some(worker) = app
        .forward_bridge
        .workers()
        .remove(&(p.reservation, p.port))
    {
        worker.stop.cancel();
    }
    edge(app)
        .await?
        .delete(format!("{BASE}/public/{}", p.reservation))
        .timeout(Duration::from_secs(3))
        .send()
        .await?
        .error_for_status()?;
    policy(app, p.port, false).await?;
    app.collection("connections").delete_one(filter).await?;
    Ok(())
}

pub(super) async fn withdraw_all(app: &App, owner: ObjectId, id: ObjectId) -> Result<()> {
    let mut rows=app.collection("connections").find(doc!{"forward_reservation":id,"forward_owner":owner,"host_public_state":{"$exists":true}}).await?;
    while let Some(row) = rows.try_next().await? {
        withdraw(app, &row).await?;
    }
    Ok(())
}

pub(super) async fn recover(
    app: &Arc<App>,
    existing: &HashSet<(ObjectId, u16)>,
) -> Result<HashSet<(ObjectId, u16)>> {
    let _changes = app.connection_lock.lock().await;
    let mut rows = app
        .collection("connections")
        .find(doc! {"host_public_state":{"$exists":true}})
        .await?;
    let mut keep = HashSet::new();
    while let Some(row) = rows.try_next().await? {
        let p = Publication::parse(&row)?;
        if row.get_str("host_public_state")!=Ok("active") || app.collection(COLLECTION).count_documents(doc!{"_id":p.host,"workspace_id":p.owner,"state":"active","mappings.direction":"host"}).await?==0 {
            withdraw(app,&row).await?;
        } else {
            let key=(p.reservation,p.port);
            keep.insert(key);
            if !existing.contains(&key) || !app.forward_bridge.workers().contains_key(&key) { activate(app,&row).await?; }
        }
    }
    Ok(keep)
}
