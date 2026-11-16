//! Indexed sparse control helpers. Cached directory names never confer membership or ACL authority.
use crate::domain::private_rule_index::Index;
use crate::{
    domain::{private_domains, private_names},
    error::{ApiError, ApiResult},
    store, App,
};
use futures_util::TryStreamExt;
use mongodb::{
    bson::{doc, oid::ObjectId, DateTime, Document},
    IndexModel,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc, time::Instant};
use tokio::sync::{Mutex, OnceCell};

#[derive(Default)]
pub struct State {
    directory: Mutex<()>,
    indices: OnceCell<()>,
    rules: Mutex<HashMap<String, (Arc<Index>, Instant)>>,
}
pub struct Rules {
    pub index: Arc<Index>,
    pub manifest: Vec<Document>,
}
async fn manifest(app: &App, owner: ObjectId) -> ApiResult<Vec<Document>> {
    let rows: Vec<_> = app
        .collection("access_rulebooks")
        .find(doc! {"user_id":owner})
        .projection(doc! {"user_id":1,"revision":1,"enabled":1,"group_id":1,"updated_at":1})
        .hint(mongodb::options::Hint::Keys(
            doc! {"user_id":1,"_id":1,"revision":1,"enabled":1,"group_id":1,"updated_at":1},
        ))
        .sort(doc! {"_id":1})
        .limit(101)
        .await?
        .try_collect()
        .await?;
    if rows.len() > 100 {
        return Err(ApiError::bad_request(
            "Private rule-book count exceeds supported budget",
        ));
    }
    Ok(rows)
}
fn stamp(rows: &[Document]) -> String {
    format!(
        "{:x}",
        Sha256::digest(mongodb::bson::to_vec(&doc! {"books":rows}).expect("typed rule manifest"))
    )
}
pub async fn rules(app: &App, owner: ObjectId) -> ApiResult<Rules> {
    let rows = manifest(app, owner).await?;
    let signature = stamp(&rows);
    let cacheable = rows
        .iter()
        .all(|r| r.get_i64("revision").is_ok_and(|v| v > 0));
    if cacheable {
        let mut cache = app.private_sparse.rules.lock().await;
        if let Some((index, used)) = cache.get_mut(&signature) {
            *used = Instant::now();
            return Ok(Rules {
                index: index.clone(),
                manifest: rows,
            });
        }
    }
    let mut cursor = app
        .collection("access_rulebooks")
        .find(doc! {"user_id":owner})
        .projection(
            doc! {"user_id":1,"revision":1,"enabled":1,"group_id":1,"updated_at":1,"rules":1},
        )
        .sort(doc! {"_id":1})
        .batch_size(4)
        .limit(101)
        .await?;
    let mut books = Vec::new();
    let mut bytes = 0usize;
    while let Some(row) = cursor.try_next().await? {
        bytes += mongodb::bson::to_vec(&row)
            .map_err(|_| ApiError::bad_request("Invalid rule book"))?
            .len();
        if bytes > 4 * 1024 * 1024 || books.len() >= 100 {
            return Err(ApiError::bad_request(
                "Private rule definition bytes exceed resource budget",
            ));
        }
        books.push(store::document(&row));
    }
    let index = Arc::new(Index::compile(&books)?);
    if stamp(&manifest(app, owner).await?) != signature {
        return Err(ApiError::bad_request(
            "Private rules changed while compiling; retry discovery",
        ));
    }
    if cacheable {
        let mut cache = app.private_sparse.rules.lock().await;
        while cache.len() >= 64
            || cache.values().map(|(i, _)| i.weight_bytes()).sum::<usize>() + index.weight_bytes()
                > 32 * 1024 * 1024
        {
            let Some(old) = cache
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            cache.remove(&old);
        }
        cache.insert(signature, (index.clone(), Instant::now()));
    }
    Ok(Rules {
        index,
        manifest: rows,
    })
}
pub async fn verify_rules(app: &App, owner: ObjectId, rules: &Rules) -> ApiResult<()> {
    if stamp(&manifest(app, owner).await?) != stamp(&rules.manifest) {
        return Err(ApiError::bad_request(
            "Private authorization changed; retry discovery",
        ));
    }
    Ok(())
}
fn bson_id(value: &str) -> mongodb::bson::Bson {
    ObjectId::parse_str(value)
        .map(mongodb::bson::Bson::ObjectId)
        .unwrap_or_else(|_| mongodb::bson::Bson::String(value.into()))
}
/// Fresh index-only membership decisions. Never fetch an N-member user_ids array into a sync response/cache.
pub async fn groups(
    app: &App,
    owner: ObjectId,
    index: &Index,
    owners: &[String],
) -> ApiResult<HashMap<String, Value>> {
    let ids: Vec<_> = index.referenced_groups().map(bson_id).collect();
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<_> = app
        .collection("machine_groups")
        .find(doc! {"user_id":owner,"_id":{"$in":&ids}})
        .projection(doc! {"_id":1})
        .hint(mongodb::options::Hint::Keys(doc! {"user_id":1,"_id":1}))
        .await?
        .try_collect()
        .await?;
    let mut result: HashMap<_, _> = rows
        .iter()
        .map(|r| {
            (
                store::id(r.get("_id")),
                json!({"_id":store::id(r.get("_id")),"user_ids":[]}),
            )
        })
        .collect();
    for member in owners.iter().collect::<std::collections::BTreeSet<_>>() {
        let values = vec![
            bson_id(member),
            mongodb::bson::Bson::String(member.to_string()),
        ];
        let matches: Vec<_> = app
            .collection("machine_groups")
            .find(doc! {"user_id":owner,"_id":{"$in":&ids},"user_ids":{"$in":values}})
            .projection(doc! {"_id":1})
            .hint(mongodb::options::Hint::Keys(
                doc! {"user_id":1,"user_ids":1,"_id":1},
            ))
            .await?
            .try_collect()
            .await?;
        for row in matches {
            if let Some(group) = result.get_mut(&store::id(row.get("_id"))) {
                group["user_ids"]
                    .as_array_mut()
                    .expect("typed memberships")
                    .push(json!(member));
            }
        }
    }
    Ok(result)
}

fn key(workspace: ObjectId, kind: &str, value: &str) -> String {
    format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&json!([workspace.to_hex(), kind, value])).expect("directory key")
        )
    )
}
pub fn name_digest(peer: &Document, machine: &Document, suffix: &str) -> String {
    format!("{:x}",Sha256::digest(serde_json::to_vec(&json!({"peer":store::id(peer.get("_id")),"hostname":store::field(peer,"hostname"),"machine":store::id(machine.get("_id")),"name":store::field(machine,"name"),"aliases":store::field(machine,"aliases"),"private_domains":store::field(machine,"private_domains"),"suffix":suffix})).expect("directory metadata")))
}
pub async fn indices(app: &App) -> ApiResult<()> {
    app.private_sparse
        .indices
        .get_or_try_init(|| async {
            for (collection, keys) in [
                ("private_peers", doc! {"workspace_id":1,"ip":1}),
                (
                    "private_name_directory",
                    doc! {"workspace_id":1,"kind":1,"name":1},
                ),
                ("machine_groups", doc! {"user_id":1,"user_ids":1,"_id":1}),
                ("machine_groups", doc! {"user_id":1,"_id":1}),
                (
                    "access_rulebooks",
                    doc! {"user_id":1,"_id":1,"revision":1,"enabled":1,"group_id":1,"updated_at":1},
                ),
                (
                    "workspace_members",
                    doc! {"workspace_id":1,"user_id":1,"role":1},
                ),
            ] {
                app.collection(collection)
                    .create_index(IndexModel::builder().keys(keys).options(if collection=="private_peers"{Some(mongodb::options::IndexOptions::builder().unique(true).build())}else{None}).build())
                    .await?;
            }
            Ok::<_, ApiError>(())
        })
        .await?;
    Ok(())
}
async fn marker(
    app: &App,
    owner: ObjectId,
    suffix: &str,
    max_age: i64,
) -> ApiResult<Option<Document>> {
    let value = app
        .collection("private_name_directory_state")
        .find_one(doc! {"_id":owner.to_hex(),"ready":true,"suffix":suffix})
        .await?;
    Ok(value.filter(|d| {
        d.get_datetime("updated_at").is_ok_and(|t| {
            (0..max_age).contains(&(DateTime::now().timestamp_millis() - t.timestamp_millis()))
        })
    }))
}
async fn peer_record(
    app: &App,
    owner: ObjectId,
    id: &str,
    generation: &str,
) -> ApiResult<Option<Document>> {
    Ok(app
        .collection("private_name_directory")
        .find_one(doc! {"_id":key(owner,"peer",id),"generation":generation})
        .await?)
}
/// Rare whole-namespace materialization, never a per-client authorization cache.
/// Initial bootstrap and name changes are O(directory size); ordinary sync/lookup uses indexes.
pub async fn directory(
    app: &App,
    owner: ObjectId,
    own: &Document,
    machine: &Document,
    suffix: &str,
) -> ApiResult<Document> {
    directory_with_age(app, owner, own, machine, suffix, 30_000).await
}
pub async fn directory_on_miss(
    app: &App,
    owner: ObjectId,
    own: &Document,
    machine: &Document,
    suffix: &str,
) -> ApiResult<Document> {
    directory_with_age(app, owner, own, machine, suffix, 5_000).await
}
async fn directory_with_age(
    app: &App,
    owner: ObjectId,
    own: &Document,
    machine: &Document,
    suffix: &str,
    max_age: i64,
) -> ApiResult<Document> {
    indices(app).await?;
    let digest = name_digest(own, machine, suffix);
    let id = store::string(own, "_id");
    if let Some(state) = marker(app, owner, suffix, max_age).await? {
        if let Some(record) =
            peer_record(app, owner, id, store::string(&state, "generation")).await?
        {
            if store::string(&record, "metadata") == digest {
                return Ok(state);
            }
        }
    }
    let _guard = app.private_sparse.directory.lock().await;
    if let Some(state) = marker(app, owner, suffix, max_age).await? {
        if let Some(record) =
            peer_record(app, owner, id, store::string(&state, "generation")).await?
        {
            if store::string(&record, "metadata") == digest {
                return Ok(state);
            }
        }
    }
    let generation = uuid::Uuid::new_v4().simple().to_string();
    app.collection("private_name_directory_state")
        .update_one(
            doc! {"_id":owner.to_hex()},
            doc! {"$set":{"ready":false,"generation":&generation,"suffix":suffix}},
        )
        .upsert(true)
        .await?;
    let mut cursor = app
        .collection("private_peers")
        .find(doc! {"workspace_id":owner})
        .projection(doc! {"machine_id":1,"created_at":1,"hostname":1})
        .batch_size(128)
        .limit(65537)
        .await?;
    let mut peers = Vec::new();
    let mut bytes = 0usize;
    while let Some(row) = cursor.try_next().await? {
        bytes += mongodb::bson::to_vec(&row)
            .map_err(|_| ApiError::bad_request("Invalid directory record"))?
            .len();
        if peers.len() >= 65536 || bytes > 32 * 1024 * 1024 {
            return Err(ApiError::bad_request(
                "Private DNS directory exceeds bootstrap resource budget",
            ));
        }
        peers.push(row);
    }
    let ids: Vec<_> = peers
        .iter()
        .filter_map(|p| p.get("machine_id").cloned())
        .collect();
    let mut cursor = app
        .collection("machines")
        .find(doc! {"$or":[{"user_id":owner},{"_id":{"$in":ids}}],"deletion_pending":{"$ne":true}})
        .projection(doc! {"name":1,"aliases":1,"private_domains":1})
        .batch_size(64)
        .limit(65537)
        .await?;
    let mut machines = Vec::new();
    while let Some(row) = cursor.try_next().await? {
        bytes += mongodb::bson::to_vec(&row)
            .map_err(|_| ApiError::bad_request("Invalid directory machine"))?
            .len();
        if machines.len() >= 65536 || bytes > 32 * 1024 * 1024 {
            return Err(ApiError::bad_request(
                "Private DNS directory metadata exceeds resource budget",
            ));
        }
        machines.push(row);
    }
    let names = private_names::assign(&machines, &peers);
    let by_id: std::collections::HashMap<_, _> = machines
        .iter()
        .map(|m| (store::id(m.get("_id")), m))
        .collect();
    app.collection("private_name_directory")
        .delete_many(doc! {"workspace_id":owner})
        .await?;
    let mut batch = Vec::new();
    let mut count = 0usize;
    for peer in &peers {
        let before_batch = batch.len();
        let id = store::string(peer, "_id");
        let Some(machine) = by_id.get(&store::id(peer.get("machine_id"))) else {
            continue;
        };
        let primary = names
            .primary
            .get(id)
            .cloned()
            .unwrap_or_else(|| "machine".into());
        let aliases = names.aliases.get(id).cloned().unwrap_or_default();
        let metadata = name_digest(peer, machine, suffix);
        batch.push(doc!{"_id":key(owner,"peer",id),"workspace_id":owner,"kind":"peer","peer":id,"metadata":&metadata,"primary":&primary,"aliases":&aliases,"generation":&generation});
        let mut full = vec![format!("{primary}.{suffix}")];
        full.extend(aliases.iter().map(|a| format!("{a}.{suffix}")));
        full.extend(
            private_domains::from_document(machine)
                .into_iter()
                .filter(|d| !d.default)
                .map(|d| format!("{}.{}", d.host, d.suffix)),
        );
        full.sort();
        full.dedup();
        for name in full {
            batch.push(doc!{"_id":key(owner,"name",&name.to_ascii_lowercase()),"workspace_id":owner,"kind":"name","name":name.to_ascii_lowercase(),"peer":id,"metadata":&metadata,"generation":&generation});
        }
        count += batch.len() - before_batch;
        if count > 262144 {
            return Err(ApiError::bad_request(
                "Private DNS directory name budget exceeded",
            ));
        }
        if batch.len() >= 256 {
            app.collection("private_name_directory")
                .insert_many(std::mem::take(&mut batch))
                .await?;
        }
    }
    if !batch.is_empty() {
        app.collection("private_name_directory")
            .insert_many(batch)
            .await?;
    }
    let at = DateTime::now();
    app.collection("private_name_directory_state")
        .update_one(
            doc! {"_id":owner.to_hex(),"generation":&generation},
            doc! {"$set":{"ready":true,"updated_at":at}},
        )
        .await?;
    Ok(
        doc! {"_id":owner.to_hex(),"generation":generation,"ready":true,"suffix":suffix,"updated_at":at},
    )
}
pub async fn names(
    app: &App,
    owner: ObjectId,
    peers: &[Document],
    generation: &str,
) -> ApiResult<private_names::Names> {
    let mut primary = std::collections::HashMap::new();
    let mut aliases = std::collections::HashMap::new();
    for peer in peers {
        let id = store::string(peer, "_id");
        let record = peer_record(app, owner, id, generation)
            .await?
            .ok_or_else(|| {
                ApiError::bad_request("Private DNS directory changed; retry discovery")
            })?;
        primary.insert(id.into(), store::string(&record, "primary").into());
        aliases.insert(
            id.into(),
            record
                .get_array("aliases")
                .ok()
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect(),
        );
    }
    Ok(private_names::Names { primary, aliases })
}
pub async fn name_peer(
    app: &App,
    owner: ObjectId,
    name: &str,
    generation: &str,
) -> ApiResult<Option<String>> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let record = app
        .collection("private_name_directory")
        .find_one(doc! {"_id":key(owner,"name",&name),"generation":generation})
        .await?;
    Ok(record.map(|d| store::string(&d, "peer").to_owned()))
}

pub struct Selection {
    pub peers: Vec<Document>,
    pub inventory: HashMap<String, Document>,
    pub names: private_names::Names,
    pub prefs: Document,
    pub suffix: String,
    pub generation: String,
}
async fn machine(app: &App, workspace: ObjectId, peer: &Document) -> ApiResult<Option<Document>> {
    use mongodb::bson::Bson;
    let owner = store::id(peer.get("owner_id"));
    let Ok(owner_id) = ObjectId::parse_str(&owner) else {
        return Ok(None);
    };
    let actors = if owner_id == workspace {
        vec![workspace]
    } else {
        vec![workspace, owner_id]
    };
    let active = app
        .collection("users")
        .count_documents(doc! {"_id":{"$in":&actors},"account_deletion":{"$exists":false}})
        .await?;
    if active != actors.len() as u64 {
        return Ok(None);
    }
    if owner_id!=workspace && app.collection("workspace_members").find_one(doc!{"workspace_id":workspace,"user_id":{"$in":[Bson::ObjectId(owner_id),Bson::String(owner)]},"role":{"$in":["member","admin"]}}).projection(doc!{"_id":1}).await?.is_none(){return Ok(None);}
    Ok(app.collection("machines").find_one(doc!{"_id":peer.get("machine_id"),"user_id":peer.get("owner_id"),"enabled":{"$ne":false},"deletion_pending":{"$ne":true},"private_owner_revoked":{"$ne":true}}).projection(doc!{"user_id":1,"private_owner_id":1,"private_owner_revoked":1,"enabled":1,"group_ids":1,"group_id":1,"name":1,"aliases":1,"private_domains":1}).await?)
}
/// Bounded identity selection: no whole-workspace inventory on an ordinary sparse sync.
/// Returned directory metadata is naming only; every selected peer/member/machine is freshly authenticated.
pub async fn select(
    app: &App,
    owner: ObjectId,
    own: &Document,
    request: &crate::domain::private_pairs::Request,
) -> ApiResult<Selection> {
    use axum::http::StatusCode;
    let own_machine = machine(app, owner, own).await?.ok_or_else(|| {
        ApiError::new(
            StatusCode::FORBIDDEN,
            "Machine or workspace membership is disabled",
        )
    })?;
    let prefs = app
        .collection("private_networks")
        .find_one(doc! {"_id":owner.to_hex()})
        .await?
        .unwrap_or_default();
    let (_, suffix) = crate::domain::enrollment::preferences(&prefs)?;
    let mut state = directory(app, owner, own, &own_machine, &suffix).await?;
    let mut selected = vec![own.clone()];
    let mut inventory = HashMap::from([(store::id(own.get("machine_id")), own_machine.clone())]);
    let mut seen = std::collections::HashSet::from([store::id(own.get("_id"))]);
    let mut wanted = request.wanted.clone();
    for id in app
        .private_relay
        .pair_neighbors(store::string(own, "_id"))
        .into_iter()
        .take(16)
    {
        if wanted.len() >= 32 {
            break;
        }
        wanted.push(crate::domain::private_pairs::Lookup {
            kind: "peer".into(),
            value: id,
        });
    }
    for query in wanted {
        let mut filter = doc! {"workspace_id":owner,"enabled":true};
        match query.kind.as_str() {
            "peer" => {
                filter.insert("_id", &query.value);
            }
            "ip" => {
                filter.insert("ip", &query.value);
            }
            "name" => {
                let mut target = name_peer(
                    app,
                    owner,
                    &query.value,
                    store::string(&state, "generation"),
                )
                .await?;
                if target.is_none() {
                    state = directory_on_miss(app, owner, own, &own_machine, &suffix).await?;
                    target = name_peer(
                        app,
                        owner,
                        &query.value,
                        store::string(&state, "generation"),
                    )
                    .await?;
                }
                let Some(target) = target else {
                    continue;
                };
                filter.insert("_id", target);
            }
            _ => continue,
        }
        let rows: Vec<_> = app
            .collection("private_peers")
            .find(filter)
            .limit(2)
            .await?
            .try_collect()
            .await?;
        if rows.len() != 1 {
            continue;
        }
        let peer = &rows[0];
        let id = store::id(peer.get("_id"));
        if seen.contains(&id) {
            continue;
        }
        let Some(current) = machine(app, owner, peer).await? else {
            continue;
        };
        let mut record = peer_record(app, owner, &id, store::string(&state, "generation")).await?;
        if record
            .as_ref()
            .is_none_or(|r| store::string(r, "metadata") != name_digest(peer, &current, &suffix))
        {
            state = directory_on_miss(app, owner, own, &own_machine, &suffix).await?;
            record = peer_record(app, owner, &id, store::string(&state, "generation")).await?;
        }
        if record
            .as_ref()
            .is_none_or(|r| store::string(r, "metadata") != name_digest(peer, &current, &suffix))
        {
            continue;
        }
        // A rebuilt namespace may have assigned a query to another identity. Never answer its old binding.
        if query.kind == "name"
            && name_peer(
                app,
                owner,
                &query.value,
                store::string(&state, "generation"),
            )
            .await?
            .as_deref()
                != Some(&id)
        {
            continue;
        }
        inventory.insert(store::id(peer.get("machine_id")), current);
        seen.insert(id);
        selected.push(peer.clone());
    }
    let generation = store::string(&state, "generation").to_owned();
    let names = names(app, owner, &selected, &generation).await?;
    if app
        .collection("private_name_directory_state")
        .find_one(doc! {"_id":owner.to_hex(),"generation":&generation,"ready":true})
        .projection(doc! {"_id":1})
        .await?
        .is_none()
    {
        return Err(ApiError::bad_request(
            "Private directory changed; retry discovery",
        ));
    }
    Ok(Selection {
        peers: selected,
        inventory,
        names,
        prefs,
        suffix,
        generation,
    })
}
