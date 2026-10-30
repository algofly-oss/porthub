//! Paged browser read model for private-access workspaces. Membership is checked
//! before every query; shared workspace reads never use machine serializers
//! containing enrollment tokens or credentials.
use crate::{
    domain::{enrollment, inventory, workspaces},
    error::{ApiError, ApiResult},
    inventory_query::{conditional, search_pipeline, Params},
    store, App,
};
use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use futures_util::TryStreamExt;
use mongodb::{
    bson::{doc, oid::ObjectId, Bson, Document},
    options::{Collation, CollationStrength},
};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

fn string(expr: &str) -> Bson {
    doc! {"$convert":{"input":expr,"to":"string","onNull":"","onError":""}}.into()
}
fn names(fields: &[&str]) -> Bson {
    Bson::Array(
        fields
            .iter()
            .map(|name| string(&format!("${name}")))
            .collect(),
    )
}
fn oid(value: &str) -> ApiResult<ObjectId> {
    workspaces::object_id(value, "Invalid inventory identifier")
}
async fn members(app: &App, owner: ObjectId) -> ApiResult<(Vec<Bson>, HashMap<String, String>)> {
    let records = app
        .collection("workspace_members")
        .find(doc! {"workspace_id":owner})
        .projection(doc! {"user_id":1,"role":1})
        .await?
        .try_collect::<Vec<_>>()
        .await?;
    let mut ids = vec![Bson::ObjectId(owner)];
    let mut roles = HashMap::from([(owner.to_hex(), "owner".to_owned())]);
    for record in records {
        if let Ok(id) = record.get_object_id("user_id") {
            ids.push(Bson::ObjectId(id));
            roles.insert(id.to_hex(), store::string(&record, "role").to_owned());
        }
    }
    Ok((ids, roles))
}
fn entity_pipeline(kind: &str, owner: ObjectId, users: &[Bson]) -> Vec<Document> {
    let filter = if kind == "user" {
        doc! {"_id":{"$in":users}}
    } else {
        doc! {"user_id":owner,"deletion_pending":{"$ne":true}}
    };
    vec![
        doc! {"$match":filter},
        doc! {"$project":{"name":1,"username":1,"email":1}},
        doc! {"$set":{"_id":{"$concat":[format!("{kind}:"),{"$toString":"$_id"}]},"kind":kind,"label":{"$concat":[format!("{} · ",match kind {"machine"=>"Machine","group"=>"Group",_=>"Person"}),{"$ifNull":["$name","$username"]}]}}},
    ]
}
pub async fn page(
    app: Arc<App>,
    kind: &str,
    p: &Params,
    headers: &HeaderMap,
    user: &Document,
) -> ApiResult<Response> {
    if kind == "workspaces" {
        return accessible_workspaces(&app, p, headers, user).await;
    }
    let (owner, role) = workspaces::access(&app, user, &p.workspace, false).await?;
    if !p.account.is_empty() {
        return Err(ApiError::bad_request(
            "Use workspace scope for access inventory",
        ));
    }
    if p.detail && (p.ids.split(',').count() != 1 || p.ids.is_empty() || p.page_size != 1) {
        return Err(ApiError::bad_request(
            "Detail reads require one ID and page size 1",
        ));
    }
    let (users, roles) = members(&app, owner).await?;
    let allowed = users
        .iter()
        .map(|id| store::id(Some(id)))
        .collect::<HashSet<_>>();
    if kind == "summary" {
        let prefs = app
            .collection("private_networks")
            .find_one(doc! {"_id":owner.to_hex()})
            .projection(doc! {"cidr":1,"dns_suffix":1})
            .await?
            .unwrap_or_default();
        let (network, suffix) = enrollment::preferences(&prefs)?;
        let mut counts = serde_json::Map::new();
        for (name, collection, filter) in [
            (
                "machines",
                "machines",
                doc! {"user_id":owner,"deletion_pending":{"$ne":true}},
            ),
            ("groups", "machine_groups", doc! {"user_id":owner}),
            ("books", "access_rulebooks", doc! {"user_id":owner}),
            ("peers", "private_peers", doc! {"workspace_id":owner}),
        ] {
            counts.insert(
                name.into(),
                json!(app.collection(collection).count_documents(filter).await?),
            );
        }
        counts.insert("people".into(), json!(allowed.len()));
        let owner_record = app
            .collection("users")
            .find_one(doc! {"_id":owner})
            .projection(doc! {"name":1,"username":1})
            .await?
            .unwrap_or_default();
        return conditional(
            headers,
            json!({"data":{"workspace_id":owner.to_hex(),"workspace_name":format!("{}'s Workspace",store::string(&owner_record,"name")),"role":role,"transport_ready":false,"network":{"cidr":network.cidr(),"dns_suffix":suffix},"counts":counts}}),
        );
    }
    let collection = match kind {
        "machines" => "machines",
        "groups" => "machine_groups",
        "people" | "entities" => "users",
        "books" => "access_rulebooks",
        "peers" => "private_peers",
        "invitations" => "workspace_invites",
        "exits" => "private_exit_nodes",
        "proxy-grants" => "private_proxy_grants",
        "dns" => "private_dns_rules",
        _ => return Err(ApiError::bad_request("Unknown access inventory kind")),
    };
    let mut filter = match kind {
        "people" => doc! {"_id":{"$in":&users}},
        "peers" | "exits" | "dns" | "proxy-grants" => doc! {"workspace_id":owner},
        _ => doc! {"user_id":owner},
    };
    if kind == "machines" {
        filter.insert("deletion_pending", doc! {"$ne":true});
    }
    if kind == "invitations" {
        if !["owner", "admin"].contains(&role.as_str()) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "Workspace administration required",
            ));
        }
        filter.extend(doc!{"consumed_at":Bson::Null,"revoked_at":Bson::Null,"expires_at":{"$gt":mongodb::bson::DateTime::now()}});
    }
    if kind == "books" && p.group != "all" && !p.group.is_empty() {
        oid(&p.group)?;
        filter.insert("group_id", &p.group);
    }
    if !p.ids.is_empty() && kind != "entities" {
        let ids = p
            .ids
            .split(',')
            .map(|id| {
                if ["peers", "invitations"].contains(&kind) && id.len() <= 128 {
                    Ok(Bson::String(id.to_owned()))
                } else {
                    oid(id).map(Bson::ObjectId)
                }
            })
            .collect::<ApiResult<Vec<_>>>()?;
        if ids.len() > 100 {
            return Err(ApiError::bad_request("At most 100 IDs are supported"));
        }
        filter.insert("_id", doc! {"$in":ids});
    }
    if p.status == "enabled" {
        filter.insert("enabled", doc! {"$ne":false});
    } else if p.status == "disabled" {
        filter.insert("enabled", false);
    }
    let mut stages = vec![doc! {"$match":filter}];
    if kind == "entities" {
        stages = entity_pipeline("user", owner, &users);
        for (collection, kind) in [("machines", "machine"), ("machine_groups", "group")] {
            stages.push(doc!{"$unionWith":{"coll":collection,"pipeline":entity_pipeline(kind,owner,&users)}});
        }
        if !p.entity_types.is_empty() {
            let types = p.entity_types.split(',').collect::<Vec<_>>();
            if types
                .iter()
                .any(|kind| !["machine", "group", "user"].contains(kind))
            {
                return Err(ApiError::bad_request("Invalid entity type"));
            }
            stages.push(doc! {"$match":{"kind":{"$in":types}}});
        }
        if !p.ids.is_empty() {
            let ids = p.ids.split(',').collect::<Vec<_>>();
            if ids.len() > 100 {
                return Err(ApiError::bad_request("At most 100 entities are supported"));
            }
            stages.push(doc! {"$match":{"_id":{"$in":ids}}});
        }
    }
    if kind == "peers" {
        stages.push(doc! {"$lookup":{"from":"machines","localField":"machine_id","foreignField":"_id","pipeline":[{"$project":{"name":1}}],"as":"_machine"}});
        stages.push(doc! {"$set":{"machine_name":{"$arrayElemAt":["$_machine.name",0]}}});
    }
    if ["books", "exits"].contains(&kind) {
        let selectors = if kind == "books" {
            doc! {"$reduce":{"input":{"$ifNull":["$rules",[]]},"initialValue":[],"in":{"$concatArrays":["$$value","$$this.sources","$$this.destinations"]}}}
        } else {
            doc! {"$concatArrays":[{"$ifNull":["$routing_selectors",[]]},{"$ifNull":["$distribution_selectors",[]]}]}
        };
        stages.push(doc! {"$set":{"_selectors":selectors}});
        for (entity_kind, entity_collection) in [
            ("machine", "machines"),
            ("group", "machine_groups"),
            ("user", "users"),
        ] {
            let scope = if entity_kind == "user" {
                doc! {"_id":{"$in":&users}}
            } else {
                doc! {"user_id":owner}
            };
            stages.push(doc!{"$lookup":{"from":entity_collection,"let":{"ids":{"$map":{"input":{"$filter":{"input":"$_selectors","as":"selector","cond":{"$eq":["$$selector.kind",entity_kind]}}},"as":"selector","in":"$$selector.id"}}},"pipeline":[{"$match":scope},{"$match":{"$expr":{"$in":[{"$toString":"$_id"},"$$ids"]}}},{"$project":{"name":1,"username":1}}],"as":format!("_{entity_kind}_names")}});
        }
    }
    let rule_names =
        doc! {"$map":{"input":{"$ifNull":["$rules",[]]},"as":"rule","in":"$$rule.name"}};
    let entity_names = doc! {"$map":{"input":{"$concatArrays":["$_machine_names","$_group_names","$_user_names"]},"as":"entity","in":{"$ifNull":["$$entity.name","$$entity.username"]}}};
    let fields: Bson = match kind {
        "books" => doc! {"$concatArrays":[names(&["name"]),rule_names,entity_names.clone()]}.into(),
        "exits" => doc! {"$concatArrays":[names(&["name"]),entity_names]}.into(),
        "people" | "entities" => names(&["name", "username", "email", "label"]),
        "peers" => names(&["hostname", "ip", "machine_name"]),
        "dns" => names(&["name", "domain", "pattern"]),
        _ => names(&["name", "email"]),
    };
    if !p.q.trim().is_empty() {
        stages.push(doc! {"$set":{"_search_fields":fields}});
        stages.extend(search_pipeline(&p.q));
    }
    let mut sort = doc! {"name":if p.sort=="name-desc" {-1}else{1},"_id":1};
    if !p.q.trim().is_empty() {
        sort = doc! {"_score":1,"name":1,"_id":1};
    }
    if p.sort == "newest" {
        sort = doc! {"created_at":-1,"_id":1};
    }
    let mut data = vec![
        doc! {"$sort":sort},
        doc! {"$skip":((p.page-1)*p.page_size) as i64},
        doc! {"$limit":p.page_size as i64},
    ];
    if kind == "books" {
        data.push(doc! {"$lookup":{"from":"machine_groups","let":{"group":"$group_id"},"pipeline":[{"$match":{"user_id":owner,"$expr":{"$eq":[{"$toString":"$_id"},"$$group"]}}},{"$project":{"name":1}}],"as":"_organising_group"}});
    }
    if kind == "books" && !p.detail {
        data.push(doc!{"$set":{"rules_count":{"$size":{"$ifNull":["$rules",[]]}},"rules":{"$slice":[{"$ifNull":["$rules",[]]},2]}}});
    }
    if kind == "groups" {
        data.push(doc!{"$lookup":{"from":"machines","let":{"group":"$_id","text":{"$toString":"$_id"}},"pipeline":[{"$match":{"user_id":owner,"deletion_pending":{"$ne":true},"$expr":{"$or":[{"$in":["$$group",{"$ifNull":["$group_ids",[]]}]},{"$in":["$$text",{"$ifNull":["$group_ids",[]]}]},{"$eq":["$group_id","$$group"]},{"$eq":["$group_id","$$text"]}]}}},{"$count":"count"}],"as":"_members"}});
        data.push(doc!{"$lookup":{"from":"access_rulebooks","let":{"group":{"$toString":"$_id"}},"pipeline":[{"$match":{"user_id":owner,"$expr":{"$eq":["$group_id","$$group"]}}},{"$count":"count"}],"as":"_books"}});
    }
    stages.push(doc! {"$facet":{"data":data,"total":[{"$count":"count"}]}});
    let result = app
        .collection(collection)
        .aggregate(stages)
        .collation(
            Collation::builder()
                .locale("en")
                .strength(CollationStrength::Primary)
                .numeric_ordering(true)
                .build(),
        )
        .max_time(Duration::from_secs(3))
        .await?
        .try_next()
        .await?
        .unwrap_or_default();
    let total = result
        .get_array("total")
        .ok()
        .and_then(|rows| rows.first())
        .and_then(Bson::as_document)
        .map(|row| store::field(row, "count"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let membership_group = if !p.membership.is_empty() && ["machines", "people"].contains(&kind) {
        Some(
            app.collection("machine_groups")
                .find_one(doc! {"_id":oid(&p.membership)?,"user_id":owner})
                .projection(doc! {"user_ids":1})
                .await?
                .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Group not found"))?,
        )
    } else {
        None
    };
    let domains = if kind == "peers" {
        let records = result
            .get_array("data")
            .ok()
            .into_iter()
            .flatten()
            .filter_map(Bson::as_document)
            .map(|peer| Bson::Document(doc! {"_peers":[peer]}))
            .collect::<Vec<_>>();
        crate::inventory_query::private_domains(&app, &doc! {"data":records}).await?
    } else {
        Default::default()
    };
    let mut rows = Vec::new();
    let mut labels = serde_json::Map::new();
    for record in result
        .get_array("data")
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Bson::as_document)
    {
        let id = store::id(record.get("_id"));
        if kind == "exits" {
            for entity_kind in ["machine", "group"] {
                for entity in record
                    .get_array(&format!("_{entity_kind}_names"))
                    .ok()
                    .into_iter()
                    .flatten()
                    .filter_map(Bson::as_document)
                {
                    labels.insert(
                        format!("{entity_kind}:{}", store::id(entity.get("_id"))),
                        json!(store::string(entity, "name")),
                    );
                }
            }
        }
        let mut row = match kind {
            "machines" => {
                json!({"_id":id,"name":store::string(record,"name"),"group_ids":inventory::group_ids(record).iter().map(|id|id.to_hex()).collect::<Vec<_>>(),"enabled":record.get_bool("enabled").unwrap_or(true),"connection_status":inventory::status(&app,record),"private_owner_id":store::id(record.get("private_owner_id")),"private_owner_revoked":record.get_bool("private_owner_revoked").unwrap_or(false)})
            }
            "peers" => {
                let mid = store::id(record.get("machine_id"));
                let hostname = domains
                    .get(&mid)
                    .and_then(|domain| domain.split_once('.'))
                    .map(|(label, _)| label)
                    .unwrap_or_else(|| store::string(record, "hostname"));
                let mut paths = record
                    .get_document("paths")
                    .ok()
                    .into_iter()
                    .flat_map(|paths| paths.values())
                    .filter_map(Bson::as_str)
                    .collect::<Vec<_>>();
                paths.sort_unstable();
                paths.dedup();
                json!({"_id":id,"machine_id":mid,"machine_name":store::field(record,"machine_name"),"ip":store::field(record,"ip"),"hostname":hostname,"custom_hostname":!store::string(record,"hostname").is_empty(),"enabled":record.get_bool("enabled").unwrap_or(true),"installed":!store::string(record,"credential_hash").is_empty(),"online":record.get_datetime("last_seen_at").is_ok_and(|last|mongodb::bson::DateTime::now().timestamp_millis().saturating_sub(last.timestamp_millis())<30_000),"last_seen_at":store::field(record,"last_seen_at"),"paths":paths})
            }
            "people" => {
                json!({"_id":id,"name":store::string(record,"name"),"email":store::string(record,"username"),"role":roles.get(&id)})
            }
            "entities" => {
                json!({"_id":id,"name":if store::string(record,"name").is_empty(){store::string(record,"username")}else{store::string(record,"name")},"kind":store::string(record,"kind")})
            }
            "groups" => {
                let count = |field: &str| {
                    record
                        .get_array(field)
                        .ok()
                        .and_then(|rows| rows.first())
                        .and_then(Bson::as_document)
                        .map(|row| store::field(row, "count"))
                        .unwrap_or(json!(0))
                };
                let people = record
                    .get_array("user_ids")
                    .ok()
                    .into_iter()
                    .flatten()
                    .map(|id| store::id(Some(id)))
                    .filter(|id| allowed.contains(id))
                    .collect::<Vec<_>>();
                json!({"_id":id,"name":store::string(record,"name"),"machine_count":count("_members"),"book_count":count("_books"),"user_count":people.len()})
            }
            "books" => {
                for kind in ["machine", "group", "user"] {
                    for entity in record
                        .get_array(&format!("_{kind}_names"))
                        .ok()
                        .into_iter()
                        .flatten()
                        .filter_map(Bson::as_document)
                    {
                        let name = store::string(entity, "name");
                        labels.insert(
                            format!("{kind}:{}", store::id(entity.get("_id"))),
                            json!(if name.is_empty() {
                                store::string(entity, "username")
                            } else {
                                name
                            }),
                        );
                    }
                }
                let mut row = serde_json::Map::new();
                for key in [
                    "_id",
                    "name",
                    "group_id",
                    "enabled",
                    "rules",
                    "revision",
                    "created_at",
                    "updated_at",
                    "rules_count",
                ] {
                    if let Some(value) = record.get(key) {
                        row.insert(key.into(), store::json(value));
                    }
                }
                row.insert(
                    "group_name".into(),
                    record
                        .get_array("_organising_group")
                        .ok()
                        .and_then(|groups| groups.first())
                        .and_then(Bson::as_document)
                        .map(|g| json!(store::string(g, "name")))
                        .unwrap_or(Value::Null),
                );
                Value::Object(row)
            }
            "exits" => crate::routes::exit_nodes::serialize(record),
            "proxy-grants" => crate::routes::proxy_grants::public(record),
            "dns" => crate::routes::dns_rules::serialize(record),
            "invitations" => {
                let mut row = serde_json::Map::new();
                for key in ["_id", "email", "role", "expires_at"] {
                    if let Some(value) = record.get(key) {
                        row.insert(key.into(), store::json(value));
                    }
                }
                Value::Object(row)
            }
            _ => json!({"_id":id}),
        };
        if !p.membership.is_empty() && ["machines", "people"].contains(&kind) {
            let group = membership_group
                .as_ref()
                .expect("group checked before query");
            row["member"] = json!(if kind == "machines" {
                inventory::group_ids(record)
                    .iter()
                    .any(|id| id.to_hex() == p.membership)
            } else {
                group
                    .get_array("user_ids")
                    .ok()
                    .into_iter()
                    .flatten()
                    .any(|value| store::id(Some(value)) == id)
            });
        }
        rows.push(row);
    }
    conditional(
        headers,
        json!({"data":rows,"labels":labels,"workspace_id":owner.to_hex(),"role":role,"can_allow_gateway_lan":store::string(user,"role")=="admin","pagination":{"page":p.page,"page_size":p.page_size,"total":total,"pages":total.div_ceil(p.page_size).max(1)}}),
    )
}

async fn accessible_workspaces(
    app: &App,
    p: &Params,
    headers: &HeaderMap,
    user: &Document,
) -> ApiResult<Response> {
    let id = user
        .get_object_id("_id")
        .map_err(|_| ApiError::unauthenticated())?;
    let memberships = app
        .collection("workspace_members")
        .find(doc! {"user_id":id,"role":{"$in":["admin","member"]}})
        .projection(doc! {"workspace_id":1,"role":1})
        .await?
        .try_collect::<Vec<_>>()
        .await?;
    let mut ids = vec![Bson::ObjectId(id)];
    let mut roles = HashMap::from([(id.to_hex(), "owner".to_owned())]);
    for membership in memberships {
        if let Some(owner) = membership.get("workspace_id") {
            ids.push(owner.clone());
            roles.insert(
                store::id(Some(owner)),
                store::string(&membership, "role").to_owned(),
            );
        }
    }
    let mut stages = vec![
        doc! {"$match":{"_id":{"$in":ids}}},
        doc! {"$project":{"name":1,"username":1}},
    ];
    if !p.ids.is_empty() {
        let ids = p.ids.split(',').map(oid).collect::<ApiResult<Vec<_>>>()?;
        if ids.len() > 100 {
            return Err(ApiError::bad_request(
                "At most 100 workspaces are supported",
            ));
        }
        stages.push(doc! {"$match":{"_id":{"$in":ids}}});
    }
    if !p.q.is_empty() {
        stages.push(doc! {"$set":{"_search_fields":names(&["name","username"])}});
        stages.extend(search_pipeline(&p.q));
    }
    stages.push(doc! {"$facet":{"data":[{"$sort":{"name":1,"_id":1}},{"$skip":((p.page-1)*p.page_size) as i64},{"$limit":p.page_size as i64}],"total":[{"$count":"count"}]}});
    let result = app
        .collection("users")
        .aggregate(stages)
        .max_time(Duration::from_secs(3))
        .await?
        .try_next()
        .await?
        .unwrap_or_default();
    let total = result
        .get_array("total")
        .ok()
        .and_then(|rows| rows.first())
        .and_then(Bson::as_document)
        .map(|row| store::field(row, "count"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let rows=result.get_array("data").ok().into_iter().flatten().filter_map(Bson::as_document).map(|row|{let id=store::id(row.get("_id"));let name=store::string(row,"name");json!({"_id":id,"id":id,"name":format!("{}'s Workspace",if name.is_empty(){store::string(row,"username")}else{name}),"role":roles.get(&id)})}).collect::<Vec<_>>();
    conditional(
        headers,
        json!({"data":rows,"pagination":{"page":p.page,"page_size":p.page_size,"total":total,"pages":total.div_ceil(p.page_size).max(1)}}),
    )
}
