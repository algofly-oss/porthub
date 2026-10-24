use crate::{
    domain::{
        private_policy::{self, Book},
        workspaces::object_id,
    },
    error::{ApiError, ApiResult},
    input::ApiBody,
    routes::access::{browser, WorkspaceQuery},
    store, App,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    routing::{post, put},
    Json, Router,
};
use futures_util::TryStreamExt;
use mongodb::{
    bson::{doc, oid::ObjectId, DateTime, Document},
    options::ReturnDocument,
};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/access/books", post(create))
        .route("/api/access/books/{id}", put(update).delete(delete))
        .route("/api/access/test", post(test_connection))
}
async fn validate(app: &App, book: &Book, owner: ObjectId) -> ApiResult<()> {
    let mut groups = HashSet::from([book.group_id.clone()]);
    let mut machines = HashSet::new();
    let mut users = HashSet::new();
    for rule in &book.rules {
        for selector in rule.sources.iter().chain(&rule.destinations) {
            match selector.kind.as_str() {
                "machine" => {
                    machines.insert(selector.id.clone());
                }
                "group" => {
                    groups.insert(selector.id.clone());
                }
                "user" => {
                    users.insert(selector.id.clone());
                }
                _ => {}
            }
        }
    }
    for (kind, collection, values) in [
        ("group", "machine_groups", groups),
        ("machine", "machines", machines),
    ] {
        let mut ids = HashSet::new();
        for id in values {
            ids.insert(object_id(&id, &format!("Invalid {kind} identifier"))?);
        }
        if !ids.is_empty() {
            let ids: Vec<_> = ids.into_iter().collect();
            let found = app
                .collection(collection)
                .count_documents(doc! {"user_id":owner,"_id":{"$in":&ids}})
                .await?;
            if found != ids.len() as u64 {
                return Err(ApiError::bad_request(&format!(
                    "Every selected {kind} must belong to this workspace"
                )));
            }
        }
    }
    users.remove(&owner.to_hex());
    let memberships: Vec<Document> = app
        .collection("workspace_members")
        .find(doc! {"workspace_id":owner})
        .projection(doc! {"user_id":1})
        .await?
        .try_collect()
        .await?;
    for membership in memberships {
        users.remove(&store::id(membership.get("user_id")));
    }
    if !users.is_empty() {
        return Err(ApiError::bad_request(
            "Selected users must belong to this workspace",
        ));
    }
    Ok(())
}
async fn create(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let book = private_policy::parse_book(raw)?;
    let (user, owner, _) = browser(&app, &headers, &Method::POST, &query.workspace, true).await?;
    validate(&app, &book, owner).await?;
    if app
        .collection("access_rulebooks")
        .count_documents(doc! {"user_id":owner})
        .await?
        >= 100
    {
        return Err(ApiError::bad_request(
            "A workspace can have up to 100 rule books",
        ));
    }
    let mut document = mongodb::bson::to_document(&book).expect("typed bounded policy model");
    let now = DateTime::now();
    document.extend(doc!{"_id":ObjectId::new(),"revision":1_i64,"user_id":owner,"created_by":user.get("_id"),"created_at":now,"updated_at":now});
    app.collection("access_rulebooks")
        .insert_one(&document)
        .await?;
    Ok(Json(json!({"data":store::document(&document)})))
}
async fn update(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    Path(id): Path<String>,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let book = private_policy::parse_book(raw)?;
    let (_, owner, _) = browser(&app, &headers, &Method::PUT, &query.workspace, true).await?;
    validate(&app, &book, owner).await?;
    let id = object_id(&id, "Invalid rule book")?;
    let mut set = mongodb::bson::to_document(&book).expect("typed bounded policy model");
    set.remove("revision");
    set.insert("updated_at", DateTime::now());
    let updated = app
        .collection("access_rulebooks")
        .find_one_and_update(
            doc! {"_id":id,"user_id":owner,"revision":book.revision},
            doc! {"$set":set,"$inc":{"revision":1_i64}},
        )
        .return_document(ReturnDocument::After)
        .await?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::CONFLICT,
                "Rule book changed or no longer exists. Reload before saving.",
            )
        })?;
    Ok(Json(json!({"data":store::document(&updated)})))
}
async fn delete(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    Path(id): Path<String>,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let revision = private_policy::parse_delete(raw)?;
    let (_, owner, _) = browser(&app, &headers, &Method::DELETE, &query.workspace, true).await?;
    let id = object_id(&id, "Invalid rule book")?;
    let result = app
        .collection("access_rulebooks")
        .delete_one(doc! {"_id":id,"user_id":owner,"revision":revision})
        .await?;
    if result.deleted_count != 1 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Rule book changed or no longer exists. Reload before deleting.",
        ));
    }
    Ok(Json(json!({"msg":"Rule book deleted"})))
}
async fn test_connection(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<WorkspaceQuery>,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let input = private_policy::parse_connection(raw)?;
    let (_, owner, _) = browser(&app, &headers, &Method::POST, &query.workspace, false).await?;
    let source = object_id(&input.source_id, "Invalid source")?;
    let destination = object_id(&input.destination_id, "Invalid destination")?;
    let machines: Vec<Document> = app
        .collection("machines")
        .find(doc! {"user_id":owner,"_id":{"$in":[source,destination]}})
        .await?
        .try_collect()
        .await?;
    let by_id: HashMap<_, _> = machines
        .iter()
        .map(|m| (store::id(m.get("_id")), store::document(m)))
        .collect();
    let Some((source, destination)) = by_id
        .get(&input.source_id)
        .zip(by_id.get(&input.destination_id))
    else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Select two machines in this workspace",
        ));
    };
    let books: Vec<Document> = app
        .collection("access_rulebooks")
        .find(doc! {"user_id":owner})
        .await?
        .try_collect()
        .await?;
    let groups: Vec<Document> = app
        .collection("machine_groups")
        .find(doc! {"user_id":owner})
        .await?
        .try_collect()
        .await?;
    let books = books.iter().map(store::document).collect::<Vec<_>>();
    let groups = groups
        .iter()
        .map(|g| (store::id(g.get("_id")), store::document(g)))
        .collect();
    let decision = private_policy::evaluate(
        source,
        destination,
        &input.protocol,
        input.port,
        &books,
        &groups,
    );
    Ok(Json(
        json!({"data":decision,"enforcement":"policy-preview","transport_ready":false}),
    ))
}
