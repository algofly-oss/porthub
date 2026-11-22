use super::*;
use crate::port_forward_bridge::host_public;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Rename {
    name: String,
}

pub(super) async fn rename(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Rename>,
) -> ApiResult<Json<Value>> {
    let owner = owner(&app, &headers, Method::PATCH).await?;
    let id = object_id(&id, "Invalid forward.")?;
    let name = input.name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(ApiError::bad_request(
            "Enter a name of up to 80 characters.",
        ));
    }
    if app
        .collection(COLLECTION)
        .update_one(
            doc! {"_id":id,"workspace_id":owner,"state":"active"},
            doc! {"$set":{"name":name}},
        )
        .await?
        .matched_count
        == 0
    {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Forward not found."));
    }
    Ok(Json(json!({"name":name})))
}

async fn check_host(app: &App, owner: ObjectId, id: ObjectId) -> ApiResult<()> {
    if app
        .collection(COLLECTION)
        .count_documents(
            doc! {"_id":id,"workspace_id":owner,"state":"active","mappings.direction":"host"},
        )
        .await?
        == 0
    {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Temporary host not found.",
        ));
    }
    Ok(())
}

async fn ports(app: &App, owner: ObjectId, id: ObjectId) -> ApiResult<Json<Value>> {
    let hostname = crate::port_forward_auth::endpoint(app)
        .map_err(unavailable)?
        .0;
    let rows = app
        .collection("connections")
        .find(doc! {"forward_owner":owner,"forward_reservation":id,"host_public_state":"active"})
        .sort(doc! {"host_client_port":1})
        .await?
        .try_collect::<Vec<Document>>()
        .await?;
    Ok(Json(
        json!({"ports":rows.iter().map(|row|json!({"clientPort":row.get_i32("host_client_port").ok(),"gatewayPort":row.get_i32("external_port").ok(),"host":hostname})).collect::<Vec<_>>()}),
    ))
}

pub(super) async fn list(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let owner = owner(&app, &headers, Method::GET).await?;
    let id = object_id(&id, "Invalid forward.")?;
    check_host(&app, owner, id).await?;
    ports(&app, owner, id).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Publication {
    client_port: u16,
}

pub(super) async fn publish(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Publication>,
) -> ApiResult<Json<Value>> {
    let owner = owner(&app, &headers, Method::POST).await?;
    let id = object_id(&id, "Invalid forward.")?;
    if input.client_port == 0 {
        return Err(ApiError::bad_request("Choose a TCP port from 1 to 65535."));
    }
    let _changes = app.connection_lock.lock().await;
    check_host(&app, owner, id).await?;
    let filter = doc! {"forward_owner":owner,"forward_reservation":id,"host_client_port":i32::from(input.client_port)};
    let records = app.collection("connections");
    let row = if let Some(existing) = records.find_one(filter.clone()).await? {
        if existing.get_str("host_public_state") != Ok("active") {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "This public port is being withdrawn.",
            ));
        }
        existing
    } else {
        if records.count_documents(doc!{"forward_owner":owner,"forward_reservation":id,"host_client_port":{"$exists":true}}).await? >= 32 {return Err(ApiError::bad_request("Publish up to 32 ports per host."));}
        let key = ObjectId::new();
        let fields = doc! {"_id":key,"host_public_state":"active","host_client_port":i32::from(input.client_port)};
        reserve_with(&app, owner, id, 1, &fields).await?;
        records
            .find_one(doc! {"_id":key})
            .await?
            .ok_or_else(|| ApiError::bad_request("Public port reservation disappeared."))?
    };
    if let Err(error) = host_public::activate(&app, &row).await {
        host_public::withdraw(&app, &row)
            .await
            .map_err(unavailable)?;
        return Err(unavailable(error));
    }
    ports(&app, owner, id).await
}

pub(super) async fn unpublish(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path((id, port)): Path<(String, u16)>,
) -> ApiResult<Json<Value>> {
    let owner = owner(&app, &headers, Method::DELETE).await?;
    let id = object_id(&id, "Invalid forward.")?;
    let _changes = app.connection_lock.lock().await;
    check_host(&app, owner, id).await?;
    if let Some(row)=app.collection("connections").find_one(doc!{"forward_owner":owner,"forward_reservation":id,"host_client_port":i32::from(port)}).await? {
        host_public::withdraw(&app,&row).await.map_err(unavailable)?;
    }
    ports(&app, owner, id).await
}
