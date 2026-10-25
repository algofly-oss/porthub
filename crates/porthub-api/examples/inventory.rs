//! Read-only migration inventory. Credentials arrive on stdin and are never
//! included in process arguments or the projected output.
use anyhow::Result;
use futures_util::TryStreamExt;
use mongodb::bson::{doc, Document};
#[tokio::main]
async fn main() -> Result<()> {
    let input: serde_json::Value = serde_json::from_reader(std::io::stdin())?;
    let client = mongodb::Client::with_uri_str(
        input["uri"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("database connection required"))?,
    )
    .await?;
    let db = client.database(
        input["database"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("database name required"))?,
    );
    let machines: Vec<Document> = db
        .collection::<Document>("machines")
        .find(doc! {})
        .projection(doc! {"_id":1,"name":1,"enabled":1,"client_version":1,"last_seen_at":1,"deletion_pending":1})
        .await?
        .try_collect()
        .await?;
    let peers: Vec<Document> = db
        .collection::<Document>("private_peers")
        .find(doc! {})
        .projection(doc! {"_id":1,"machine_id":1,"enabled":1})
        .await?
        .try_collect()
        .await?;
    serde_json::to_writer_pretty(
        std::io::stdout(),
        &serde_json::json!({"machines":machines.iter().map(porthub_api::store::document).collect::<Vec<_>>(),"private_peers":peers.iter().map(porthub_api::store::document).collect::<Vec<_>>()}),
    )?;
    Ok(())
}
