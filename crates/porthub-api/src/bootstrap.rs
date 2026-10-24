//! Initialize a new core-local MongoDB using its localhost exception. Existing
//! authenticated databases are checked first and are never reset or replaced.
use crate::config::Config;
use anyhow::{Context, Result};
use mongodb::{bson::doc, Client, Database};

pub async fn database(config: &Config) -> Result<Database> {
    let client = Client::with_uri_str(&config.mongo_uri).await?;
    let database = client.database(&config.mongo_database);
    let authenticated = database.run_command(doc! {"ping":1}).await;
    if authenticated.is_ok() {
        return Ok(database);
    }
    if std::env::var("PORTHUB_DB_INITIALIZE").as_deref() != Ok("true") {
        authenticated.context("connect to authenticated MongoDB")?;
    }
    let username = std::env::var("MONGO_INITDB_ROOT_USERNAME")
        .context("MongoDB bootstrap username required")?;
    let password = std::env::var("MONGO_INITDB_ROOT_PASSWORD")
        .context("MongoDB bootstrap password required")?;
    anyhow::ensure!(
        !username.is_empty() && !password.is_empty(),
        "MongoDB bootstrap credentials must not be empty"
    );
    let local = Client::with_uri_str(
        "mongodb://127.0.0.1:47017/?directConnection=true&serverSelectionTimeoutMS=5000",
    )
    .await?;
    local
        .database("admin")
        .run_command(
            doc! {"createUser":username,"pwd":password,"roles":[{"role":"root","db":"admin"}]},
        )
        .await
        .context("initialize core-local MongoDB administrator")?;
    // A client that already failed authentication may retain the failed pool;
    // create a fresh authenticated connection after the user is committed.
    let client = Client::with_uri_str(&config.mongo_uri).await?;
    let database = client.database(&config.mongo_database);
    database
        .run_command(doc! {"ping":1})
        .await
        .context("verify initialized MongoDB")?;
    Ok(database)
}
