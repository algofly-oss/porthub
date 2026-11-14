//! Persistent local capability policy. Only OS-authenticated local callers can
//! mutate it; gateway configuration can never override a local disabled feature.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    sync::watch,
};
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
pub enum Feature {
    Keyboard,
    Metrics,
    Images,
    Terminal,
    Expose,
    PublicForwarding,
    PrivateNetwork,
    AutoUpdate,
    DirectConnections,
}
impl Feature {
    pub const ALL: [Self; 9] = [
        Self::Keyboard,
        Self::Metrics,
        Self::Images,
        Self::Terminal,
        Self::Expose,
        Self::PublicForwarding,
        Self::PrivateNetwork,
        Self::AutoUpdate,
        Self::DirectConnections,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::Keyboard => "keyboard",
            Self::Metrics => "metrics",
            Self::Images => "images",
            Self::Terminal => "terminal",
            Self::Expose => "expose",
            Self::PublicForwarding => "public-forwarding",
            Self::PrivateNetwork => "private-network",
            Self::AutoUpdate => "auto-update",
            Self::DirectConnections => "direct-connections",
        }
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub disabled: BTreeMap<Feature, bool>,
}
impl Policy {
    pub fn enabled(&self, feature: Feature) -> bool {
        !self.disabled.get(&feature).copied().unwrap_or(false)
    }
}
fn path(profile: &Path) -> PathBuf {
    crate::profile::sibling(profile, ".client-features.json")
}
fn load(profile: &Path) -> Result<Policy> {
    let path = path(profile);
    if !path.try_exists()? {
        return Ok(Policy::default());
    }
    let bytes = crate::profile::read_private(&path)?;
    ensure!(bytes.len() <= 4096, "Invalid client feature policy");
    Ok(serde_json::from_slice(&bytes)?)
}
fn registry() -> &'static Mutex<HashMap<PathBuf, watch::Sender<Policy>>> {
    static POLICIES: OnceLock<Mutex<HashMap<PathBuf, watch::Sender<Policy>>>> = OnceLock::new();
    POLICIES.get_or_init(Mutex::default)
}
pub(crate) fn subscribe(profile: &Path) -> watch::Receiver<Policy> {
    let mut entries = registry().lock().unwrap_or_else(|e| e.into_inner());
    entries
        .entry(profile.to_owned())
        .or_insert_with(|| {
            let policy = load(profile).unwrap_or_else(|_| Policy {
                disabled: Feature::ALL.into_iter().map(|f| (f, true)).collect(),
            });
            watch::channel(policy).0
        })
        .subscribe()
}
pub(crate) fn enabled(profile: &Path, feature: Feature) -> bool {
    subscribe(profile).borrow().enabled(feature)
}
fn set(profile: &Path, feature: Feature, enabled: bool) -> Result<Policy> {
    let mut entries = registry().lock().unwrap_or_else(|e| e.into_inner());
    let sender = entries.entry(profile.to_owned()).or_insert_with(|| {
        watch::channel(load(profile).unwrap_or_else(|_| Policy {
            disabled: Feature::ALL.into_iter().map(|f| (f, true)).collect(),
        }))
        .0
    });
    let mut policy = sender.borrow().clone();
    if enabled {
        policy.disabled.remove(&feature);
    } else {
        policy.disabled.insert(feature, true);
    }
    crate::profile::write_private(&path(profile), &serde_json::to_vec(&policy)?, true)?;
    sender.send_replace(policy.clone());
    Ok(policy)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    operation: String,
    feature: Option<Feature>,
    enabled: Option<bool>,
}
pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut reader: BufReader<S>,
    profile: &Path,
    value: serde_json::Value,
) -> Result<()> {
    let request: Request = serde_json::from_value(value)?;
    ensure!(
        request.operation == "client_features",
        "Invalid feature operation"
    );
    let policy = match (request.feature, request.enabled) {
        (Some(feature), Some(enabled)) => set(profile, feature, enabled)?,
        (None, None) => subscribe(profile).borrow().clone(),
        _ => anyhow::bail!("Supply both feature and enabled"),
    };
    let rows:Vec<_>=Feature::ALL.into_iter().map(|f|serde_json::json!({"feature":f.name(),"enabled":policy.enabled(f),"source":if policy.disabled.contains_key(&f){"local override"}else{"default"}})).collect();
    reader
        .get_mut()
        .write_all(format!("{}\n", serde_json::json!({"features":rows})).as_bytes())
        .await?;
    Ok(())
}
#[derive(clap::Args)]
pub struct Args {
    #[arg(long, global = true)]
    pub user: bool,
    #[arg(long, global = true)]
    pub registration: Option<String>,
    #[command(subcommand)]
    pub command: Option<Action>,
}
#[derive(clap::Subcommand)]
pub enum Action {
    List,
    Enable {
        #[arg(value_enum)]
        feature: Feature,
    },
    Disable {
        #[arg(value_enum)]
        feature: Feature,
    },
}
pub async fn run(args: Args) -> Result<()> {
    let (layout, registration) =
        crate::keyboard::registration(args.user, args.registration.as_deref())?;
    let (feature, enabled) = match args.command {
        Some(Action::Enable { feature }) => (Some(feature), Some(true)),
        Some(Action::Disable { feature }) => (Some(feature), Some(false)),
        _ => (None, None),
    };
    let mut stream = match crate::exposure_broker::connect_stream(&layout, &registration).await {
        Ok(stream) => stream,
        Err(error) => {
            if !layout.user {
                crate::service::require_administrator().context("The agent is offline; local administrator access is required to change its persistent policy")?;
            }
            let spec = crate::service::installed(&layout, &registration)?
                .context("Registration manifest unavailable")?;
            let policy = match (feature, enabled) {
                (Some(feature), Some(on)) => set(&spec.profile, feature, on)?,
                _ => load(&spec.profile)?,
            };
            for feature in Feature::ALL {
                println!(
                    "{:<22} {}",
                    feature.name(),
                    if policy.enabled(feature) {
                        "enabled"
                    } else {
                        "disabled"
                    }
                );
            }
            let _ = error;
            return Ok(());
        }
    };
    let message =
        serde_json::json!({"operation":"client_features","feature":feature,"enabled":enabled});
    stream.write_all(format!("{message}\n").as_bytes()).await?;
    let mut reader = BufReader::new(stream);
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        crate::exposure_protocol::line(&mut reader),
    )
    .await
    .context("Client feature request timed out")??;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if let Some(error) = value["error"].as_str() {
        anyhow::bail!("{error}");
    }
    for row in value["features"]
        .as_array()
        .context("Update the installed agent to support client feature policy")?
    {
        println!(
            "{:<22} {:<9} {}",
            row["feature"].as_str().unwrap_or_default(),
            if row["enabled"] == true {
                "enabled"
            } else {
                "disabled"
            },
            row["source"].as_str().unwrap_or_default()
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_enable_capabilities_and_overrides_survive() {
        let mut p = Policy::default();
        assert!(Feature::ALL.into_iter().all(|f| p.enabled(f)));
        p.disabled.insert(Feature::Keyboard, true);
        let p: Policy = serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
        assert!(!p.enabled(Feature::Keyboard));
        assert!(p.enabled(Feature::Images));
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    #[tokio::test]
    async fn local_disable_is_durable_and_rejects_remote_input_before_any_gateway_request(
    ) -> Result<()> {
        let root = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let path = root.path().join("profile.json");
        let mut watch = subscribe(&path);
        assert!(watch.borrow().enabled(Feature::Keyboard));
        set(&path, Feature::Keyboard, false)?;
        watch.changed().await?;
        assert!(!watch.borrow_and_update().enabled(Feature::Keyboard));
        assert!(!load(&path)?.enabled(Feature::Keyboard));
        let profile: crate::profile::Profile = serde_json::from_value(
            serde_json::json!({"server":"http://127.0.0.1:1","machine_id":"0123456789abcdef01234567","token":"never-share-machine-credential","allow_insecure_http_for_tests":true}),
        )?;
        let control = std::sync::Arc::new(crate::control::Control::new(profile)?);
        let (client, service) = tokio::io::duplex(8192);
        let broker = crate::exposure_protocol::serve_connection(
            service,
            control,
            tokio_util::sync::CancellationToken::new(),
            path.clone(),
        );
        let client = async {
            let mut c = BufReader::new(client);
            c.get_mut()
                .write_all(b"{\"operation\":\"keyboard_host\"}\n")
                .await?;
            let bytes = crate::exposure_protocol::line(&mut c).await?;
            let text = String::from_utf8(bytes)?;
            ensure!(text.contains("disabled locally") && !text.contains("never-share"));
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(broker, client)?;
        set(&path, Feature::Keyboard, true)?;
        assert!(load(&path)?.enabled(Feature::Keyboard));
        Ok(())
    }
}
