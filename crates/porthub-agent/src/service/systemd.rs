//! Direct D-Bus control; systemctl and shell helpers are not runtime dependencies.
use super::{Manager, Spec, State};
use anyhow::{Context, Result};
use futures_util::StreamExt;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
type Properties = Vec<(String, OwnedValue)>;
#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
trait SystemdManager {
    fn start_transient_unit(
        &self,
        name: &str,
        mode: &str,
        properties: Properties,
        auxiliary: Vec<(String, Properties)>,
    ) -> zbus::Result<OwnedObjectPath>;
    fn reload(&self) -> zbus::Result<()>;
    fn subscribe(&self) -> zbus::Result<()>;
    fn reset_failed_unit(&self, name: &str) -> zbus::Result<()>;
    fn enable_unit_files(
        &self,
        files: Vec<String>,
        runtime: bool,
        force: bool,
    ) -> zbus::Result<(bool, Vec<(String, String, String)>)>;
    fn disable_unit_files(
        &self,
        files: Vec<String>,
        runtime: bool,
    ) -> zbus::Result<Vec<(String, String, String)>>;
    fn restart_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn stop_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn get_unit_file_state(&self, name: &str) -> zbus::Result<String>;
    fn load_unit(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
}
fn missing(error: &zbus::Error) -> bool {
    matches!(error,zbus::Error::MethodError(name,_,_) if ["org.freedesktop.systemd1.NoSuchUnitFile","org.freedesktop.systemd1.NoSuchUnit","org.freedesktop.DBus.Error.FileNotFound"].contains(&name.as_str()))
}
pub struct Systemd {
    connection: zbus::Connection,
    subscribed: tokio::sync::OnceCell<()>,
}
impl Systemd {
    /// Queue an owned native adoption executable in an independent service.
    /// ExecStart is a typed argv array, never an interpreted shell command.
    /// Returning the manager's job receipt does not depend on the caller's
    /// process group surviving the subsequent stop of its old service.
    pub async fn schedule_adoption(
        &self,
        executable: &std::path::Path,
        arguments: &[String],
    ) -> Result<String> {
        self.schedule(executable, arguments, "adopt-legacy", "porthub-adoption")
            .await
    }
    pub async fn schedule_update(
        &self,
        executable: &std::path::Path,
        arguments: &[String],
    ) -> Result<String> {
        self.schedule(executable, arguments, "update", "porthub-update")
            .await
    }
    async fn schedule(
        &self,
        executable: &std::path::Path,
        arguments: &[String],
        command: &str,
        prefix: &str,
    ) -> Result<String> {
        use sha2::{Digest, Sha256};
        let executable = executable
            .to_str()
            .context("maintenance executable must be Unicode")?;
        anyhow::ensure!(
            std::path::Path::new(executable).is_absolute()
                && arguments
                    .first()
                    .is_some_and(|argument| argument == command)
                && arguments.iter().any(|argument| argument == "--apply")
                && arguments.len() <= 32
                && arguments
                    .iter()
                    .all(|argument| argument.len() <= 4096
                        && !argument.chars().any(char::is_control)),
            "invalid native maintenance command"
        );
        let digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&(executable, arguments))?)
        );
        let name = format!("{prefix}-{}.service", &digest[..24]);
        let mut argv = vec![executable.to_owned()];
        argv.extend_from_slice(arguments);
        let mut properties = vec![
            (
                "Description".into(),
                OwnedValue::try_from(Value::from("PortHub native agent maintenance"))?,
            ),
            ("Type".into(), OwnedValue::try_from(Value::from("exec"))?),
            (
                "CollectMode".into(),
                OwnedValue::try_from(Value::from("inactive-or-failed"))?,
            ),
            ("UMask".into(), OwnedValue::from(0o077u32)),
            ("NoNewPrivileges".into(), OwnedValue::from(true)),
            (
                "ExecStartEx".into(),
                OwnedValue::try_from(Value::from(vec![(
                    executable.to_owned(),
                    argv,
                    vec!["no-env-expand".to_owned()],
                )]))?,
            ),
        ];
        if command == "update" && arguments.iter().any(|argument| argument == "--user") {
            let mut environment = Vec::new();
            for name in ["XDG_CONFIG_HOME", "XDG_DATA_HOME"] {
                if let Some(value) = std::env::var_os(name) {
                    let value = value
                        .to_str()
                        .context("user service directory must be Unicode")?;
                    anyhow::ensure!(
                        std::path::Path::new(value).is_absolute()
                            && value.len() <= 4096
                            && !value.chars().any(char::is_control),
                        "invalid user service directory"
                    );
                    environment.push(format!("{name}={value}"));
                }
            }
            if !environment.is_empty() {
                properties.push((
                    "Environment".into(),
                    OwnedValue::try_from(Value::from(environment))?,
                ));
            }
        }
        let proxy = self.proxy().await?;
        proxy
            .start_transient_unit(&name, "fail", properties, vec![])
            .await
            .context("could not schedule native maintenance")?;
        Ok(name)
    }
    pub async fn connect() -> Result<Self> {
        Ok(Self {
            connection: zbus::connection::Builder::system()?
                .method_timeout(super::OPERATION_TIMEOUT)
                .build()
                .await
                .context("systemd D-Bus is required for boot-time services")?,
            subscribed: Default::default(),
        })
    }
    pub async fn connect_user() -> Result<Self> {
        Ok(Self {
            connection: zbus::connection::Builder::session()?
                .method_timeout(super::OPERATION_TIMEOUT)
                .build()
                .await
                .context("a systemd user session is required")?,
            subscribed: Default::default(),
        })
    }
    pub fn from_connection(connection: zbus::Connection) -> Self {
        Self {
            connection,
            subscribed: Default::default(),
        }
    }
    async fn proxy(&self) -> Result<SystemdManagerProxy<'_>> {
        Ok(SystemdManagerProxy::new(&self.connection).await?)
    }
    async fn job(&self, spec: &Spec, start: bool) -> Result<()> {
        let proxy = self.proxy().await?;
        self.subscribed
            .get_or_try_init(|| async { proxy.subscribe().await })
            .await?;
        // Subscribe before enqueueing so fast jobs cannot finish between the
        // method reply and registration. An old active process is not success.
        let mut signals = proxy.inner().receive_signal("JobRemoved").await?;
        let name = format!("{}.service", spec.service);
        let job = if start {
            proxy.restart_unit(&name, "replace").await?
        } else {
            match proxy.stop_unit(&name, "replace").await {
                Ok(job) => job,
                Err(error) if missing(&error) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        };
        tokio::time::timeout(super::OPERATION_TIMEOUT, async {
            while let Some(signal) = signals.next().await {
                let (_, path, unit, result): (u32, OwnedObjectPath, String, String) =
                    signal.body().deserialize()?;
                if path == job && unit == name {
                    anyhow::ensure!(
                        result == "done",
                        "PortHub service job did not complete successfully ({result})"
                    );
                    return Ok::<(), anyhow::Error>(());
                }
            }
            anyhow::bail!("systemd job signal stream closed")
        })
        .await
        .context("systemd service job timed out")??;
        self.wait(spec, start).await
    }
    async fn active(&self, spec: &Spec) -> Result<String> {
        let path = self
            .proxy()
            .await?
            .load_unit(&format!("{}.service", spec.service))
            .await?;
        let unit = zbus::Proxy::new(
            &self.connection,
            "org.freedesktop.systemd1",
            path,
            "org.freedesktop.systemd1.Unit",
        )
        .await?;
        Ok(unit.get_property::<String>("ActiveState").await?)
    }
    async fn wait(&self, spec: &Spec, active: bool) -> Result<()> {
        tokio::time::timeout(super::OPERATION_TIMEOUT, async {
            loop {
                let state = self.active(spec).await?;
                if active && state == "active"
                    || !active && ["inactive", "failed"].contains(&state.as_str())
                {
                    return Ok::<(), anyhow::Error>(());
                }
                anyhow::ensure!(
                    !active || state != "failed",
                    "PortHub service failed to start"
                );
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .context("systemd service operation timed out")?
    }
}
#[async_trait::async_trait]
impl Manager for Systemd {
    async fn state(&self, spec: &Spec) -> Result<State> {
        let proxy = self.proxy().await?;
        let enabled = match proxy
            .get_unit_file_state(&format!("{}.service", spec.service))
            .await
        {
            Ok(state) => state,
            Err(zbus::Error::MethodError(name, _, _))
                if [
                    "org.freedesktop.systemd1.NoSuchUnitFile",
                    "org.freedesktop.systemd1.NoSuchUnit",
                    "org.freedesktop.DBus.Error.FileNotFound",
                ]
                .contains(&name.as_str()) =>
            {
                return Ok(State {
                    installed: false,
                    enabled: false,
                    active: false,
                })
            }
            Err(error) => return Err(error.into()),
        };
        Ok(State {
            installed: true,
            enabled: ["enabled", "enabled-runtime"].contains(&enabled.as_str()),
            active: self.active(spec).await? == "active",
        })
    }
    async fn reload(&self) -> Result<()> {
        self.proxy().await?.reload().await?;
        Ok(())
    }
    async fn enable(&self, spec: &Spec) -> Result<()> {
        self.proxy()
            .await?
            .enable_unit_files(
                vec![spec
                    .unit
                    .to_str()
                    .context("service unit path must be Unicode")?
                    .to_owned()],
                false,
                false,
            )
            .await?;
        Ok(())
    }
    async fn disable(&self, spec: &Spec) -> Result<()> {
        self.proxy()
            .await?
            .disable_unit_files(vec![format!("{}.service", spec.service)], false)
            .await?;
        Ok(())
    }
    async fn reset_failed(&self, spec: &Spec) -> Result<()> {
        match self
            .proxy()
            .await?
            .reset_failed_unit(&format!("{}.service", spec.service))
            .await
        {
            Ok(()) => Ok(()),
            Err(error) if missing(&error) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
    async fn start(&self, spec: &Spec) -> Result<()> {
        self.job(spec, true).await
    }
    async fn stop(&self, spec: &Spec) -> Result<()> {
        self.job(spec, false).await
    }
}
