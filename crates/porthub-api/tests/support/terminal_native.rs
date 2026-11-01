//! Isolated enrolled layout: real broker and CLI supervisor, no OS service calls.
use anyhow::{ensure, Context, Result};
use porthub_terminal::{multiplexer::Workspace, protocol::*};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};

pub struct Native {
    pub task: Option<AbortOnDropHandle<Result<()>>>,
    pub data: PathBuf,
    pub executable: PathBuf,
    _broker: porthub_agent::exposure_broker::Guard,
}
pub async fn start(
    root: &Path,
    workspace: &Workspace,
    hello: &HostHello,
    origin: &str,
    machine: &str,
    token: &str,
) -> Result<Native> {
    ensure!(
        cfg!(target_os = "linux"),
        "isolated native broker fixture currently requires Linux"
    );
    use std::os::unix::fs::DirBuilderExt;
    let data = root.join("native-data");
    let config = root.join("native-config");
    let state = config.join("porthub/native");
    let terminal = data.join("porthub/terminal");
    for path in [&state, &terminal] {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    let profile: porthub_agent::profile::Profile = serde_json::from_value(serde_json::json!({
        "server":origin,"machine_id":machine,"token":token,"allow_insecure_http_for_tests":true,
    }))?;
    let id = porthub_agent::service::identity(&profile);
    let layout = porthub_agent::service::Layout {
        user: true,
        state: state.clone(),
        releases: data.join("porthub/releases"),
        units: config.join("systemd/user"),
    };
    let profile_path = state.join(format!("{id}.json"));
    let spec = porthub_agent::service::Spec {
        user: true,
        identity: id.clone(),
        service: format!("porthub-{}", &id[..24]),
        profile: profile_path.clone(),
        executable: layout.releases.join("a".repeat(64)).join("porthub"),
        unit: layout.units.join(format!("porthub-{}.service", &id[..24])),
        cli: None,
    };
    porthub_agent::profile::write_private(&profile_path, &serde_json::to_vec(&profile)?, false)?;
    porthub_agent::profile::write_private(
        &state.join(format!("{id}.service.json")),
        &serde_json::to_vec(&spec)?,
        false,
    )?;
    let command = workspace.command();
    let binary = PathBuf::from(command.get_program());
    let terminfo = command
        .get_envs()
        .find_map(|(key, value)| (key == "TERMINFO").then_some(value).flatten())
        .context("bundled terminfo")?;
    use sha2::{Digest, Sha256};
    let job = serde_json::json!({"id":hello.id,"name":hello.options.name,"executable":binary,"executable_sha256":format!("{:x}",Sha256::digest(std::fs::read(&binary)?)),"terminfo":PathBuf::from(terminfo),"workspace":workspace.socket().parent(),"created_at":now()});
    porthub_agent::profile::write_private(
        &terminal.join(format!("{}.json", hello.id)),
        &serde_json::to_vec(&job)?,
        false,
    )?;
    let sharing = serde_json::json!({"hello":hello,"registration":id,"user":true,"ready":null,"state":"connecting"});
    let sharing_path = terminal.join(format!("{}.share", hello.id));
    porthub_agent::profile::write_private(&sharing_path, &serde_json::to_vec(&sharing)?, false)?;
    let control = Arc::new(porthub_agent::control::Control::new(profile)?);
    let broker = porthub_agent::exposure_broker::start_registered(
        &profile_path,
        control,
        CancellationToken::new(),
        &layout,
    )?;
    // Exercise the upcoming broker contract without installing a system service
    // or claiming that this development binary is a published 1.10 release.
    let display = porthub_agent::service::readable::Record {
        format_version: 1,
        id: id.clone(),
        machine_id: machine.into(),
        email: String::new(),
        gateway: origin.into(),
        private: false,
        enabled: true,
        active: Some(true),
        state: "running".into(),
        agent_version: "1.10.0".into(),
        ports: 0,
        route: String::new(),
        updated_at: now() as u64,
        strategy: Default::default(),
        strategy_override: false,
        private_status: None,
    };
    porthub_agent::profile::write_private(
        &state.with_file_name("status").join(format!("{id}.json")),
        &serde_json::to_vec(&display)?,
        false,
    )?;
    porthub_agent::service::readable::select(&layout, Some(&id), Some(false))?;
    let executable = PathBuf::from(
        std::env::var_os("PORTHUB_TEST_AGENT_EXECUTABLE").context("set bundled CLI path")?,
    );
    let mut child = tokio::process::Command::new(&executable)
        .args(["terminal", "__serve", &hello.id])
        .env("XDG_DATA_HOME", &data)
        .env("XDG_CONFIG_HOME", &config)
        .env_remove("TMUX")
        .env_remove("TMUX_PANE")
        .kill_on_drop(true)
        .spawn()?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            ensure!(
                child.try_wait()?.is_none(),
                "native terminal host ended before connecting"
            );
            let saved: serde_json::Value =
                serde_json::from_slice(&porthub_agent::profile::read_private(&sharing_path)?)?;
            if saved["state"] == "connected" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    let workspace = workspace.clone();
    let task = AbortOnDropHandle::new(tokio::spawn(async move {
        while workspace.is_alive() {
            ensure!(child.try_wait()?.is_none(), "native host stopped early");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let status = tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
        ensure!(status.success(), "native host failed on final shell exit");
        Ok(())
    }));
    Ok(Native {
        task: Some(task),
        data,
        executable,
        _broker: broker,
    })
}
