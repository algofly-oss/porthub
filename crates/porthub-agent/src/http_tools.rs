//! Integrated file-server lifecycle, optional temporary exposure and detachment.
use anyhow::{ensure, Context, Result};
use porthub_transfer::server;
use std::{
    fs::OpenOptions,
    process::{Command, Stdio},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
pub struct Exposure {
    pub enabled: bool,
    pub public_port: Option<u16>,
    pub subdomain: Option<String>,
    pub registration: Option<String>,
    pub user: bool,
}

pub async fn run(
    options: server::Options,
    exposure: Exposure,
    detach: bool,
    cancel: CancellationToken,
) -> Result<()> {
    if exposure.enabled {
        ensure!(
            options.bind.is_ipv4()
                && (options.bind.is_unspecified() || options.bind == std::net::Ipv4Addr::LOCALHOST),
            "--expose requires --bind 0.0.0.0 or --bind 127.0.0.1"
        );
    }
    if detach {
        return background(options, exposure).await;
    }
    if !exposure.enabled {
        return server::serve(options, cancel).await;
    }
    #[cfg(any(unix, windows))]
    {
        // Validate registration selection before opening a publicly requested
        // listener; machine authorization remains enforced by the agent/API.
        let layout = if exposure.user {
            crate::service::Layout::user()?
        } else {
            crate::service::Layout::system()?
        };
        crate::service::readable::select(&layout, exposure.registration.as_deref(), Some(false))?;
        let work = cancel.child_token();
        let _cleanup = work.clone().drop_guard();
        let (ready, port) = tokio::sync::oneshot::channel();
        let mut server_task = tokio::spawn(server::serve_ready(options, work.clone(), Some(ready)));
        let port = match port.await {
            Ok(port) => port,
            Err(_) => return server_task.await?,
        };
        let exposure_work = work.clone();
        let mut exposure_task = tokio::spawn(async move {
            crate::expose::start_registered(
                exposure.user,
                exposure.registration.as_deref(),
                port,
                exposure.public_port,
                exposure.subdomain,
                false,
                exposure_work,
            )
            .await
        });
        let (result, server_finished) = tokio::select! {
            result = &mut server_task => (result.context("HTTP server task failed")?, true),
            result = &mut exposure_task => (result.context("exposure task failed")?, false),
        };
        work.cancel();
        if server_finished {
            let cleanup = tokio::time::timeout(Duration::from_secs(16), &mut exposure_task).await;
            match cleanup {
                Ok(Ok(cleanup)) => {
                    cleanup?;
                }
                Ok(Err(error)) => return Err(error).context("exposure cleanup failed"),
                Err(_) => {
                    exposure_task.abort();
                    anyhow::bail!(
                        "exposure cleanup timed out; its gateway lease will expire automatically"
                    );
                }
            }
        } else {
            if tokio::time::timeout(Duration::from_secs(5), &mut server_task)
                .await
                .is_err()
            {
                server_task.abort();
            }
        }
        result
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = cancel;
        anyhow::bail!("integrated exposure requires an updated local registration agent")
    }
}
async fn background(options: server::Options, exposure: Exposure) -> Result<()> {
    let root = std::fs::canonicalize(&options.root).context("document root is unavailable")?;
    ensure!(root.is_dir(), "document root must be a directory");
    let state = crate::expose::job_layout()?.state;
    crate::service::directory(&state, true)?;
    let log_path = state.join(format!("http-{}.log", uuid::Uuid::new_v4().simple()));
    let log = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&log_path)?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg(if options.accept_uploads {
            "http.receive"
        } else {
            "http.server"
        })
        .arg(options.port.to_string())
        .arg(root)
        .arg("--bind")
        .arg(options.bind.to_string());
    if exposure.enabled {
        command.arg("--expose");
    }
    if let Some(port) = exposure.public_port {
        command.arg("--public-port").arg(port.to_string());
    }
    if let Some(subdomain) = exposure.subdomain {
        command.arg("--subdomain").arg(subdomain);
    }
    if let Some(registration) = exposure.registration {
        command.arg("--registration").arg(registration);
    }
    if exposure.user {
        command.arg("--user");
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x00000200 | 0x00000008);
    }
    let mut child = command.spawn()?;
    let started = tokio::time::timeout(Duration::from_secs(55), async {
        loop {
            if let Some(record) = server::list()
                .await?
                .into_iter()
                .find(|record| record.pid == child.id())
            {
                if !exposure.enabled || crate::expose::print_ready_for_pid(child.id(), record.port)?
                {
                    println!(
                        "HTTP {} running in background on {}:{}",
                        if record.accepts_uploads {
                            "receiver"
                        } else {
                            "server"
                        },
                        record.bind,
                        record.port
                    );
                    println!(
                        "Stop with: porthub http.{} stop {}",
                        if record.accepts_uploads {
                            "receive"
                        } else {
                            "server"
                        },
                        record.port
                    );
                    return Ok::<_, anyhow::Error>(());
                }
            }
            ensure!(
                child.try_wait()?.is_none(),
                "background HTTP server failed; details: {}",
                log_path.display()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    match started {
        Ok(Ok(())) => Ok(()),
        result => {
            let _ = child.kill();
            let _ = child.wait();
            match result {
                Ok(Err(error)) => Err(error),
                Err(_) => anyhow::bail!(
                    "background HTTP server timed out; details: {}",
                    log_path.display()
                ),
                _ => unreachable!(),
            }
        }
    }
}
