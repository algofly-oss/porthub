//! Sharing supervisor belongs to the invoking OS user and outlives the CLI
//! terminal. The system service brokers credentials, never launches the shell.
use super::*;
use porthub_terminal::{host::Attachments, protocol::*};
use std::{
    os::unix::process::CommandExt,
    process::{Command as Process, Stdio},
    time::Duration,
};
use tokio::io::{AsyncWriteExt, BufReader};

#[derive(Args)]
pub struct Share {
    /// Existing local workspace; omit to create one.
    existing: Option<String>,
    #[command(flatten)]
    local: New,
    #[arg(long)]
    registration: Option<String>,
    /// Select a registration installed for this OS user.
    #[arg(long)]
    user: bool,
    /// New-join invitation lifetime in seconds; zero means until session end.
    #[arg(long, default_value_t = 0)]
    link_expires: u32,
    /// Explicit workspace lifetime in seconds; zero disables this limit.
    #[arg(long, default_value_t = 0)]
    session_timeout: u32,
    /// Explicit idle limit in seconds; zero disables this limit.
    #[arg(long, default_value_t = 0)]
    idle_timeout: u32,
    #[arg(long, default_value_t = 60)]
    reconnect_timeout: u32,
    #[arg(long, default_value_t = 16)]
    max_viewers: u8,
    #[arg(long)]
    read_only: bool,
    #[arg(long,default_value="both",value_parser=["ssh","web","both"])]
    access: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Ready {
    ssh_host: String,
    ssh_port: u16,
    public_base: String,
}
#[derive(Serialize, Deserialize)]
struct Sharing {
    hello: HostHello,
    registration: String,
    user: bool,
    ready: Option<Ready>,
    state: String,
}

fn path(root: &Path, id: &str) -> Result<PathBuf> {
    ensure!(token(id, 32), "invalid terminal session identity");
    Ok(root.join(format!("{id}.share")))
}
fn load(root: &Path, id: &str) -> Result<Sharing> {
    let sharing: Sharing =
        serde_json::from_slice(&crate::profile::read_private(&path(root, id)?)?)?;
    ensure!(sharing.hello.id == id, "terminal sharing identity mismatch");
    sharing.hello.validate(now())?;
    Ok(sharing)
}
fn save(root: &Path, sharing: &Sharing, replace: bool) -> Result<()> {
    crate::profile::write_private(
        &path(root, &sharing.hello.id)?,
        &serde_json::to_vec(sharing)?,
        replace,
    )
}
fn worker_lock(root: &Path, id: &str) -> Result<fs::File> {
    ensure!(token(id, 32), "invalid terminal session identity");
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(root.join(format!("{id}.share.lock")))?;
    ensure!(
        file.metadata()?.uid() == unsafe { libc::geteuid() },
        "invalid terminal supervisor lock owner"
    );
    file.try_lock_exclusive()
        .context("terminal sharing supervisor is already running")?;
    Ok(file)
}
fn launch(root: &Path, id: &str) -> Result<()> {
    let log = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(root.join(format!("{id}.share.log")))?;
    ensure!(
        log.metadata()?.uid() == unsafe { libc::geteuid() },
        "invalid terminal supervisor log owner"
    );
    let mut command = Process::new(std::env::current_exe()?);
    command
        .args(["terminal", "__serve", id])
        .env_remove("TMUX")
        .env_remove("TMUX_PANE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log);
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    command.spawn()?;
    Ok(())
}

fn enforce_limits(workspace: &Workspace, options: &Options) -> Result<()> {
    if !workspace.is_alive() {
        return Ok(());
    }
    let session_expired = options.session_expires_at.is_some_and(|at| now() >= at);
    let idle = options.idle_timeout != 0
        && now().saturating_sub(workspace.last_activity()?) >= i64::from(options.idle_timeout);
    if session_expired || idle {
        workspace.stop()?;
    }
    Ok(())
}

pub(super) async fn start(root: &Path, args: Share) -> Result<()> {
    let layout = if args.user {
        crate::service::Layout::user()?
    } else {
        crate::service::Layout::system()?
    };
    let registration =
        crate::service::readable::select(&layout, args.registration.as_deref(), Some(false))?;
    let detach = args.local.detach;
    let json = args.local.json;
    // Validate before starting any shells or publishing session capabilities.
    let options = Options {
        name: "validation".into(),
        expires_at: if args.link_expires == 0 {
            0
        } else {
            now() + i64::from(args.link_expires)
        },
        session_expires_at: if args.session_timeout == 0 {
            None
        } else {
            Some(now() + i64::from(args.session_timeout))
        },
        idle_timeout: args.idle_timeout,
        reconnect_timeout: args.reconnect_timeout,
        history_limit: args.local.history_limit,
        mouse: !args.local.no_mouse,
        read_only: args.read_only,
        size_policy: SizePolicy::Smallest,
        max_viewers: args.max_viewers,
        access: match args.access.as_str() {
            "ssh" => Access::Ssh,
            "web" => Access::Web,
            _ => Access::Both,
        },
    };
    options.validate(now())?;
    let job = if let Some(name) = args.existing {
        select(root, &name)?
    } else {
        create(root, args.local)?
    };
    ensure!(
        workspace(&job)?.is_alive(),
        "cannot share an ended workspace"
    );
    let _registry = lock(root)?;
    if path(root, &job.id)?.exists() {
        let previous = load(root, &job.id)?;
        ensure!(
            previous.state != "ended",
            "this sharing invitation was ended; create a new workspace to share"
        );
        if let Ok(guard) = worker_lock(root, &job.id) {
            drop(guard);
            launch(root, &job.id)?;
        }
    } else {
        let mut options = options;
        options.name = job.name.clone();
        let sharing = Sharing {
            hello: HostHello {
                id: job.id.clone(),
                secret: random_token(32),
                write_token: random_token(32),
                read_token: random_token(32),
                options,
            },
            registration: registration.id,
            user: args.user,
            ready: None,
            state: "connecting".into(),
        };
        save(root, &sharing, false)?;
        launch(root, &job.id)?;
    }
    drop(_registry);
    for _ in 0..300 {
        let state = load(root, &job.id)?;
        if state.state == "connected" {
            break;
        }
        ensure!(
            state.state != "ended",
            "workspace ended before sharing connected"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    invite(root, &job, json)?;
    if !detach {
        attach(&job)?;
    }
    Ok(())
}

pub(super) fn invite(root: &Path, job: &Job, json: bool) -> Result<()> {
    let sharing = load(root, &job.id)?;
    ensure!(sharing.state != "ended", "sharing session has ended");
    let Some(ready) = sharing.ready else {
        anyhow::bail!("workspace {} is running locally, but sharing is still reconnecting; use terminal invite {} when the gateway is available",job.name,job.name);
    };
    let link = |token: &str| {
        format!(
            "{}/terminal#{token}",
            ready.public_base.trim_end_matches('/')
        )
    };
    let ssh = |token: &str| format!("ssh -p {} -l {} {}", ready.ssh_port, token, ready.ssh_host);
    let web = sharing.hello.options.access != Access::Ssh;
    let ssh_enabled = sharing.hello.options.access != Access::Web;
    let interactive = !sharing.hello.options.read_only;
    let data = serde_json::json!({"name":job.name,"id":job.id,"state":sharing.state,
        "interactive_url":(web && interactive).then(||link(&sharing.hello.write_token)),
        "read_only_url":web.then(||link(&sharing.hello.read_token)),
        "interactive_ssh":(ssh_enabled && interactive).then(||ssh(&sharing.hello.write_token)),
        "read_only_ssh":ssh_enabled.then(||ssh(&sharing.hello.read_token)),
        "expires_at":sharing.hello.options.expires_at,"access":sharing.hello.options.access});
    if json {
        println!("{}", serde_json::to_string(&data)?);
    } else {
        println!("Workspace {}", job.name);
        for (key, label) in [
            ("interactive_url", "Interactive"),
            ("read_only_url", "Read only"),
            ("interactive_ssh", "SSH"),
            ("read_only_ssh", "Read-only SSH"),
        ] {
            if let Some(value) = data[key].as_str() {
                println!("{label}: {value}");
            }
        }
        println!("Reattach: porthub terminal attach {}", job.name);
        if sharing.hello.options.expires_at != 0 && sharing.hello.options.expires_at <= now() {
            println!(
                "Invitation expired: existing participants may continue; new joins are blocked."
            );
        }
    }
    Ok(())
}

pub(super) async fn join(invitation: &str) -> Result<()> {
    let mut url =
        url::Url::parse(invitation).context("provide the complete terminal invitation URL")?;
    ensure!(
        url.scheme() == "https" && url.username().is_empty() && url.password().is_none(),
        "terminal invitations must use HTTPS"
    );
    let capability = url
        .fragment()
        .context("terminal invitation is missing its capability")?
        .to_owned();
    ensure!(token(&capability, 64), "invalid terminal invitation");
    url.set_fragment(None);
    url.set_query(None);
    url.set_path("/api/terminal/info");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()?;
    let response = client
        .post(url)
        .json(&serde_json::json!({"token":capability}))
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "terminal invitation expired, revoked, or host unavailable"
    );
    let info: serde_json::Value = response.json().await?;
    let info = info.get("data").unwrap_or(&info);
    ensure!(
        info["access"] != "web",
        "this invitation allows browser access only; open it in your browser"
    );
    let host = info["ssh_host"]
        .as_str()
        .context("SSH endpoint is unavailable")?;
    ensure!(valid_ssh_host(host), "invalid terminal SSH endpoint");
    let port = info["ssh_port"]
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port > 0)
        .context("invalid terminal SSH port")?;
    let status = Process::new("ssh")
        .args(["-p", &port.to_string(), "-l", &capability, "--", host])
        .status()
        .context("SSH client unavailable; install OpenSSH or open the browser invitation")?;
    ensure!(
        status.success(),
        "terminal SSH connection ended with an error"
    );
    Ok(())
}

fn valid_ssh_host(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
        || !host.is_empty()
            && host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
}

pub(super) async fn serve(root: &Path, id: &str) -> Result<()> {
    let _guard = worker_lock(root, id)?;
    let job = select(root, id)?;
    let workspace = workspace(&job)?;
    let mut owner = super::participant_control::Server::start(&job)?;
    let mut sharing = load(root, id)?;
    ensure!(sharing.state != "ended", "sharing session has ended");
    let layout = if sharing.user {
        crate::service::Layout::user()?
    } else {
        crate::service::Layout::system()?
    };
    let mut delay = 1;
    loop {
        enforce_limits(&workspace, &sharing.hello.options)?;
        {
            let mut state = owner.state.lock().expect("owner state");
            state.connected = false;
            state.members.clear();
        }
        sharing.state = "reconnecting".into();
        save(root, &sharing, true)?;
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            crate::exposure_broker::connect_stream(&layout, &sharing.registration),
        )
        .await;
        if let Ok(Ok(stream)) = result {
            let mut local = BufReader::new(stream);
            let mut request = serde_json::to_vec(
                &serde_json::json!({"operation":"terminal_host","hello":sharing.hello}),
            )?;
            request.push(b'\n');
            if local.get_mut().write_all(&request).await.is_ok() {
                let mut attachments = Attachments::new(
                    workspace.clone(),
                    usize::from(sharing.hello.options.max_viewers),
                )?;
                let mut partial = Vec::new();
                let mut tick = tokio::time::interval(Duration::from_secs(1));
                let mut last_gateway = tokio::time::Instant::now();
                loop {
                    tokio::select! {
                        bytes=crate::terminal_transport::frame(&mut local,&mut partial)=> {
                            let Ok(bytes)=bytes else{break;};
                            let Ok(event)=serde_json::from_slice::<HostEvent>(&bytes) else{break;};
                            last_gateway=tokio::time::Instant::now();
                            if matches!(event,HostEvent::Stop{..}) {
                                sharing.state="ended".into();save(root,&sharing,true)?;
                                // Revocation ends sharing. The local owner keeps
                                // the workspace and can explicitly stop it.
                                return Ok(());
                            }
                            if let HostEvent::Presence { members } = &event {
                                let mut state=owner.state.lock().expect("owner state");state.connected=true;state.members=members.clone();
                            }
                            if let HostEvent::Ready{ssh_host,ssh_port,public_base}=&event {
                                sharing.ready=Some(Ready{ssh_host:ssh_host.clone(),ssh_port:*ssh_port,public_base:public_base.clone()});
                                sharing.state="connected".into();save(root,&sharing,true)?;delay=1;
                            }
                            if !attachments.apply(event)?{break;}
                        }
                        request=owner.requests.recv()=> {
                            let Some((client, reply))=request else {break;};
                            let bytes=serde_json::to_vec(&HostOutput::Kick {client})?;
                            let mut frame=bytes;frame.push(b'\n');
                            let result=tokio::time::timeout(Duration::from_secs(2),local.get_mut().write_all(&frame)).await;
                            let ok=matches!(result,Ok(Ok(())));
                            let _=reply.send(if ok {Ok(())} else {Err("gateway connection unavailable".into())});
                            if !ok {break;}
                        }
                        output=attachments.next()=> {
                            let Some(output)=output else{break;};
                            let mut bytes=serde_json::to_vec(&output)?;bytes.push(b'\n');
                            if !matches!(tokio::time::timeout(Duration::from_secs(5),local.get_mut().write_all(&bytes)).await,Ok(Ok(()))){break;}
                        }
                        _=tick.tick()=> {
                            enforce_limits(&workspace,&sharing.hello.options)?;
                            if !workspace.is_alive(){
                                sharing.state="ended".into();save(root,&sharing,true)?;
                                let _=tokio::time::timeout(Duration::from_secs(2),local.get_mut().write_all(b"{\"type\":\"end\"}\n")).await;
                                return Ok(());
                            }
                            if last_gateway.elapsed()>Duration::from_secs(45){break;}
                        }
                    }
                }
            }
        }
        {
            let mut state = owner.state.lock().expect("owner state");
            state.connected = false;
            state.members.clear();
        }
        while let Ok((_, reply)) = owner.requests.try_recv() {
            let _ = reply.send(Err("gateway reconnecting; refresh participants".into()));
        }
        sharing.state = "reconnecting".into();
        save(root, &sharing, true)?;
        if !workspace.is_alive() {
            sharing.state = "ended".into();
            save(root, &sharing, true)?;
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(delay)).await;
        delay = (delay * 2).min(15);
    }
}
