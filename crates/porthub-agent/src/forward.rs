//! Plain TCP forwarding over the machine's existing network routes.
use anyhow::{ensure, Context, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

#[derive(clap::Args)]
#[command(subcommand_negates_reqs = true, args_conflicts_with_subcommands = true)]
pub struct Args {
    /// Reachable hostname/IP and TCP port, e.g. 192.168.1.20:3000 or peer.phub:3000.
    #[arg(value_name = "HOST:PORT", required = true)]
    pub target: Option<String>,
    /// Local interface IP, or localhost for loopback only.
    #[arg(long, visible_alias = "host", default_value = "0.0.0.0", value_parser = bind_address)]
    pub bind: IpAddr,
    /// Local listening port; defaults to the target port.
    #[arg(short = 'p', long, visible_alias = "port", value_parser = clap::value_parser!(u16).range(1..))]
    pub local_port: Option<u16>,
    /// Run in the background and recover the mapping after restart.
    #[arg(short = 'd', short_alias = 'D', long)]
    pub detach: bool,
    #[command(subcommand)]
    pub command: Option<Command>,
}
#[derive(clap::Subcommand)]
pub enum Command {
    /// List saved forwards and their current state.
    #[command(alias = "ls")]
    List,
    /// Show a forward; a unique ID prefix or local port is accepted.
    Status { id: Option<String> },
    /// Stop a forward and remove its restart configuration.
    Stop { id: Option<String> },
}
pub fn bind_address(value: &str) -> Result<IpAddr> {
    if value.eq_ignore_ascii_case("localhost") {
        return Ok(Ipv4Addr::LOCALHOST.into());
    }
    value
        .parse()
        .context("Use a local interface IP, 0.0.0.0, ::, or localhost")
}
pub fn destination(value: &str) -> Result<(String, u16)> {
    let (host, port) = value
        .rsplit_once(':')
        .context("Use HOST:PORT (IPv6: [ADDRESS]:PORT)")?;
    let port: u16 = port.parse().context("Invalid target TCP port")?;
    let host = if host.starts_with('[') && host.ends_with(']') {
        let address: std::net::Ipv6Addr = host[1..host.len() - 1]
            .parse()
            .context("Invalid IPv6 target")?;
        address.to_string()
    } else {
        ensure!(
            !host.is_empty()
                && host.len() <= 253
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)),
            "Invalid target hostname; use HOST:PORT"
        );
        host.to_owned()
    };
    ensure!(port > 0, "Target port must be between 1 and 65535");
    Ok((host, port))
}
pub async fn run(args: Args, cancel: CancellationToken) -> Result<()> {
    if let Some(command) = args.command {
        ensure!(
            args.target.is_none() && args.local_port.is_none() && !args.detach,
            "Mapping flags apply only when starting a forward"
        );
        return match command {
            Command::List => crate::mapping_jobs::list(false),
            Command::Status { id } => crate::mapping_jobs::status(false, id.as_deref()),
            Command::Stop { id } => crate::mapping_jobs::stop(false, id.as_deref()).await,
        };
    }
    let target = args.target.context("Use porthub forward HOST:PORT")?;
    let (_, port) = destination(&target)?;
    crate::mapping_jobs::start(
        crate::mapping_jobs::Spec::Forward {
            target,
            bind: args.bind,
            port: args.local_port.unwrap_or(port),
        },
        args.detach,
        cancel,
    )
    .await
}
pub async fn serve(listener: TcpListener, target: String, cancel: CancellationToken) -> Result<()> {
    let (host, port) = destination(&target)?;
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept(), if connections.len() < 256 => {
                let (mut local, _) = accepted?;
                let host = host.clone();
                connections.spawn(async move {
                    let result = async {
                        let mut remote = tokio::time::timeout(std::time::Duration::from_secs(15), TcpStream::connect((host.as_str(),port))).await??;
                        let _ = local.set_nodelay(true); let _ = remote.set_nodelay(true);
                        tokio::io::copy_bidirectional(&mut local, &mut remote).await?;
                        Ok::<_, anyhow::Error>(())
                    }.await;
                    if let Err(error) = result { eprintln!("Forward connection failed: {error}"); }
                });
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}
pub fn address(bind: IpAddr, port: u16) -> SocketAddr {
    SocketAddr::new(bind, port)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoints_and_localhost_are_supported_without_registration() {
        assert_eq!(
            bind_address("localhost").unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            destination("localhost:3000").unwrap(),
            ("localhost".into(), 3000)
        );
        assert_eq!(destination("[::1]:5432").unwrap(), ("::1".into(), 5432));
        assert!(destination("example.com:0").is_err());
        assert!(destination("http://example.com:80").is_err());
        assert!(destination("::1:80").is_err());
    }
    #[tokio::test]
    async fn raw_tcp_forward_preserves_half_close_and_cancels_open_streams() -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let remote = TcpListener::bind("127.0.0.1:0").await?;
        let target = remote.local_addr()?.to_string();
        let server = tokio::spawn(async move {
            let (mut stream, _) = remote.accept().await?;
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await?;
            stream.write_all(&bytes).await?;
            Ok::<_, anyhow::Error>(())
        });
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let cancel = CancellationToken::new();
        let worker = tokio::spawn(serve(listener, target, cancel.clone()));
        let mut client = TcpStream::connect(address).await?;
        client
            .write_all(b"forward without SSH or a remote agent")
            .await?;
        client.shutdown().await?;
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await?;
        assert_eq!(bytes, b"forward without SSH or a remote agent");
        server.await??;
        cancel.cancel();
        worker.await??;
        assert!(TcpStream::connect(address).await.is_err());
        Ok(())
    }
}
