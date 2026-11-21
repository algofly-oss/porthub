//! A managed launchd worker keeps only the supplemental DNS registration and
//! duplicate kernel endpoints. Every answer comes from a freshly admitted agent.
mod ipc;
use super::{
    authority_clock::{NativeClock, SuspendClock},
    dns,
    dns_convergence_macos::{self as convergence, Endpoint},
    dns_private_macos,
    dns_recovery::Scope,
    sleep_generation::Generation,
};
use crate::{private_profile::Profile, service::launchd::dns_guard as job};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    net::{Ipv4Addr, TcpListener, UdpSocket},
    os::fd::OwnedFd,
    path::Path,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
use tokio_util::sync::CancellationToken;

const WINDOW: Duration = Duration::from_secs(12);
const IDLE: Duration = Duration::from_secs(10);

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Claim {
    binding: String,
    suffixes: Vec<String>,
}

pub(super) struct Handle {
    stream: UnixStream,
    key: String,
    pub(super) endpoints: Vec<Endpoint>,
}

impl Handle {
    pub(super) async fn published(&self, suffixes: &[String], port: u16) -> Result<bool> {
        if self.endpoints.len() != suffixes.len()
            || !self
                .endpoints
                .iter()
                .all(|e| e.port == port && suffixes.contains(&e.suffix))
        {
            return Ok(false);
        }
        dns_private_macos::published(&self.key, &self.endpoints, suffixes, port).await
    }

    pub(super) fn maintain(&self, recovered: bool) -> std::io::Result<()> {
        // No responses are sent during service. Detect a dead companion even
        // when the OS has not emitted a DNS notification.
        match self.stream.try_read(&mut [0u8]) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
            Ok(_) => return Err(std::io::ErrorKind::BrokenPipe.into()),
        }
        if recovered {
            self.stream.try_write(b"R")?;
        }
        Ok(())
    }

    pub(super) async fn close(&mut self) -> Result<()> {
        self.stream.write_all(b"X").await?;
        ensure!(
            tokio::time::timeout(Duration::from_secs(3), self.stream.read_u8()).await?? == b'X',
            "DNS guard did not acknowledge closure"
        );
        Ok(())
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        let _ = self.stream.try_write(b"X");
    }
}

pub(super) async fn claim(
    path: &Path,
    profile: &Profile,
    scope: &Scope,
) -> Result<Option<(dns::Server, Handle)>> {
    let Some(socket) = job::registered_socket(path).await? else {
        return Ok(None);
    };
    let request = Claim {
        binding: scope.binding(profile)?,
        suffixes: scope.suffixes().to_vec(),
    };
    let claim = async {
        let mut stream = ipc::connect(&socket).await?;
        ipc::write(&mut stream, &serde_json::to_vec(&request)?).await?;
        let key = String::from_utf8(ipc::read(&mut stream).await?)?;
        let uuid = key
            .strip_prefix("State:/Network/Service/PortHub-Private-")
            .and_then(|s| s.strip_suffix("/DNS"))
            .context("invalid owned resolver key")?;
        ensure!(
            uuid.len() == 32 && uuid.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid owned resolver ID"
        );
        let server = dns::Server::from_local_queue(ipc::receive(&stream).await?)?;
        let port = server.port()?;
        let endpoints = request
            .suffixes
            .iter()
            .map(|suffix| Endpoint {
                suffix: suffix.clone(),
                port,
            })
            .collect();
        let guard = Handle {
            stream,
            key,
            endpoints,
        };
        ensure!(
            guard.published(&request.suffixes, port).await?,
            "DNS guard registration changed"
        );
        ensure!(
            Profile::load(path)? == *profile,
            "profile changed while claiming DNS endpoints"
        );
        Ok(Some((server, guard)))
    };
    tokio::time::timeout(Duration::from_secs(12), claim)
        .await
        .context("local DNS guard unavailable")?
}

struct Published {
    claim: Claim,
    handles: (File, File),
    session: dns_private_macos::Session,
    generation: Option<Generation>,
}
impl Published {
    async fn open(claim: Claim) -> Result<Self> {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr = udp.local_addr()?;
        let tcp = TcpListener::bind(addr)?;
        udp.set_nonblocking(true)?;
        tcp.set_nonblocking(true)?;
        let mut session = dns_private_macos::register(addr.port(), &claim.suffixes, &[]).await?;
        session.wait_for_change().await?;
        convergence::wait(&session.endpoints, &[]).await?;
        Ok(Self {
            claim,
            handles: (
                File::from(OwnedFd::from(udp)),
                File::from(OwnedFd::from(tcp)),
            ),
            session,
            generation: Generation::read(),
        })
    }
    async fn close(mut self) -> Result<()> {
        self.session.close().await?;
        convergence::wait(&[], &self.session.endpoints).await
    }
    async fn client(&mut self, stream: &mut UnixStream) -> Result<bool> {
        let port = self.session.endpoints[0].port;
        ensure!(
            self.session
                .is_published(&self.claim.suffixes, port)
                .await?,
            "owned DNS registration changed"
        );
        ipc::write(stream, self.session.key().as_bytes()).await?;
        ipc::send(stream, &self.handles).await?;
        // No DNS reader exists here. A dead agent therefore cannot leave an
        // answer cache, permit or upstream service behind in this process.
        let mut inspect = tokio::time::interval(Duration::from_secs(5));
        loop {
            let mut command = [0];
            tokio::select! {
                n=stream.read(&mut command)=>match (n?,command[0]){
                    (0,_)=>return Ok(true),
                    (1,b'X')=>return Ok(false),
                    (1,b'R')=>self.session.maintain(true),
                    _=>anyhow::bail!("invalid DNS guard control byte"),
                },
                _=inspect.tick()=>self.session.maintain(false),
            }
        }
    }
}

pub async fn run(registration: &str, cancel: CancellationToken) -> Result<()> {
    ensure!(
        rustix::process::geteuid().is_root(),
        "DNS guard requires the managed system service"
    );
    let listener = ipc::activated(&job::socket(registration)?)?;
    tokio::select! {biased; _=cancel.cancelled()=>Ok(()), result=serve(listener, |pid| job::authorized(registration,pid))=>result}
}

async fn serve<F, A>(listener: tokio::net::UnixListener, authorize: F) -> Result<()>
where
    F: Fn(u32) -> A,
    A: std::future::Future<Output = Result<bool>>,
{
    let mut previous: Option<Published> = None;
    let mut deadline = None;
    loop {
        let remaining = deadline.map_or(IDLE, |end: Duration| {
            end.saturating_sub(NativeClock.elapsed_since_boot().unwrap_or(Duration::MAX))
        });
        let next = async {
            let (mut stream, _) = listener.accept().await?;
            ensure!(
                authorize(ipc::peer_pid(&stream)?).await?,
                "DNS guard client is not the registered service"
            );
            let request: Claim = serde_json::from_slice(&ipc::read(&mut stream).await?)?;
            ensure!(
                request.binding.len() == 64
                    && request.binding.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid DNS guard registration binding"
            );
            Ok::<_, anyhow::Error>((stream, request))
        };
        let (mut stream, request) = tokio::select! {
            biased;
            _=crate::unified::suspend_aware_delay(remaining)=>{ if let Some(old)=previous.take(){old.close().await?;} return Ok(()); },
            pair=next=>pair?,
        };
        let resume = previous.as_ref().is_some_and(|old| {
            old.claim == request
                && old.generation.is_some()
                && old.generation == Generation::read()
                && deadline
                    .is_some_and(|end| NativeClock.elapsed_since_boot().is_ok_and(|now| now < end))
        });
        let mut current = if resume {
            previous.take().unwrap()
        } else {
            if let Some(old) = previous.take() {
                old.close().await?;
            }
            Published::open(request).await?
        };
        if !current.client(&mut stream).await? {
            // The parent reconciles the OS table against the replacement and
            // may intentionally keep overlapping endpoints during a rule edit.
            current.session.close().await?;
            stream.write_all(b"X").await?;
            return Ok(());
        }
        if current.generation.is_none() || current.generation != Generation::read() {
            current.close().await?;
            return Ok(());
        }
        deadline = Some(
            NativeClock
                .elapsed_since_boot()?
                .checked_add(WINDOW)
                .context("invalid DNS restart deadline")?,
        );
        previous = Some(current);
    }
}

#[cfg(test)]
mod tests;
