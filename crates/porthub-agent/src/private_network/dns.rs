//! Authoritative private-zone DNS with bounded forwarding for controlled names.
//! Explicit local-Tor exit policies also route public-name resolution through Tor.
use super::policy::Snapshot;
use anyhow::{ensure, Result};
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{rdata::A, DNSClass, RData, Record, RecordType},
};
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    sync::Arc,
};
use tokio::{net::{TcpListener, UdpSocket}, sync::RwLock};
use tokio_util::sync::CancellationToken;
#[derive(Default)]
pub struct Zone {
    suffixes: HashSet<String>,
    records: HashMap<String, Ipv4Addr>,
    rules: Vec<porthub_mesh::dns_policy::Rule>,
    forward_all: bool,
    management_names: HashSet<String>,
}
impl Zone {
    pub fn update(&mut self, snapshot: &Snapshot) -> Result<()> {
        let own = snapshot
            .peers
            .iter()
            .find(|p| p.id == snapshot.self_)
            .ok_or_else(|| anyhow::anyhow!("private DNS identity missing"))?;
        let (_, suffix) = own
            .hostname
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("private DNS suffix missing"))?;
        ensure!(
            !suffix.is_empty() && suffix.len() < 254 && !suffix.ends_with('.'),
            "invalid private DNS suffix"
        );
        let mut suffixes: HashSet<String> = snapshot
            .dns_suffixes
            .iter()
            .map(|suffix| format!("{}.", suffix.trim_matches('.').to_ascii_lowercase()))
            .collect();
        suffixes.insert(format!(
            "{}.",
            suffix.trim_matches('.').to_ascii_lowercase()
        ));
        let mut records = HashMap::new();
        for peer in &snapshot.peers {
            for name in std::iter::once(&peer.hostname).chain(&peer.aliases) {
                let name = format!("{}.", name.trim_end_matches('.').to_ascii_lowercase());
                ensure!(
                    name.len() <= 254
                        && suffixes
                            .iter()
                            .any(|suffix| name.ends_with(&format!(".{suffix}"))),
                    "private name outside assigned DNS suffixes"
                );
                ensure!(
                    records
                        .insert(name, peer.ip)
                        .is_none_or(|old| old == peer.ip),
                    "private DNS name collision"
                );
            }
        }
        let rules = porthub_mesh::dns_policy::prepare(&snapshot.dns_rules)?;
        for rule in &rules {
            let domain = format!("{}.", porthub_mesh::dns_policy::zone(rule));
            ensure!(!suffixes.iter().any(|suffix| domain == *suffix
                || domain.ends_with(&format!(".{suffix}"))
                || suffix.ends_with(&format!(".{domain}"))),
                "DNS policy conflicts with a private identity zone");
        }
        self.rules = rules;
        self.suffixes = suffixes;
        self.records = records;
        self.forward_all=snapshot.exit_routes.iter().any(|route|route.tor_enabled && route.traffic_mode.internet() && route.clients.contains(&snapshot.self_));
        Ok(())
    }
    pub fn answer(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        if bytes.len() > 1500 {
            return None;
        }
        let query = Message::from_vec(bytes).ok()?;
        if query.metadata.message_type != MessageType::Query || query.queries.len() != 1 {
            return None;
        }
        let q = &query.queries[0];
        let name = q.name().to_ascii().to_ascii_lowercase();
        let mut reply = Message::new(
            query.metadata.id,
            MessageType::Response,
            query.metadata.op_code,
        );
        reply.metadata.authoritative = true;
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.add_query(q.clone());
        if query.metadata.op_code == OpCode::Query {
            if porthub_mesh::dns_policy::matching(&self.rules, &name).is_some() {
                reply.metadata.response_code = ResponseCode::NXDomain;
                return reply.to_vec().ok();
            }
        }
        let code = if query.metadata.op_code != OpCode::Query {
            ResponseCode::NotImp
        } else if !self
            .suffixes
            .iter()
            .any(|suffix| name == *suffix || name.ends_with(&format!(".{suffix}")))
        {
            ResponseCode::Refused
        } else if !self.records.contains_key(&name) && !self.suffixes.contains(&name) {
            ResponseCode::NXDomain
        } else {
            ResponseCode::NoError
        };
        reply.metadata.response_code = code;
        if code == ResponseCode::NoError
            && q.query_class() == DNSClass::IN
            && q.query_type() == RecordType::A
        {
            if let Some(ip) = self.records.get(&name) {
                reply.add_answer(Record::from_rdata(q.name().clone(), 5, RData::A(A(*ip))));
            }
        }
        reply.to_vec().ok()
    }

    fn needs_upstream(&self, bytes: &[u8]) -> bool {
        let Ok(query) = Message::from_vec(bytes) else { return false; };
        if bytes.len() > 1500 || query.metadata.message_type != MessageType::Query
            || query.metadata.op_code != OpCode::Query || query.queries.len() != 1 { return false; }
        let question = &query.queries[0];
        if question.query_class() != DNSClass::IN { return false; }
        let name = question.name().to_ascii().trim_end_matches('.').to_ascii_lowercase();
        if self.suffixes.iter().any(|suffix| within(&name, suffix.trim_end_matches('.'))) { return false; }
        if self.management_names.contains(&name) {return true;}
        porthub_mesh::dns_policy::matching(&self.rules, &name).is_none()
            && (self.forward_all || self.rules.iter().any(|rule| within(&name, porthub_mesh::dns_policy::zone(rule))))
    }
}

fn within(name: &str, suffix: &str) -> bool {
    name == suffix || name.strip_suffix(suffix).is_some_and(|prefix| prefix.ends_with('.'))
}

#[cfg(test)]
mod tor_coexistence_tests {
    use super::*;
    use hickory_proto::{op::Query,rr::Name};
    #[test]
    fn private_identity_and_dns_rules_win_while_control_hosts_stay_reachable() -> Result<()> {
        use porthub_mesh::dns_policy::{Rule,Action};
        let zone=Zone {
            suffixes:HashSet::from(["phub.".into()]),
            records:HashMap::from([("miro.phub.".into(),"10.203.0.2".parse()?)]),
            rules:vec![Rule {domain:"blocked.test".into(),include_subdomains:false,action:Action::Block},Rule {domain:"gateway.test".into(),include_subdomains:false,action:Action::Block}],
            forward_all:true,management_names:HashSet::from(["gateway.test".into()]),
        };
        let query=|name:&str|->Result<Vec<u8>> {let mut query=Message::query();query.add_query(Query::query(Name::from_ascii(name)?,RecordType::A));Ok(query.to_vec()?)};
        let private=query("miro.phub.")?;assert!(!zone.needs_upstream(&private));
        assert_eq!(Message::from_vec(&zone.answer(&private).unwrap())?.answers.len(),1);
        let blocked=query("blocked.test.")?;assert!(!zone.needs_upstream(&blocked));
        assert_eq!(Message::from_vec(&zone.answer(&blocked).unwrap())?.metadata.response_code,ResponseCode::NXDomain);
        assert!(zone.needs_upstream(&query("public.test.")?));
        assert!(zone.needs_upstream(&query("gateway.test.")?));
        Ok(())
    }
}
pub struct Server {
    socket: UdpSocket,
    tcp: TcpListener,
    pub zone: Arc<RwLock<Zone>>,
    pub(super) upstream: Arc<super::dns_upstream::Upstream>,
}
impl Server {
    #[cfg(feature="local-tor")]
    pub(super) async fn protect_management(&self,names:HashSet<String>,sources:tokio::sync::watch::Receiver<Vec<std::net::SocketAddr>>) {
        self.zone.write().await.management_names=names.clone();
        self.upstream.protect_management(names,sources);
    }
    pub async fn bind(own: Ipv4Addr) -> Result<Self> {
        ensure!(
            own.is_private(),
            "private DNS requires the assigned address"
        );
        // Bind TCP and UDP on the same private resolver endpoint. OS resolver
        // registration applies to both transports.
        #[cfg(target_os = "linux")]
        let address = (own, 0);
        #[cfg(target_os = "macos")]
        let address = (Ipv4Addr::LOCALHOST, 0);
        #[cfg(windows)]
        let address = (Ipv4Addr::LOCALHOST, 53);
        let socket = UdpSocket::bind(address).await?;
        let tcp = TcpListener::bind(socket.local_addr()?).await?;
        Ok(Self { socket, tcp, zone: Default::default(), upstream: Default::default() })
    }
    pub fn port(&self) -> Result<u16> {
        Ok(self.socket.local_addr()?.port())
    }
    pub async fn serve(self, cancel: CancellationToken) -> Result<()> {
        let upstream=self.upstream.clone();
        self.serve_with(cancel, upstream).await
    }
    async fn serve_with(self, cancel: CancellationToken, upstream: Arc<super::dns_upstream::Upstream>) -> Result<()> {
        let address = self.socket.local_addr()?;
        let own = address.ip();
        let socket = Arc::new(self.socket);
        let mut buffer = [0; 1501];
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _=cancel.cancelled()=>return Ok(()),
                _=connections.join_next(), if !connections.is_empty()=>{},
                accepted=self.tcp.accept()=>{
                    let (mut stream, remote) = accepted?;
                    if (remote.ip()!=own && !remote.ip().is_loopback()) || connections.len() >= 32 { continue; }
                    let zone = self.zone.clone();
                    let upstream = upstream.clone();
                    connections.spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let exchange = async {
                            for _ in 0..64 {
                                let length = stream.read_u16().await? as usize;
                                anyhow::ensure!((12..=1500).contains(&length), "invalid DNS query size");
                                let mut query = vec![0; length];
                                stream.read_exact(&mut query).await?;
                                let answer = answer_with_upstream(&zone, &upstream, &query, address, true).await;
                                if let Some(answer) = answer {
                                    stream.write_u16(answer.len() as u16).await?;
                                    stream.write_all(&answer).await?;
                                } else { break; }
                            }
                            Ok::<_, anyhow::Error>(())
                        };
                        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), exchange).await;
                    });
                },
                packet=socket.recv_from(&mut buffer)=>{
                let (n,remote)=packet?; if remote.ip()!=own && !remote.ip().is_loopback() {continue;}
                if self.zone.read().await.needs_upstream(&buffer[..n]) {
                    if connections.len() >= 32 { continue; }
                    let query = buffer[..n].to_vec();
                    let upstream = upstream.clone();
                    let socket = socket.clone();
                    let zone = self.zone.clone();
                    connections.spawn(async move {
                        if let Some(answer) = answer_with_upstream(&zone, &upstream, &query, address, false).await {
                            let _ = socket.send_to(&answer, remote).await;
                        }
                    });
                    continue;
                }
                let answer=self.zone.read().await.answer(&buffer[..n]);
                if let Some(answer)=answer {tokio::select! {_=cancel.cancelled()=>return Ok(()),result=socket.send_to(&answer,remote)=>{result?;}}}
            }}
        }
    }
}

async fn answer_with_upstream(zone: &RwLock<Zone>, upstream: &super::dns_upstream::Upstream,
    bytes: &[u8], address: std::net::SocketAddr, tcp: bool) -> Option<Vec<u8>> {
    {
        let zone = zone.read().await;
        if !zone.needs_upstream(bytes) { return zone.answer(bytes); }
    }
    let answer = upstream.answer(bytes, address, tcp).await;
    // A rule can change during network I/O. Enforce the latest policy before
    // returning an upstream answer instead of leaking a newly blocked name.
    let zone = zone.read().await;
    if zone.needs_upstream(bytes) { answer } else { zone.answer(bytes) }
}
#[derive(Default)]
pub struct Registration {
    #[cfg(target_os = "macos")]
    paths: Vec<(std::path::PathBuf, Vec<u8>)>,
    #[cfg(target_os="macos")]
    tor_default: Option<super::dns_default_macos::Registration>,
    #[cfg(windows)]
    interface: Option<windows_sys::core::GUID>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        for (path, contents) in self.paths.drain(..) {
            if std::fs::read(&path).ok().as_deref() == Some(contents.as_slice()) {
                if let Err(error) = std::fs::remove_file(path) {
                    tracing::warn!("could not remove owned macOS private DNS resolver: {error}");
                }
            }
        }
        #[cfg(windows)]
        if let Some(interface) = self.interface.take() {
            use windows_sys::Win32::NetworkManagement::IpHelper::{
                SetInterfaceDnsSettings, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS3,
                DNS_INTERFACE_SETTINGS_VERSION3, DNS_SETTING_DOMAIN, DNS_SETTING_NAMESERVER,
                DNS_SETTING_SUPPLEMENTAL_SEARCH_LIST,
            };
            let settings = DNS_INTERFACE_SETTINGS3 {
                Version: DNS_INTERFACE_SETTINGS_VERSION3,
                Flags: u64::from(
                    DNS_SETTING_DOMAIN
                        | DNS_SETTING_NAMESERVER
                        | DNS_SETTING_SUPPLEMENTAL_SEARCH_LIST,
                ),
                ..Default::default()
            };
            // SAFETY: The interface GUID and settings structure are valid for
            // the duration of the call. Null field pointers clear these values.
            if unsafe {
                SetInterfaceDnsSettings(
                    interface,
                    &settings as *const _ as *const DNS_INTERFACE_SETTINGS,
                )
            } != 0
            {
                tracing::warn!("could not clear owned Windows private DNS settings");
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub async fn register(
    index: u32,
    own: Ipv4Addr,
    port: u16,
    suffixes: &[String],
) -> Result<Registration> {
    let connection = zbus::Connection::system()
        .await
        .map_err(|_| anyhow::anyhow!("private DNS system bus unavailable"))?;
    let proxy = zbus::Proxy::new(
        &connection,
        "org.freedesktop.resolve1",
        "/org/freedesktop/resolve1",
        "org.freedesktop.resolve1.Manager",
    )
    .await?;
    proxy
        .call::<_, _, ()>(
            "SetLinkDNSEx",
            &(
                index as i32,
                vec![(libc::AF_INET, own.octets().to_vec(), port, "")],
            ),
        )
        .await
        .map_err(|_| anyhow::anyhow!("private DNS per-interface registration failed"))?;
    let domains = suffixes
        .iter()
        .map(|suffix| (suffix.as_str(), true))
        .collect::<Vec<_>>();
    proxy
        .call::<_, _, ()>("SetLinkDomains", &(index as i32, domains))
        .await?;
    proxy
        .call::<_, _, ()>("SetLinkDefaultRoute", &(index as i32, false))
        .await?;
    // A removed block or changed address should not remain in the system
    // resolver cache. Registration is refreshed only when policy changes.
    let _ = proxy.call::<_, _, ()>("FlushCaches", &()).await;
    Ok(Registration::default())
}

#[cfg(target_os = "macos")]
pub async fn register(
    _index: u32,
    _own: Ipv4Addr,
    port: u16,
    suffixes: &[String],
) -> Result<Registration> {
    let private:Vec<_>=suffixes.iter().filter(|suffix|suffix.as_str()!=".").cloned().collect();
    let mut registration=register_files(std::path::Path::new("/etc/resolver"), port, &private)?;
    if suffixes.iter().any(|suffix|suffix==".") {
        registration.tor_default=Some(super::dns_default_macos::register(port).await?);
    }
    Ok(registration)
}

#[cfg(target_os = "macos")]
fn register_files(directory: &std::path::Path, port: u16, suffixes: &[String]) -> Result<Registration> {
    use std::{fs, io::Write, os::unix::fs::OpenOptionsExt};

    ensure!(!suffixes.is_empty(), "private DNS suffix is missing");
    fs::create_dir_all(directory)?;
    // Keep ownership in the guard throughout installation. If any suffix
    // conflicts, Drop removes only files already created by this attempt.
    let mut registration = Registration::default();
    for suffix in suffixes {
        ensure!(
            !suffix.is_empty()
                && suffix.len() < 254
                && suffix.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                }),
            "invalid private DNS suffix"
        );
        let path = directory.join(suffix);
        let contents = format!(
        "# Managed by PortHub native agent\ndomain {suffix}\nnameserver 127.0.0.1\nport {port}\nsearch_order 100\ntimeout 2\n"
    )
    .into_bytes();
        let temporary = directory.join(format!(".porthub-{}-{port}.tmp", std::process::id()));
        let result = (|| -> Result<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(&temporary)?;
            file.write_all(&contents)?;
            file.sync_all()?;
            fs::hard_link(&temporary, &path)?;
            registration.paths.push((path.clone(), contents.clone()));
            fs::remove_file(&temporary)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
    }
    Ok(registration)
}

#[cfg(all(test, target_os = "macos"))]
mod macos_registration_tests {
    use super::*;

    #[test]
    fn a_conflicting_suffix_rolls_back_only_owned_resolvers() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let foreign = directory.path().join("other.test");
        std::fs::write(&foreign, b"nameserver 192.0.2.53\n")?;
        assert!(register_files(directory.path(), 53001, &["private.test".into(), "other.test".into()]).is_err());
        assert!(!directory.path().join("private.test").exists());
        assert_eq!(std::fs::read(&foreign)?, b"nameserver 192.0.2.53\n");
        assert_eq!(std::fs::read_dir(directory.path())?.count(), 1);
        Ok(())
    }
}

#[cfg(windows)]
pub async fn register(
    index: u32,
    _own: Ipv4Addr,
    port: u16,
    suffixes: &[String],
) -> Result<Registration> {
    use windows_sys::Win32::NetworkManagement::{
        IpHelper::{
            ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToGuid, SetInterfaceDnsSettings,
            DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS3, DNS_INTERFACE_SETTINGS_VERSION3,
            DNS_SETTING_DOMAIN, DNS_SETTING_NAMESERVER, DNS_SETTING_SUPPLEMENTAL_SEARCH_LIST,
        },
        Ndis::NET_LUID_LH,
    };

    ensure!(
        port == 53,
        "Windows private DNS must use the standard DNS port"
    );
    ensure!(!suffixes.is_empty(), "private DNS suffix is missing");
    ensure!(
        suffixes.iter().all(|suffix| !suffix.is_empty()
            && suffix.len() < 254
            && suffix.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    && !label.starts_with('-')
                    && !label.ends_with('-')
            })),
        "invalid private DNS suffix"
    );
    // SAFETY: Each output pointer refers to an initialized local value.
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { ConvertInterfaceIndexToLuid(index, &mut luid) } == 0,
        "cannot identify Windows private DNS interface"
    );
    let mut interface = windows_sys::core::GUID::default();
    ensure!(
        unsafe { ConvertInterfaceLuidToGuid(&luid, &mut interface) } == 0,
        "cannot identify Windows private DNS interface"
    );
    let server = "127.0.0.1"
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let domain = suffixes[0]
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let supplemental_search_list = suffixes
        .join(",")
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let settings = DNS_INTERFACE_SETTINGS3 {
        Version: DNS_INTERFACE_SETTINGS_VERSION3,
        Flags: u64::from(
            DNS_SETTING_DOMAIN | DNS_SETTING_NAMESERVER | DNS_SETTING_SUPPLEMENTAL_SEARCH_LIST,
        ),
        Domain: domain.as_ptr() as *mut u16,
        NameServer: server.as_ptr() as *mut u16,
        SupplementalSearchList: supplemental_search_list.as_ptr() as *mut u16,
        ..Default::default()
    };
    // SAFETY: Both strings and the settings structure stay live through this call.
    ensure!(
        unsafe {
            SetInterfaceDnsSettings(
                interface,
                &settings as *const _ as *const DNS_INTERFACE_SETTINGS,
            )
        } == 0,
        "cannot register Windows private DNS resolver"
    );
    Ok(Registration {
        interface: Some(interface),
    })
}

#[cfg(test)]
mod tcp_tests {
    use super::*;
    use hickory_proto::{op::Query, rr::Name};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Windows runner images can exclude dynamic port ranges independently for
    // TCP and UDP. Probe bounded random non-dynamic ports accepted by both
    // stacks, without changing host exclusions or enabling address reuse.
    #[cfg(windows)]
    async fn test_sockets() -> Result<(UdpSocket, TcpListener)> {
        let mut last = None;
        for _ in 0..32 {
            let mut random = [0; 2];
            getrandom::fill(&mut random)?;
            let port = 10000 + u16::from_ne_bytes(random) % 30000;
            let tcp = match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
                Ok(tcp) => tcp,
                Err(error) if matches!(error.kind(), std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied) => { last = Some(error); continue; },
                Err(error) => return Err(error.into()),
            };
            match UdpSocket::bind(tcp.local_addr()?).await {
                Ok(socket) => return Ok((socket, tcp)),
                Err(error) if matches!(error.kind(), std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied) => last = Some(error),
                Err(error) => return Err(error.into()),
            }
        }
        Err(last.unwrap().into())
    }

    #[tokio::test]
    #[ignore = "requires the machine's configured upstream DNS and internet access"]
    async fn configured_upstream_resolves_apex_while_wildcard_blocks_children() -> Result<()> {
        let zone = RwLock::new(Zone { rules: porthub_mesh::dns_policy::prepare(&[
            porthub_mesh::dns_policy::Rule { domain: "*.example.com".into(), include_subdomains: true,
                action: porthub_mesh::dns_policy::Action::Block }
        ])?, ..Default::default() });
        let upstream = super::super::dns_upstream::Upstream::default();
        for (name, expected) in [("example.com.", ResponseCode::NoError), ("www.example.com.", ResponseCode::NXDomain)] {
            let mut query = Message::query();
            query.add_query(Query::query(Name::from_ascii(name)?, RecordType::A));
            let reply = answer_with_upstream(&zone, &upstream, &query.to_vec()?, "127.0.0.1:53001".parse()?, false).await.unwrap();
            let reply = Message::from_vec(&reply)?;
            assert_eq!(reply.metadata.response_code, expected, "{name}");
            if expected == ResponseCode::NoError { assert!(!reply.answers.is_empty()); }
        }
        Ok(())
    }

    #[tokio::test]
    async fn exact_and_wildcard_rules_forward_only_unmatched_names() -> Result<()> {
        use porthub_mesh::dns_policy::{Rule, Action};
        let mock = UdpSocket::bind("127.0.0.1:0").await?;
        let upstream = Arc::new(super::super::dns_upstream::Upstream::fixture(mock.local_addr()?));
        let forwarded = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = forwarded.clone();
        let mock_task = tokio::spawn(async move {
            let mut bytes = [0; 1500];
            loop {
                let (n, peer) = mock.recv_from(&mut bytes).await.unwrap();
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut response = Message::from_vec(&bytes[..n]).unwrap();
                response.metadata.message_type = MessageType::Response;
                let name = response.queries[0].name().clone();
                response.add_answer(Record::from_rdata(name, 5, RData::A(A("192.0.2.20".parse().unwrap()))));
                mock.send_to(&response.to_vec().unwrap(), peer).await.unwrap();
            }
        });
        #[cfg(windows)]
        let (socket, tcp) = test_sockets().await?;
        #[cfg(not(windows))]
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let address = socket.local_addr()?;
        #[cfg(not(windows))]
        let tcp = TcpListener::bind(address).await?;
        let zone = Zone {
            suffixes: HashSet::from(["private.test.".into()]),
            rules: porthub_mesh::dns_policy::prepare(&[
                Rule { domain: "*.example.test".into(), include_subdomains: true, action: Action::Block },
                Rule { domain: "exact.test".into(), include_subdomains: false, action: Action::Block },
            ])?, ..Default::default()
        };
        let server = Server { socket, tcp, zone: Arc::new(RwLock::new(zone)), upstream: Default::default() };
        let cancel = CancellationToken::new();
        let task = tokio::spawn(server.serve_with(cancel.clone(), upstream));
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        let checks = async {
            for (name, expected) in [
                ("example.test.", ResponseCode::NoError),
                ("child.example.test.", ResponseCode::NXDomain),
                ("deep.child.example.test.", ResponseCode::NXDomain),
                ("exact.test.", ResponseCode::NXDomain),
                ("child.exact.test.", ResponseCode::NoError),
                ("missing.private.test.", ResponseCode::NXDomain),
                ("unrelated.test.", ResponseCode::Refused),
            ] {
                let mut query = Message::query();
                query.add_query(Query::query(Name::from_ascii(name)?, RecordType::A));
                client.send_to(&query.to_vec()?, address).await?;
                let mut bytes = [0; 1500];
                let n = tokio::time::timeout(std::time::Duration::from_secs(2), client.recv(&mut bytes)).await??;
                let response = Message::from_vec(&bytes[..n])?;
                assert_eq!(response.metadata.response_code, expected, "{name}");
                if expected == ResponseCode::NoError { assert_eq!(response.answers.len(), 1); }
            }
            assert_eq!(forwarded.load(std::sync::atomic::Ordering::SeqCst), 2);
            anyhow::Ok(())
        }.await;
        cancel.cancel();
        task.await??;
        mock_task.abort();
        checks
    }

    #[tokio::test]
    async fn tcp_and_udp_share_policy_and_shutdown_closes_idle_clients() -> Result<()> {
        #[cfg(windows)]
        let (socket, tcp) = test_sockets().await?;
        #[cfg(not(windows))]
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = socket.local_addr()?;
        #[cfg(not(windows))]
        let tcp = TcpListener::bind(address).await?;
        let zone = Zone { rules: vec![porthub_mesh::dns_policy::Rule {
            domain: "blocked.example".into(), action: porthub_mesh::dns_policy::Action::Block,
            include_subdomains: true,
        }], ..Default::default() };
        let server = Server { socket, tcp, zone: Arc::new(RwLock::new(zone)), upstream: Default::default() };
        let cancel = CancellationToken::new();
        let task = tokio::spawn(server.serve(cancel.clone()));
        let mut query = Message::query();
        query.add_query(Query::query(Name::from_ascii("blocked.example")?, RecordType::AAAA));
        let wire = query.to_vec()?;
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        udp.send_to(&wire, address).await?;
        let mut buffer = [0; 1500];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), udp.recv(&mut buffer)).await??;
        let expected = buffer[..n].to_vec();
        assert_eq!(Message::from_vec(&expected)?.metadata.response_code, ResponseCode::NXDomain);
        let mut stream = tokio::net::TcpStream::connect(address).await?;
        for _ in 0..2 {
            stream.write_u16(wire.len() as u16).await?;
            stream.write_all(&wire).await?;
            let length = stream.read_u16().await? as usize;
            let mut answer = vec![0; length];
            stream.read_exact(&mut answer).await?;
            assert_eq!(answer, expected);
        }
        cancel.cancel();
        task.await??;
        assert_eq!(tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buffer)).await??, 0);
        Ok(())
    }
}
