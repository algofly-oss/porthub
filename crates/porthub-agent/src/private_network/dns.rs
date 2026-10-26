//! Authoritative private-zone DNS. No forwarding, global resolver files, or
//! claims on a host application's port 53 are needed.
use super::policy::Snapshot;
use anyhow::{ensure, Result};
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{rdata::{A, AAAA}, DNSClass, RData, Record, RecordType},
};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};
use tokio::{net::{TcpListener, UdpSocket}, sync::RwLock};
use tokio_util::sync::CancellationToken;
#[derive(Default)]
pub struct Zone {
    suffixes: HashSet<String>,
    records: HashMap<String, Ipv4Addr>,
    rules: Vec<porthub_mesh::dns_policy::Rule>,
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
            let domain = format!("{}.", rule.domain);
            ensure!(!suffixes.iter().any(|suffix| domain == *suffix
                || domain.ends_with(&format!(".{suffix}"))
                || suffix.ends_with(&format!(".{domain}"))),
                "DNS policy conflicts with a private identity zone");
        }
        self.rules = rules;
        self.suffixes = suffixes;
        self.records = records;
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
            if let Some(rule) = porthub_mesh::dns_policy::matching(&self.rules, &name) {
                use porthub_mesh::dns_policy::Action;
                match &rule.action {
                    Action::Block => reply.metadata.response_code = ResponseCode::NXDomain,
                    Action::Override { addresses } => {
                        if q.query_class() == DNSClass::IN {
                            for address in addresses {
                                let data = match (q.query_type(), address) {
                                    (RecordType::A, IpAddr::V4(ip)) => Some(RData::A(A(*ip))),
                                    (RecordType::AAAA, IpAddr::V6(ip)) => Some(RData::AAAA(AAAA(*ip))),
                                    _ => None,
                                };
                                if let Some(data) = data { reply.add_answer(Record::from_rdata(q.name().clone(), 5, data)); }
                            }
                        }
                    }
                }
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
}
pub struct Server {
    socket: UdpSocket,
    tcp: TcpListener,
    pub zone: Arc<RwLock<Zone>>,
}
impl Server {
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
        Ok(Self { socket, tcp, zone: Default::default() })
    }
    pub fn port(&self) -> Result<u16> {
        Ok(self.socket.local_addr()?.port())
    }
    pub async fn serve(self, cancel: CancellationToken) -> Result<()> {
        let own = self.socket.local_addr()?.ip();
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
                    connections.spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let exchange = async {
                            for _ in 0..64 {
                                let length = stream.read_u16().await? as usize;
                                anyhow::ensure!((12..=1500).contains(&length), "invalid DNS query size");
                                let mut query = vec![0; length];
                                stream.read_exact(&mut query).await?;
                                let answer = zone.read().await.answer(&query);
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
                packet=self.socket.recv_from(&mut buffer)=>{
                let (n,remote)=packet?; if remote.ip()!=own && !remote.ip().is_loopback() {continue;}
                let answer=self.zone.read().await.answer(&buffer[..n]);
                if let Some(answer)=answer {tokio::select! {_=cancel.cancelled()=>return Ok(()),result=self.socket.send_to(&answer,remote)=>{result?;}}}
            }}
        }
    }
}
#[derive(Default)]
pub struct Registration {
    #[cfg(target_os = "macos")]
    paths: Vec<(std::path::PathBuf, Vec<u8>)>,
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
    use std::{fs, io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf};

    ensure!(!suffixes.is_empty(), "private DNS suffix is missing");
    let directory = PathBuf::from("/etc/resolver");
    fs::create_dir_all(&directory)?;
    let mut paths = Vec::new();
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
            fs::remove_file(&temporary)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        paths.push((path, contents));
    }
    Ok(Registration { paths })
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

    #[tokio::test]
    async fn tcp_and_udp_share_policy_and_shutdown_closes_idle_clients() -> Result<()> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = socket.local_addr()?;
        let tcp = TcpListener::bind(address).await?;
        let zone = Zone { rules: vec![porthub_mesh::dns_policy::Rule {
            domain: "blocked.example".into(), action: porthub_mesh::dns_policy::Action::Block,
            include_subdomains: true,
        }], ..Default::default() };
        let server = Server { socket, tcp, zone: Arc::new(RwLock::new(zone)) };
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
