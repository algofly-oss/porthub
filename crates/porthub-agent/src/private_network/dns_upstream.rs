//! Bounded forwarding for names captured by a DNS rule's resolver route but not
//! matched by that rule. Private-zone answers never reach this module. Upstream
//! configuration is refreshed lazily; an idle agent does no DNS polling.
use anyhow::{ensure, Context, Result};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use std::{net::SocketAddr, time::{Duration, Instant}};
#[cfg(target_os = "linux")]
use std::net::IpAddr;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpStream, UdpSocket}, sync::Mutex};

#[derive(Default)]
pub(super) struct Upstream {
    cache: Mutex<Option<(Instant, Vec<SocketAddr>)>>,
    #[cfg(feature="local-tor")]
    tor: std::sync::RwLock<Option<TorDns>>,
    #[cfg(feature="local-tor")]
    management: std::sync::RwLock<Option<Management>>,
}

#[cfg(feature="local-tor")]
#[derive(Clone)]
struct Management {
    names: std::collections::HashSet<String>,
    sources: tokio::sync::watch::Receiver<Vec<SocketAddr>>,
}

#[cfg(feature="local-tor")]
#[derive(Clone)]
pub(super) struct TorDns {
    pub resolver: Option<std::sync::Arc<dyn porthub_egress::Resolver>>,
    pub allow_other: bool,
    pub valid_until: Instant,
}

impl Upstream {
    #[cfg(test)]
    pub(super) fn fixture(server: SocketAddr) -> Self {
        Self { cache: Mutex::new(Some((Instant::now(), vec![server]))), ..Self::default() }
    }
    #[cfg(feature="local-tor")]
    pub(super) fn set_tor(&self, configuration: Option<TorDns>) {
        *self.tor.write().unwrap_or_else(|poison|poison.into_inner())=configuration;
    }
    #[cfg(feature="local-tor")]
    pub(super) fn protect_management(&self,names:std::collections::HashSet<String>,sources:tokio::sync::watch::Receiver<Vec<SocketAddr>>) {
        *self.management.write().unwrap_or_else(|poison|poison.into_inner())=Some(Management {names,sources});
    }
    async fn servers(&self, own: SocketAddr) -> Vec<SocketAddr> {
        let mut cache = self.cache.lock().await;
        if cache.as_ref().is_none_or(|(at, _)| at.elapsed() >= Duration::from_secs(30)) {
            let discovered = tokio::time::timeout(Duration::from_secs(2), discover()).await;
            let servers = discovered.ok().and_then(Result::ok).unwrap_or_default();
            let mut unique = Vec::new();
            for server in servers {
                if usable(server, own) && !unique.contains(&server) { unique.push(server); }
                if unique.len() == 4 { break; }
            }
            *cache = Some((Instant::now(), unique));
        }
        cache.as_ref().unwrap().1.clone()
    }

    pub(super) async fn answer(&self, bytes: &[u8], own: SocketAddr, tcp: bool) -> Option<Vec<u8>> {
        let query = Message::from_vec(bytes).ok()?;
        #[cfg(feature="local-tor")]
        {
            let management=self.management.read().unwrap_or_else(|poison|poison.into_inner()).clone();
            if let Some(management)=management.filter(|management|query.queries.len()==1 && management.names.contains(&query.queries[0].name().to_ascii().trim_end_matches('.').to_ascii_lowercase())) {
                let sources=management.sources.borrow().clone();
                for server in self.servers(own).await {
                    for source in sources.iter().filter(|source|source.is_ipv4()==server.is_ipv4()).take(2) {
                        if let Ok(Ok(reply))=tokio::time::timeout(Duration::from_secs(2),exchange_from(bytes,&query,server,tcp,Some(source.ip()))).await {return Some(reply);}
                    }
                }
                return failure(&query);
            }
        }
        #[cfg(feature="local-tor")]
        {
            let tor=self.tor.read().unwrap_or_else(|poison|poison.into_inner()).clone();
            if let Some(tor)=tor {
                if let Some(resolver)=&tor.resolver {
                    if let Some(answer)=tor_answer(&query,resolver.as_ref()).await {return Some(answer);}
                }
                if !tor.allow_other || tor.valid_until <= Instant::now() {return failure(&query);}
            }
        }
        let servers = self.servers(own).await;
        for server in servers {
            let result = tokio::time::timeout(Duration::from_secs(2), exchange(bytes, &query, server, tcp)).await;
            if let Ok(Ok(reply)) = result { return Some(reply); }
        }
        failure(&query)
    }
}

#[cfg(feature="local-tor")]
async fn tor_answer(query:&Message,resolver:&dyn porthub_egress::Resolver)->Option<Vec<u8>> {
    use hickory_proto::{op::OpCode,rr::{DNSClass,RecordType,RData,Record,rdata::{A,AAAA}}};
    if query.metadata.message_type!=MessageType::Query || query.metadata.op_code!=OpCode::Query || query.queries.len()!=1 {return failure(query);}
    let question=&query.queries[0];
    let mut reply=Message::new(query.metadata.id,MessageType::Response,query.metadata.op_code);
    reply.metadata.recursion_desired=query.metadata.recursion_desired;
    reply.metadata.recursion_available=true;
    reply.add_query(question.clone());
    // Tor's RESOLVE protocol returns address records. Return NODATA for other
    // types rather than leak an unsupported query to an underlay DNS server.
    if question.query_class()!=DNSClass::IN || !matches!(question.query_type(),RecordType::A|RecordType::AAAA) {return reply.to_vec().ok();}
    let name=question.name().to_ascii();
    let addresses=resolver.resolve(name.trim_end_matches('.')).await.ok()?;
    for address in addresses.into_iter().take(16) {
        let data=match (question.query_type(),address) {
            (RecordType::A,std::net::IpAddr::V4(ip))=>Some(RData::A(A(ip))),
            (RecordType::AAAA,std::net::IpAddr::V6(ip))=>Some(RData::AAAA(AAAA(ip))),
            _=>None,
        };
        if let Some(data)=data {reply.add_answer(Record::from_rdata(question.name().clone(),30,data));}
    }
    reply.to_vec().ok()
}

fn usable(server: SocketAddr, own: SocketAddr) -> bool {
    server.ip() != own.ip() && !server.ip().is_unspecified() && !server.ip().is_multicast()
        // System stubs route these names back to PortHub. Read their real
        // upstream configuration instead, preventing recursive forwarding.
        && !server.ip().is_loopback()
}

fn failure(query: &Message) -> Option<Vec<u8>> {
    let mut reply = Message::new(query.metadata.id, MessageType::Response, query.metadata.op_code);
    reply.metadata.recursion_desired = query.metadata.recursion_desired;
    reply.metadata.response_code = ResponseCode::ServFail;
    for question in &query.queries { reply.add_query(question.clone()); }
    reply.to_vec().ok()
}

async fn exchange(bytes: &[u8], query: &Message, server: SocketAddr, tcp: bool) -> Result<Vec<u8>> {
    exchange_from(bytes,query,server,tcp,None).await
}
async fn exchange_from(bytes: &[u8], query: &Message, server: SocketAddr, tcp: bool,source:Option<std::net::IpAddr>) -> Result<Vec<u8>> {
    let mut bytes = bytes.to_vec();
    let id = getrandom::u32()? as u16;
    bytes[..2].copy_from_slice(&id.to_be_bytes());
    let reply = if tcp {
        let mut stream = if let Some(source)=source {
            let socket=if server.is_ipv4(){tokio::net::TcpSocket::new_v4()?}else{tokio::net::TcpSocket::new_v6()?};
            socket.bind(SocketAddr::new(source,0))?;socket.connect(server).await?
        } else {TcpStream::connect(server).await?};
        stream.write_u16(bytes.len() as u16).await?;
        stream.write_all(&bytes).await?;
        let len = stream.read_u16().await? as usize;
        ensure!(len >= 12, "invalid upstream DNS response");
        let mut reply = vec![0; len];
        stream.read_exact(&mut reply).await?;
        reply
    } else {
        let local: SocketAddr = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse()?;
        let socket = UdpSocket::bind(source.map_or(local,|source|SocketAddr::new(source,0))).await?;
        socket.connect(server).await?;
        socket.send(&bytes).await?;
        let mut reply = vec![0; 65535];
        let len = socket.recv(&mut reply).await?;
        reply.truncate(len);
        reply
    };
    let response = Message::from_vec(&reply)?;
    ensure!(response.metadata.id == id && response.metadata.message_type == MessageType::Response
        && response.metadata.op_code == query.metadata.op_code && response.queries == query.queries,
        "upstream DNS response does not match query");
    ensure!(!matches!(response.metadata.response_code, ResponseCode::ServFail | ResponseCode::Refused), "upstream DNS unavailable");
    let mut reply = reply;
    reply[..2].copy_from_slice(&query.metadata.id.to_be_bytes());
    if !tcp {
        // Do not turn a small local UDP request into an oversized datagram.
        // The client retries truncated responses over our TCP listener.
        let limit = query.edns.as_ref().map_or(512, |edns| usize::from(edns.max_payload()).clamp(512, 4096));
        if reply.len() > limit {
            let mut truncated = Message::new(query.metadata.id, MessageType::Response, query.metadata.op_code);
            truncated.metadata.truncation = true;
            truncated.metadata.recursion_desired = query.metadata.recursion_desired;
            truncated.metadata.recursion_available = response.metadata.recursion_available;
            for question in &query.queries { truncated.add_query(question.clone()); }
            return Ok(truncated.to_vec()?);
        }
    }
    Ok(reply)
}

async fn discover() -> Result<Vec<SocketAddr>> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(servers) = resolved_servers().await {
            if !servers.is_empty() { return Ok(servers); }
        }
        // resolved's upstream file excludes its local stub and is maintained
        // when DHCP/VPN configuration changes. It is read, never modified.
        if let Ok(bytes) = tokio::fs::read("/run/systemd/resolve/resolv.conf").await {
            ensure!(bytes.len() <= 65536, "DNS configuration exceeds size limit");
            let (config, _) = hickory_resolver::system_conf::parse_resolv_conf(bytes)?;
            return Ok(config.name_servers().iter().map(|server| SocketAddr::new(server.ip, 53)).collect());
        }
    }
    // macOS uses SystemConfiguration; Windows enumerates active adapters. No
    // public DNS provider is hardcoded and no helper needs to be installed.
    tokio::task::spawn_blocking(|| {
        let (config, _) = hickory_resolver::system_conf::read_system_conf()?;
        Ok(config.name_servers().iter().map(|server| SocketAddr::new(server.ip, 53)).collect())
    }).await.context("DNS configuration reader stopped")?
}

#[cfg(target_os = "linux")]
async fn resolved_servers() -> Result<Vec<SocketAddr>> {
    use nlink::netlink::{Connection, Route};
    let links = Connection::<Route>::new()?.get_links().await?;
    let owned: std::collections::HashSet<_> = links.iter()
        .filter(|link| link.name().is_some_and(|name| name.starts_with("ph")))
        .map(|link| link.ifindex() as i32).collect();
    let connection = zbus::Connection::system().await?;
    let manager = zbus::Proxy::new(&connection, "org.freedesktop.resolve1",
        "/org/freedesktop/resolve1", "org.freedesktop.resolve1.Manager").await?;
    let servers: Vec<(i32, i32, Vec<u8>, u16, String)> = manager.get_property("DNSEx").await?;
    Ok(servers.into_iter().filter(|(index, _, _, _, _)| !owned.contains(index))
        .filter_map(|(_, family, bytes, port, _)| {
            let ip = match family {
                libc::AF_INET => IpAddr::V4(<[u8; 4]>::try_from(bytes).ok()?.into()),
                libc::AF_INET6 => IpAddr::V6(<[u8; 16]>::try_from(bytes).ok()?.into()),
                _ => return None,
            };
            Some(SocketAddr::new(ip, if port == 0 { 53 } else { port }))
        }).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{op::Query, rr::{Name, RecordType}};

    #[cfg(feature="local-tor")]
    struct TorFixture(bool);
    #[cfg(feature="local-tor")]
    #[async_trait::async_trait]
    impl porthub_egress::Resolver for TorFixture {
        async fn resolve(&self, hostname:&str)->Result<Vec<std::net::IpAddr>> {
            ensure!(hostname=="example.test","unexpected DNS destination");
            ensure!(self.0,"Tor unavailable");
            Ok(vec!["93.184.216.34".parse()?])
        }
    }

    #[cfg(feature="local-tor")]
    #[tokio::test]
    async fn only_exact_control_hosts_bypass_tor_and_require_a_physical_source() -> Result<()> {
        let listener=UdpSocket::bind("127.0.0.1:0").await?;
        let upstream=Upstream::fixture(listener.local_addr()?);
        upstream.set_tor(Some(TorDns {resolver:None,allow_other:false,valid_until:Instant::now()}));
        let (sources,receiver)=tokio::sync::watch::channel(vec!["127.0.0.1:0".parse()?]);
        upstream.protect_management(std::collections::HashSet::from(["gateway.example.test".into()]),receiver);
        let server=tokio::spawn(async move {
            let mut bytes=[0;1500];let(n,source)=listener.recv_from(&mut bytes).await?;
            assert_eq!(source.ip(),"127.0.0.1".parse::<std::net::IpAddr>()?);
            let mut reply=Message::from_vec(&bytes[..n])?;
            reply.metadata.message_type=MessageType::Response;reply.metadata.response_code=ResponseCode::NXDomain;
            listener.send_to(&reply.to_vec()?,source).await?;
            let mut next=[0;1500];
            assert!(tokio::time::timeout(Duration::from_millis(50),listener.recv_from(&mut next)).await.is_err());
            anyhow::Ok(())
        });
        let mut query=Message::query();query.add_query(Query::query(Name::from_ascii("gateway.example.test.")?,RecordType::A));
        let answer=upstream.answer(&query.to_vec()?,"127.0.0.1:53000".parse()?,false).await.unwrap();
        assert_eq!(Message::from_vec(&answer)?.metadata.response_code,ResponseCode::NXDomain);
        sources.send_replace(Vec::new());
        let answer=upstream.answer(&query.to_vec()?,"127.0.0.1:53000".parse()?,false).await.unwrap();
        assert_eq!(Message::from_vec(&answer)?.metadata.response_code,ResponseCode::ServFail);
        sources.send_replace(vec!["127.0.0.1:0".parse()?]);
        let mut other=Message::query();other.add_query(Query::query(Name::from_ascii("child.gateway.example.test.")?,RecordType::A));
        let answer=upstream.answer(&other.to_vec()?,"127.0.0.1:53000".parse()?,false).await.unwrap();
        assert_eq!(Message::from_vec(&answer)?.metadata.response_code,ResponseCode::ServFail);
        server.await??;Ok(())
    }

    #[cfg(feature="local-tor")]
    #[tokio::test]
    async fn tor_dns_keeps_queries_off_the_underlay_and_honors_lease() -> Result<()> {
        let underlay=UdpSocket::bind("127.0.0.1:0").await?;
        let upstream=Upstream::fixture(underlay.local_addr()?);
        let mut query=Message::query();query.metadata.id=321;
        query.add_query(Query::query(Name::from_ascii("example.test.")?,RecordType::A));
        let wire=query.to_vec()?;
        let configuration=|ready,valid_until|Some(TorDns {resolver:Some(std::sync::Arc::new(TorFixture(ready))),allow_other:false,valid_until});
        upstream.set_tor(configuration(true,Instant::now()+Duration::from_secs(30)));
        let answer=Message::from_vec(&upstream.answer(&wire,"127.0.0.1:53000".parse()?,false).await.unwrap())?;
        assert_eq!(answer.metadata.id,321);assert_eq!(answer.answers.len(),1);
        upstream.set_tor(configuration(false,Instant::now()+Duration::from_secs(30)));
        let answer=Message::from_vec(&upstream.answer(&wire,"127.0.0.1:53000".parse()?,false).await.unwrap())?;
        assert_eq!(answer.metadata.response_code,ResponseCode::ServFail);
        upstream.set_tor(configuration(true,Instant::now()));
        let answer=Message::from_vec(&upstream.answer(&wire,"127.0.0.1:53000".parse()?,false).await.unwrap())?;
        assert_eq!(answer.answers.len(),1);
        upstream.set_tor(Some(TorDns {resolver:Some(std::sync::Arc::new(TorFixture(false))),allow_other:true,valid_until:Instant::now()}));
        let answer=Message::from_vec(&upstream.answer(&wire,"127.0.0.1:53000".parse()?,false).await.unwrap())?;
        assert_eq!(answer.metadata.response_code,ResponseCode::ServFail);
        upstream.set_tor(Some(TorDns {resolver:None,allow_other:false,valid_until:Instant::now()+Duration::from_secs(30)}));
        let answer=Message::from_vec(&upstream.answer(&wire,"127.0.0.1:53000".parse()?,false).await.unwrap())?;
        assert_eq!(answer.metadata.response_code,ResponseCode::ServFail);
        let mut buffer=[0;1500];
        assert!(tokio::time::timeout(Duration::from_millis(30),underlay.recv_from(&mut buffer)).await.is_err());
        Ok(())
    }

    #[cfg(feature="local-tor")]
    #[tokio::test]
    async fn unsupported_tor_dns_types_return_nodata_without_fallback() -> Result<()> {
        let mut query=Message::query();
        query.add_query(Query::query(Name::from_ascii("example.test.")?,RecordType::TXT));
        let reply=Message::from_vec(&tor_answer(&query,&TorFixture(false)).await.unwrap())?;
        assert_eq!(reply.metadata.response_code,ResponseCode::NoError);
        assert!(reply.answers.is_empty());
        Ok(())
    }

    #[cfg(feature="local-tor")]
    #[tokio::test]
    async fn dns_underlay_fallback_requires_explicit_permission() -> Result<()> {
        let listener=UdpSocket::bind("127.0.0.1:0").await?;
        let upstream=Upstream::fixture(listener.local_addr()?);
        upstream.set_tor(Some(TorDns {resolver:Some(std::sync::Arc::new(TorFixture(false))),allow_other:true,valid_until:Instant::now()+Duration::from_secs(30)}));
        let server=tokio::spawn(async move {
            let mut bytes=[0;1500];let(n,source)=listener.recv_from(&mut bytes).await?;
            let mut reply=Message::from_vec(&bytes[..n])?;
            reply.metadata.message_type=MessageType::Response;
            reply.metadata.response_code=ResponseCode::NXDomain;
            listener.send_to(&reply.to_vec()?,source).await?;anyhow::Ok(())
        });
        let mut query=Message::query();query.add_query(Query::query(Name::from_ascii("example.test.")?,RecordType::A));
        let answer=Message::from_vec(&upstream.answer(&query.to_vec()?,"127.0.0.1:53000".parse()?,false).await.unwrap())?;
        assert_eq!(answer.metadata.response_code,ResponseCode::NXDomain);
        server.await??;Ok(())
    }

    #[tokio::test]
    async fn tcp_upstream_uses_dns_framing_and_restores_client_id() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let len = stream.read_u16().await? as usize;
            let mut bytes = vec![0; len];
            stream.read_exact(&mut bytes).await?;
            let mut response = Message::from_vec(&bytes)?;
            response.metadata.message_type = MessageType::Response;
            response.metadata.response_code = ResponseCode::NXDomain;
            let bytes = response.to_vec()?;
            stream.write_u16(bytes.len() as u16).await?;
            stream.write_all(&bytes).await?;
            anyhow::Ok(())
        });
        let mut query = Message::query();
        query.metadata.id = 567;
        query.add_query(Query::query(Name::from_ascii("example.test.")?, RecordType::AAAA));
        let bytes = query.to_vec()?;
        let query = Message::from_vec(&bytes)?;
        let response = Message::from_vec(&exchange(&bytes, &query, address, true).await?)?;
        assert_eq!(response.metadata.id, 567);
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn upstream_checks_question_and_id_and_preserves_negative_answers() -> Result<()> {
        let listener = UdpSocket::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let mut query = Message::query();
        query.metadata.id = 123;
        query.add_query(Query::query(Name::from_ascii("example.test")?, RecordType::A));
        let wire = query.to_vec()?;
        let query = Message::from_vec(&wire)?;
        let server = tokio::spawn(async move {
            for invalid in [false, true] {
                let mut buffer = [0; 1500];
                let (n, peer) = listener.recv_from(&mut buffer).await?;
                let request = Message::from_vec(&buffer[..n])?;
                let mut reply = request.clone();
                reply.metadata.message_type = MessageType::Response;
                reply.metadata.response_code = ResponseCode::NXDomain;
                if invalid { reply.metadata.id = reply.metadata.id.wrapping_add(1); }
                listener.send_to(&reply.to_vec()?, peer).await?;
            }
            anyhow::Ok(())
        });
        let reply = exchange(&wire, &query, address, false).await?;
        let reply = Message::from_vec(&reply)?;
        assert_eq!(reply.metadata.id, 123);
        assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
        assert!(exchange(&wire, &query, address, false).await.is_err());
        server.await??;
        assert!(!usable(address, address));
        assert!(!usable("127.0.0.53:53".parse()?, address));
        assert!(usable("192.0.2.53:53".parse()?, address));
        Ok(())
    }
}
