//! Authoritative private-zone DNS. No forwarding, global resolver files, or
//! claims on a host application's port 53 are needed.
use super::policy::Snapshot;
use anyhow::{ensure, Result};
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{rdata::A, DNSClass, RData, Record, RecordType},
};
use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};
use tokio::{net::UdpSocket, sync::RwLock};
use tokio_util::sync::CancellationToken;
#[derive(Default)]
pub struct Zone {
    suffix: String,
    records: HashMap<String, Ipv4Addr>,
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
        let suffix = format!("{}.", suffix.to_ascii_lowercase());
        let mut records = HashMap::new();
        for peer in &snapshot.peers {
            for name in std::iter::once(&peer.hostname).chain(&peer.aliases) {
                let name = format!("{}.", name.trim_end_matches('.').to_ascii_lowercase());
                ensure!(
                    name.len() <= 254 && name.ends_with(&format!(".{suffix}")),
                    "private name outside assigned suffix"
                );
                ensure!(
                    records
                        .insert(name, peer.ip)
                        .is_none_or(|old| old == peer.ip),
                    "private DNS name collision"
                );
            }
        }
        self.suffix = suffix;
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
        let code = if query.metadata.op_code != OpCode::Query {
            ResponseCode::NotImp
        } else if self.suffix.is_empty()
            || !(name == self.suffix || name.ends_with(&format!(".{}", self.suffix)))
        {
            ResponseCode::Refused
        } else if !self.records.contains_key(&name) && name != self.suffix {
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
    pub zone: Arc<RwLock<Zone>>,
}
impl Server {
    pub async fn bind(own: Ipv4Addr) -> Result<Self> {
        ensure!(
            own.is_private(),
            "private DNS requires the assigned address"
        );
        Ok(Self {
            // resolved binds per-link queries to that link. A loopback target
            // would consequently leave through TUN instead of reaching lo.
            socket: UdpSocket::bind((own, 0)).await?,
            zone: Default::default(),
        })
    }
    pub fn port(&self) -> Result<u16> {
        Ok(self.socket.local_addr()?.port())
    }
    pub async fn serve(self, cancel: CancellationToken) -> Result<()> {
        let own = self.socket.local_addr()?.ip();
        let mut buffer = [0; 1501];
        loop {
            tokio::select! {_=cancel.cancelled()=>return Ok(()), packet=self.socket.recv_from(&mut buffer)=>{
                let (n,remote)=packet?; if remote.ip()!=own && !remote.ip().is_loopback() {continue;}
                let answer=self.zone.read().await.answer(&buffer[..n]);
                if let Some(answer)=answer {tokio::select! {_=cancel.cancelled()=>return Ok(()),result=self.socket.send_to(&answer,remote)=>{result?;}}}
            }}
        }
    }
}
#[cfg(target_os = "linux")]
pub async fn register(index: u32, own: Ipv4Addr, port: u16, suffix: &str) -> Result<()> {
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
    proxy
        .call::<_, _, ()>("SetLinkDomains", &(index as i32, vec![(suffix, true)]))
        .await?;
    proxy
        .call::<_, _, ()>("SetLinkDefaultRoute", &(index as i32, false))
        .await?;
    Ok(())
}
