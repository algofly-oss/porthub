//! PRIVATE QA only: observe one exact fixture question, never foreign DNS.
use super::*;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
#[derive(Debug, Default, serde::Serialize)]
pub(crate) struct Counts {
    pub direct: u64,
    pub a: u64,
    pub aaaa: u64,
    pub other: u64,
    pub loopback: u64,
    pub replies: u64,
    pub expected_a: u64,
    pub noerror: u64,
}
pub(crate) struct Observer {
    name: String,
    expected: Ipv4Addr,
    direct_port: AtomicU16,
    counts: [AtomicU64; 8],
}
impl Observer {
    pub fn new(name: String, nonce: &str, expected: Ipv4Addr) -> Result<Self> {
        ensure!(
            nonce.len() == 32 && nonce.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid fixture nonce"
        );
        ensure!(
            name == format!("peer.s{nonce}.phub.") || name == format!("peer.v{nonce}.phub."),
            "observer question outside exact fixture"
        );
        Ok(Self {
            name,
            expected,
            direct_port: AtomicU16::new(0),
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
        })
    }
    pub fn direct_port(&self, port: u16) {
        self.direct_port.store(port, Ordering::SeqCst);
    }
    fn matched(&self, bytes: &[u8], remote: std::net::SocketAddr) -> Option<(Message, bool)> {
        if bytes.len() > 1500 {
            return None;
        }
        let q = Message::from_vec(bytes).ok()?;
        if q.metadata.message_type != MessageType::Query
            || q.metadata.op_code != OpCode::Query
            || q.queries.len() != 1
            || q.queries[0].query_class() != DNSClass::IN
            || q.queries[0].name().to_ascii().to_ascii_lowercase() != self.name
        {
            return None;
        }
        let direct = q.metadata.id == 63701
            && remote.ip().is_loopback()
            && remote.port() == self.direct_port.load(Ordering::SeqCst);
        Some((q, direct))
    }
    pub fn query(&self, bytes: &[u8], remote: std::net::SocketAddr) {
        let Some((q, direct)) = self.matched(bytes, remote) else {
            return;
        };
        let index = if direct {
            0
        } else {
            match q.queries[0].query_type() {
                RecordType::A => 1,
                RecordType::AAAA => 2,
                _ => 3,
            }
        };
        self.counts[index].fetch_add(1, Ordering::SeqCst);
        if !direct && remote.ip().is_loopback() {
            self.counts[4].fetch_add(1, Ordering::SeqCst);
        }
    }
    pub fn reply(&self, query: &[u8], reply: &[u8], remote: std::net::SocketAddr) {
        let Some((q, direct)) = self.matched(query, remote) else {
            return;
        };
        if direct {
            return;
        }
        let Ok(answer) = Message::from_vec(reply) else {
            return;
        };
        if answer.metadata.id != q.metadata.id
            || answer.metadata.message_type != MessageType::Response
        {
            return;
        }
        self.counts[5].fetch_add(1, Ordering::SeqCst);
        if answer.metadata.response_code == ResponseCode::NoError {
            self.counts[7].fetch_add(1, Ordering::SeqCst);
        }
        if answer
            .answers
            .iter()
            .any(|r| matches!(&r.data,RData::A(A(ip)) if *ip==self.expected))
        {
            self.counts[6].fetch_add(1, Ordering::SeqCst);
        }
    }
    pub fn snapshot(&self) -> Counts {
        let a = self.counts.each_ref().map(|n| n.load(Ordering::SeqCst));
        Counts {
            direct: a[0],
            a: a[1],
            aaaa: a[2],
            other: a[3],
            loopback: a[4],
            replies: a[5],
            expected_a: a[6],
            noerror: a[7],
        }
    }
}
pub(crate) fn direct_answer(bytes: &[u8], name: &str, expected: Ipv4Addr) -> Result<()> {
    ensure!(bytes.len() <= 1500, "direct DNS reply bound");
    let m = Message::from_vec(bytes)?;
    ensure!(
        m.metadata.id == 63701
            && m.metadata.message_type == MessageType::Response
            && m.metadata.op_code == OpCode::Query
            && m.metadata.response_code == ResponseCode::NoError
            && m.queries.len() == 1,
        "direct DNS response identity"
    );
    ensure!(
        m.queries[0].name().to_ascii().to_ascii_lowercase() == name
            && m.queries[0].query_type() == RecordType::A
            && m.queries[0].query_class() == DNSClass::IN,
        "direct DNS question mismatch"
    );
    ensure!(
        m.answers.len() == 1
            && m.answers
                .iter()
                .any(|r| r.name.to_ascii().to_ascii_lowercase() == name
                    && matches!(&r.data,RData::A(A(ip)) if *ip==expected)),
        "direct DNS expected A missing"
    );
    Ok(())
}
#[test]
fn observer_rejects_foreign_and_separates_direct_from_system() -> Result<()> {
    let nonce = "0123456789abcdef0123456789abcdef";
    let name = format!("peer.s{nonce}.phub.");
    let expected = "10.254.254.2".parse()?;
    let observer = Observer::new(name.clone(), nonce, expected)?;
    let mut q = Message::new(63701, MessageType::Query, OpCode::Query);
    q.add_query(hickory_proto::op::Query::query(
        name.parse()?,
        RecordType::A,
    ));
    let bytes = q.to_vec()?;
    observer.direct_port(10001);
    observer.query(&bytes, "127.0.0.1:10001".parse()?);
    observer.query(&bytes, "127.0.0.1:10002".parse()?);
    let mut foreign = q.clone();
    foreign.queries.clear();
    foreign.add_query(hickory_proto::op::Query::query(
        "foreign.invalid.".parse()?,
        RecordType::A,
    ));
    observer.query(&foreign.to_vec()?, "127.0.0.1:10002".parse()?);
    let mut reply = Message::new(63701, MessageType::Response, OpCode::Query);
    reply.add_query(q.queries[0].clone());
    reply.add_answer(Record::from_rdata(name.parse()?, 5, RData::A(A(expected))));
    observer.reply(&bytes, &reply.to_vec()?, "127.0.0.1:10001".parse()?);
    observer.reply(&bytes, &reply.to_vec()?, "127.0.0.1:10002".parse()?);
    let counts = observer.snapshot();
    assert_eq!(
        (counts.replies, counts.expected_a, counts.noerror),
        (1, 1, 1)
    );
    assert_eq!((counts.direct, counts.a, counts.loopback), (1, 1, 1));
    assert!(Observer::new("foreign.invalid.".into(), nonce, expected).is_err());
    assert!(Observer::new(format!("peer.v{nonce}.phub."), nonce, expected).is_ok());
    assert!(Observer::new(format!("peer.t{nonce}.phub."), nonce, expected).is_err());
    Ok(())
}
#[test]
fn direct_reply_requires_exact_question_id_and_expected_address() -> Result<()> {
    let name = "peer.s0123456789abcdef0123456789abcdef.phub.";
    let ip = "10.254.254.2".parse()?;
    let mut m = Message::new(63701, MessageType::Response, OpCode::Query);
    m.add_query(hickory_proto::op::Query::query(
        name.parse()?,
        RecordType::A,
    ));
    m.add_answer(Record::from_rdata(name.parse()?, 5, RData::A(A(ip))));
    assert!(direct_answer(&m.to_vec()?, name, ip).is_ok());
    m.metadata.id = 2;
    assert!(direct_answer(&m.to_vec()?, name, ip).is_err());
    m.metadata.id = 63701;
    assert!(direct_answer(&m.to_vec()?, name, "10.254.254.3".parse()?).is_err());
    assert!(direct_answer(&[0; 12], name, ip).is_err());
    Ok(())
}
