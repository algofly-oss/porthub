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
    pub metadata: Vec<ReplyMetadata>,
    pub metadata_dropped: u64,
    pub malformed_replies: u64,
    pub mismatched_ids: u64,
    pub mismatched_types: u64,
}
// At most eight exchanges per exact-owned phase (32 total); no names, addresses, or packet bytes.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ReplyMetadata {
    order: u64,
    phase: u8,
    query_type: u16,
    query_class: u16,
    query_flags: u16,
    response_flags: u16,
    query_id: u16,
    response_id: u16,
    id_equal: bool,
    question_count: usize,
    question_name_case_equal: bool,
    question_name_folded_equal: bool,
    question_type_equal: bool,
    question_class_equal: bool,
    answers: usize,
    expected_answer_count: usize,
    answer_name_case_equal: bool,
    answer_class_equal: bool,
    ttl_min: Option<u32>,
    ttl_max: Option<u32>,
    peer_loopback: bool,
    peer_port: u16,
}
pub(crate) struct Observer {
    names: [String; 4],
    expected: Ipv4Addr,
    direct_port: AtomicU16,
    counts: [AtomicU64; 8],
    metadata: std::sync::Mutex<Vec<ReplyMetadata>>,
    metadata_dropped: AtomicU64,
    rejected: [AtomicU64; 3],
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
            names: ['s', 't', 'u', 'v'].map(|stage| format!("peer.{stage}{nonce}.phub.")),
            expected,
            direct_port: AtomicU16::new(0),
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
            metadata: std::sync::Mutex::new(Vec::new()),
            metadata_dropped: AtomicU64::new(0),
            rejected: std::array::from_fn(|_| AtomicU64::new(0)),
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
            || !self
                .names
                .contains(&q.queries[0].name().to_ascii().to_ascii_lowercase())
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
            self.rejected[0].fetch_add(1, Ordering::SeqCst);
            return;
        };
        let wrong_id = answer.metadata.id != q.metadata.id;
        let wrong_type = answer.metadata.message_type != MessageType::Response;
        if wrong_id {
            self.rejected[1].fetch_add(1, Ordering::SeqCst);
        }
        if wrong_type {
            self.rejected[2].fetch_add(1, Ordering::SeqCst);
        }
        if wrong_id || wrong_type {
            return;
        }
        let order = self.counts[5].fetch_add(1, Ordering::SeqCst);
        let question = answer.queries.first();
        let expected: Vec<_> = answer
            .answers
            .iter()
            .filter(|r| matches!(&r.data, RData::A(A(ip)) if *ip == self.expected))
            .collect();
        let phase = self
            .names
            .iter()
            .position(|name| *name == q.queries[0].name().to_ascii().to_ascii_lowercase())
            .unwrap() as u8;
        let row = ReplyMetadata {
            order,
            phase,
            query_type: q.queries[0].query_type().into(),
            query_class: q.queries[0].query_class().into(),
            query_flags: u16::from_be_bytes([query[2], query[3]]),
            response_flags: u16::from_be_bytes([reply[2], reply[3]]),
            query_id: q.metadata.id,
            response_id: answer.metadata.id,
            id_equal: q.metadata.id == answer.metadata.id,
            question_count: answer.queries.len(),
            question_name_case_equal: question
                .is_some_and(|v| v.name().to_ascii() == q.queries[0].name().to_ascii()),
            question_name_folded_equal: question.is_some_and(|v| {
                v.name()
                    .to_ascii()
                    .eq_ignore_ascii_case(&q.queries[0].name().to_ascii())
            }),
            question_type_equal: question
                .is_some_and(|v| v.query_type() == q.queries[0].query_type()),
            question_class_equal: question
                .is_some_and(|v| v.query_class() == q.queries[0].query_class()),
            answers: answer.answers.len(),
            expected_answer_count: expected.len(),
            answer_name_case_equal: expected
                .iter()
                .all(|v| v.name.to_ascii() == q.queries[0].name().to_ascii()),
            answer_class_equal: expected
                .iter()
                .all(|v| v.dns_class == q.queries[0].query_class()),
            ttl_min: answer.answers.iter().map(|v| v.ttl).min(),
            ttl_max: answer.answers.iter().map(|v| v.ttl).max(),
            peer_loopback: remote.ip().is_loopback(),
            peer_port: remote.port(),
        };
        if let Ok(mut rows) = self.metadata.lock() {
            if rows.iter().filter(|row| row.phase == phase).count() < 8 {
                rows.push(row);
            } else {
                self.metadata_dropped.fetch_add(1, Ordering::SeqCst);
            }
        }

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
            metadata: self.metadata.lock().unwrap().clone(),
            metadata_dropped: self.metadata_dropped.load(Ordering::SeqCst),
            malformed_replies: self.rejected[0].load(Ordering::SeqCst),
            mismatched_ids: self.rejected[1].load(Ordering::SeqCst),
            mismatched_types: self.rejected[2].load(Ordering::SeqCst),
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

#[test]
fn metadata_retains_case_mismatch_and_bounds_exact_owned_rows() -> Result<()> {
    let nonce = "0123456789abcdef0123456789abcdef";
    let name = format!("peer.s{nonce}.phub.");
    let ip = "10.254.254.2".parse()?;
    let observer = Observer::new(name.clone(), nonce, ip)?;
    let mut q = Message::new(7, MessageType::Query, OpCode::Query);
    q.add_query(hickory_proto::op::Query::query(
        name.to_uppercase().parse()?,
        RecordType::A,
    ));
    let mut query = q.to_vec()?;
    // Preserve actual wire case rather than Name's presentation normalization.
    for byte in &mut query[12..] {
        if byte.is_ascii_lowercase() {
            *byte = byte.to_ascii_uppercase();
        }
    }
    let mut a = Message::new(7, MessageType::Response, OpCode::Query);
    a.add_query(hickory_proto::op::Query::query(
        name.parse()?,
        RecordType::A,
    ));
    a.add_answer(Record::from_rdata(name.parse()?, 5, RData::A(A(ip))));
    let reply = a.to_vec()?;
    for _ in 0..10 {
        observer.reply(&query, &reply, "127.0.0.1:12345".parse()?);
    }
    let counts = observer.snapshot();
    assert_eq!(counts.metadata.len(), 8);
    assert_eq!(counts.metadata_dropped, 2);
    let row = &counts.metadata[0];
    assert!(!row.question_name_case_equal && row.question_name_folded_equal);
    assert!(!row.answer_name_case_equal && row.answer_class_equal);
    assert!(row.id_equal && row.question_type_equal && row.question_class_equal);
    assert_eq!(
        (row.ttl_min, row.ttl_max, row.expected_answer_count),
        (Some(5), Some(5), 1)
    );
    assert_eq!(
        (row.query_id, row.response_id, row.peer_port),
        (7, 7, 12345)
    );
    Ok(())
}

#[test]
fn rejected_response_identity_remains_visible_without_accepted_counts() -> Result<()> {
    let nonce = "0123456789abcdef0123456789abcdef";
    let name = format!("peer.s{nonce}.phub.");
    let observer = Observer::new(name.clone(), nonce, "10.254.254.2".parse()?)?;
    let mut q = Message::new(7, MessageType::Query, OpCode::Query);
    q.add_query(hickory_proto::op::Query::query(
        name.parse()?,
        RecordType::A,
    ));
    let query = q.to_vec()?;
    let peer = "127.0.0.1:12345".parse()?;
    let mut a = q.clone();
    a.metadata.message_type = MessageType::Response;
    a.metadata.id = 8;
    observer.reply(&query, &a.to_vec()?, peer);
    observer.reply(&query, &query, peer);
    observer.reply(&query, &[0], peer);
    let c = observer.snapshot();
    assert_eq!(
        (c.mismatched_ids, c.mismatched_types, c.malformed_replies),
        (1, 1, 1)
    );
    assert_eq!((c.replies, c.expected_a, c.noerror), (0, 0, 0));
    assert!(c.metadata.is_empty());
    Ok(())
}

#[test]
fn phase_metadata_is_bounded_independently_for_exact_owned_lifecycle_names() -> Result<()> {
    let nonce = "0123456789abcdef0123456789abcdef";
    let observer = Observer::new(
        format!("peer.s{nonce}.phub."),
        nonce,
        "10.254.254.2".parse()?,
    )?;
    for stage in ['s', 't', 'u', 'v'] {
        let mut q = Message::new(7, MessageType::Query, OpCode::Query);
        q.add_query(hickory_proto::op::Query::query(
            format!("peer.{stage}{nonce}.phub.").parse()?,
            RecordType::AAAA,
        ));
        let query = q.to_vec()?;
        q.metadata.message_type = MessageType::Response;
        for _ in 0..9 {
            observer.reply(&query, &q.to_vec()?, "127.0.0.1:12345".parse()?);
        }
    }
    let c = observer.snapshot();
    assert_eq!(c.metadata.len(), 32);
    assert_eq!(c.metadata_dropped, 4);
    for phase in 0..4 {
        assert_eq!(
            c.metadata.iter().filter(|row| row.phase == phase).count(),
            8
        );
    }
    Ok(())
}
