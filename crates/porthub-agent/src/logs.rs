//! Bounded, profile-scoped diagnostics. Redaction happens before both console
//! output and retention. No log files, tail processes or disk polling are used.
use crate::{
    control::{Control, Failure},
    profile::Profile,
};
use std::{
    collections::VecDeque,
    io::{self, Write},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::fmt::MakeWriter;

const MAX_LINES: usize = 256;
const MAX_BYTES: usize = 128 * 1024;
const MAX_RAW_EVENT: usize = 16 * 1024;
const MAX_LINE_CHARS: usize = 4000;

#[derive(Default)]
struct Redaction {
    secrets: Vec<String>,
    hosts: Vec<String>,
}
impl Redaction {
    fn profile(profile: &Profile) -> Self {
        let mut secrets = vec![
            profile.token.clone(),
            url::form_urlencoded::byte_serialize(profile.token.as_bytes()).collect(),
        ];
        if let Ok(json) = serde_json::to_string(&profile.token) {
            secrets.push(json[1..json.len() - 1].to_owned());
        }
        let debug = format!("{:?}", profile.token);
        secrets.push(debug[1..debug.len() - 1].to_owned());
        secrets.retain(|value| !value.is_empty());
        secrets.sort_by_key(|value| std::cmp::Reverse(value.len()));
        secrets.dedup();
        let mut hosts = Vec::new();
        for base in std::iter::once(&profile.server).chain(&profile.fallback_servers) {
            if let Ok(url) = url::Url::parse(base) {
                if let Some(host) = url.host_str() {
                    hosts.push(host.to_owned());
                }
            }
        }
        Self { secrets, hosts }
    }
    fn clean(&self, text: &str) -> String {
        // Match credentials before URL delimiters or address tokenization can
        // split a quoted/escaped token and leave a readable suffix behind.
        let mut text = text.to_owned();
        for secret in &self.secrets {
            text = text.replace(secret, "[redacted]");
        }
        let mut clean = String::with_capacity(text.len());
        let mut rest = text.as_str();
        // A URL can contain arbitrary encoded credentials and query strings;
        // remove the whole endpoint before formatting or truncation.
        while !rest.is_empty() {
            let scheme = ["https://", "http://", "wss://", "ws://", "tcp://", "udp://"]
                .iter()
                .any(|prefix| {
                    rest.get(..prefix.len())
                        .is_some_and(|part| part.eq_ignore_ascii_case(prefix))
                });
            if scheme {
                let end = rest
                    .char_indices()
                    .find(|(_, ch)| {
                        ch.is_whitespace() || matches!(ch, '\'' | '"' | '<' | '>' | '`' | ')')
                    })
                    .map_or(rest.len(), |(i, _)| i);
                clean.push_str("[endpoint]");
                rest = &rest[end..];
            } else {
                let ch = rest.chars().next().unwrap();
                if !ch.is_control() || matches!(ch, '\n' | '\t') {
                    clean.push(ch);
                }
                rest = &rest[ch.len_utf8()..];
            }
        }
        let mut output = String::with_capacity(clean.len());
        let mut token = String::new();
        let flush = |token: &mut String, output: &mut String| {
            let ip = token.split('%').next().unwrap_or_default();
            if ip.parse::<IpAddr>().is_ok() || token.parse::<SocketAddr>().is_ok() {
                output.push_str("[address]");
            } else {
                output.push_str(token);
            }
            token.clear();
        };
        for ch in clean.chars() {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | ':' | '%' | '_' | '-') {
                token.push(ch);
            } else {
                flush(&mut token, &mut output);
                output.push(ch);
            }
        }
        flush(&mut token, &mut output);
        for host in &self.hosts {
            output = output.replace(host, "[gateway]");
        }
        output
    }
}
#[derive(Default)]
struct Ring {
    lines: VecDeque<(u64, String)>,
    sequence: u64,
    bytes: usize,
}
#[derive(Default)]
struct Inner {
    ring: Mutex<Ring>,
    redaction: Mutex<Redaction>,
}
#[derive(Clone, Default)]
pub struct Buffer(Arc<Inner>);
pub struct Batch {
    pub lines: Vec<String>,
    pub next: u64,
}
impl Buffer {
    pub fn configure(&self, profile: &Profile) {
        *self.0.redaction.lock().unwrap_or_else(|p| p.into_inner()) = Redaction::profile(profile);
    }
    pub fn configure_private(&self, profile: &crate::private_profile::Profile) {
        self.configure(&Profile {
            format_version: 1,
            server: profile.server.clone(),
            machine_id: profile.peer_id.clone(),
            token: profile.token.clone(),
            fallback_servers: profile.fallback_servers.clone(),
            setup_overrides: Default::default(),
            allow_insecure_http_for_tests: profile.allow_insecure_http_for_tests,
        });
    }
    fn clean(&self, text: &str) -> String {
        self.0
            .redaction
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clean(text)
    }
    fn retain(&self, text: &str) {
        let mut ring = self.0.ring.lock().unwrap_or_else(|p| p.into_inner());
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let line: String = line.chars().take(MAX_LINE_CHARS).collect();
            ring.sequence = ring.sequence.saturating_add(1);
            let sequence = ring.sequence;
            ring.bytes += line.len();
            ring.lines.push_back((sequence, line));
            while ring.lines.len() > MAX_LINES || ring.bytes > MAX_BYTES {
                if let Some((_, line)) = ring.lines.pop_front() {
                    ring.bytes -= line.len();
                }
            }
        }
    }
    /// Record a diagnostic without writing to stdout. Used by native callers
    /// that already have a console sink, and by isolated tests.
    pub fn record(&self, text: &str) {
        if text.len() > MAX_RAW_EVENT {
            self.retain("diagnostic event omitted (size limit)");
        } else {
            self.retain(&self.clean(text));
        }
    }
    pub fn batch(&self, cursor: Option<u64>, initial: usize, limit: usize) -> Batch {
        let ring = self.0.ring.lock().unwrap_or_else(|p| p.into_inner());
        let start = if cursor.is_none() {
            ring.lines.len().saturating_sub(initial.min(MAX_LINES))
        } else {
            0
        };
        let selected: Vec<_> = ring
            .lines
            .iter()
            .skip(start)
            .filter(|(seq, _)| cursor.is_none_or(|cursor| *seq > cursor))
            .take(limit.min(100))
            .collect();
        Batch {
            next: selected
                .last()
                .map_or(cursor.unwrap_or(ring.sequence), |(seq, _)| *seq),
            lines: selected.into_iter().map(|(_, line)| line.clone()).collect(),
        }
    }
}
pub struct EventWriter {
    buffer: Buffer,
    raw: Vec<u8>,
    overflow: bool,
}
impl Write for EventWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.overflow {
            if self.raw.len() + bytes.len() > MAX_RAW_EVENT {
                self.raw.clear();
                self.overflow = true;
            } else {
                self.raw.extend_from_slice(bytes);
            }
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Drop for EventWriter {
    fn drop(&mut self) {
        let text = if self.overflow {
            "diagnostic event omitted (size limit)\n".into()
        } else {
            self.buffer.clean(&String::from_utf8_lossy(&self.raw))
        };
        self.buffer.retain(&text);
        let _ = io::stdout().lock().write_all(text.as_bytes());
    }
}
impl<'a> MakeWriter<'a> for Buffer {
    type Writer = EventWriter;
    fn make_writer(&'a self) -> EventWriter {
        EventWriter {
            buffer: self.clone(),
            raw: Vec::new(),
            overflow: false,
        }
    }
}

pub struct Options {
    pub poll: Duration,
    pub flush: Duration,
    pub max_retry: Duration,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            poll: Duration::from_secs(5),
            flush: Duration::from_secs(2),
            max_retry: Duration::from_secs(60),
        }
    }
}
pub struct Guard {
    cancel: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl Guard {
    pub fn start(control: Arc<Control>, buffer: Buffer, cancel: CancellationToken) -> Self {
        let task = tokio::spawn(run(control, buffer, cancel.clone(), Options::default()));
        Self {
            cancel,
            task: Some(task),
        }
    }
    pub async fn stop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
pub async fn run(
    control: Arc<Control>,
    buffer: Buffer,
    cancel: CancellationToken,
    options: Options,
) {
    if options.poll.is_zero() || options.flush.is_zero() || options.max_retry < options.poll {
        return;
    }
    let mut poll = tokio::time::Instant::now();
    let mut flush = poll;
    let mut poll_retry = options.poll;
    let mut upload_retry = options.poll;
    let mut active = false;
    let mut cursor = None;
    let mut pending: Option<Batch> = None;
    loop {
        let due = if active { poll.min(flush) } else { poll };
        tokio::select! { biased; _=cancel.cancelled()=>return, _=tokio::time::sleep_until(due)=>{} }
        if tokio::time::Instant::now() >= poll {
            let status = tokio::select! { biased; _=cancel.cancelled()=>return, result=control.log_requested()=>result };
            match status {
                Ok(requested) => {
                    if !requested {
                        cursor = None;
                        pending = None;
                        upload_retry = options.poll;
                    }
                    if requested && !active {
                        flush = tokio::time::Instant::now();
                    }
                    active = requested;
                    poll_retry = options.poll;
                    poll = tokio::time::Instant::now() + options.poll;
                }
                Err(Failure::Rejected(410)) => return,
                Err(_) => {
                    active = false;
                    pending = None;
                    cursor = None;
                    poll = tokio::time::Instant::now() + poll_retry;
                    poll_retry = (poll_retry * 2).min(options.max_retry);
                }
            }
        }
        if active && tokio::time::Instant::now() >= flush {
            let batch = pending
                .take()
                .unwrap_or_else(|| buffer.batch(cursor, 3, 100));
            if !batch.lines.is_empty() {
                let uploaded = tokio::select! { biased; _=cancel.cancelled()=>return, result=control.upload_logs(&batch.lines)=>result };
                match uploaded {
                    Ok(()) => {
                        cursor = Some(batch.next);
                        upload_retry = options.poll;
                    }
                    Err(Failure::Rejected(410)) => return,
                    Err(_) => {
                        pending = Some(batch);
                        flush = tokio::time::Instant::now() + upload_retry;
                        upload_retry = (upload_retry * 2).min(options.max_retry);
                        continue;
                    }
                }
            }
            flush = tokio::time::Instant::now() + options.flush;
        }
    }
}
