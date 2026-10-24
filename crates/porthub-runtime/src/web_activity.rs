//! Request counts are aggregated in memory, then written as bounded batches.
//! The core reads this edge-owned volume read-only. No request addresses, paths,
//! queries, credentials or payloads enter this journal.
use anyhow::{Context, Result};
use chrono::Datelike;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};
use tokio::sync::{watch, Notify};

pub const MAX_RECORDS: usize = 512;
const MAX_PENDING: usize = 16_384;
const ROTATE_BYTES: u64 = 10 * 1024 * 1024;
const MAX_READ: u64 = 2 * 1024 * 1024;

pub fn segments(path: &Path) -> [PathBuf; 3] {
    let suffix = |number| {
        let mut value = path.as_os_str().to_os_string();
        value.push(format!(".{number}"));
        PathBuf::from(value)
    };
    [suffix(2), suffix(1), path.into()]
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub identity: String,
    pub offset: u64,
}
pub struct Read {
    pub checkpoint: Checkpoint,
    pub batches: Vec<Batch>,
    pub gap: bool,
    pub more: bool,
}

pub fn read_batch(path: &Path, checkpoint: Option<&Checkpoint>) -> Result<Option<Read>> {
    use std::{
        io::{Read as _, Seek, SeekFrom},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let mut files = Vec::new();
    for path in segments(path) {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file(),
            "activity journal must be a regular file"
        );
        files.push((
            file,
            format!("{}:{}", metadata.dev(), metadata.ino()),
            metadata.len(),
        ));
    }
    if files.is_empty() {
        return Ok(None);
    }
    let found = checkpoint.and_then(|checkpoint| {
        files
            .iter()
            .position(|(_, identity, _)| identity == &checkpoint.identity)
    });
    let mut gap = checkpoint.is_some() && found.is_none();
    let file_count = files.len();
    let start = found.unwrap_or(0);
    let mut remaining = MAX_READ;
    let mut batches = Vec::new();
    let mut result = None;
    let mut more = false;
    for (index, (mut file, identity, length)) in files.into_iter().enumerate().skip(start) {
        let mut offset = if Some(index) == found {
            checkpoint.unwrap().offset
        } else {
            0
        };
        if offset > length {
            gap = true;
            offset = 0;
        }
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = Vec::new();
        file.take(remaining).read_to_end(&mut bytes)?;
        let end = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map(|position| position + 1)
            .unwrap_or(0);
        for line in bytes[..end]
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            match serde_json::from_slice::<Batch>(line) {
                Ok(batch)
                    if batch.version == 1
                        && uuid::Uuid::parse_str(&batch.id).is_ok()
                        && batch.records.len() <= MAX_RECORDS
                        && batch.records.iter().all(|record| {
                            !record.route_id.is_empty()
                                && record.route_id.len() <= 128
                                && record.host.len() <= 253
                                && record.count >= 0
                                && chrono::DateTime::from_timestamp_millis(record.timestamp)
                                    .is_some()
                        }) =>
                {
                    batches.push(batch)
                }
                _ => gap = true,
            }
        }
        let consumed = if end == 0 && bytes.len() as u64 == MAX_READ {
            gap = true;
            bytes.len()
        } else {
            end
        };
        offset += consumed as u64;
        remaining = remaining.saturating_sub(bytes.len() as u64);
        // A rotated segment is closed. An incomplete tail there can never
        // finish, so mark the gap and continue to the next segment.
        if index + 1 < file_count
            && offset < length
            && (bytes.len() as u64) < MAX_READ
            && remaining > 0
        {
            gap = true;
            offset = length;
        }
        result = Some(Checkpoint { identity, offset });
        if offset < length {
            more = remaining == 0;
            break;
        }
        if remaining == 0 {
            more = index + 1 < file_count;
            break;
        }
    }
    Ok(result.map(|checkpoint| Read {
        checkpoint,
        batches,
        gap,
        more,
    }))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub route_id: String,
    pub count: i64,
    pub timestamp: i64,
    pub host: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    pub version: u8,
    pub id: String,
    pub coverage_warning: bool,
    pub records: Vec<Record>,
}
#[derive(Default)]
struct Pending {
    counts: BTreeMap<(String, i32), Record>,
    warning: bool,
}
#[derive(Default)]
pub struct WebActivity {
    pending: Mutex<Pending>,
    changed: Notify,
}
impl WebActivity {
    pub fn record(&self, route: &str, host: &str) {
        self.record_at(route, host, chrono::Utc::now());
    }
    fn record_at(&self, route: &str, host: &str, now: chrono::DateTime<chrono::Utc>) {
        let key = (route.to_owned(), now.year() * 100 + now.month() as i32);
        let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        if pending.counts.len() >= MAX_PENDING && !pending.counts.contains_key(&key) {
            pending.warning = true;
            drop(pending);
            self.changed.notify_one();
            return;
        }
        let record = pending.counts.entry(key).or_insert_with(|| Record {
            route_id: route.into(),
            count: 0,
            timestamp: 0,
            host: String::new(),
        });
        record.count = record.count.saturating_add(1);
        if now.timestamp_millis() >= record.timestamp {
            record.timestamp = now.timestamp_millis();
            if record.host != host {
                record.host.clear();
                record.host.push_str(host);
            }
        }
        drop(pending);
        self.changed.notify_one();
    }
    fn take(&self) -> Option<Batch> {
        let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        if pending.counts.is_empty() {
            return None;
        }
        let mut records = Vec::with_capacity(pending.counts.len().min(MAX_RECORDS));
        for _ in 0..MAX_RECORDS {
            match pending.counts.pop_first() {
                Some((_, record)) => records.push(record),
                None => break,
            }
        }
        Some(Batch {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            coverage_warning: pending.warning,
            records,
        })
    }
    pub async fn run(
        &self,
        path: PathBuf,
        mut stop: watch::Receiver<bool>,
        interval: Duration,
    ) -> Result<()> {
        let mut opening_backoff = Duration::from_secs(1);
        let mut journal = loop {
            let path = path.clone();
            let attempt = tokio::task::spawn_blocking(move || Journal::open(&path)).await?;
            match attempt {
                Ok(journal) => break journal,
                Err(error) => {
                    if *stop.borrow() {
                        return Err(error);
                    }
                    self.pending
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .warning = true;
                    tracing::warn!("web activity journal unavailable; retrying");
                    tracing::debug!(%error,"web activity journal details");
                    tokio::select! {_=tokio::time::sleep(opening_backoff)=>{},_=stop.changed()=>return Err(error)}
                    opening_backoff = (opening_backoff * 2).min(Duration::from_secs(30));
                }
            }
        };
        let warning = journal.unclean
            || self
                .pending
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .warning;
        let mut batch = warning.then(|| Batch {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            coverage_warning: true,
            records: Vec::new(),
        });
        let mut stopping = *stop.borrow();
        let mut backoff = Duration::from_secs(1);
        let mut next_flush = tokio::time::Instant::now() + interval;
        loop {
            if batch.is_none() {
                if !stopping {
                    tokio::select! {_=tokio::time::sleep_until(next_flush)=>{},_=stop.changed()=>stopping=true}
                }
                batch = self.take();
                if batch.is_none() {
                    if stopping {
                        break;
                    }
                    tokio::select! {_=self.changed.notified()=>{},_=stop.changed()=>stopping=true}
                    if !stopping {
                        next_flush = tokio::time::Instant::now() + interval;
                        continue;
                    }
                    batch = self.take();
                    if batch.is_none() {
                        continue;
                    }
                }
            }
            let item = batch.take().unwrap();
            let (returned, result) = tokio::task::spawn_blocking(move || {
                let result = journal.append(&item);
                (journal, (item, result))
            })
            .await?;
            journal = returned;
            let (item, result) = result;
            match result {
                Ok(()) => {
                    backoff = Duration::from_secs(1);
                    next_flush = tokio::time::Instant::now() + interval;
                }
                Err(error) => {
                    self.pending
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .warning = true;
                    if stopping {
                        return Err(error);
                    }
                    tracing::warn!("web activity journal write failed; retrying");
                    tracing::debug!(%error,"web activity journal details");
                    batch = Some(item);
                    tokio::select! {_=tokio::time::sleep(backoff)=>{},_=stop.changed()=>stopping=true}
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
        tokio::task::spawn_blocking(move || journal.finish()).await??;
        Ok(())
    }
}

struct Journal {
    path: PathBuf,
    file: File,
    _lock: File,
    unclean: bool,
    start: Option<u64>,
}
impl Journal {
    fn open(path: &Path) -> Result<Self> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let parent = path
            .parent()
            .context("activity journal needs a parent directory")?;
        std::fs::create_dir_all(parent)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o640)
            .open(path.with_extension("lock"))?;
        fs2::FileExt::try_lock_exclusive(&lock).context("activity journal already has a writer")?;
        let marker = path.with_extension("unclean");
        let unclean = marker.exists();
        let file = Self::file(path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o640))?;
        std::fs::write(&marker, b"running\n")?;
        File::open(&marker)?.sync_all()?;
        File::open(parent)?.sync_all()?;
        Ok(Self {
            path: path.into(),
            file,
            _lock: lock,
            unclean,
            start: None,
        })
    }
    fn file(path: &Path) -> Result<File> {
        use std::os::unix::fs::OpenOptionsExt;
        Ok(OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o640)
            .open(path)?)
    }
    fn append(&mut self, batch: &Batch) -> Result<()> {
        if self.start.is_none() {
            if self.file.metadata()?.len() >= ROTATE_BYTES {
                self.file.sync_data()?;
                let [two, one, _] = segments(&self.path);
                match std::fs::remove_file(&two) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                if one.exists() {
                    std::fs::rename(&one, &two)?;
                }
                std::fs::rename(&self.path, &one)?;
                self.file = Self::file(&self.path)?;
                File::open(self.path.parent().unwrap())?.sync_all()?;
            }
            self.start = Some(self.file.metadata()?.len());
        }
        let start = self.start.unwrap();
        // Retries reuse the batch ID and restore any incomplete previous append.
        // Core persists its checkpoint and bounded recent-ID set with the counts.
        self.file.set_len(start)?;
        let mut encoded = serde_json::to_vec(batch)?;
        encoded.push(b'\n');
        self.file.write_all(&encoded)?;
        self.file.sync_data()?;
        self.start = None;
        Ok(())
    }
    fn finish(self) -> Result<()> {
        self.file.sync_data()?;
        std::fs::remove_file(self.path.with_extension("unclean"))?;
        File::open(self.path.parent().unwrap())?.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    fn batch(count: i64) -> Batch {
        Batch {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            coverage_warning: false,
            records: vec![Record {
                route_id: "route-one".into(),
                count,
                timestamp: 1_700_000_000_000,
                host: "app.example.invalid".into(),
            }],
        }
    }
    #[test]
    fn aggregation_is_bounded_and_keeps_months_separate() {
        let activity = WebActivity::default();
        let old = chrono::Utc
            .with_ymd_and_hms(2026, 9, 30, 23, 59, 0)
            .unwrap();
        let new = old + chrono::Duration::minutes(2);
        activity.record_at("a", "old.invalid", old);
        activity.record_at("a", "new.invalid", new);
        activity.record_at("a", "latest.invalid", new + chrono::Duration::seconds(1));
        let records = activity.take().unwrap().records;
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].count, 1);
        assert_eq!(records[1].count, 2);
        assert_eq!(records[1].host, "latest.invalid");
        assert!(activity.take().is_none());
        for index in 0..MAX_PENDING + 1 {
            activity.record_at(&format!("{index}"), "app.invalid", new);
        }
        assert_eq!(activity.pending.lock().unwrap().counts.len(), MAX_PENDING);
        let batch = activity.take().unwrap();
        assert!(batch.coverage_warning);
        assert_eq!(batch.records.len(), MAX_RECORDS);
    }
    #[test]
    fn writer_lease_crash_marker_rotation_and_partial_tail() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("activity.log");
        let mut writer = Journal::open(&path)?;
        assert!(!writer.unclean);
        assert!(Journal::open(&path).is_err());
        let first = batch(2);
        writer.append(&first)?;
        let read = read_batch(&path, None)?.unwrap();
        assert_eq!(read.batches[0].id, first.id);
        let cp = read.checkpoint;
        // Simulate a full segment without writing ten MiB of fixture payload.
        writer.file.set_len(ROTATE_BYTES)?;
        writer.append(&batch(3))?;
        let read = read_batch(&path, Some(&cp))?.unwrap();
        assert!(read.more);
        let mut cp = read.checkpoint;
        loop {
            let read = read_batch(&path, Some(&cp))?.unwrap();
            cp = read.checkpoint;
            if !read.more {
                assert_eq!(read.batches.last().unwrap().records[0].count, 3);
                break;
            }
        }
        let third = batch(7);
        let encoded = serde_json::to_vec(&third)?;
        writer.file.write_all(&encoded[..encoded.len() / 2])?;
        let read = read_batch(&path, Some(&cp))?.unwrap();
        assert!(read.batches.is_empty());
        assert_eq!(read.checkpoint, cp);
        writer.file.write_all(&encoded[encoded.len() / 2..])?;
        writer.file.write_all(b"\n")?;
        assert_eq!(
            read_batch(&path, Some(&cp))?.unwrap().batches[0].id,
            third.id
        );
        drop(writer);
        let writer = Journal::open(&path)?;
        assert!(writer.unclean);
        writer.finish()?;
        let writer = Journal::open(&path)?;
        assert!(!writer.unclean);
        writer.finish()?;
        Ok(())
    }
    #[test]
    fn reader_rejects_symlinks_and_marks_corrupt_or_missing_history() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("activity.log");
        let target = temp.path().join("target");
        std::fs::write(&target, b"private")?;
        std::os::unix::fs::symlink(&target, &path)?;
        assert!(read_batch(&path, None).is_err());
        std::fs::remove_file(&path)?;
        std::fs::write(&path, b"{invalid}\n")?;
        let read = read_batch(
            &path,
            Some(&Checkpoint {
                identity: "old".into(),
                offset: 10,
            }),
        )?
        .unwrap();
        assert!(read.gap);
        assert!(read.batches.is_empty());
        assert_eq!(read.checkpoint.offset, 10);
        Ok(())
    }
    #[tokio::test]
    async fn writer_coalesces_busy_requests_and_flushes_on_shutdown() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("activity.log");
        let activity = std::sync::Arc::new(WebActivity::default());
        let (stop, stopping) = watch::channel(false);
        let shared = activity.clone();
        let log = path.clone();
        let task =
            tokio::spawn(
                async move { shared.run(log, stopping, Duration::from_millis(100)).await },
            );
        for _ in 0..100 {
            activity.record("route-one", "app.invalid");
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        for _ in 0..100 {
            activity.record("route-one", "app.invalid");
            tokio::task::yield_now().await;
        }
        stop.send(true)?;
        task.await??;
        let read = read_batch(&path, None)?.unwrap();
        assert_eq!(
            read.batches
                .iter()
                .flat_map(|batch| &batch.records)
                .map(|record| record.count)
                .sum::<i64>(),
            200
        );
        assert!(read.batches.len() <= 2, "busy requests must coalesce");
        assert!(!path.with_extension("unclean").exists());
        Ok(())
    }
}
