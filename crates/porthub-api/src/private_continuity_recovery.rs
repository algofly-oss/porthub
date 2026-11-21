//! Recover abandoned policy writers only after proving both halves of retirement:
//! the process released its exclusive file and standalone MongoDB has drained
//! every connection and operation tagged with that unique process identity.
use crate::App;
use futures_util::TryStreamExt;
use mongodb::bson::{doc, Document};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};
use uuid::Uuid;

pub(crate) struct Writer {
    directory: PathBuf,
    directory_id: String,
    slot: u8,
    _lock: File,
    last: Mutex<(Option<Instant>, usize)>,
}
impl Writer {
    pub fn start(directory: PathBuf, process: &str) -> Option<Self> {
        fs::create_dir_all(&directory).ok()?;
        if !fs::symlink_metadata(&directory).ok()?.is_dir() {
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = fs::symlink_metadata(&directory).ok()?;
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
                return None;
            }
        }
        let anchor = directory.join("directory-id");
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&anchor)
        {
            Ok(mut f) => {
                f.write_all(Uuid::new_v4().to_string().as_bytes()).ok()?;
                f.sync_data().ok()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            _ => return None,
        }
        if !fs::symlink_metadata(&anchor).ok()?.is_file() {
            return None;
        }
        let directory_id = Uuid::parse_str(&fs::read_to_string(&anchor).ok()?)
            .ok()?
            .to_string();
        for slot in 0..32u8 {
            let path = directory.join(format!("writer-{slot}"));
            if fs::symlink_metadata(&path).is_ok_and(|m| !m.is_file()) {
                return None;
            }
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(path)
                .ok()?;
            if file.try_lock().is_err() {
                continue;
            }
            file.set_len(0).ok()?;
            file.write_all(process.as_bytes()).ok()?;
            file.sync_data().ok()?;
            return Some(Self {
                directory,
                directory_id,
                slot,
                _lock: file,
                last: Mutex::new((None, 0)),
            });
        }
        None
    }
    pub fn identity(&self) -> Document {
        doc! {"directory":&self.directory_id,"slot":i32::from(self.slot)}
    }
    fn retired(&self, record: &Document, process: &str) -> bool {
        let Some(result) = (|| {
            let identity = record.get_document("owner").ok()?;
            if identity.get_str("directory").ok()? != self.directory_id {
                return Some(false);
            }
            let slot = identity.get_i32("slot").ok()?;
            if !(0..32).contains(&slot) {
                return Some(false);
            }
            let path = self.directory.join(format!("writer-{slot}"));
            if !fs::symlink_metadata(&path).ok()?.is_file() {
                return None;
            }
            let mut file = OpenOptions::new().read(true).write(true).open(path).ok()?;
            let mut actual = String::new();
            std::io::Read::by_ref(&mut file)
                .take(64)
                .read_to_string(&mut actual)
                .ok()?;
            Uuid::parse_str(&actual).ok()?;
            // Slot identity only changes while the new process exclusively owns
            // this same file. The old process never reacquires a retired slot.
            Some(actual != process || file.try_lock().is_ok())
        })() else {
            return false;
        };
        result
    }
    #[cfg(test)]
    pub(super) fn reset_throttle(&self) {
        self.last.lock().unwrap().0 = None;
    }
    pub async fn recover(&self, app: &App, row: &Document) {
        let Ok(writers) = row.get_document("writers") else {
            return;
        };
        if writers.is_empty() {
            return;
        }
        // No filesystem/database reconciliation on the common stable path.
        let offset = {
            let Ok(mut state) = self.last.lock() else {
                return;
            };
            if state
                .0
                .is_some_and(|t| t.elapsed() < Duration::from_secs(15))
            {
                return;
            }
            state.0 = Some(Instant::now());
            let offset = state.1 % writers.len();
            state.1 = (offset + 8) % writers.len();
            offset
        };
        let recover = async {
            let id = row.get_str("_id").ok()?;
            let admin = app.db.client().database("admin");
            let hello = admin.run_command(doc! {"hello":1}).await.ok()?;
            if hello.contains_key("setName") || hello.get_str("msg").ok() == Some("isdbgrid") {
                return None;
            }
            for (ticket, value) in writers
                .iter()
                .skip(offset)
                .chain(writers.iter().take(offset))
                .take(writers.len().min(8))
            {
                if Uuid::parse_str(ticket).is_err() {
                    continue;
                }
                let record = value.as_document()?;
                if record.get_bool("tagged") != Ok(true) {
                    continue;
                }
                let process = record.get_str("process").ok()?;
                if !self.retired(record, process) {
                    continue;
                }
                let old = super::private_continuity::app_name(process);
                let own = super::private_continuity::app_name(super::private_continuity::process());
                let names = [old.as_str(), own.as_str()];
                let mut operations=admin.aggregate(vec![
                    doc!{"$currentOp":{"allUsers":true,"idleConnections":true,"idleSessions":true}},
                    doc!{"$match":{"$or":[{"appName":{"$in":names.to_vec()}},{"clientMetadata.application.name":{"$in":names.to_vec()}}]}},
                    doc!{"$project":{"_id":0,"appName":{"$ifNull":["$appName","$clientMetadata.application.name"]}}},
                    doc!{"$group":{"_id":"$appName"}}
                ]).await.ok()?;
                let mut own_visible = false;
                let mut old_visible = false;
                while let Some(op) = operations.try_next().await.ok()? {
                    let name = op.get_str("_id").ok()?;
                    own_visible |= name == own;
                    old_visible |= name == old;
                }
                if !own_visible || old_visible {
                    continue;
                }
                let key = format!("writers.{ticket}");
                // A retired process identity is never reused.
                super::private_continuity::collection(app)
                    .update_one(
                        doc! {"_id":id,format!("{key}.process"):process},
                        doc! {"$unset":{key:""},"$set":{"generation":Uuid::new_v4().to_string()}},
                    )
                    .await
                    .ok()?;
            }
            Some(())
        };
        let _ = tokio::time::timeout(Duration::from_millis(200), recover).await;
    }
}
pub(crate) fn directory() -> PathBuf {
    std::env::var_os("PORTHUB_PRIVATE_CONTINUITY_WRITER_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new("/data/private-policy-writers").into())
}
