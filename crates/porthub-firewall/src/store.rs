use crate::{Policy, Sample};
use anyhow::{ensure, Result};
use std::{collections::BTreeMap, path::Path, time::Duration};
use tokio_rusqlite::{params, Connection};

type StoredSample = (u16, Sample, String, String, String);

#[derive(Clone)]
pub struct Store {
    db: Connection,
}
impl Store {
    pub async fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let db = Connection::open(path).await?;
        db.call(|db|->tokio_rusqlite::rusqlite::Result<()> {
            db.busy_timeout(Duration::from_secs(5))?;
            db.execute_batch("PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS port_policies(port INTEGER PRIMARY KEY,is_public INTEGER NOT NULL DEFAULT 1,allowed_ips TEXT NOT NULL DEFAULT '[]',updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS traffic_buffer(port INTEGER NOT NULL,ts INTEGER NOT NULL,in_bytes INTEGER NOT NULL,out_bytes INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS active_ports(port INTEGER PRIMARY KEY,last_seen INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS recent_ip_hits(port INTEGER NOT NULL,ip TEXT NOT NULL,last_seen INTEGER NOT NULL,PRIMARY KEY(port,ip));
CREATE TABLE IF NOT EXISTS porthub_schema(key TEXT PRIMARY KEY,value TEXT NOT NULL);")?;
            let columns:Vec<String>=db.prepare("PRAGMA table_info(traffic_buffer)")?.query_map([],|row|row.get(1))?.collect::<Result<_,_>>()?;
            for (name,definition) in [("drop_bytes","INTEGER NOT NULL DEFAULT 0"),("blocked_ips","TEXT NOT NULL DEFAULT '[]'"),("incoming_ips","TEXT NOT NULL DEFAULT '[]'"),("outgoing_ips","TEXT NOT NULL DEFAULT '[]'"),("interval_seconds","REAL NOT NULL DEFAULT 1")] {
                if !columns.iter().any(|c|c==name){db.execute_batch(&format!("ALTER TABLE traffic_buffer ADD COLUMN {name} {definition}"))?;}
            }
            let legacy:i64=db.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='allowlists'",[],|r|r.get(0))?;
            let migrated:i64=db.query_row("SELECT count(*) FROM porthub_schema WHERE key='legacy_allowlists'",[],|r|r.get(0))?;
            if legacy>0 && migrated==0 {
                let tx=db.transaction()?;
                tx.execute_batch("INSERT OR IGNORE INTO port_policies(port,is_public,allowed_ips,updated_at) SELECT port,0,ips,strftime('%s','now') FROM allowlists; INSERT INTO porthub_schema(key,value) VALUES('legacy_allowlists','1');")?;
                tx.commit()?;
            }
            db.execute_batch("CREATE INDEX IF NOT EXISTS traffic_by_port_time ON traffic_buffer(port,ts);")?;
            Ok(())
        }).await?;
        Ok(Self { db })
    }
    pub async fn policies(&self) -> Result<BTreeMap<u16, Policy>> {
        let rows = self
            .db
            .call(
                |db| -> tokio_rusqlite::rusqlite::Result<Vec<(i64, bool, String)>> {
                    db.prepare(
                        "SELECT port,is_public,allowed_ips FROM port_policies ORDER BY port",
                    )?
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                    .collect()
                },
            )
            .await?;
        let mut policies = BTreeMap::new();
        for (port, is_public, ips) in rows {
            ensure!(
                (1..=65535).contains(&port),
                "invalid persisted firewall port"
            );
            policies.insert(
                port as u16,
                Policy {
                    is_public,
                    allowed_ips: serde_json::from_str(&ips)?,
                },
            );
        }
        Ok(policies)
    }
    pub async fn policy(&self, port: u16, policy: Option<Policy>) -> Result<()> {
        let encoded = policy
            .map(|p| serde_json::to_string(&p.allowed_ips).map(|ips| (p.is_public, ips)))
            .transpose()?;
        self.db.call(move|db|->tokio_rusqlite::rusqlite::Result<()> {
            if let Some((public,ips))=encoded {
                db.execute("INSERT OR REPLACE INTO port_policies(port,is_public,allowed_ips,updated_at) VALUES(?,?,?,strftime('%s','now'))",params![port,public,ips])?;
            } else {db.execute("DELETE FROM port_policies WHERE port=?",[port])?;}
            Ok(())
        }).await?;
        Ok(())
    }
    pub async fn purge(&self, port: u16) -> Result<()> {
        self.db.call(move |db| -> tokio_rusqlite::rusqlite::Result<()> {
            let tx=db.transaction()?;
            for table in ["traffic_buffer","active_ports","recent_ip_hits"] {
                tx.execute(&format!("DELETE FROM {table} WHERE port=?"), [port])?;
            }
            tx.commit()
        }).await?;
        Ok(())
    }
    pub async fn record(&self, samples: Vec<(u16, Sample)>) -> Result<()> {
        let rows: Vec<_> = samples
            .into_iter()
            .map(|(port, s)| {
                let incoming = serde_json::to_string(&s.incoming_ips)?;
                let outgoing = serde_json::to_string(&s.outgoing_ips)?;
                let blocked = serde_json::to_string(&s.blocked_ips)?;
                Ok::<_, serde_json::Error>((port, s, incoming, outgoing, blocked))
            })
            .collect::<Result<_, _>>()?;
        self.db.call(move|db|->tokio_rusqlite::rusqlite::Result<()> {
            let tx=db.transaction()?;
            let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
            for (port,s,incoming,outgoing,blocked) in rows {
                tx.execute("INSERT INTO traffic_buffer(port,ts,in_bytes,out_bytes,drop_bytes,incoming_ips,outgoing_ips,blocked_ips,interval_seconds) VALUES(?,?,?,?,?,?,?,?,?)",params![port,s.timestamp,s.in_bytes,s.out_bytes,s.drop_bytes,incoming,outgoing,blocked,s.interval_seconds])?;
                if s.in_bytes>0||s.out_bytes>0||s.drop_bytes>0 {
                    tx.execute("INSERT OR REPLACE INTO active_ports(port,last_seen) VALUES(?,?)",params![port,s.timestamp])?;
                }
                for ip in &s.incoming_ips {tx.execute("INSERT OR REPLACE INTO recent_ip_hits(port,ip,last_seen) VALUES(?,?,?)",params![port,ip,s.timestamp])?;}
                tx.execute("DELETE FROM recent_ip_hits WHERE port=? AND ip NOT IN (SELECT ip FROM recent_ip_hits WHERE port=? ORDER BY last_seen DESC,ip LIMIT 10)",params![port,port])?;
            }
            tx.execute("DELETE FROM traffic_buffer WHERE ts<?",[now-300])?;
            tx.execute("DELETE FROM active_ports WHERE last_seen<?",[now-300])?;
            tx.commit()
        }).await?;
        Ok(())
    }
    pub async fn snapshot(&self, ports: Vec<u16>) -> Result<BTreeMap<u16, Vec<Sample>>> {
        let filter = if ports.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&ports)?)
        };
        let rows=self.db.call(move|db|->tokio_rusqlite::rusqlite::Result<Vec<StoredSample>> {
            let mut query="SELECT port,ts,interval_seconds,in_bytes,out_bytes,drop_bytes,incoming_ips,outgoing_ips,blocked_ips FROM traffic_buffer WHERE ts>=strftime('%s','now')-300".to_owned();
            let mut parameters=Vec::new();
            if let Some(filter)=filter {query.push_str(" AND port IN (SELECT value FROM json_each(?))");parameters.push(filter);}
            query.push_str(" ORDER BY port,ts");
            db.prepare(&query)?.query_map(tokio_rusqlite::rusqlite::params_from_iter(parameters),|r|Ok((r.get(0)?,Sample{timestamp:r.get(1)?,interval_seconds:r.get(2)?,in_bytes:r.get(3)?,out_bytes:r.get(4)?,drop_bytes:r.get(5)?,incoming_ips:vec![],outgoing_ips:vec![],blocked_ips:vec![]},r.get(6)?,r.get(7)?,r.get(8)?)))?.collect()
        }).await?;
        let mut output: BTreeMap<u16, Vec<Sample>> = BTreeMap::new();
        for (port, mut sample, incoming, outgoing, blocked) in rows {
            sample.incoming_ips = serde_json::from_str(&incoming)?;
            sample.outgoing_ips = serde_json::from_str(&outgoing)?;
            sample.blocked_ips = serde_json::from_str(&blocked)?;
            output.entry(port).or_default().push(sample);
        }
        Ok(output)
    }
    pub async fn active(&self) -> Result<Vec<serde_json::Value>> {
        Ok(self.db.call(|db|->tokio_rusqlite::rusqlite::Result<Vec<serde_json::Value>> {
            db.prepare("SELECT port,last_seen FROM active_ports WHERE last_seen>=strftime('%s','now')-300 ORDER BY port")?.query_map([],|r|Ok(serde_json::json!({"port":r.get::<_,u16>(0)?,"last_seen":r.get::<_,i64>(1)?})))?.collect()
        }).await?)
    }
    pub async fn hits(&self, port: u16, limit: u16) -> Result<Vec<serde_json::Value>> {
        Ok(self.db.call(move|db|->tokio_rusqlite::rusqlite::Result<Vec<serde_json::Value>> {
            db.prepare("SELECT ip,last_seen FROM recent_ip_hits WHERE port=? ORDER BY last_seen DESC,ip LIMIT ?")?.query_map(params![port,limit],|r|Ok(serde_json::json!({"ip":r.get::<_,String>(0)?,"last_seen":r.get::<_,i64>(1)?})))?.collect()
        }).await?)
    }
}
