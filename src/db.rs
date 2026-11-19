//! Local SQLite store: per-minute traffic per (program, host, port, protocol), kept for 7 days.

use rusqlite::{Connection, OpenFlags, params};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

pub fn data_dir() -> PathBuf {
    crate::winutil::program_data().join("NetStop")
}

pub fn db_path() -> PathBuf {
    data_dir().join("traffic.db")
}

pub(crate) const SCHEMA: &str = "
PRAGMA journal_mode=DELETE;
CREATE TABLE IF NOT EXISTS traffic(
  minute INTEGER NOT NULL, app TEXT NOT NULL, host TEXT NOT NULL,
  port INTEGER NOT NULL, proto INTEGER NOT NULL,
  up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(minute, app, host, port, proto)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS apps(app TEXT PRIMARY KEY, label TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS names(app TEXT PRIMARY KEY, name TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS blocked(app TEXT PRIMARY KEY) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v INTEGER NOT NULL) WITHOUT ROWID;
";

/// Read-write; creates the folder and schema. Used by the recorder and the (elevated) window.
pub fn open_rw() -> rusqlite::Result<Connection> {
    let _ = std::fs::create_dir_all(data_dir());
    let c = Connection::open(db_path())?;
    c.busy_timeout(Duration::from_secs(5))?;
    c.execute_batch(SCHEMA)?;
    Ok(c)
}

/// Read-only; used by the browser extension's host, which runs without admin rights.
/// Rollback-journal mode (not WAL) so a reader never needs write access to the folder.
pub fn open_ro() -> rusqlite::Result<Connection> {
    let c = Connection::open_with_flags(db_path(), OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    c.busy_timeout(Duration::from_secs(5))?;
    Ok(c)
}

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct Key {
    pub minute: i64,
    pub app: std::sync::Arc<str>,
    pub host: std::sync::Arc<str>,
    pub port: u16,
    pub proto: u8,
}

/// Adds the counts to whatever is already stored for that minute.
pub fn flush(c: &mut Connection, rows: &HashMap<Key, (u64, u64)>, labels: &[(std::sync::Arc<str>, String)]) -> rusqlite::Result<()> {
    let tx = c.transaction()?;
    {
        let mut st = tx.prepare_cached(
            "INSERT INTO traffic(minute,app,host,port,proto,up,down) VALUES(?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT DO UPDATE SET up=up+excluded.up, down=down+excluded.down",
        )?;
        for (k, (up, down)) in rows {
            st.execute(params![k.minute, &*k.app, &*k.host, k.port, k.proto, *up as i64, *down as i64])?;
        }
        let mut st = tx.prepare_cached("INSERT INTO apps(app,label) VALUES(?1,?2) ON CONFLICT DO UPDATE SET label=excluded.label")?;
        for (app, label) in labels {
            st.execute(params![&**app, label])?;
        }
        tx.execute("INSERT INTO meta(k,v) VALUES('last_write',?1) ON CONFLICT DO UPDATE SET v=excluded.v", [chrono::Utc::now().timestamp()])?;
    }
    tx.commit()
}

/// Keeps today plus the 6 days before it (local time); everything older is deleted.
pub fn prune(c: &Connection) -> rusqlite::Result<usize> {
    let cutoff = crate::report::local_midnight_days_ago(6) / 60;
    c.execute("DELETE FROM traffic WHERE minute < ?1", [cutoff])
        .and_then(|n| c.execute("DELETE FROM apps WHERE app NOT IN (SELECT DISTINCT app FROM traffic)", []).map(|_| n))
}

pub fn set_name(c: &Connection, app: &str, name: &str) -> rusqlite::Result<()> {
    let name = name.trim();
    if name.is_empty() {
        c.execute("DELETE FROM names WHERE app=?1", [app])?;
    } else {
        c.execute("INSERT INTO names(app,name) VALUES(?1,?2) ON CONFLICT DO UPDATE SET name=excluded.name", [app, name])?;
    }
    Ok(())
}

pub fn names(c: &Connection) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Ok(mut st) = c.prepare("SELECT app, name FROM names") {
        if let Ok(rows) = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?))) {
            out.extend(rows.flatten());
        }
    }
    out
}

pub fn blocked(c: &Connection) -> Vec<String> {
    c.prepare("SELECT app FROM blocked ORDER BY app")
        .and_then(|mut st| st.query_map([], |r| r.get(0))?.collect())
        .unwrap_or_default()
}

pub fn set_blocked(c: &Connection, app: &str, on: bool) -> rusqlite::Result<()> {
    if on {
        c.execute("INSERT OR IGNORE INTO blocked(app) VALUES(?1)", [app])?;
    } else {
        c.execute("DELETE FROM blocked WHERE app=?1", [app])?;
    }
    Ok(())
}
