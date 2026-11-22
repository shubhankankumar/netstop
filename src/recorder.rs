//! Background recorder: runs from boot (scheduled task as SYSTEM), aggregates per minute in
//! memory and writes to SQLite every 15 s. Makes no network connections and opens no ports.

use crate::capture::{self, Dir};
use crate::db::{self, Key};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Held open with no sharing while the recorder runs. Lives in the admin-only data folder, with
/// no user access at all (set at install), so another account can't hold it to stop recording.
const MAX_ROWS_PER_APP_MINUTE: usize = 300;
const MAX_PENDING: usize = 200_000;
/// Host name for traffic folded together once a program passes the per-minute row limit.
pub const OTHER: &str = "(many other addresses)";

pub fn lock_path() -> std::path::PathBuf {
    db::data_dir().join("recorder.lock")
}

pub fn run() -> Result<(), String> {
    use std::os::windows::fs::OpenOptionsExt;
    if !db::data_dir().is_dir() {
        return Err("NetStop is not installed (run: netstop install)".into());
    }
    let _lock = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .share_mode(0)
        .open(lock_path())
        .map_err(|e| format!("recorder is already running ({e})"))?;
    let mut conn = db::open_rw().map_err(|e| format!("open database: {e}"))?;
    let _ = db::prune(&conn);

    let pending: Arc<Mutex<HashMap<Key, (u64, u64)>>> = Arc::default();
    // Distinct (host, port) rows per (minute, app) so far. Spoofed UDP sources would otherwise add
    // a row each and grow the database without limit.
    let seen: Arc<Mutex<HashMap<(i64, Arc<str>), HashSet<(Arc<str>, u16, u8)>>>> = Arc::default();
    let other: Arc<str> = Arc::from(OTHER);
    let (p, s) = (pending.clone(), seen.clone());
    let _trace = capture::start(
        "NetStop-Recorder",
        Arc::new(move |e| {
            let mut k = Key { minute: e.unix_ms / 60_000, app: e.app.clone(), host: e.host_or_ip(), port: e.port, proto: e.proto };
            {
                let mut s = s.lock().unwrap_or_else(|e| e.into_inner());
                let set = s.entry((k.minute, k.app.clone())).or_default();
                if !set.contains(&(k.host.clone(), k.port, k.proto)) {
                    if set.len() < MAX_ROWS_PER_APP_MINUTE {
                        set.insert((k.host.clone(), k.port, k.proto));
                    } else {
                        (k.host, k.port) = (other.clone(), 0);
                    }
                }
            }
            let mut m = p.lock().unwrap_or_else(|e| e.into_inner());
            let v = m.entry(k).or_default();
            match e.dir {
                Dir::Up => v.0 += e.bytes as u64,
                Dir::Down => v.1 += e.bytes as u64,
            }
        }),
    )?;

    let mut labeled: HashSet<Arc<str>> = HashSet::new();
    let mut last_prune = Instant::now();
    loop {
        // shortcut: up to 5 s of counts are lost if the PC loses power; shorter flushes cost more disk writes.
        std::thread::sleep(Duration::from_secs(5));
        let batch = std::mem::take(&mut *pending.lock().unwrap_or_else(|e| e.into_inner()));
        let now_min = chrono::Utc::now().timestamp() / 60;
        seen.lock().unwrap_or_else(|e| e.into_inner()).retain(|(m, _), _| *m >= now_min - 2);
        let labels: Vec<_> = batch
            .keys()
            .filter(|k| !labeled.contains(&k.app))
            .map(|k| k.app.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .map(|a| {
                let l = crate::procinfo::label(&a);
                (a, l)
            })
            .collect();
        if let Err(e) = db::flush(&mut conn, &batch, &labels) {
            // Put the counts back so a locked database doesn't lose them.
            let mut m = pending.lock().unwrap_or_else(|e| e.into_inner());
            if m.len() + batch.len() > MAX_PENDING {
                eprintln!("netstop: write failed and backlog is full, dropping {} rows: {e}", batch.len());
                continue; // a long outage (disk full) must not grow SYSTEM's memory forever
            }
            for (k, (u, d)) in batch {
                let v = m.entry(k).or_default();
                v.0 += u;
                v.1 += d;
            }
            eprintln!("netstop: write failed, will retry: {e}");
            continue;
        }
        labeled.extend(labels.into_iter().map(|(a, _)| a));
        if last_prune.elapsed() >= Duration::from_secs(3600) {
            let _ = db::prune(&conn);
            last_prune = Instant::now();
        }
    }
}
