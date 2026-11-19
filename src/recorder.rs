//! Background recorder: runs from boot (scheduled task as SYSTEM), aggregates per minute in
//! memory and writes to SQLite every 15 s. Makes no network connections and opens no ports.

use crate::capture::{self, Dir};
use crate::db::{self, Key};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub fn run() -> Result<(), String> {
    let Some(_guard) = crate::winutil::single_instance("Global\\NetStopRecorder") else {
        return Err("recorder is already running".into());
    };
    let mut conn = db::open_rw().map_err(|e| format!("open database: {e}"))?;
    let _ = db::prune(&conn);

    let pending: Arc<Mutex<HashMap<Key, (u64, u64)>>> = Arc::default();
    let p = pending.clone();
    let _trace = capture::start(
        "NetStop-Recorder",
        Arc::new(move |e| {
            let k = Key { minute: e.unix_ms / 60_000, app: e.app.clone(), host: e.host_or_ip(), port: e.port, proto: e.proto };
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
        // shortcut: up to 15 s of counts are lost if the PC loses power; shorter flushes cost more disk writes.
        std::thread::sleep(Duration::from_secs(15));
        let batch = std::mem::take(&mut *pending.lock().unwrap_or_else(|e| e.into_inner()));
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
