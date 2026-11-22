//! Chrome native-messaging host. Chrome starts `netstop.exe chrome-extension://<id>/` and talks
//! over stdin/stdout (4-byte length + JSON). Read-only: it can only answer report questions.
//! No port is opened, so web pages can't reach it; only the extension ID below is accepted.

use serde::Deserialize;
use std::io::{Read, Write};

/// Fixed by the "key" in extension/manifest.json.
pub const EXTENSION_ID: &str = include_str!("../extension/ID").trim_ascii();

const MAX_IN: u32 = 4 * 1024;
const MAX_OUT: usize = 1024 * 1024; // Chrome's limit for host -> extension messages

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    cmd: String,
    #[serde(default)]
    date: Option<String>,
    #[serde(default)]
    detail: bool,
}

pub fn origin_ok(origin: &str) -> bool {
    origin.trim_end_matches('/') == format!("chrome-extension://{EXTENSION_ID}")
}

pub fn run(origin: &str) -> Result<(), String> {
    if !origin_ok(origin) {
        return Err("caller is not the NetStop extension".into());
    }
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    loop {
        let mut len = [0u8; 4];
        if stdin.read_exact(&mut len).is_err() {
            return Ok(()); // Chrome closed the pipe
        }
        let len = u32::from_le_bytes(len);
        if len > MAX_IN {
            return Err("request too large".into());
        }
        let mut buf = vec![0u8; len as usize];
        stdin.read_exact(&mut buf).map_err(|e| e.to_string())?;
        let reply = answer(&buf);
        stdout.write_all(&(reply.len() as u32).to_le_bytes()).and_then(|_| stdout.write_all(reply.as_bytes())).and_then(|_| stdout.flush()).map_err(|e| e.to_string())?;
    }
}

fn err(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
}

pub fn answer(raw: &[u8]) -> String {
    let Ok(req) = serde_json::from_slice::<Request>(raw) else { return err("bad request") };
    if req.cmd != "day" {
        return err("unknown command");
    }
    match crate::db::open_ro() {
        Ok(conn) => reply(&conn, req),
        Err(_) => err("No data yet. Is the NetStop recorder installed and running?"),
    }
}

fn reply(conn: &rusqlite::Connection, req: Request) -> String {
    let date = req.date.unwrap_or_else(|| chrono::Local::now().format("%Y-%m-%d").to_string());
    let mut limit = if req.detail { 4000 } else { 0 };
    loop {
        let mut day = match crate::report::day(conn, &date, limit) {
            Ok(d) => d,
            Err(e) => return err(&e),
        };
        if !req.detail {
            // Popup: top 8 sites plus 2 new ones for "New sites", names before bare IPs (an IP says
            // little). True counts are in hosts_total / new_hosts.
            let mut keep: Vec<bool> = (0..day.hosts.len()).map(|i| i < 8).collect();
            let mut new: Vec<usize> = (0..day.hosts.len()).filter(|&i| day.hosts[i].is_new).collect();
            new.sort_by_key(|&i| day.hosts[i].host.parse::<std::net::IpAddr>().is_ok()); // stable: biggest first within each
            new.iter().take(2).for_each(|&i| keep[i] = true);
            let mut k = keep.into_iter();
            day.hosts.retain(|_| k.next().unwrap_or(false));
            day.apps.truncate(300);
            day.night.truncate(300);
        }
        let s = serde_json::to_string(&day).unwrap_or_else(|_| err("encode failed"));
        if s.len() <= MAX_OUT {
            return s;
        }
        if limit >= 100 {
            limit /= 2; // too big for one message: send the biggest connections only
            continue;
        }
        day.hosts.truncate(500);
        day.apps.truncate(500);
        day.night.truncate(50);
        day.conns.clear();
        let s = serde_json::to_string(&day).unwrap_or_else(|_| err("encode failed"));
        // Chrome drops anything bigger, which the extension would show as "not installed".
        return if s.len() <= MAX_OUT { s } else { err("Today's report is too large to show here. Open the NetStop window.") };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_bad_input() {
        assert!(!origin_ok("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"));
        assert!(origin_ok(&format!("chrome-extension://{EXTENSION_ID}/")));
        assert!(answer(b"not json").contains("bad request"));
        assert!(answer(br#"{"cmd":"drop table"}"#).contains("unknown command"));
        assert!(answer(br#"{"cmd":"day","sql":"x"}"#).contains("bad request"));
        assert!(answer(br#"{"cmd":"day","date":"2026-02-30"}"#).contains("error"));
    }

    #[test]
    fn popup_reply_is_trimmed_but_counts_stay_true() {
        use std::sync::Arc;
        let mut c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();
        let s = crate::report::local_midnight_days_ago(0) / 60;
        let mut rows = std::collections::HashMap::new();
        rows.insert(crate::db::Key { minute: s - 10, app: Arc::from(r"C:\old.exe"), host: Arc::from("old.com"), port: 443, proto: 6 }, (1, 1));
        for i in 0..20u64 {
            // 20 programs at 1 am, each to its own new site; s0.com is the smallest
            let k = crate::db::Key { minute: s + 60, app: Arc::from(format!(r"C:\p{i}.exe")), host: Arc::from(format!("s{i}.com")), port: 443, proto: 6 };
            rows.insert(k, (i + 1, 0));
        }
        for i in 0..8u64 {
            // the 8 biggest sites are bare IPs, all new
            rows.insert(crate::db::Key { minute: s + 60, app: Arc::from(r"C:\p0.exe"), host: Arc::from(format!("2404:6800::{i}")), port: 443, proto: 6 }, (1000 + i, 0));
        }
        crate::db::flush(&mut c, &rows, &[]).unwrap();
        let date = crate::report::last_7_days()[0].clone();
        let v: serde_json::Value = serde_json::from_str(&reply(&c, Request { cmd: "day".into(), date: Some(date.clone()), detail: false })).unwrap();
        let hosts: Vec<&str> = v["hosts"].as_array().unwrap().iter().map(|h| h["host"].as_str().unwrap()).collect();
        assert_eq!(hosts.len(), 10); // top 8 (all IPs) + the 2 biggest new names, so "New sites" can name them
        assert!(hosts.contains(&"s19.com") && hosts.contains(&"s18.com"), "{hosts:?}");
        assert_eq!((v["hosts_total"].as_u64(), v["new_hosts"].as_u64()), (Some(28), Some(28)));
        assert_eq!(v["night"].as_array().unwrap().len(), 20); // all of them, so the popup's night total is right
        assert!(v["conns"].as_array().unwrap().is_empty());
        let v: serde_json::Value = serde_json::from_str(&reply(&c, Request { cmd: "day".into(), date: Some(date), detail: true })).unwrap();
        assert_eq!((v["conns"].as_array().unwrap().len(), v["conns_total"].as_u64()), (28, Some(28)));
    }
}
