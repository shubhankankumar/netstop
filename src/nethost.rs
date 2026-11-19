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
    let date = req.date.unwrap_or_else(|| chrono::Local::now().format("%Y-%m-%d").to_string());
    let conn = match crate::db::open_ro() {
        Ok(c) => c,
        Err(_) => return err("No data yet. Is the NetStop recorder installed and running?"),
    };
    let mut limit = if req.detail { 4000 } else { 0 };
    loop {
        let mut day = match crate::report::day(&conn, &date, limit) {
            Ok(d) => d,
            Err(e) => return err(&e),
        };
        if !req.detail {
            day.apps.truncate(8);
            day.hosts.truncate(8);
            day.night.truncate(5);
        }
        let s = serde_json::to_string(&day).unwrap_or_else(|_| err("encode failed"));
        if s.len() <= MAX_OUT || limit == 0 {
            return s;
        }
        limit /= 2; // too big for one message: send the biggest connections only
        if limit < 50 {
            day.hosts.truncate(500);
            day.apps.truncate(500);
            day.conns.clear();
            return serde_json::to_string(&day).unwrap_or_else(|_| err("encode failed"));
        }
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
    }
}
