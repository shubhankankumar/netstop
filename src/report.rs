//! Day reports from the 7-day store. Shared by the window and the browser extension host.

use chrono::{Duration, Local, NaiveDate, TimeZone, Timelike};
use rusqlite::{Connection, params};
use serde::Serialize;

/// Unix seconds of local midnight `days` days before today.
pub fn local_midnight_days_ago(days: i64) -> i64 {
    day_start(Local::now().date_naive() - Duration::days(days))
}

fn day_start(d: NaiveDate) -> i64 {
    let naive = d.and_hms_opt(0, 0, 0).expect("midnight is valid");
    // .earliest() handles DST days where midnight is skipped or repeated.
    Local.from_local_datetime(&naive).earliest().map(|t| t.timestamp()).unwrap_or_else(|| naive.and_utc().timestamp())
}

fn local_6am(d: NaiveDate) -> i64 {
    let naive = d.and_hms_opt(6, 0, 0).expect("6am is valid");
    Local.from_local_datetime(&naive).earliest().map(|t| t.timestamp()).unwrap_or_else(|| naive.and_utc().timestamp())
}

/// The last 7 local dates, newest first, as "YYYY-MM-DD".
pub fn last_7_days() -> Vec<String> {
    let today = Local::now().date_naive();
    (0..7).map(|i| (today - Duration::days(i)).format("%Y-%m-%d").to_string()).collect()
}

#[derive(Serialize, Clone, Default)]
pub struct AppRow {
    pub app: String,
    pub name: String,
    pub up: u64,
    pub down: u64,
    pub hosts: u32,
    pub first: i64,
    pub last: i64,
    pub is_new: bool,
    /// A VPN client: its traffic is the wrapped copy of other rows, so it is left out of totals.
    pub tunnel: bool,
}

#[derive(Serialize, Clone, Default)]
pub struct HostRow {
    pub host: String,
    pub up: u64,
    pub down: u64,
    pub apps: u32,
    pub is_new: bool,
}

#[derive(Serialize, Clone, Default)]
pub struct ConnRow {
    pub name: String,
    pub app: String,
    pub host: String,
    pub port: u16,
    pub proto: &'static str,
    pub up: u64,
    pub down: u64,
    pub first: i64,
    pub last: i64,
}

#[derive(Serialize, Default)]
pub struct Day {
    pub date: String,
    pub up: u64,
    pub down: u64,
    /// 24 local hours, [up, down] bytes each.
    pub hours: Vec<[u64; 2]>,
    pub apps: Vec<AppRow>,
    pub hosts: Vec<HostRow>,
    /// Counts before any trimming (the browser popup gets shortened lists).
    pub hosts_total: usize,
    pub new_hosts: usize,
    /// Programs with traffic between midnight and 6 am.
    pub night: Vec<AppRow>,
    pub conns: Vec<ConnRow>,
    pub conns_total: u64,
    /// False on the first recorded day: nothing earlier to compare "new" against.
    pub has_history: bool,
    pub recorder_last_write: Option<i64>,
    pub days: Vec<String>,
}

const NAME_SQL: &str = "COALESCE((SELECT name FROM names n WHERE n.app=t.app), (SELECT label FROM apps a WHERE a.app=t.app), t.app)";

/// `conn_limit` caps the connection list (the browser host has a 1 MB message limit).
pub fn day(c: &Connection, date: &str, conn_limit: usize) -> Result<Day, String> {
    let d = NaiveDate::parse_from_str(date, "%Y-%m-%d").map_err(|_| "bad date".to_string())?;
    let (s, e) = (day_start(d) / 60, day_start(d + Duration::days(1)) / 60);
    let night_end = local_6am(d) / 60;
    let q = |e: rusqlite::Error| e.to_string();

    let mut out = Day { date: date.to_string(), hours: vec![[0, 0]; 24], days: last_7_days(), ..Default::default() };
    out.recorder_last_write = c.query_row("SELECT v FROM meta WHERE k='last_write'", [], |r| r.get(0)).ok();
    out.has_history = c
        .query_row("SELECT EXISTS(SELECT 1 FROM traffic WHERE minute < ?1)", [s], |r| r.get::<_, bool>(0))
        .map_err(q)?;

    // Hourly strip, grouped by 15-minute block then mapped to local hour. Every real UTC offset
    // (+5:30, +5:45, DST) is a multiple of 15 min, so a block never straddles two local hours.
    let sql = format!("SELECT minute/15, SUM(up), SUM(down) FROM traffic WHERE minute>=?1 AND minute<?2 AND {} GROUP BY 1", crate::names::not_tunnel_sql());
    let mut st = c.prepare(&sql).map_err(q)?;
    let rows = st.query_map([s, e], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))).map_err(q)?;
    for row in rows {
        let (b, up, down) = row.map_err(q)?;
        let hour = Local.timestamp_opt(b * 900, 0).single().map(|t| t.hour() as usize).unwrap_or(0);
        out.hours[hour][0] += up as u64;
        out.hours[hour][1] += down as u64;
        out.up += up as u64;
        out.down += down as u64;
    }

    let app_rows = |from: i64, to: i64| -> Result<Vec<AppRow>, String> {
        let sql = format!(
            "SELECT t.app, {NAME_SQL}, SUM(up), SUM(down), COUNT(DISTINCT host), MIN(minute), MAX(minute),
               NOT EXISTS(SELECT 1 FROM traffic p WHERE p.app=t.app AND p.minute < ?3)
             FROM traffic t WHERE minute>=?1 AND minute<?2 GROUP BY t.app ORDER BY SUM(up)+SUM(down) DESC"
        );
        let mut st = c.prepare(&sql).map_err(q)?;
        let it = st
            .query_map(params![from, to, s], |r| {
                Ok(AppRow {
                    app: r.get(0)?,
                    name: r.get(1)?,
                    up: r.get::<_, i64>(2)? as u64,
                    down: r.get::<_, i64>(3)? as u64,
                    hosts: r.get(4)?,
                    first: r.get::<_, i64>(5)? * 60,
                    last: r.get::<_, i64>(6)? * 60,
                    is_new: r.get(7)?,
                    tunnel: false,
                })
            })
            .map_err(q)?;
        it.collect::<Result<_, _>>().map_err(q)
    };
    out.apps = app_rows(s, e)?;
    out.night = app_rows(s, night_end)?;
    out.apps.iter_mut().chain(out.night.iter_mut()).for_each(|a| a.tunnel = crate::names::is_tunnel(&a.app));

    let mut st = c
        .prepare(
            "SELECT host, SUM(up), SUM(down), COUNT(DISTINCT app),
               NOT EXISTS(SELECT 1 FROM traffic p WHERE p.host=t.host AND p.minute < ?1)
             FROM traffic t WHERE minute>=?1 AND minute<?2 GROUP BY host ORDER BY SUM(up)+SUM(down) DESC",
        )
        .map_err(q)?;
    out.hosts = st
        .query_map([s, e], |r| {
            Ok(HostRow { host: r.get(0)?, up: r.get::<_, i64>(1)? as u64, down: r.get::<_, i64>(2)? as u64, apps: r.get(3)?, is_new: r.get(4)? })
        })
        .map_err(q)?
        .collect::<Result<_, _>>()
        .map_err(q)?;

    out.conns_total = c
        .query_row(
            "SELECT COUNT(*) FROM (SELECT 1 FROM traffic WHERE minute>=?1 AND minute<?2 GROUP BY app, host, port, proto)",
            [s, e],
            |r| r.get::<_, i64>(0),
        )
        .map_err(q)? as u64;
    let sql = format!(
        "SELECT {NAME_SQL}, t.app, host, port, proto, SUM(up), SUM(down), MIN(minute), MAX(minute)
         FROM traffic t WHERE minute>=?1 AND minute<?2 GROUP BY t.app, host, port, proto
         ORDER BY SUM(up)+SUM(down) DESC LIMIT ?3"
    );
    let mut st = c.prepare(&sql).map_err(q)?;
    out.conns = st
        .query_map(params![s, e, conn_limit as i64], |r| {
            Ok(ConnRow {
                name: r.get(0)?,
                app: r.get(1)?,
                host: r.get(2)?,
                port: r.get(3)?,
                proto: if r.get::<_, u8>(4)? == 17 { "UDP" } else { "TCP" },
                up: r.get::<_, i64>(5)? as u64,
                down: r.get::<_, i64>(6)? as u64,
                first: r.get::<_, i64>(7)? * 60,
                last: r.get::<_, i64>(8)? * 60,
            })
        })
        .map_err(q)?
        .collect::<Result<_, _>>()
        .map_err(q)?;

    if !out.has_history {
        out.apps.iter_mut().chain(out.night.iter_mut()).for_each(|a| a.is_new = false);
        out.hosts.iter_mut().for_each(|h| h.is_new = false);
    }
    out.hosts_total = out.hosts.len();
    out.new_hosts = out.hosts.iter().filter(|h| h.is_new).count();
    Ok(out)
}

/// "1.2 MB", "312 B": exact below 1 KB so a single tiny packet is visible.
pub fn human(b: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if b < 1024 {
        return format!("{b} B");
    }
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", U[i])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn day_report() {
        let mut c = Connection::open_in_memory().unwrap();
        c.execute_batch(crate::db::SCHEMA).unwrap();
        let today = Local::now().date_naive();
        let s = day_start(today) / 60;
        let k = |m: i64, app: &str, host: &str| crate::db::Key { minute: m, app: Arc::from(app), host: Arc::from(host), port: 443, proto: 6 };
        let mut rows = HashMap::new();
        rows.insert(k(s - 600, r"C:\a\old.exe", "old.com"), (10, 10));
        rows.insert(k(s - 500, r"C:\a\chrome.exe", "old.com"), (1, 1)); // chrome also seen the day before
        rows.insert(k(s + 30, r"C:\a\chrome.exe", "old.com"), (1, 2000));
        rows.insert(k(s + 400, r"C:\a\chrome.exe", "new.com"), (5, 5));
        rows.insert(k(s + 401, r"C:\a\sneaky.exe", "new.com"), (900, 0));
        rows.insert(k(s + 402, r"C:\Program Files\b\Warp-Svc.exe", "162.159.192.1"), (50, 50)); // VPN wrapper: listed, not summed
        rows.insert(k(s + 403, r"C:\tmp\warp-svc.exe", "x.com"), (7, 0)); // same name outside Program Files: counted
        crate::db::flush(&mut c, &rows, &[(Arc::from(r"C:\a\chrome.exe"), "Google Chrome".into())]).unwrap();
        crate::db::flush(&mut c, &rows, &[]).unwrap(); // second flush must add, not replace

        let d = day(&c, &today.format("%Y-%m-%d").to_string(), 10).unwrap();
        assert!(d.has_history);
        assert_eq!((d.up, d.down), (2 * 913, 2 * 2005));
        assert_eq!(d.apps.len(), 4);
        assert_eq!(d.apps.iter().filter(|a| a.tunnel).count(), 1);
        assert!(d.hours.iter().map(|h| h[0]).sum::<u64>() == d.up);
        let chrome = d.apps.iter().find(|a| a.name == "Google Chrome").unwrap();
        assert!(!chrome.is_new);
        let sneaky = d.apps.iter().find(|a| a.app.ends_with("sneaky.exe")).unwrap();
        assert!(sneaky.is_new && sneaky.up == 1800);
        assert!(d.hosts.iter().find(|h| h.host == "new.com").unwrap().is_new);
        assert!(!d.hosts.iter().find(|h| h.host == "old.com").unwrap().is_new);
        assert_eq!(d.conns_total, 5);
        assert_eq!((d.hosts_total, d.new_hosts), (4, 3));
        assert_eq!(human(1), "1 B");
        assert_eq!(human(1536), "1.5 KB");
        assert!(day(&c, "2026-13-01", 10).is_err());
    }
}
