//! The window's live view: bytes per program and per connection since the window opened, plus a
//! feed of recent traffic. Written by the capture thread, read once a second by the window.
//! Memory is bounded so a window left open for days can't grow without limit.

use crate::capture::{Dir, Event};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

pub const FEED_MAX: usize = 5000;
/// Distinct (host, port, protocol) kept per program; the rest are folded into one row.
const MAX_CONNS_PER_APP: usize = 2000;
const MAX_PIDS_PER_APP: usize = 256;

#[derive(Default)]
pub struct ConnLive {
    pub up: u64,
    pub down: u64,
    pub last_ms: i64,
}

#[derive(Default)]
pub struct AppLive {
    pub up: u64,
    pub down: u64,
    pub pids: HashSet<u32>,
    pub conns: HashMap<(Arc<str>, u16, u8), ConnLive>,
}

#[derive(Clone)]
pub struct FeedRow {
    pub ms: i64,
    pub app: Arc<str>,
    pub dir: Dir,
    pub bytes: u64,
    pub packets: u32,
    pub host: Arc<str>,
    pub port: u16,
    pub proto: u8,
}

#[derive(Default)]
pub struct Live {
    pub apps: HashMap<Arc<str>, AppLive>,
    pub feed: VecDeque<FeedRow>,
    other: Option<Arc<str>>,
}

impl Live {
    pub fn add(&mut self, e: Event) {
        let mut host = e.host_or_ip();
        let mut port = e.port;
        let a = self.apps.entry(e.app.clone()).or_default();
        if a.pids.len() < MAX_PIDS_PER_APP {
            a.pids.insert(e.pid);
        }
        if a.conns.len() >= MAX_CONNS_PER_APP && !a.conns.contains_key(&(host.clone(), port, e.proto)) {
            host = self.other.get_or_insert_with(|| Arc::from(crate::recorder::OTHER)).clone();
            port = 0;
        }
        let c = a.conns.entry((host.clone(), port, e.proto)).or_default();
        c.last_ms = e.unix_ms;
        let n = e.bytes as u64;
        match e.dir {
            Dir::Up => (a.up += n, c.up += n),
            Dir::Down => (a.down += n, c.down += n),
        };
        // Merge bursts (same program, host, port, direction, within 1 s) into one feed line.
        if let Some(last) = self.feed.back_mut()
            && last.app == e.app
            && last.host == host
            && last.port == port
            && last.proto == e.proto
            && last.dir == e.dir
            && (0..1000).contains(&(e.unix_ms - last.ms))
        {
            last.bytes += n;
            last.packets += 1;
            return;
        }
        if self.feed.len() >= FEED_MAX {
            self.feed.pop_front();
        }
        self.feed.push_back(FeedRow { ms: e.unix_ms, app: e.app, dir: e.dir, bytes: n, packets: 1, host, port, proto: e.proto });
    }
}

#[cfg(test)]
pub fn event(app: &str, host: &str, port: u16, dir: Dir, bytes: u32, ms: i64) -> Event {
    Event {
        unix_ms: ms,
        pid: 7,
        app: Arc::from(app),
        remote: "203.0.113.9".parse().unwrap(),
        port,
        proto: 6,
        dir,
        bytes,
        host: Some(Arc::from(host)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totals_feed_merging_and_caps() {
        let mut l = Live::default();
        l.add(event("a", "x.com", 443, Dir::Up, 100, 1_000));
        l.add(event("a", "x.com", 443, Dir::Up, 50, 1_500)); // same burst: merged
        l.add(event("a", "x.com", 443, Dir::Down, 70, 1_600)); // other direction: new line
        l.add(event("a", "x.com", 443, Dir::Down, 1, 3_000)); // over 1 s later: new line
        l.add(event("a", "x.com", 443, Dir::Down, 1, 2_900)); // out of order (earlier): new line, not merged backwards
        let a = &l.apps[&Arc::from("a")];
        assert_eq!((a.up, a.down), (150, 72));
        assert_eq!(l.feed.len(), 4);
        assert_eq!((l.feed[0].bytes, l.feed[0].packets), (150, 2));

        for i in 0..MAX_CONNS_PER_APP as u16 + 10 {
            l.add(event("b", &format!("h{i}"), i, Dir::Down, 1, 10_000 + i as i64 * 2000));
        }
        let b = &l.apps[&Arc::from("b")];
        assert_eq!(b.conns.len(), MAX_CONNS_PER_APP + 1); // the cap plus the folded row
        assert_eq!(b.conns[&(Arc::from(crate::recorder::OTHER), 0, 6)].down, 10);
        assert_eq!(b.down, MAX_CONNS_PER_APP as u64 + 10); // nothing lost from the total

        for i in 0..FEED_MAX as i64 {
            l.add(event("c", "y.com", 1, Dir::Up, 1, 10_000_000 + i * 2000));
        }
        assert_eq!(l.feed.len(), FEED_MAX); // oldest lines dropped
        assert_eq!(&*l.feed[0].app, "c");
    }
}
