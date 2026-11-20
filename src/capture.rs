//! Live capture from Windows' own kernel network events (ETW). Every TCP/UDP send and
//! receive arrives with its process ID and payload size; no driver, nothing in the data path.

use crate::procinfo::{Resolver, local_ips};
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::trace::{TraceProperties, UserTrace, stop_trace_by_name};
use ferrisetw::{EventRecord, SchemaLocator};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
const DNS_CLIENT: &str = "1C95126E-7EEA-49A9-A3FE-A378B03DDB4D";
const KERNEL_PROCESS: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Dir {
    Up,
    Down,
}

#[derive(Clone)]
pub struct Event {
    pub unix_ms: i64,
    pub pid: u32,
    pub app: Arc<str>,
    pub remote: IpAddr,
    pub port: u16,
    /// 6 = TCP, 17 = UDP
    pub proto: u8,
    pub dir: Dir,
    pub bytes: u32,
    /// Domain name if a DNS lookup for this IP was seen, else None.
    pub host: Option<Arc<str>>,
}

impl Event {
    pub fn host_or_ip(&self) -> Arc<str> {
        self.host.clone().unwrap_or_else(|| Arc::from(self.remote.to_string()))
    }
}

/// (direction, protocol, IPv6?) for the Kernel-Network event IDs we count.
/// Retransmits (14, 30) are left out so resent data isn't counted twice.
fn classify(id: u16) -> Option<(Dir, u8)> {
    Some(match id {
        10 | 26 => (Dir::Up, 6),
        11 | 27 => (Dir::Down, 6),
        42 | 58 => (Dir::Up, 17),
        43 | 59 => (Dir::Down, 17),
        _ => return None,
    })
}

struct State {
    resolver: Resolver,
    dns: HashMap<IpAddr, Arc<str>>,
    local: HashSet<IpAddr>,
    local_at: Instant,
}

/// ETW real-time timestamps reach consumers as FILETIME (100 ns since 1601). Falls back to the
/// clock if the value is more than a minute off, so a bad clock source can't misfile an event.
fn event_ms(filetime: i64) -> i64 {
    let ms = (filetime - 116_444_736_000_000_000) / 10_000;
    let now = chrono::Utc::now().timestamp_millis();
    if (now - ms).abs() < 60_000 { ms } else { now }
}

/// Parses a DNS-Client 3008 "QueryResults" string ("::ffff:1.2.3.4;type: 5 cdn.x.com;...").
pub fn dns_ips(results: &str) -> Vec<IpAddr> {
    results
        .split(';')
        .filter_map(|t| {
            let t = t.trim();
            let t = t.strip_prefix("::ffff:").unwrap_or(t);
            t.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
        })
        .collect()
}

pub type Sink = Arc<dyn Fn(Event) + Send + Sync>;

/// Starts a real-time session named `name`. Events stream into `sink` on a background thread
/// until the returned trace is dropped. Needs admin rights.
pub fn start(name: &str, sink: Sink) -> Result<UserTrace, String> {
    let _ = stop_trace_by_name(name); // left over from a crash
    let state = Arc::new(Mutex::new(State { resolver: Resolver::new(), dns: HashMap::new(), local: local_ips(), local_at: Instant::now() }));

    let st = state.clone();
    let net = Provider::by_guid(KERNEL_NETWORK)
        .any(0x30) // KERNEL_NETWORK_KEYWORD_IPV4 | _IPV6
        .add_callback(move |rec: &EventRecord, loc: &SchemaLocator| {
            let Some((dir, proto)) = classify(rec.event_id()) else { return };
            let Ok(schema) = loc.event_schema(rec) else { return };
            let p = Parser::create(rec, &schema);
            let (Ok(pid), Ok(size), Ok(daddr), Ok(saddr), Ok(dport), Ok(sport)) = (
                p.try_parse::<u32>("PID"),
                p.try_parse::<u32>("size"),
                p.try_parse::<IpAddr>("daddr").map(|a| a.to_canonical()),
                p.try_parse::<IpAddr>("saddr").map(|a| a.to_canonical()),
                p.try_parse::<u16>("dport"),
                p.try_parse::<u16>("sport"),
            ) else {
                return;
            };
            let ev = {
                let mut s = st.lock().unwrap_or_else(|e| e.into_inner());
                if s.local_at.elapsed().as_secs() >= 10 {
                    s.local = local_ips();
                    s.local_at = Instant::now();
                }
                // Ports arrive in network byte order. Pick whichever end is not this PC.
                let (remote, port) = if s.local.contains(&daddr) && !s.local.contains(&saddr) {
                    (saddr, u16::from_be(sport))
                } else {
                    (daddr, u16::from_be(dport))
                };
                if remote.is_loopback() || remote.is_unspecified() || s.local.contains(&remote) {
                    return; // never left the laptop
                }
                Event {
                    // When the packet happened, not when ETW delivered it (up to ~1 s later).
                    unix_ms: event_ms(rec.raw_timestamp()),
                    pid,
                    app: s.resolver.resolve(pid),
                    remote,
                    port,
                    proto,
                    dir,
                    bytes: size,
                    host: s.dns.get(&remote).cloned(),
                }
            };
            sink(ev);
        })
        .build();

    let st = state.clone();
    let dns = Provider::by_guid(DNS_CLIENT)
        .any(u64::MAX)
        .add_callback(move |rec: &EventRecord, loc: &SchemaLocator| {
            if rec.event_id() != 3008 {
                return;
            }
            let Ok(schema) = loc.event_schema(rec) else { return };
            let p = Parser::create(rec, &schema);
            let (Ok(name), Ok(results)) = (p.try_parse::<String>("QueryName"), p.try_parse::<String>("QueryResults")) else { return };
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            if name.is_empty() || name.len() > 253 {
                return;
            }
            let name: Arc<str> = Arc::from(name);
            let mut s = st.lock().unwrap_or_else(|e| e.into_inner());
            // shortcut: wipe the map at 100k entries instead of LRU; names come back on the next lookup.
            if s.dns.len() > 100_000 {
                s.dns.clear();
            }
            for ip in dns_ips(&results) {
                s.dns.insert(ip, name.clone());
            }
        })
        .build();

    // Process starts name each PID the moment it exists, so short-lived programs and reused PIDs
    // are attributed correctly.
    let st = state;
    let procs = Provider::by_guid(KERNEL_PROCESS)
        .any(0x10) // WINEVENT_KEYWORD_PROCESS
        .add_callback(move |rec: &EventRecord, loc: &SchemaLocator| {
            if rec.event_id() != 1 {
                return; // ProcessStart only
            }
            let Ok(schema) = loc.event_schema(rec) else { return };
            let p = Parser::create(rec, &schema);
            let (Ok(pid), Ok(image)) = (p.try_parse::<u32>("ProcessID"), p.try_parse::<String>("ImageName")) else { return };
            st.lock().unwrap_or_else(|e| e.into_inner()).resolver.started(pid, &image);
        })
        .build();

    // Bigger buffers than the 32 KB default so bursts at gigabit speed don't drop events.
    let props = TraceProperties { buffer_size: 128, min_buffer: 4, max_buffer: 64, flush_timer: Duration::from_secs(1), ..Default::default() };
    UserTrace::new()
        .named(name.to_string())
        .set_trace_properties(props)
        .enable(procs)
        .enable(net)
        .enable(dns)
        .start_and_process()
        .map_err(|e| format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_dns_results() {
        let ips = dns_ips("type:  5 www.example.cdn.net;::ffff:93.184.216.34;2606:2800:220:1::248;");
        assert_eq!(ips, vec!["93.184.216.34".parse::<IpAddr>().unwrap(), "2606:2800:220:1::248".parse().unwrap()]);
        assert!(dns_ips("").is_empty());
        assert_eq!(classify(10), Some((Dir::Up, 6)));
        assert_eq!(classify(59), Some((Dir::Down, 17)));
        assert_eq!(classify(14), None);
    }
}
