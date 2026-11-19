//! Who is PID x? Turns process IDs into stable app keys ("C:\path\app.exe", or
//! "C:\..\svchost.exe|service" for Windows services), plus window/version lookups.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{CloseHandle, HWND, LPARAM};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};
use windows::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, GetUnicastIpAddressTable, MIB_IF_TABLE2, MIB_UNICASTIPADDRESS_TABLE};
use windows::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW, SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE,
    SERVICE_ACTIVE, SERVICE_WIN32,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW};
use windows::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowTextLengthW, GetWindowThreadProcessId, IsWindowVisible};
use windows::core::{BOOL, PCWSTR, PWSTR};

// shortcut: a PID is re-resolved after 60 s idle; a PID reused by a new process inside that window keeps the old name.
const TTL: Duration = Duration::from_secs(60);

pub struct Resolver {
    cache: HashMap<u32, (Arc<str>, Instant)>,
    services: HashMap<u32, Vec<String>>,
    services_at: Option<Instant>,
}

impl Resolver {
    pub fn new() -> Self {
        Resolver { cache: HashMap::new(), services: HashMap::new(), services_at: None }
    }

    pub fn resolve(&mut self, pid: u32) -> Arc<str> {
        let now = Instant::now();
        if let Some((k, t)) = self.cache.get_mut(&pid) {
            if now.duration_since(*t) < TTL {
                *t = now;
                return k.clone();
            }
        }
        let key: Arc<str> = match pid {
            0 | 4 => Arc::from("System"),
            _ => match image_path(pid) {
                Some(p) if p.to_ascii_lowercase().ends_with("\\svchost.exe") => {
                    if !self.services.contains_key(&pid) && self.services_at.is_none_or(|t| now.duration_since(t) > Duration::from_secs(2)) {
                        self.services = service_pids();
                        self.services_at = Some(now);
                    }
                    match self.services.get(&pid) {
                        Some(s) => Arc::from(format!("{p}|{}", s.join(","))),
                        None => Arc::from(p),
                    }
                }
                Some(p) => Arc::from(p),
                None => Arc::from(format!("pid:{pid}")),
            },
        };
        if self.cache.len() > 4096 {
            self.cache.retain(|_, (_, t)| now.duration_since(*t) < TTL);
        }
        self.cache.insert(pid, (key.clone(), now));
        key
    }
}

pub fn image_path(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len).is_ok();
        let _ = CloseHandle(h);
        ok.then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// PID -> running service short names, for splitting svchost.exe into real services.
fn service_pids() -> HashMap<u32, Vec<String>> {
    let mut out: HashMap<u32, Vec<String>> = HashMap::new();
    unsafe {
        let Ok(scm) = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) else { return out };
        let mut buf = vec![0u8; 256 * 1024];
        let (mut needed, mut count, mut resume) = (0u32, 0u32, 0u32);
        loop {
            let r = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, Some(&mut buf), &mut needed, &mut count, Some(&mut resume), PCWSTR::null());
            let items = std::slice::from_raw_parts(buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW, count as usize);
            for it in items {
                let pid = it.ServiceStatusProcess.dwProcessId;
                if pid != 0 {
                    out.entry(pid).or_default().push(it.lpServiceName.to_string().unwrap_or_default());
                }
            }
            // ERROR_MORE_DATA: grow and continue from `resume`.
            if r.is_ok() || needed == 0 {
                break;
            }
            buf.resize(buf.len().max(needed as usize * 2), 0);
        }
        let _ = CloseServiceHandle(scm);
    }
    out
}

/// The exe's "File description" from its version resource, e.g. "Antimalware Service Executable".
pub fn file_description(path: &str) -> Option<String> {
    use windows::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
    let wpath = crate::winutil::wide(path);
    unsafe {
        let size = GetFileVersionInfoSizeW(PCWSTR(wpath.as_ptr()), None);
        if size == 0 || size > 16 * 1024 * 1024 {
            return None;
        }
        let mut data = vec![0u8; size as usize];
        GetFileVersionInfoW(PCWSTR(wpath.as_ptr()), None, size, data.as_mut_ptr() as _).ok()?;
        let mut p: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len = 0u32;
        let q = crate::winutil::wide(r"\VarFileInfo\Translation");
        if !VerQueryValueW(data.as_ptr() as _, PCWSTR(q.as_ptr()), &mut p, &mut len).as_bool() || len < 4 {
            return None;
        }
        let lang = *(p as *const u16);
        let cp = *(p as *const u16).add(1);
        let q = crate::winutil::wide(&format!(r"\StringFileInfo\{lang:04x}{cp:04x}\FileDescription"));
        if !VerQueryValueW(data.as_ptr() as _, PCWSTR(q.as_ptr()), &mut p, &mut len).as_bool() || len == 0 {
            return None;
        }
        let s = std::slice::from_raw_parts(p as *const u16, len as usize);
        let s = String::from_utf16_lossy(s.split(|&c| c == 0).next().unwrap_or(s));
        Some(s.trim().to_string()).filter(|s| !s.is_empty())
    }
}

/// Plain name for an app key, using the exe's description as a fallback.
pub fn label(key: &str) -> String {
    let path = key.split('|').next().unwrap_or(key);
    let desc = if path.contains('\\') { file_description(path) } else { None };
    crate::names::plain(key, desc.as_deref())
}

/// PIDs that own a visible, titled window. Anything else is running in the background.
pub fn windowed_pids() -> HashSet<u32> {
    unsafe extern "system" fn cb(h: HWND, l: LPARAM) -> BOOL {
        unsafe {
            if IsWindowVisible(h).as_bool() && GetWindowTextLengthW(h) > 0 {
                let mut pid = 0;
                GetWindowThreadProcessId(h, Some(&mut pid));
                (*(l.0 as *mut HashSet<u32>)).insert(pid);
            }
        }
        BOOL(1)
    }
    let mut set = HashSet::new();
    unsafe {
        let _ = EnumWindows(Some(cb), LPARAM(&mut set as *mut _ as isize));
    }
    set
}

/// This machine's own IP addresses (to tell local from remote, and skip PC-to-itself traffic).
pub fn local_ips() -> HashSet<IpAddr> {
    let mut set = HashSet::new();
    unsafe {
        let mut t: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
        if GetUnicastIpAddressTable(AF_UNSPEC, &mut t).is_ok() && !t.is_null() {
            let rows = std::slice::from_raw_parts((*t).Table.as_ptr(), (*t).NumEntries as usize);
            for r in rows {
                let a = &r.Address;
                if a.si_family == AF_INET {
                    set.insert(IpAddr::from(a.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()));
                } else if a.si_family == AF_INET6 {
                    set.insert(IpAddr::from(a.Ipv6.sin6_addr.u.Byte));
                }
            }
            FreeMibTable(t as _);
        }
    }
    set
}

/// Total bytes (in, out) on physical Wi-Fi / Ethernet / mobile adapters that are up.
/// Headers, ARP, ping etc. are included here but not in per-program counts.
pub fn adapter_totals() -> (u64, u64) {
    let (mut rx, mut tx) = (0, 0);
    unsafe {
        let mut t: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        if GetIfTable2(&mut t).is_ok() && !t.is_null() {
            let rows = std::slice::from_raw_parts((*t).Table.as_ptr(), (*t).NumEntries as usize);
            for r in rows {
                let f = r.InterfaceAndOperStatusFlags._bitfield;
                let hardware = f & 1 != 0 && f & 2 == 0; // physical, not a filter-driver layer (would double count)
                let kind_ok = matches!(r.Type, 6 | 71 | 243); // Ethernet, Wi-Fi, mobile broadband
                if hardware && kind_ok && r.OperStatus.0 == 1 {
                    rx += r.InOctets;
                    tx += r.OutOctets;
                }
            }
            FreeMibTable(t as _);
        }
    }
    (rx, tx)
}
