//! Plain-English names for processes. Order of preference:
//! user rename (DB) > curated table below > file description > exe name.

/// Program file name (lowercase) -> plain name.
const PROGRAMS: &[(&str, &str)] = &[
    // Browsers and everyday apps
    ("chrome.exe", "Google Chrome"),
    ("msedge.exe", "Microsoft Edge"),
    ("msedgewebview2.exe", "Web page inside an app (Edge WebView2)"),
    ("firefox.exe", "Firefox"),
    ("brave.exe", "Brave"),
    ("opera.exe", "Opera"),
    ("vivaldi.exe", "Vivaldi"),
    ("code.exe", "VS Code"),
    ("cursor.exe", "Cursor"),
    ("claude.exe", "Claude"),
    ("warp-svc.exe", "Cloudflare WARP (VPN)"),
    ("onedrive.exe", "OneDrive (cloud file sync)"),
    ("filecoauth.exe", "Office file co-editing"),
    ("ms-teams.exe", "Microsoft Teams"),
    ("teams.exe", "Microsoft Teams"),
    ("outlook.exe", "Outlook"),
    ("olk.exe", "Outlook (new)"),
    ("winword.exe", "Word"),
    ("excel.exe", "Excel"),
    ("powerpnt.exe", "PowerPoint"),
    ("hxtsr.exe", "Mail & Calendar sync"),
    ("hxoutlook.exe", "Mail & Calendar"),
    ("discord.exe", "Discord"),
    ("spotify.exe", "Spotify"),
    ("steam.exe", "Steam"),
    ("steamwebhelper.exe", "Steam (store & web pages)"),
    ("epicgameslauncher.exe", "Epic Games Launcher"),
    ("whatsapp.exe", "WhatsApp"),
    ("whatsapp.root.exe", "WhatsApp"),
    ("telegram.exe", "Telegram"),
    ("zoom.exe", "Zoom"),
    ("slack.exe", "Slack"),
    ("skype.exe", "Skype"),
    ("dropbox.exe", "Dropbox (cloud file sync)"),
    ("googledrivefs.exe", "Google Drive (cloud file sync)"),
    ("vlc.exe", "VLC"),
    ("obs64.exe", "OBS Studio"),
    ("idman.exe", "Internet Download Manager"),
    ("qbittorrent.exe", "qBittorrent"),
    ("utorrent.exe", "uTorrent"),
    ("copilot.exe", "Copilot"),
    ("winstore.app.exe", "Microsoft Store"),
    ("phoneexperiencehost.exe", "Phone Link"),
    ("yourphone.exe", "Phone Link"),
    ("widgets.exe", "Widgets (news & weather)"),
    ("widgetservice.exe", "Widgets (news & weather)"),
    ("gamebar.exe", "Xbox Game Bar"),
    ("gamingservices.exe", "Xbox gaming services"),
    ("xboxpcapp.exe", "Xbox app"),
    // Developer tools
    ("node.exe", "Node.js"),
    ("python.exe", "Python"),
    ("pythonw.exe", "Python"),
    ("git.exe", "Git"),
    ("git-remote-https.exe", "Git (push / pull)"),
    ("ssh.exe", "SSH"),
    ("curl.exe", "curl"),
    ("cargo.exe", "Rust cargo"),
    ("powershell.exe", "PowerShell"),
    ("pwsh.exe", "PowerShell"),
    ("cmd.exe", "Command Prompt"),
    ("wsl.exe", "WSL (Linux)"),
    ("wslservice.exe", "WSL (Linux)"),
    ("wslhost.exe", "WSL (Linux)"),
    ("vmmem", "Virtual machine / WSL"),
    ("vmmemwsl", "Virtual machine / WSL"),
    // Windows itself
    ("system", "Windows core (file sharing, drivers)"),
    ("explorer.exe", "File Explorer & taskbar"),
    ("searchhost.exe", "Start menu search"),
    ("searchapp.exe", "Start menu search"),
    ("searchindexer.exe", "Search indexer"),
    ("startmenuexperiencehost.exe", "Start menu"),
    ("shellexperiencehost.exe", "Taskbar & notification panels"),
    ("textinputhost.exe", "Touch keyboard & emoji panel"),
    ("lockapp.exe", "Lock screen"),
    ("ctfmon.exe", "Keyboard & language input"),
    ("msmpeng.exe", "Defender antivirus"),
    ("mpdefendercoreservice.exe", "Defender antivirus"),
    ("nissrv.exe", "Defender network scanner"),
    ("mpcmdrun.exe", "Defender updater"),
    ("smartscreen.exe", "SmartScreen (checks downloads)"),
    ("securityhealthservice.exe", "Windows Security"),
    ("securityhealthsystray.exe", "Windows Security"),
    ("lsass.exe", "Windows sign-in & security"),
    ("services.exe", "Windows service manager"),
    ("wmiprvse.exe", "Windows system queries (WMI)"),
    ("spoolsv.exe", "Printing"),
    ("dllhost.exe", "Windows helper process (COM)"),
    ("rundll32.exe", "Windows helper process (rundll32)"),
    ("backgroundtaskhost.exe", "Store app background task"),
    ("runtimebroker.exe", "Store app permissions"),
    ("taskhostw.exe", "Scheduled task"),
    ("mousocoreworker.exe", "Windows Update (checking & downloading)"),
    ("usocoreworker.exe", "Windows Update (checking & downloading)"),
    ("tiworker.exe", "Windows Update installer"),
    ("trustedinstaller.exe", "Windows Update installer"),
    ("wuauclt.exe", "Windows Update"),
    ("sihclient.exe", "Windows Update repair"),
    ("mrt.exe", "Malware removal tool"),
    ("compattelrunner.exe", "Windows telemetry (app compatibility)"),
    ("devicecensus.exe", "Windows telemetry (device info)"),
    ("wermgr.exe", "Windows error reporting"),
    ("werfault.exe", "Crash reporter"),
    ("msiexec.exe", "Installer (MSI)"),
    ("sppsvc.exe", "Windows activation"),
    ("slui.exe", "Windows activation"),
    // Updaters and vendor helpers
    ("microsoftedgeupdate.exe", "Edge updater"),
    ("googleupdate.exe", "Google updater"),
    ("updater.exe", "Updater"),
    ("officeclicktorun.exe", "Office updater"),
    ("officec2rclient.exe", "Office updater"),
    ("armsvc.exe", "Adobe updater"),
    ("adobe desktop service.exe", "Adobe Creative Cloud"),
    ("creative cloud.exe", "Adobe Creative Cloud"),
    ("acrobat.exe", "Adobe Acrobat"),
    ("acrocef.exe", "Adobe Acrobat"),
    ("nvcontainer.exe", "NVIDIA background service"),
    ("nvidia share.exe", "NVIDIA overlay"),
    ("nvidia web helper.exe", "NVIDIA web helper"),
    ("nvidia app.exe", "NVIDIA app"),
    ("amdrsserv.exe", "AMD Radeon software"),
    ("lenovovantageservice.exe", "Lenovo Vantage"),
    ("armourycrate.service.exe", "ASUS Armoury Crate"),
    ("netstop.exe", "NetStop (this app)"),
];

/// Windows service short name (lowercase) -> plain name. Services run inside svchost.exe.
const SERVICES: &[(&str, &str)] = &[
    ("wuauserv", "Windows Update"),
    ("usosvc", "Windows Update scheduler"),
    ("waasmedicsvc", "Windows Update repair"),
    ("bits", "Background downloads (BITS)"),
    ("dosvc", "Delivery Optimization (shares updates with other PCs)"),
    ("dnscache", "DNS lookups"),
    ("dhcp", "Getting an IP address (DHCP)"),
    ("nlasvc", "Internet connection check"),
    ("netprofm", "Network list"),
    ("diagtrack", "Windows telemetry"),
    ("dps", "Diagnostics"),
    ("wpnservice", "Push notifications"),
    ("wpnuserservice", "Push notifications"),
    ("cdpsvc", "Connected devices (phone & PC sync)"),
    ("cdpusersvc", "Connected devices (phone & PC sync)"),
    ("onesyncsvc", "Mail, contacts & calendar sync"),
    ("w32time", "Clock sync"),
    ("cryptsvc", "Certificate checks"),
    ("lanmanworkstation", "File sharing (client)"),
    ("lanmanserver", "File sharing (server)"),
    ("ssdpsrv", "Device discovery (UPnP)"),
    ("fdphost", "Device discovery"),
    ("fdrespub", "Device discovery"),
    ("iphlpsvc", "IPv6 tunnels"),
    ("mpssvc", "Firewall"),
    ("bfe", "Firewall engine"),
    ("licensemanager", "Store licences"),
    ("clipsvc", "Store licences"),
    ("installservice", "Store app installs"),
    ("wlansvc", "Wi-Fi"),
    ("wcmsvc", "Connection manager"),
    ("schedule", "Task Scheduler"),
    ("winmgmt", "Windows system queries (WMI)"),
    ("tokenbroker", "Account sign-in"),
    ("wlidsvc", "Microsoft account sign-in"),
    ("lfsvc", "Location"),
    ("mapsbroker", "Offline maps download"),
    ("xblauthmanager", "Xbox Live sign-in"),
    ("xblgamesave", "Xbox cloud saves"),
    ("spooler", "Printing"),
    ("rasman", "VPN"),
    ("ikeext", "VPN keys"),
    ("sstpsvc", "VPN"),
    ("winhttpautoproxysvc", "Proxy auto-detect"),
    ("webclient", "Web folders (WebDAV)"),
    ("sysmain", "App pre-loading (SysMain)"),
    ("wsearch", "Search indexer"),
    ("edgeupdate", "Edge updater"),
    ("gupdate", "Google updater"),
    ("staterepository", "Store app database"),
    ("pcasvc", "App compatibility"),
    ("sgrmbroker", "System integrity checks"),
];

/// VPN clients whose own traffic is the encrypted copy of other programs' traffic. Counting both
/// would double every total, so they are listed but left out of sums.
/// shortcut: user-mode VPN clients only; kernel VPNs (WireGuard NT, IKEv2) show up as System. Add exe names as users report them.
const TUNNELS: &[&str] = &["warp-svc.exe", "openvpn.exe", "tailscaled.exe"];

/// Folders a VPN client must run from to be left out of totals. Admin-only, so a user's program
/// named warp-svc.exe in Temp can't hide its traffic. Lowercase, with a trailing backslash.
static TRUSTED_DIRS: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    [crate::winutil::program_files(), crate::winutil::program_files_x86()].iter().map(|p| format!("{}\\", p.display()).to_ascii_lowercase()).collect()
});

pub fn is_tunnel(key: &str) -> bool {
    let (file, svc) = split_key(key);
    let lower = key.to_ascii_lowercase();
    svc.is_none() && TUNNELS.iter().any(|t| file.eq_ignore_ascii_case(t)) && TRUSTED_DIRS.iter().any(|d| lower.starts_with(d.as_str()))
}

/// SQL condition, true for rows that are not VPN tunnel traffic. Same rule as `is_tunnel`; built
/// from constants and the admin-controlled Program Files paths (quotes doubled anyway).
pub fn not_tunnel_sql() -> String {
    let dirs = TRUSTED_DIRS.iter().map(|d| format!("substr(lower(app),1,{})='{}'", d.chars().count(), d.replace('\'', "''"))).collect::<Vec<_>>().join(" OR ");
    TUNNELS.iter().map(|t| format!("NOT (lower(app) LIKE '%\\{t}' AND ({dirs}))")).collect::<Vec<_>>().join(" AND ")
}

fn lookup(table: &[(&str, &'static str)], key: &str) -> Option<&'static str> {
    table.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

/// Per-user services carry a random suffix: "cdpusersvc_3f2a1" -> "cdpusersvc".
fn service_base(s: &str) -> String {
    let s = s.to_ascii_lowercase();
    match s.rsplit_once('_') {
        Some((base, tail)) if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_hexdigit()) => base.to_string(),
        _ => s,
    }
}

/// Split an app key ("C:\..\svchost.exe|dnscache,dhcp") into (exe file name, services).
pub fn split_key(key: &str) -> (&str, Option<&str>) {
    let (path, svc) = match key.split_once('|') {
        Some((p, s)) => (p, Some(s)),
        None => (key, None),
    };
    (path.rsplit(['\\', '/']).next().unwrap_or(path), svc)
}

/// New names for programs whose plain names collide, so no two rows read the same: the exe file
/// ("Defender antivirus (MpDefenderCoreService.exe)") or, for svchost, the services it hosts.
/// Input: (app key, name) pairs. Output: key -> new name, only for keys that collide.
pub fn distinct_names<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> std::collections::HashMap<String, String> {
    let mut by_name: std::collections::HashMap<&str, std::collections::BTreeSet<&str>> = Default::default();
    for (key, name) in pairs {
        by_name.entry(name).or_default().insert(key);
    }
    let mut out = std::collections::HashMap::new();
    for (name, keys) in by_name.into_iter().filter(|(_, k)| k.len() > 1) {
        for key in keys {
            let (file, services) = split_key(key);
            out.insert(key.to_string(), format!("{name} ({})", services.unwrap_or(file)));
        }
    }
    out
}

/// Plain name for an app key. `description` is the exe's FileDescription, if known.
pub fn plain(key: &str, description: Option<&str>) -> String {
    if let Some(pid) = key.strip_prefix("pid:") {
        return format!("Ended before it could be named (PID {pid})");
    }
    let (file, services) = split_key(key);
    if let Some(svcs) = services {
        let names: Vec<String> = svcs
            .split(',')
            .map(|s| lookup(SERVICES, &service_base(s)).map(str::to_string).unwrap_or_else(|| s.to_string()))
            .collect();
        return format!("Windows service: {}", names.join(" + "));
    }
    let lower = file.to_ascii_lowercase();
    if let Some(n) = lookup(PROGRAMS, &lower) {
        return n.to_string();
    }
    match description.map(str::trim).filter(|d| !d.is_empty()) {
        Some(d) => d.to_string(),
        None => file.strip_suffix(".exe").or_else(|| file.strip_suffix(".EXE")).unwrap_or(file).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names() {
        assert_eq!(plain(r"C:\Windows\System32\svchost.exe|wuauserv", None), "Windows service: Windows Update");
        assert_eq!(plain(r"C:\Windows\System32\svchost.exe|CDPUserSvc_4f2a1,Dhcp", None),
            "Windows service: Connected devices (phone & PC sync) + Getting an IP address (DHCP)");
        assert_eq!(plain(r"C:\Program Files\Google\Chrome\Application\chrome.exe", None), "Google Chrome");
        assert_eq!(plain(r"C:\x\Foo.exe", Some("Foo Helper")), "Foo Helper");
        assert_eq!(plain(r"C:\x\Foo.exe", None), "Foo");
        assert_eq!(plain("System", None), "Windows core (file sharing, drivers)");
        assert!(is_tunnel(r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-svc.exe"));
        assert!(!is_tunnel(r"C:\x\notwarp-svc.exe"));
        assert!(!is_tunnel(r"C:\Users\x\AppData\Local\Temp\warp-svc.exe")); // fake VPN outside Program Files

        let m = distinct_names([
            (r"C:\d\MsMpEng.exe", "Defender antivirus"),
            (r"C:\d\MpDefenderCoreService.exe", "Defender antivirus"),
            (r"C:\w\svchost.exe|CDPUserSvc_1", "Windows service: Connected devices"),
            (r"C:\w\svchost.exe|CDPUserSvc_2", "Windows service: Connected devices"),
            (r"C:\a\chrome.exe", "Google Chrome"),
        ]);
        assert_eq!(m.len(), 4, "Chrome is unique and keeps its name");
        assert_eq!(m[r"C:\d\MpDefenderCoreService.exe"], "Defender antivirus (MpDefenderCoreService.exe)");
        assert_eq!(m[r"C:\w\svchost.exe|CDPUserSvc_2"], "Windows service: Connected devices (CDPUserSvc_2)");
    }
}
