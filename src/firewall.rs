//! Block / unblock a program's internet access with ordinary Windows Firewall rules
//! (visible and removable in "Windows Defender Firewall with Advanced Security").
//! Uses the firewall COM API directly: no shell, no command-line parsing. The firewall itself is
//! the only record of what is blocked, so a rule deleted there shows as unblocked here too.

use std::collections::HashSet;
use windows::Win32::Foundation::VARIANT_TRUE;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_ALL, NET_FW_RULE_DIR_OUT, NetFwPolicy2, NetFwRule,
};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::System::Com::IDispatch;
use windows::core::{BSTR, Interface};

const PREFIX: &str = "NetStop block: ";

/// Which keys can be blocked: real program paths like `C:\...` (and services inside svchost).
pub fn blockable(app: &str) -> bool {
    let b = app.as_bytes();
    b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
}

/// One rule per (program, service). Outbound only: that stops data leaving, and replies to
/// anything it would have sent.
fn rules_for(app: &str) -> Vec<(String, String, Option<String>)> {
    match app.split_once('|') {
        Some((path, svcs)) => svcs
            .split(',')
            .map(|s| (format!("{PREFIX}{path}|{s}"), path.to_string(), Some(s.to_string())))
            .collect(),
        None => vec![(format!("{PREFIX}{app}"), app.to_string(), None)],
    }
}

fn with_policy<T>(f: impl FnOnce(&INetFwPolicy2) -> windows::core::Result<T>) -> Result<T, String> {
    unsafe {
        let init = CoInitializeEx(None, COINIT_MULTITHREADED);
        let r = CoCreateInstance::<_, INetFwPolicy2>(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER).and_then(|p| f(&p));
        if init.is_ok() {
            CoUninitialize();
        }
        r.map_err(|e| e.message().to_string())
    }
}

/// Names of every NetStop rule currently in Windows Firewall.
pub fn rules() -> Result<HashSet<String>, String> {
    with_policy(|p| unsafe {
        let en: IEnumVARIANT = p.Rules()?._NewEnum()?.cast()?;
        let mut out = HashSet::new();
        loop {
            let mut v = [VARIANT::default()];
            let mut n = 0;
            if en.Next(&mut v, &mut n).is_err() || n == 0 {
                break;
            }
            let Ok(rule) = IDispatch::try_from(&v[0]).and_then(|d| d.cast::<INetFwRule>()) else { continue };
            let name = rule.Name().map(|b| b.to_string()).unwrap_or_default();
            if name.starts_with(PREFIX) {
                out.insert(name);
            }
        }
        Ok(out)
    })
}

/// True when every rule this key needs is present.
pub fn is_blocked(rules: &HashSet<String>, app: &str) -> bool {
    blockable(app) && rules_for(app).iter().all(|(name, _, _)| rules.contains(name))
}

/// Removes every NetStop rule (uninstall). Returns how many were removed.
pub fn remove_all() -> Result<usize, String> {
    let names = rules()?;
    with_policy(|p| unsafe {
        let rules = p.Rules()?;
        for n in &names {
            rules.Remove(&BSTR::from(n.as_str()))?;
        }
        Ok(names.len())
    })
}

pub fn set_blocked(app: &str, block: bool) -> Result<(), String> {
    if !blockable(app) {
        return Err("This entry can't be blocked by program (it is Windows itself or already closed).".into());
    }
    with_policy(|p| unsafe {
        let rules = p.Rules()?;
        for (name, path, svc) in rules_for(app) {
            let bname = BSTR::from(name.as_str());
            if block {
                if rules.Item(&bname).is_ok() {
                    continue;
                }
                let r: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)?;
                r.SetName(&bname)?;
                r.SetDescription(&BSTR::from("Added by NetStop. Delete to allow this program again."))?;
                r.SetApplicationName(&BSTR::from(path.as_str()))?;
                if let Some(s) = &svc {
                    r.SetServiceName(&BSTR::from(s.as_str()))?;
                }
                r.SetDirection(NET_FW_RULE_DIR_OUT)?;
                r.SetAction(NET_FW_ACTION_BLOCK)?;
                r.SetProfiles(NET_FW_PROFILE2_ALL.0)?;
                r.SetEnabled(VARIANT_TRUE)?;
                rules.Add(&r)?;
            } else {
                // Remove deletes one match per call; loop in case of duplicates.
                while rules.Item(&bname).is_ok() {
                    rules.Remove(&bname)?;
                }
            }
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rule_names() {
        let svc = r"C:\Windows\System32\svchost.exe|wuauserv,bits";
        let r = rules_for(svc);
        assert_eq!(r.len(), 2);
        assert_eq!(r[1].0, r"NetStop block: C:\Windows\System32\svchost.exe|bits");
        assert_eq!(r[1].2.as_deref(), Some("bits"));
        assert!(!blockable("System"));
        assert!(!blockable("pid:12"));
        assert!(!blockable(r"\Device\HarddiskVolume3\a.exe"));
        assert!(blockable(r"C:\a\b.exe"));
        let set: HashSet<String> = r.into_iter().map(|x| x.0).collect();
        assert!(is_blocked(&set, svc));
        assert!(!is_blocked(&set, &format!("{svc},dhcp")));
    }
}
