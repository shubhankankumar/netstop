//! Block / unblock a program's internet access with ordinary Windows Firewall rules
//! (visible and removable in "Windows Defender Firewall with Advanced Security").
//! Uses the firewall COM API directly: no shell, no command-line parsing.

use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_ALL, NET_FW_RULE_DIR_OUT, NetFwPolicy2, NetFwRule,
};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize};
use windows::Win32::Foundation::VARIANT_TRUE;
use windows::core::BSTR;

/// Which keys can be blocked: real program paths (and services inside svchost).
pub fn blockable(app: &str) -> bool {
    app.contains('\\') && !app.starts_with("pid:")
}

/// One rule per (program, service). Outbound only: that stops data leaving, and replies to
/// anything it would have sent.
fn rules_for(app: &str) -> Vec<(String, String, Option<String>)> {
    match app.split_once('|') {
        Some((path, svcs)) => svcs
            .split(',')
            .map(|s| (format!("NetStop block: {path}|{s}"), path.to_string(), Some(s.to_string())))
            .collect(),
        None => vec![(format!("NetStop block: {app}"), app.to_string(), None)],
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
        let r = rules_for(r"C:\Windows\System32\svchost.exe|wuauserv,bits");
        assert_eq!(r.len(), 2);
        assert_eq!(r[1].0, r"NetStop block: C:\Windows\System32\svchost.exe|bits");
        assert_eq!(r[1].2.as_deref(), Some("bits"));
        assert!(!blockable("System"));
        assert!(!blockable("pid:12"));
        assert!(blockable(r"C:\a\b.exe"));
    }
}
