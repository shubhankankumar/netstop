//! `netstop install` / `netstop uninstall` (run as admin).
//! Security: the boot-time task runs as SYSTEM, so it must only ever point at a copy of the exe in
//! Program Files (admin-only writable). The data folder is locked to admins + SYSTEM for writing,
//! read-only for the account that installed it (so its browser extension can read reports; other
//! accounts on the PC can't, and nothing can change them).

use crate::winutil::{program_files, system32};
use std::path::{Path, PathBuf};
use std::process::Command;
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, REG_SZ, RegDeleteTreeW, RegSetKeyValueW};
use windows::core::HSTRING;

const TASK: &str = "NetStop Recorder";
const HOST_KEY: &str = r"SOFTWARE\Google\Chrome\NativeMessagingHosts\com.netstop.host";

pub fn install_dir() -> PathBuf {
    program_files().join("NetStop")
}

fn shortcut() -> PathBuf {
    crate::winutil::common_programs().join("NetStop.lnk")
}

fn run(exe: &str, args: &[&str]) -> Result<(), String> {
    let out = Command::new(system32(exe)).args(args).output().map_err(|e| format!("{exe}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("{exe} failed: {}{}", String::from_utf8_lossy(&out.stdout).trim(), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

fn task_xml(exe: &Path) -> String {
    // Starts at boot as SYSTEM, no time limit, restarts if it crashes, low priority.
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Records which programs use the network (NetStop). Keeps 7 days.</Description></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author"><Exec><Command>"{}"</Command><Arguments>record</Arguments></Exec></Actions>
</Task>"#,
        exe.display()
    )
}

/// Any user can create folders in ProgramData, so an existing data folder may have been planted
/// (with links inside that would redirect SYSTEM's writes or icacls). Keep it only if it is a real
/// folder owned by Administrators or SYSTEM, which only a previous install can produce.
fn data_dir_trusted(dir: &Path) -> Result<bool, String> {
    use std::os::windows::fs::MetadataExt;
    use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, WinBuiltinAdministratorsSid, WinLocalSystemSid};
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e.to_string()),
    };
    if !meta.is_dir() || meta.file_attributes() & 0x400 != 0 {
        return Ok(false); // a file, junction or symlink
    }
    unsafe {
        let mut owner = PSID::default();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let r = GetNamedSecurityInfoW(&HSTRING::from(dir.as_os_str()), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, Some(&mut owner), None, None, None, &mut sd);
        if r != ERROR_SUCCESS {
            return Err(format!("read owner of {}: {r:?}", dir.display()));
        }
        let ok = IsWellKnownSid(owner, WinBuiltinAdministratorsSid).as_bool() || IsWellKnownSid(owner, WinLocalSystemSid).as_bool();
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        Ok(ok)
    }
}

/// SYSTEM + Administrators: full. Installing user: read only. Protected, so nothing looser inherits.
fn sddl(reader_sid: &str) -> String {
    format!("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;{reader_sid})")
}

/// Creates `dir` with its final ACL in one call; fails if anything already exists there.
fn create_locked_dir(dir: &Path, reader_sid: &str) -> Result<(), String> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::CreateDirectoryW;
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(&HSTRING::from(sddl(reader_sid)), 1, &mut sd, None).map_err(|e| format!("security descriptor: {e}"))?;
        let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd.0, bInheritHandle: false.into() };
        let r = CreateDirectoryW(&HSTRING::from(dir.as_os_str()), Some(&sa));
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        r.map_err(|e| format!("create {}: {e} (something else created it during install; run install again)", dir.display()))
    }
}

/// Replaces an existing folder's owner and whole DACL with `sddl` in one call (icacls /grant:r would
/// keep entries for anyone it doesn't name, e.g. an older install's Users:RX). The folder was checked
/// to be a real folder, not a link, by `data_dir_trusted`.
fn lock_dir(dir: &Path, reader_sid: &str) -> Result<(), String> {
    use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SE_FILE_OBJECT, SetNamedSecurityInfoW};
    use windows::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };
    use windows::core::BOOL;
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(&HSTRING::from(sddl(reader_sid)), 1, &mut sd, None).map_err(|e| format!("security descriptor: {e}"))?;
        let (mut present, mut defaulted, mut dacl, mut owner) = (BOOL(0), BOOL(0), std::ptr::null_mut::<ACL>(), PSID::default());
        let r = GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted)
            .and_then(|_| GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted))
            .map_err(|e| e.to_string())
            .and_then(|_| {
                let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
                let e = SetNamedSecurityInfoW(&HSTRING::from(dir.as_os_str()), SE_FILE_OBJECT, info, Some(owner), None, Some(dacl), None);
                if e == ERROR_SUCCESS { Ok(()) } else { Err(format!("{e:?}")) }
            });
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        r.map_err(|e| format!("lock {}: {e}", dir.display()))
    }
}

pub fn install() -> Result<String, String> {
    if !crate::winutil::is_admin() {
        return Err("Run this from an Administrator terminal.".into());
    }
    let dir = install_dir();
    let exe = dir.join("netstop.exe");
    let me = std::env::current_exe().map_err(|e| e.to_string())?;

    let _ = run("schtasks.exe", &["/End", "/TN", TASK]); // release the old exe
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    if me.canonicalize().ok() != exe.canonicalize().ok() {
        let mut ok = false;
        // The ended recorder releases the exe within a few hundred ms; poll quickly, give up after 5 s.
        for _ in 0..100 {
            if std::fs::copy(&me, &exe).is_ok() {
                ok = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if !ok {
            return Err(format!("could not copy to {} (close NetStop windows and retry)", exe.display()));
        }
    }

    // The history lists every site visited, so only the installing account may read it (for the
    // browser extension), not every account on the PC. whoami prints "domain\name","S-1-5-21-...".
    let out = Command::new(system32("whoami.exe")).args(["/user", "/fo", "csv", "/nh"]).output().map_err(|e| format!("whoami: {e}"))?;
    let me_sid = String::from_utf8_lossy(&out.stdout).trim().rsplit(',').next().unwrap_or("").trim_matches('"').to_string();
    if !me_sid.starts_with("S-1-") || me_sid.contains(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
        return Err(format!("could not read your account ID from whoami ({me_sid:?})"));
    }

    let data = crate::db::data_dir();
    if !data_dir_trusted(&data)? {
        // std's remove_dir_all deletes links themselves, never what they point at.
        std::fs::remove_dir_all(&data).or_else(|_| std::fs::remove_file(&data)).map_err(|e| format!("{} was not created by NetStop and could not be removed: {e}", data.display()))?;
    }
    if !data.exists() {
        // Born locked: a folder made with ProgramData's inherited ACL lets any user drop files in
        // (and keep them open) before icacls runs.
        create_locked_dir(&data, &me_sid)?;
    } else {
        // Existing folder from a previous install. Lock the folder itself first (one ACL write, never
        // looser in between), then make everything inside inherit it. /L: act on links, not targets.
        lock_dir(&data, &me_sid)?;
        if std::fs::read_dir(&data).map_err(|e| e.to_string())?.next().is_some() {
            let inside = data.join("*").display().to_string();
            run("icacls.exe", &[&inside, "/setowner", "*S-1-5-32-544", "/T", "/C", "/L"])?;
            run("icacls.exe", &[&inside, "/reset", "/T", "/C", "/L"])?; // drops explicit entries anyone added
        }
    }
    drop(crate::db::open_rw().map_err(|e| format!("create database: {e}"))?);
    // The recorder's single-instance lock: users get no access at all, so they can't hold it open.
    let lock = crate::recorder::lock_path();
    std::fs::OpenOptions::new().create(true).append(true).open(&lock).map_err(|e| format!("create {}: {e}", lock.display()))?;
    run("icacls.exe", &[&lock.display().to_string(), "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F", "/L"])?;

    // In Program Files (admin-only), never the data folder, so no user can swap it before schtasks reads it.
    let xml_path = dir.join("task.xml");
    let mut bytes = vec![0xFF, 0xFE]; // schtasks wants UTF-16 LE with BOM
    task_xml(&exe).encode_utf16().for_each(|u| bytes.extend_from_slice(&u.to_le_bytes()));
    std::fs::write(&xml_path, bytes).map_err(|e| e.to_string())?;
    let r = run("schtasks.exe", &["/Create", "/TN", TASK, "/XML", &xml_path.display().to_string(), "/F"]);
    let _ = std::fs::remove_file(&xml_path);
    r?;
    run("schtasks.exe", &["/Run", "/TN", TASK])?;

    // Browser extension bridge. Path is relative to the manifest, i.e. the exe next to it.
    let manifest = dir.join("chrome-host.json");
    let json = serde_json::json!({
        "name": "com.netstop.host",
        "description": "NetStop traffic reports (read-only)",
        "path": "netstop.exe",
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{}/", crate::nethost::EXTENSION_ID)],
    });
    std::fs::write(&manifest, serde_json::to_vec_pretty(&json).unwrap_or_default()).map_err(|e| e.to_string())?;
    let val: Vec<u16> = crate::winutil::wide(&manifest.display().to_string());
    let r = unsafe {
        RegSetKeyValueW(HKEY_LOCAL_MACHINE, &HSTRING::from(HOST_KEY), None, REG_SZ.0, Some(val.as_ptr() as _), (val.len() * 2) as u32)
    };
    if r.is_err() {
        return Err(format!("registry write failed: {r:?}"));
    }

    // The target never changes, so a reinstall keeps the existing shortcut (COM setup costs ~0.7 s).
    let made = if shortcut().exists() { Ok(()) } else { crate::winutil::create_shortcut(&shortcut(), &exe) };
    let start_menu = match made {
        Ok(()) => "Start menu: NetStop".to_string(),
        Err(e) => format!("Start menu shortcut not created ({e}); open {} directly", exe.display()),
    };
    Ok(format!(
        "Installed to {}

The recorder is running and starts at every boot.
Data: {}
{start_menu}
Chrome extension ID: {}",
        dir.display(),
        data.display(),
        crate::nethost::EXTENSION_ID
    ))
}

pub fn uninstall() -> Result<String, String> {
    if !crate::winutil::is_admin() {
        return Err("Run this from an Administrator terminal.".into());
    }
    let _ = run("schtasks.exe", &["/End", "/TN", TASK]);
    let _ = run("schtasks.exe", &["/Delete", "/TN", TASK, "/F"]);
    unsafe {
        let _ = RegDeleteTreeW(HKEY_LOCAL_MACHINE, &HSTRING::from(HOST_KEY));
    }
    let _ = std::fs::remove_file(shortcut());
    let mut msg = String::from("NetStop removed: recorder, data, Start menu shortcut, extension bridge and all NetStop firewall blocks.");
    // Lift every block NetStop added, so nothing stays blocked by an app that is gone.
    if let Err(e) = crate::firewall::remove_all() {
        msg.push_str(&format!("\n\nSome firewall rules could not be removed ({e}). Delete rules named \"NetStop block: …\" in Windows Firewall."));
    }
    std::thread::sleep(std::time::Duration::from_secs(1)); // let the recorder release the database
    let data = crate::db::data_dir();
    if std::fs::remove_dir_all(&data).is_err() && data.exists() {
        msg.push_str(&format!("\n\nDelete {} by hand.", data.display()));
    }
    let dir = install_dir();
    if std::fs::remove_dir_all(&dir).is_err() && dir.exists() {
        msg.push_str(&format!("\n\nDelete {} by hand once NetStop is closed.", dir.display()));
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    #[test]
    fn data_folder_sddl_parses() {
        use windows::Win32::Foundation::{HLOCAL, LocalFree};
        use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        use windows::Win32::Security::PSECURITY_DESCRIPTOR;
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let s = super::sddl("S-1-5-21-1-2-3-1001");
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(&windows::core::HSTRING::from(s), 1, &mut sd, None).unwrap();
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
    }
}
