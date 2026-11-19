//! `netstop install` / `netstop uninstall` (run as admin).
//! Security: the boot-time task runs as SYSTEM, so it must only ever point at a copy of the exe in
//! Program Files (admin-only writable). The data folder is locked to admins + SYSTEM for writing,
//! read-only for normal users (so the browser extension can read reports, but nothing can change them).

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
        for _ in 0..10 {
            if std::fs::copy(&me, &exe).is_ok() {
                ok = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        if !ok {
            return Err(format!("could not copy to {} (close NetStop windows and retry)", exe.display()));
        }
    }

    let data = crate::db::data_dir();
    std::fs::create_dir_all(&data).map_err(|e| format!("create {}: {e}", data.display()))?;
    // Any user can create folders in ProgramData, so the folder may have been planted. Refuse a
    // junction/symlink (would redirect SYSTEM's writes), then take ownership and reset all ACLs.
    let meta = std::fs::symlink_metadata(&data).map_err(|e| e.to_string())?;
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(format!("{} is a link; delete it and run install again", data.display()));
        }
    }
    let d = data.display().to_string();
    run("icacls.exe", &[&d, "/setowner", "*S-1-5-32-544", "/T", "/C"])?;
    run("icacls.exe", &[&d, "/reset", "/T", "/C"])?; // drops any explicit entries a planter added
    // SYSTEM + Administrators: full. Users: read only. Inheritance off so nothing looser applies.
    run("icacls.exe", &[&d, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX", "/T", "/C"])?;
    drop(crate::db::open_rw().map_err(|e| format!("create database: {e}"))?);

    let xml_path = data.join("task.xml");
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

    Ok(format!(
        "Installed to {}

The recorder is running and starts at every boot.
Data: {}

Open the window: {}
Chrome extension ID: {}",
        dir.display(),
        data.display(),
        exe.display(),
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
    // Lift every block NetStop added, so nothing stays blocked by an app that is gone.
    if let Ok(c) = crate::db::open_rw() {
        for app in crate::db::blocked(&c) {
            if let Err(e) = crate::firewall::set_blocked(&app, false) {
                eprintln!("could not remove block for {app}: {e}");
            }
        }
    }
    std::thread::sleep(std::time::Duration::from_secs(1));
    let data = crate::db::data_dir();
    let _ = std::fs::remove_dir_all(&data);
    let dir = install_dir();
    let _ = std::fs::remove_file(dir.join("chrome-host.json"));
    let mut msg = String::from("NetStop removed: recorder, data, extension bridge and all NetStop firewall blocks.");
    if std::fs::remove_dir_all(&dir).is_err() {
        msg.push_str(&format!("

Delete {} by hand once NetStop is closed.", dir.display()));
    }
    Ok(msg)
}
