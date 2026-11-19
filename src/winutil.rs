//! Small Windows helpers: known folders, elevation, single instance, wide strings.

use std::path::PathBuf;
use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::UI::Shell::{FOLDERID_Downloads, FOLDERID_ProgramData, FOLDERID_ProgramFiles, IsUserAnAdmin, KNOWN_FOLDER_FLAG, SHGetKnownFolderPath, ShellExecuteW};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{GUID, HSTRING, PCWSTR};

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn known_folder(id: &GUID, fallback: &str) -> PathBuf {
    unsafe {
        match SHGetKnownFolderPath(id, KNOWN_FOLDER_FLAG(0), None) {
            Ok(p) => {
                let s = p.to_string().unwrap_or_default();
                CoTaskMemFree(Some(p.0 as _));
                PathBuf::from(s)
            }
            Err(_) => PathBuf::from(fallback),
        }
    }
}

pub fn program_data() -> PathBuf {
    known_folder(&FOLDERID_ProgramData, r"C:\ProgramData")
}

pub fn program_files() -> PathBuf {
    known_folder(&FOLDERID_ProgramFiles, r"C:\Program Files")
}

pub fn downloads() -> PathBuf {
    known_folder(&FOLDERID_Downloads, ".")
}

/// Absolute path to a System32 tool, so a planted exe on PATH can't be run instead.
pub fn system32(exe: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    root.join("System32").join(exe)
}

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin().as_bool() }
}

/// Re-run this exe with the UAC prompt. Returns true if the elevated copy was started.
pub fn relaunch_elevated(args: &str) -> bool {
    let Ok(exe) = std::env::current_exe() else { return false };
    let r = unsafe {
        ShellExecuteW(None, &HSTRING::from("runas"), &HSTRING::from(exe.as_os_str()), &HSTRING::from(args), PCWSTR::null(), SW_SHOWNORMAL)
    };
    r.0 as isize > 32
}

/// Holds a named mutex for the process lifetime; None if another instance already holds it.
pub fn single_instance(name: &str) -> Option<HANDLE> {
    unsafe {
        let h = CreateMutexW(None, true, &HSTRING::from(name)).ok()?;
        if GetLastError() == ERROR_ALREADY_EXISTS { None } else { Some(h) }
    }
}

/// Lets CLI subcommands print to the console they were started from (the exe is a GUI app).
pub fn attach_console() {
    use windows::Win32::System::Console::{ATTACH_PARENT_PROCESS, AttachConsole};
    unsafe {
        let _ = AttachConsole(ATTACH_PARENT_PROCESS);
    }
}
