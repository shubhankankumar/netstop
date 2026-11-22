//! Small Windows helpers: known folders, elevation, single instance, wide strings.

use std::path::PathBuf;
use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::UI::Shell::{FOLDERID_CommonPrograms, FOLDERID_Downloads, FOLDERID_ProgramData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, IsUserAnAdmin, KNOWN_FOLDER_FLAG, SHGetKnownFolderPath, ShellExecuteW};
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

pub fn program_files_x86() -> PathBuf {
    known_folder(&FOLDERID_ProgramFilesX86, r"C:\Program Files (x86)")
}

/// This process's Windows logon session (0 if unknown).
pub fn session_id() -> u32 {
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    let mut s = 0;
    unsafe {
        let _ = ProcessIdToSessionId(std::process::id(), &mut s);
    }
    s
}

pub fn downloads() -> PathBuf {
    known_folder(&FOLDERID_Downloads, ".")
}

/// All-users Start menu "Programs" folder.
pub fn common_programs() -> PathBuf {
    known_folder(&FOLDERID_CommonPrograms, r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs")
}

/// Writes a .lnk at `lnk` that opens `target`.
pub fn create_shortcut(lnk: &std::path::Path, target: &std::path::Path) -> Result<(), String> {
    use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize, IPersistFile};
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
    use windows::core::Interface;
    unsafe {
        let init = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let r = (|| {
            let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
            link.SetPath(&HSTRING::from(target.as_os_str()))?;
            link.SetDescription(&HSTRING::from("See and block what each program sends and receives"))?;
            link.cast::<IPersistFile>()?.Save(&HSTRING::from(lnk.as_os_str()), true)
        })();
        if init.is_ok() {
            CoUninitialize();
        }
        r.map_err(|e| e.message().to_string())
    }
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

/// The primary screen's area above the taskbar in egui points: [x, y, width, height]. Both calls
/// see this process's DPI view (scaled or not) the same way, so their ratio is right either way.
pub fn work_area_points() -> Option<[f32; 4]> {
    use windows::Win32::Foundation::RECT;
    use windows::Win32::UI::HiDpi::GetDpiForSystem;
    use windows::Win32::UI::WindowsAndMessaging::{SPI_GETWORKAREA, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS, SystemParametersInfoW};
    let mut r = RECT::default();
    unsafe { SystemParametersInfoW(SPI_GETWORKAREA, 0, Some(&mut r as *mut RECT as _), SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0)).ok()? };
    let s = unsafe { GetDpiForSystem() } as f32 / 96.0;
    (r.right > r.left && s > 0.0).then(|| [r.left as f32 / s, r.top as f32 / s, (r.right - r.left) as f32 / s, (r.bottom - r.top) as f32 / s])
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
