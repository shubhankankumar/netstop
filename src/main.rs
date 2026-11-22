// GUI subsystem: no console window for the window or the boot-time recorder.
#![windows_subsystem = "windows"]

mod capture;
mod db;
mod firewall;
mod gui;
mod install;
mod live;
mod names;
mod nethost;
mod procinfo;
mod recorder;
mod report;
mod winutil;

const USAGE: &str = "netstop            open the window (asks for admin)
netstop install    install the boot-time recorder + browser bridge (admin)
netstop uninstall  remove everything NetStop added (admin)
netstop record     run the recorder in the foreground (admin)";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let first = args.first().map(String::as_str).unwrap_or("");

    // Chrome starts native hosts with the caller's origin as the first argument.
    if first.starts_with("chrome-extension://") {
        std::process::exit(match nethost::run(first) {
            Ok(()) => 0,
            Err(_) => 1,
        });
    }

    let result = match first {
        "" => {
            if !winutil::is_admin() {
                if !winutil::relaunch_elevated("") {
                    message("NetStop needs administrator rights to see network traffic.", false);
                }
                return;
            }
            // Started from a download (not the installed copy): offer to install, so people never need a terminal.
            let me = std::env::current_exe().ok().and_then(|p| p.parent()?.canonicalize().ok());
            if me.is_some() && me != install::install_dir().canonicalize().ok() && ask("Install NetStop (or update it)?

It keeps recording after you close this window and starts with Windows. Choose No to just look this time.") {
                match install::install() {
                    Ok(m) => message(&m, true),
                    Err(e) => message(&format!("NetStop install failed:

{e}"), false),
                }
            }
            gui::run()
        }
        "record" => {
            winutil::attach_console();
            // Without this, a normal user sees "already running": the lock file denies them.
            if winutil::is_admin() { recorder::run() } else { Err("record needs an Administrator terminal.".into()) }
        }
        "install" | "uninstall" => {
            winutil::attach_console();
            if !winutil::is_admin() {
                // Ask Windows for admin (UAC prompt); the elevated copy shows the result in a popup.
                if winutil::relaunch_elevated(first) {
                    println!("Approve the Windows prompt. A NetStop message will show the result.");
                    Ok(())
                } else {
                    Err("Admin rights were not granted.".into())
                }
            } else {
                let r = if first == "install" { install::install() } else { install::uninstall() };
                match &r {
                    Ok(m) => message(m, true),
                    Err(e) => message(&format!("NetStop {first} failed:

{e}"), false),
                }
                r.map(|m| println!("{m}"))
            }
        }
        _ => {
            winutil::attach_console();
            println!("{USAGE}");
            Ok(())
        }
    };
    if let Err(e) = result {
        if first.is_empty() {
            message(&e, false);
        } else {
            eprintln!("netstop: {e}");
        }
        std::process::exit(1);
    }
}

fn message(text: &str, ok: bool) {
    use windows::Win32::UI::WindowsAndMessaging::{MB_ICONINFORMATION, MB_ICONWARNING, MB_OK, MessageBoxW};
    use windows::core::HSTRING;
    let icon = if ok { MB_ICONINFORMATION } else { MB_ICONWARNING };
    unsafe {
        MessageBoxW(None, &HSTRING::from(text), &HSTRING::from("NetStop"), MB_OK | icon);
    }
}

fn ask(text: &str) -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{IDYES, MB_ICONQUESTION, MB_YESNO, MessageBoxW};
    use windows::core::HSTRING;
    unsafe { MessageBoxW(None, &HSTRING::from(text), &HSTRING::from("NetStop"), MB_YESNO | MB_ICONQUESTION) == IDYES }
}
