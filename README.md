# NetStop

See every byte each program on this laptop sends and receives, block any of them, and look back over the last 7 days.

- **Window** (`netstop.exe`): live list of programs with upload and download speed, a per-packet feed, the 7-day report and Block / Unblock buttons.
- **Recorder** (`netstop record`): starts at boot as SYSTEM, saves per-minute totals per program and site, and deletes anything older than 7 days.
- **Chrome extension** (`extension/`): one click shows a summary of the day; "Open full report" opens every program, site and connection in a tab.

## Install

```powershell
# Administrator terminal, from this folder
cargo build --release
.\target\release\netstop.exe install
```

`install` copies the exe to `C:\Program Files\NetStop`, locks down `C:\ProgramData\NetStop` (data folder), registers the boot-time recorder and the browser bridge. After that, run `C:\Program Files\NetStop\netstop.exe` (pin it to Start) to open the window.

Extension: open `chrome://extensions`, turn on Developer mode, click **Load unpacked** and pick the `extension` folder. Its ID is fixed (`extension/ID`), and the bridge only answers that ID.

Remove everything: `netstop uninstall` (admin). This also deletes the data and every block NetStop added.

## How the counting works

- Per-program bytes come from Windows' own kernel network events (ETW, `Microsoft-Windows-Kernel-Network`): one event per TCP/UDP send or receive, with the process ID and payload size. No driver is installed and nothing sits in the data path.
- IPs become names from Windows' DNS-Client events (`chrome.exe → youtube.com`). Apps that use their own encrypted DNS (Chrome's "Secure DNS", Firefox DoH) show IP addresses instead.
- The "Headers, ping, ARP and other" line is the Wi-Fi/Ethernet adapter total minus everything attributed to programs, so the window always adds up to what really went over the wire.
- Traffic between the laptop and itself (localhost) is ignored: it never leaves the machine.
- Plain names: a built-in table (`src/names.rs`) for common Windows parts, services and apps; otherwise the exe's description; right-click any name to rename it.

## Security

- No network access and no listening ports anywhere. The browser bridge is Chrome native messaging (stdin/stdout), not a local web server, so web pages cannot reach it.
- The bridge opens the database read-only, accepts one JSON request shape up to 4 KB, and checks the caller is the NetStop extension.
- The boot task points only at the copy in Program Files (admin-only writable). The data folder's owner and permissions are reset at install: admins and SYSTEM can write, users can only read.
- Blocking uses the Windows Firewall COM API (no shell commands). Rules are named `NetStop block: …` and are visible in Windows Firewall.
- The extension asks for one permission (`nativeMessaging`), runs under a strict content security policy, loads no remote code or fonts, and places all text with `textContent`.
- CSV exports prefix values that a spreadsheet would run as formulas.

## Build notes

This machine has no Visual Studio build tools, so `rust-toolchain.toml` selects the GNU toolchain and the MSYS2 `gcc` on PATH. With Visual Studio Build Tools installed, delete `rust-toolchain.toml` to build with MSVC instead.

`cargo test` covers names, the report queries, DNS parsing, the bridge's input checks, firewall rule names and CSV escaping. Live capture needs admin rights, so test it by running the window.
