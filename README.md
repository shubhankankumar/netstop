# NetStop

See every byte each program on this laptop sends and receives, block any of them, and look back over the last 7 days.

- **Window** (`netstop.exe`): four tabs. **Now**: every program using the network since the window opened, with upload and download speed, what kind it is (app, background, Windows service, VPN, Windows itself) and its connections. **Live feed**: traffic as it happens. **History**: the recorder's last 7 days, by program, site or connection, sortable and filterable. **Blocked**: what you blocked. Block / Unblock sits next to every program.
- **Recorder** (`netstop record`): starts at boot as SYSTEM, saves per-minute totals per program and site, and deletes anything older than 7 days.
- **Chrome extension** (`extension/`): one click shows a summary of the day; "Open full report" opens every program, site and connection in a tab.

Everything stays on your PC. NetStop has no server, no account and no telemetry, and it never sends anything anywhere.

## Install (Windows 10 or 11, 64-bit)

1. Download `netstop.exe` and `netstop-extension.zip` from the [latest release](../../releases/latest).
2. Double-click `netstop.exe`, approve the admin prompt and choose **Yes** to install.
   - The exe isn't code-signed, so Windows SmartScreen may warn you. Click **More info**, then **Run anyway**. To check the file first, compare its SHA-256 (`Get-FileHash netstop.exe` in PowerShell) with the one in the release notes.
3. From then on, open **NetStop** from the Start menu. The recorder runs in the background and starts with Windows.

Install copies the exe to `C:\Program Files\NetStop`, locks down `C:\ProgramData\NetStop` (data folder), and registers the boot-time recorder and the browser bridge. Running `netstop install` from an admin terminal does the same thing.

**Chrome extension (optional):** unzip `netstop-extension.zip` somewhere you'll keep it. Open `chrome://extensions`, turn on Developer mode, click **Load unpacked** and pick the unzipped folder. Its ID is fixed (`extension/ID`), and the bridge only answers that ID.

**Update:** download the new `netstop.exe`, double-click it and choose **Yes**. Your history is kept.

**Remove everything:** run `"C:\Program Files\NetStop\netstop.exe" uninstall`. This deletes the recorder, the data, the Start menu entry and every block NetStop added.

### From source

```powershell
cargo build --release
.\target\release\netstop.exe install
```

## How the counting works

- Per-program bytes come from Windows' own kernel network events (ETW, `Microsoft-Windows-Kernel-Network`): one event per TCP/UDP send or receive, with the process ID, payload size and the kernel's own timestamp. No driver is installed and nothing sits in the data path.
- Every process is named the moment it starts (`Microsoft-Windows-Kernel-Process` events), so programs that run for a split second are still named, and a reused process ID never inherits an old name.
- IPs become names from Windows' DNS-Client events (`chrome.exe → youtube.com`). Apps that use their own encrypted DNS (Chrome's "Secure DNS", Firefox DoH) show IP addresses instead.
- The "Headers, ping, ARP and other" line is the Wi-Fi/Ethernet adapter total minus everything attributed to programs, so the window always adds up to what really went over the wire.
- Traffic between the laptop and itself (localhost) is ignored: it never leaves the machine.
- Plain names: a built-in table (`src/names.rs`) for common Windows parts, services and apps; otherwise the exe's description; right-click any name to rename it.

## Security

- No network access and no listening ports anywhere. The browser bridge is Chrome native messaging (stdin/stdout), not a local web server, so web pages cannot reach it.
- The bridge opens the database read-only, accepts one JSON request shape up to 4 KB, and checks the caller is the NetStop extension.
- The boot task points only at the copy in Program Files (admin-only writable).
- Only `install` creates the data folder. Anyone can create folders in ProgramData, so if one already exists and isn't owned by Administrators or SYSTEM, install deletes it first. That way, planted links can't redirect SYSTEM's writes. A new data folder is created already locked, so there is no moment when other accounts can drop files into it. The boot task's XML is staged in Program Files, not ProgramData. Afterwards admins and SYSTEM can write, the account that installed NetStop can only read, and other accounts on the PC can't open it at all.
- What is stored: program, site name or IP, port, and byte counts per minute. Never packet contents, so no passwords, messages or page data. History older than 7 days is deleted, so the database stays around 15 MB at most.
- The recorder's single-instance lock is a file users can't open at all, so another account can't stop recording by holding it.
- Blocking uses the Windows Firewall COM API (no shell commands). Rules are named `NetStop block: …` and are visible in Windows Firewall. The firewall is the only record of what is blocked, and uninstall removes every rule with that name.
- The extension asks for one permission (`nativeMessaging`), runs under a strict content security policy, loads no remote code or fonts, and places all text with `textContent`.
- CSV exports prefix values that a spreadsheet would run as formulas.
- Storage is capped: at most 300 sites per program per minute (the rest are grouped as "many other addresses") and about 1 GB in total, so traffic floods can't fill the drive.
- The recorder never opens program files on network shares, so it never sends this PC's credentials to another computer.

## Known limits

- Windows only. Needs admin rights, because kernel network events require them.
- VPNs: the Cloudflare WARP, OpenVPN and Tailscale clients (only when they run from Program Files, so a look-alike name elsewhere is still counted) are labelled "VPN" and left out of totals, since their traffic is a wrapped copy of everyone else's. Built-in Windows VPNs and WireGuard show up as "System" and are counted twice.
- Apps with their own DNS (Chrome Secure DNS, WARP) show IP addresses instead of site names.
- The browser bridge is registered for Chrome only.
- A power cut loses up to the last 5 seconds of counts.

## Build notes

Without Visual Studio build tools, use the GNU toolchain with MSYS2's `gcc` on PATH: run `rustup override set stable-x86_64-pc-windows-gnu` once in this folder. With Visual Studio Build Tools installed, plain `cargo build --release` works.

Published downloads are built with `cargo build --profile dist` (full LTO: slower to build, smaller exe).

`cargo test` covers names, the report queries, DNS parsing, the bridge's input checks and popup trimming, the recorder's per-minute row cap, firewall rule names, CSV escaping, and the window itself: every tab is driven headlessly through egui's accessibility tree (clicks, typing, right-click rename, Block / Unblock against a fake firewall). `NETSTOP_SHOTS=<folder> cargo test screenshots -- --ignored` renders every tab to PNGs, with this PC's real history if it has one. `node --test tests/extension.test.js` covers the extension's helpers. Live capture needs admin rights, so test it by running the window.
