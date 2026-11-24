# NetStop

NetStop shows which programs on your Windows PC are using the network, how much each one sends and receives, and where that traffic goes. You can block any program with one click, and it keeps 7 days of history so you can look back at what happened yesterday or last week.

Everything stays on your PC. There is no server, no account and no telemetry.

## Install

You need Windows 10 or 11, 64-bit.

1. Download `netstop.exe` from the [latest release](../../releases/latest).
2. Double-click it, accept the admin prompt, and choose **Yes** when it offers to install.
3. From then on, open NetStop from the Start menu. The recorder keeps running after you close the window and starts with Windows.

The exe isn't code-signed yet, so SmartScreen will probably warn you. Click **More info**, then **Run anyway**. To verify the download, run `Get-FileHash netstop.exe` in PowerShell and compare the result with the SHA-256 in the release notes.

To **update**, download the new exe, double-click it and choose **Yes**. Your history is kept.

To **uninstall**, run:

```powershell
& "C:\Program Files\NetStop\netstop.exe" uninstall
```

This removes the recorder, the data, the Start menu shortcut and every firewall rule NetStop created.

## Usage

The window has four tabs:

1. **Now** lists every program that has used the network since the window opened, with its upload and download speed, its connections, and what kind of program it is: an app, a background process, a Windows service, a VPN, or Windows itself.
2. **Live feed** shows traffic as it happens.
3. **History** shows the last 7 days, grouped by program, site or connection. You can sort and filter it, and export any day to a CSV file in your Downloads folder.
4. **Blocked** lists everything you've blocked.

Every program has a **Block** button next to it. Blocking adds a Windows Firewall rule named `NetStop block: …`, so you can also see and remove it in Windows Firewall.

Right-click any program name to rename it.

### Chrome extension (optional)

The extension shows a summary of today's traffic in a popup, lets you step back through earlier days, and opens the full report in a tab.

1. Download `netstop-extension.zip` from the same release and unzip it somewhere permanent.
2. Open `chrome://extensions` and turn on **Developer mode**.
3. Click **Load unpacked** and select the unzipped folder.

## How it works

NetStop has three parts in one exe:

```
netstop            the window (asks for admin)
netstop record     the recorder, started at boot as SYSTEM
netstop install    sets up the recorder and the browser bridge
netstop uninstall  removes everything NetStop added
```

**Counting.** Windows already reports every TCP and UDP send and receive through ETW kernel network events, each with a process ID, a byte count and a kernel timestamp. NetStop listens to those events. It installs no driver and never sits in the data path.

**Naming programs.** Each process is named the moment it starts, from kernel process events. A program that runs for half a second still gets the right name, and a reused process ID never inherits an old one. Friendly names come from a built-in table in `src/names.rs`, or from the exe's own description.

**Naming sites.** IP addresses are matched to domain names using Windows DNS client events, so you see `chrome.exe → youtube.com` instead of a bare IP.

**Making the totals add up.** The row called "Headers, ping, ARP and other" is your network adapter's total minus everything matched to a program. That way the window always adds up to what actually went over the wire. Localhost traffic is ignored because it never leaves the machine.

**Storage.** The recorder writes per-minute totals for each program and site to a local SQLite database and deletes anything older than 7 days, which keeps it under about 15 MB. Packet contents are never stored.

## Security

The window and recorder run with high privileges, so NetStop is built to give nothing away:

* **No network surface.** NetStop opens no connections and listens on no ports. The browser bridge uses Chrome native messaging over stdin and stdout, so web pages can't reach it. It opens the database read-only, accepts one JSON request shape up to 4 KB, and only answers the NetStop extension's fixed ID.
* **Locked-down files.** The boot task only runs the copy in Program Files, which only admins can write. The data folder in ProgramData is created already locked: admins and SYSTEM can write, the installing user can read, and other accounts can't open it. If a folder with that name already exists and isn't owned by Administrators or SYSTEM, install deletes it first, so planted links can't redirect SYSTEM's writes.
* **No shell commands.** Blocking goes through the Windows Firewall COM API.
* **Bounded storage.** At most 300 sites per program per minute (the rest are grouped as "many other addresses") and about 1 GB in total, so a traffic flood can't fill your disk.
* **Other details.** The recorder's lock file can't be opened by normal users, so another account can't stop recording. It never opens program files on network shares, so it never sends this PC's credentials to another machine. CSV exports escape values a spreadsheet would run as formulas. The extension requests only `nativeMessaging`, runs under a strict CSP, loads nothing remote, and writes all text with `textContent`.

## Known limitations

* Windows only, and it needs admin rights, because Windows only gives kernel network events to admins.
* The Cloudflare WARP, OpenVPN and Tailscale clients are labelled VPN and excluded from totals, since their traffic is a wrapped copy of everyone else's. This only applies when they run from Program Files, so a lookalike elsewhere is still counted. Windows' built-in VPN and WireGuard show up as System and are counted twice.
* Apps that do their own encrypted DNS, like Chrome's Secure DNS or Firefox with DoH, show IP addresses instead of site names.
* The browser bridge is only registered for Chrome.
* A power cut can lose up to the last 5 seconds of counts.

## Building from source

```powershell
cargo build --release
.\target\release\netstop.exe install
```

Without the Visual Studio build tools, use the GNU toolchain with MSYS2's `gcc` on your PATH. Run this once inside the repo:

```powershell
rustup override set stable-x86_64-pc-windows-gnu
```

Release downloads are built with `cargo build --profile dist`, which enables full LTO for a smaller exe at the cost of a slower build.

## Tests

```powershell
cargo test                          # Rust tests
node --test tests/extension.test.js # extension helpers
```

The Rust tests cover the name table, report queries, DNS parsing, the bridge's input checks, the per-minute row cap, firewall rule names and CSV escaping. They also drive every tab of the window headlessly through egui's accessibility tree, including clicking, typing, renaming, and blocking against a fake firewall.

To render every tab to PNG files, using this PC's real history if there is any:

```powershell
$env:NETSTOP_SHOTS = "shots"
cargo test screenshots -- --ignored
```

Live capture needs admin rights, so test that part by running the window.
