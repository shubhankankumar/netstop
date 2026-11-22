//! Window tests: the real `App` driven headlessly through its accessibility tree (clicks, typing,
//! right-clicks), with a fake backend so nothing touches the firewall or the real database.
//! `NETSTOP_SHOTS=<dir> cargo test screenshots -- --ignored` also renders every tab to PNGs.

use super::*;
use crate::capture::Dir;
use crate::live::event;
use egui::accesskit::Role;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};

// Not the real Chrome path: a running Chrome with a window would make this row "App".
const CHROME: &str = r"C:\Apps\Chrome\chrome.exe";
const SNEAKY: &str = r"C:\Users\x\AppData\Local\Temp\sneaky.exe";
/// The real window's default size (gui::run).
const SIZE: [f32; 2] = [1040.0, 620.0];
const SVC: &str = r"C:\Windows\System32\svchost.exe|Dnscache";

fn warp() -> String {
    format!(r"{}\Cloudflare\Cloudflare WARP\warp-svc.exe", crate::winutil::program_files().display())
}

#[derive(Default)]
struct Fake {
    rules: Mutex<HashSet<String>>,
    block_calls: AtomicUsize,
    fail_block: AtomicBool,
    fail_day: AtomicBool,
    saved: Mutex<Vec<(String, String)>>,
}

/// Yesterday: Chrome to old.com. Today: Chrome (also at 00:30), a new program, a VPN and a service.
fn history_db() -> rusqlite::Connection {
    let mut c = rusqlite::Connection::open_in_memory().unwrap();
    c.execute_batch(crate::db::SCHEMA).unwrap();
    let s = report::local_midnight_days_ago(0) / 60;
    let k = |m: i64, app: &str, host: &str| crate::db::Key { minute: m, app: Arc::from(app), host: Arc::from(host), port: 443, proto: 6 };
    let rows = HashMap::from([
        (k(s - 600, CHROME, "old.com"), (1, 1)),
        (k(s + 30, CHROME, "old.com"), (10, 2000)),
        (k(s + 400, CHROME, "new.com"), (5, 5)),
        (k(s + 401, SNEAKY, "new.com"), (900, 0)),
        (k(s + 402, &warp(), "162.159.192.1"), (5000, 5000)),
        (k(s + 403, SVC, "dns.google"), (3, 3)),
    ]);
    let labels: Vec<_> = rows.keys().map(|k| (k.app.clone(), crate::procinfo::label(&k.app))).collect();
    crate::db::flush(&mut c, &rows, &labels).unwrap();
    c
}

fn backend(f: Arc<Fake>) -> Backend {
    let conn = Mutex::new(history_db());
    let (f0, f1, f2, f3) = (f.clone(), f.clone(), f.clone(), f);
    Backend {
        load_day: Box::new(move |date| {
            if f0.fail_day.load(SeqCst) {
                return Err("The disk is on fire".into());
            }
            report::day(&conn.lock().unwrap(), date, 100_000)
        }),
        fw_rules: Box::new(move || Ok(f1.rules.lock().unwrap().clone())),
        set_blocked: Box::new(move |app, block| {
            f2.block_calls.fetch_add(1, SeqCst);
            std::thread::sleep(Duration::from_millis(30)); // a real firewall change takes a moment
            if f2.fail_block.load(SeqCst) {
                return Err("Access is denied.".into());
            }
            let mut r = f2.rules.lock().unwrap();
            for (name, _, _) in crate::firewall::rules_for(app) {
                if block { r.insert(name) } else { r.remove(&name) };
            }
            Ok(())
        }),
        save_name: Box::new(move |app, name| {
            f3.saved.lock().unwrap().push((app.into(), name.into()));
            Ok(())
        }),
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn feed_live(live: &Mutex<Live>, scale: u32) {
    let t = now_ms();
    let mut l = live.lock().unwrap();
    l.add(event(CHROME, "x.com", 443, Dir::Up, 5000 * scale, t));
    l.add(event(CHROME, "youtube.com", 443, Dir::Down, 90_000 * scale, t + 5));
    l.add(event(&warp(), "162.159.192.1", 2408, Dir::Down, 1000 * scale, t + 6));
    l.add(event(SVC, "dns.google", 53, Dir::Up, 100 * scale, t + 7));
    l.add(event("System", "10.0.0.2", 445, Dir::Up, 10 * scale, t + 8));
}

fn harness(f: Arc<Fake>) -> (Harness<'static, App>, Arc<Mutex<Live>>) {
    let live: Arc<Mutex<Live>> = Arc::default();
    feed_live(&live, 1);
    let app = App::new(backend(f), live.clone(), None, HashMap::new());
    let mut h = Harness::builder().with_size(SIZE).build_ui_state(|ui, app: &mut App| app.show(ui), app);
    h.run_steps(3);
    (h, live)
}

/// Steps the UI until `ok`, giving worker threads time to answer. A wall-clock limit, not a step
/// count: on a busy PC (a build running alongside) 400 short steps were not enough.
fn wait(h: &mut Harness<'static, App>, what: &str, ok: impl Fn(&App) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        h.step();
        if ok(h.state()) {
            h.run_steps(2);
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let s = h.state();
    panic!("timed out waiting for {what}: status={:?} changing={:?} selected={:?}", s.status, s.changing, s.selected);
}

/// Clicks the first widget labelled `label` the way a mouse does: over it first, then the press.
/// (A press that teleports onto a widget can miss if that frame's layout moved, e.g. on a busy PC.)
fn press(h: &mut Harness<'static, App>, label: &str) {
    h.get_all_by_label(label).next().unwrap().hover();
    h.run_steps(1);
    h.get_all_by_label(label).next().unwrap().click();
}

/// The once-a-second refresh, now.
fn tick(h: &mut Harness<'static, App>) {
    h.state_mut().tick = Instant::now() - Duration::from_secs(1);
    h.run_steps(2);
}

fn type_into(h: &mut Harness<'static, App>, label: &str, text: &str) {
    h.get_by_role_and_label(Role::TextInput, label).focus();
    h.run_steps(1);
    h.get_by_role_and_label(Role::TextInput, label).type_text(text);
    h.run_steps(2);
}

#[test]
fn now_lists_programs_by_kind_with_details_and_filter() {
    let (mut h, live) = harness(Arc::default());
    for label in ["Google Chrome", "Cloudflare WARP (VPN)", "Windows service: DNS lookups", "Windows core (file sharing, drivers)"] {
        h.get_by_label(label);
    }
    for kind in ["VPN", "Service", "System", "Background"] {
        h.get_by_label(kind);
    }
    assert_eq!(&*h.state().rows[0].key, CHROME, "biggest total first");

    // Rates: the VPN row is shown but left out of the top-bar total.
    feed_live(&live, 2);
    tick(&mut h);
    let s = h.state();
    let vpn = s.rows.iter().find(|r| r.kind == Kind::Vpn).unwrap();
    assert!(vpn.down_s > 0);
    let counted: u64 = s.rows.iter().filter(|r| r.kind != Kind::Vpn).map(|r| r.down_s).sum();
    assert_eq!(s.rate.1, counted + s.other.1);

    // Click a program: its connections open in a panel. Close, Esc and a second click each close it.
    let open = |h: &mut Harness<'static, App>| {
        h.get_by_label("Google Chrome").click();
        h.run_steps(2);
        h.get_by_label("youtube.com");
    };
    open(&mut h);
    h.get_by_label("x.com");
    h.get_by_label_contains("2 connections");
    let close = h.get_by_label("Close");
    assert!(close.rect().top() > SIZE[1] - 24.0 - 240.0 + 6.0, "clear of the resize edge: {:?}", close.rect());
    close.click();
    h.run_steps(2);
    assert!(h.query_by_label("youtube.com").is_none(), "Close");
    // As the live UI Automation test did: open and close through accessibility actions.
    h.get_by_label("Google Chrome").click_accesskit();
    h.run_steps(2);
    h.get_by_label("Close").click_accesskit();
    h.run_steps(2);
    assert!(h.query_by_label("youtube.com").is_none(), "Close via accessibility");
    open(&mut h);
    h.key_press(egui::Key::Escape);
    h.run_steps(2);
    assert!(h.query_by_label("youtube.com").is_none(), "Esc");
    open(&mut h);
    h.get_by_role_and_label(Role::Button, "Google Chrome").click();
    h.run_steps(2);
    assert!(h.query_by_label("youtube.com").is_none(), "second click");

    // Filter by name or path; × clears it.
    type_into(&mut h, "Filter", "warp");
    assert!(h.query_by_label("Google Chrome").is_none());
    h.get_by_label("Cloudflare WARP (VPN)");
    h.get_by_label("×").click();
    h.run_steps(2);
    h.get_by_label("Google Chrome");
}

#[test]
fn block_and_unblock_through_the_firewall_backend() {
    let f = Arc::new(Fake::default());
    let (mut h, _live) = harness(f.clone());
    // Only real program paths get a button: Chrome, WARP and the service row.
    assert_eq!(h.get_all_by_label("Block").count(), 3);
    press(&mut h, "Block"); // Chrome: biggest total, first row
    h.run_steps(2);
    // While the change runs, the button is disabled, so a second click can't undo the first.
    h.get_by_label("…").click();
    wait(&mut h, "block", |a| a.status == "Blocked Google Chrome");
    assert_eq!(f.block_calls.load(SeqCst), 1);
    assert!(f.rules.lock().unwrap().contains(&format!("NetStop block: {CHROME}")));
    h.get_by_label("Unblock");

    h.get_by_label("Blocked").click();
    h.run_steps(2);
    h.get_by_label(CHROME); // path column
    press(&mut h, "Unblock");
    wait(&mut h, "unblock", |a| a.status == "Unblocked Google Chrome");
    h.get_by_label_contains("Nothing is blocked");
    assert!(f.rules.lock().unwrap().is_empty());

    // A failed change says so and leaves the button usable.
    f.fail_block.store(true, SeqCst);
    h.get_by_label("Now").click();
    h.run_steps(2);
    press(&mut h, "Block");
    wait(&mut h, "failed block", |a| a.status.starts_with("Could not block"));
    assert_eq!(h.state().status, "Could not block Google Chrome: Access is denied.");
    assert_eq!(h.get_all_by_label("Block").count(), 3);
}

#[test]
fn history_views_sorting_filter_and_days() {
    let (mut h, _live) = harness(Arc::default());
    h.get_by_label("History").click();
    wait(&mut h, "today's report", |a| matches!(&a.day, Some(Ok(_))));
    // VPN rows are listed but not counted: 10+5+900+3 sent, 2000+5+3 received.
    h.get_by_label(&format!("Total {}", human(918 + 2008)));
    h.get_by_label("Programs (4)").click();
    h.run_steps(2);
    for name in ["Google Chrome", "sneaky", "Cloudflare WARP (VPN)"] {
        h.get_by_label(name);
    }
    assert_eq!(h.get_all_by_label("new").count(), 2, "sneaky.exe and the service are new today; Chrome isn't");

    // Sites: sort by Sent (biggest first, then smallest first, then back to the report's order).
    h.get_by_label("Sites (4)").click();
    h.run_steps(2);
    let order = |h: &Harness<'static, App>| {
        let s = h.state();
        let Some(Ok(day)) = &s.day else { panic!() };
        s.view_rows.as_ref().unwrap().1.iter().map(|&i| day.hosts[i].host.clone()).collect::<Vec<_>>()
    };
    let default = order(&h);
    h.get_by_label("Sent").click();
    h.run_steps(2);
    assert_eq!(order(&h)[0], "162.159.192.1");
    h.get_by_label("Sent").click();
    h.run_steps(2);
    assert_eq!(order(&h)[0], "dns.google");
    h.get_by_label("Sent").click();
    h.run_steps(2);
    assert_eq!(order(&h), default);

    // Filter applies to the current view.
    type_into(&mut h, "Filter", "new.");
    assert_eq!(order(&h), vec!["new.com"]);

    h.get_by_label("Connections (5)").click();
    h.run_steps(2);
    assert_eq!(h.state().view_rows.as_ref().unwrap().1.len(), 2, "filter 'new.' keeps Chrome and sneaky to new.com");
    h.get_by_label("00:00 to 06:00 (1)");

    // Yesterday: only Chrome. A late reply for today must not replace it.
    h.get_by_label("Yesterday").click();
    let yesterday = report::last_7_days()[1].clone();
    wait(&mut h, "yesterday's report", |a| matches!(&a.day, Some(Ok(d)) if d.date == yesterday));
    let today = report::last_7_days()[0].clone();
    h.state().tx.send(Msg::Day(today, Ok(Day::default()))).unwrap();
    h.run_steps(2);
    assert!(matches!(&h.state().day, Some(Ok(d)) if d.date == yesterday));
}

#[test]
fn history_shows_load_errors_without_retrying_every_frame() {
    let f = Arc::new(Fake::default());
    f.fail_day.store(true, SeqCst);
    let (mut h, _live) = harness(f);
    h.get_by_label("History").click();
    wait(&mut h, "error", |a| matches!(&a.day, Some(Err(_))));
    h.get_by_label("The disk is on fire");
    h.run_steps(20);
    assert!(h.state().loading.is_none(), "no reload loop after an error");
}

#[test]
fn feed_pause_filter_and_resume() {
    let (mut h, live) = harness(Arc::default());
    h.get_by_label("Live feed").click();
    tick(&mut h);
    h.get_by_label_contains("5 lines, newest first.");
    h.get_by_label("Pause").click();
    h.run_steps(2);
    feed_live(&live, 1);
    tick(&mut h);
    h.get_by_label_contains("5 lines, newest first (paused)");
    // Narrowing and then widening the filter while paused works on the frozen lines.
    type_into(&mut h, "Filter", "youtube");
    h.get_by_label_contains("1 line, newest first (paused)");
    h.get_by_label("×").click();
    h.run_steps(2);
    h.get_by_label_contains("5 lines, newest first (paused)");
    h.get_by_label("Resume").click();
    h.run_steps(3);
    h.get_by_label_contains("10 lines, newest first.");
}

#[test]
fn rename_from_the_right_click_menu() {
    let f = Arc::new(Fake::default());
    let (mut h, _live) = harness(f.clone());
    h.get_by_label("Google Chrome").click_secondary();
    h.run_steps(2);
    h.get_by_label("Rename…").click();
    h.run_steps(2);
    h.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
    h.get_by_role_and_label(Role::TextInput, "Name").type_text("My browser");
    h.run_steps(1);
    h.key_press(egui::Key::Enter);
    wait(&mut h, "save", |_| !f.saved.lock().unwrap().is_empty());
    assert_eq!(f.saved.lock().unwrap()[0], (CHROME.to_string(), "My browser".to_string()));
    tick(&mut h);
    h.get_by_label("My browser");
    assert!(h.query_by_label("Rename").is_none(), "dialog closed");
}

#[test]
fn csv_export_is_spreadsheet_safe() {
    assert_eq!(csv_field("=cmd|x"), "\"'=cmd|x\"");
    assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
    let day = report::day(&history_db(), &report::last_7_days()[0], 100).unwrap();
    let out = csv(&day);
    assert_eq!(out.lines().count(), 1 + day.conns.len());
    assert!(out.lines().nth(1).unwrap().starts_with("\"Cloudflare WARP (VPN)\""));
}

#[test]
fn window_fits_above_the_taskbar() {
    // 1080p at 150% scaling with a 48 px taskbar: 1280 x 672 points.
    let (pos, size) = initial_window(Some([0.0, 0.0, 1280.0, 672.0]));
    let pos = pos.unwrap();
    assert!(pos.y + TITLE_BAR + size.y <= 672.0, "{pos:?} {size:?}");
    assert!(pos.x >= 0.0 && pos.x + size.x <= 1280.0);
    // A big screen gets the default size, centred.
    let (pos, size) = initial_window(Some([0.0, 0.0, 2560.0, 1400.0]));
    assert_eq!(size, DEFAULT_SIZE);
    assert_eq!(pos.unwrap().x, (2560.0 - 1040.0) / 2.0);
    // Unknown screen: let Windows place it.
    assert_eq!(initial_window(None), (None, DEFAULT_SIZE));
    // This PC's real answer is sane.
    let [_, _, w, h] = crate::winutil::work_area_points().unwrap();
    assert!(w > 300.0 && h > 200.0, "{w} x {h}");
}

#[test]
fn small_helpers() {
    assert_eq!(day_label(0, "2026-11-22"), "Today");
    assert_eq!(day_label(2, "2026-11-20"), "Fri 20 Nov");
    assert_eq!(ago_text(59), "59 s");
    assert_eq!(ago_text(600), "10 min");
    assert_eq!(ago_text(3 * 86_400), "3 days");
    assert_eq!(port(53, 17), "53 UDP");
}

/// Renders each tab (synthetic live data, real history if this PC has it) to PNGs for a person to
/// look at. Read-only: the real backend is used only to load reports and read firewall rules.
#[test]
#[ignore]
fn screenshots() {
    let Some(dir) = std::env::var_os("NETSTOP_SHOTS").map(std::path::PathBuf::from) else { return };
    std::fs::create_dir_all(&dir).unwrap();
    for (theme, tname) in [(egui::Theme::Dark, "dark"), (egui::Theme::Light, "light")] {
        let live: Arc<Mutex<Live>> = Arc::default();
        feed_live(&live, 1);
        let real = Backend::real();
        let b = Backend { set_blocked: Box::new(|_, _| Err("disabled in screenshots".into())), save_name: Box::new(|_, _| Ok(())), ..real };
        let app = App::new(b, live.clone(), None, HashMap::new());
        let mut h = Harness::builder().with_size(SIZE).with_theme(theme).wgpu().build_ui_state(|ui, app: &mut App| app.show(ui), app);
        h.run_steps(3);
        feed_live(&live, 3);
        tick(&mut h);
        let shot = |h: &mut Harness<'static, App>, name: &str| {
            h.run_steps(3);
            h.render().unwrap().save(dir.join(format!("{tname}-{name}.png"))).unwrap();
        };
        shot(&mut h, "1-now");
        h.get_by_label("Google Chrome").click();
        shot(&mut h, "2-now-selected");
        h.get_by_label("Live feed").click();
        tick(&mut h);
        shot(&mut h, "3-feed");
        h.get_by_label("History").click();
        wait(&mut h, "report", |a| a.day.is_some());
        shot(&mut h, "4-history");
        if let Some(n) = h.query_by_label_contains("Sites (") {
            n.click();
            shot(&mut h, "5-history-sites");
        }
        h.get_by_label("Blocked").click();
        wait(&mut h, "rules", |a| a.fw_error.is_some() || a.tab == Tab::Blocked);
        shot(&mut h, "6-blocked");
    }
}

/// egui's built-in fonts are small: a symbol they lack draws as an empty box in the real window.
#[test]
fn every_symbol_used_has_a_glyph() {
    let mut h = Harness::new_ui(|ui| {
        for c in "×…–·".chars() {
            assert!(ui.ctx().fonts_mut(|f| f.has_glyph(&egui::FontId::proportional(14.0), c)), "{c}");
        }
        for c in "↑↓".chars() {
            assert!(ui.ctx().fonts_mut(|f| f.has_glyph(&egui::FontId::monospace(14.0), c)), "{c}");
        }
    });
    h.step();
}




/// The connections panel must not move once it is open: a click aimed at the frame-1 position of
/// "Close" landed nowhere when the panel grew on frame 2.
#[test]
fn connections_panel_does_not_jump_when_opening() {
    let (mut h, _live) = harness(Arc::default());
    h.get_by_label("Google Chrome").click();
    h.run_steps(2); // the click is seen in frame 1; the panel is drawn from frame 2
    let first = h.get_by_label("Close").rect();
    for _ in 0..4 {
        h.step();
        assert_eq!(h.get_by_label("Close").rect(), first);
    }
    h.get_by_label("Close").click(); // no hover, straight after opening
    h.run_steps(2);
    assert!(h.state().selected.is_none());
}

