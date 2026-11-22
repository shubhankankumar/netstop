//! The window. Tabs: Now (live, since the window opened), Live feed, History (the recorder's last
//! 7 days) and Blocked. Slow work (reports, firewall, saving renames) runs on worker threads and
//! reports back through one channel, so the window never stalls and never shows a stale result.

use crate::capture::Dir;
use crate::live::{FeedRow, Live};
use crate::report::{self, AppRow, ConnRow, Day, HostRow, human};
use eframe::egui::{self, Align, Color32, Layout, RichText, Sense};
use egui_extras::{Column, TableBuilder};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Everything the window reads or changes outside itself. `real()` talks to the database and
/// Windows Firewall; tests pass fakes.
pub struct Backend {
    pub load_day: LoadDay,
    pub fw_rules: Box<dyn Fn() -> Rules + Send + Sync>,
    pub set_blocked: SetBlocked,
    pub save_name: SaveName,
}

type LoadDay = Box<dyn Fn(&str) -> Result<Day, String> + Send + Sync>;
/// (program key, block?)
type SetBlocked = Box<dyn Fn(&str, bool) -> Result<(), String> + Send + Sync>;
/// (program key, new name; empty means the default name)
type SaveName = Box<dyn Fn(&str, &str) -> Result<(), String> + Send + Sync>;

/// NetStop's rule names in Windows Firewall.
type Rules = Result<HashSet<String>, String>;

impl Backend {
    pub fn real() -> Self {
        Backend {
            load_day: Box::new(|date| {
                let c = crate::db::open_ro().map_err(|_| "No history yet. Install NetStop so the recorder runs (netstop install, as admin).".to_string())?;
                report::day(&c, date, 100_000)
            }),
            fw_rules: Box::new(crate::firewall::rules),
            set_blocked: Box::new(crate::firewall::set_blocked),
            save_name: Box::new(|app, name| {
                let c = crate::db::open_rw().map_err(|e| e.to_string())?;
                crate::db::set_name(&c, app, name).map_err(|e| e.to_string())
            }),
        }
    }
}

enum Msg {
    Day(String, Result<Day, String>),
    Rules(Rules),
    /// One message with the rules read afterwards, so no frame shows the result with old rules.
    Block { app: String, block: bool, result: Result<(), String>, rules: Rules },
    Saved(Result<(), String>),
}

#[derive(PartialEq, Clone, Copy, Debug)]
enum Tab {
    Now,
    Feed,
    History,
    Blocked,
}

#[derive(PartialEq, Clone, Copy, Debug)]
enum View {
    Programs,
    Sites,
    Connections,
    Night,
}

#[derive(PartialEq, Clone, Copy)]
enum Kind {
    App,
    Background,
    Service,
    Vpn,
    System,
}

impl Kind {
    fn of(key: &str, windowed: &HashSet<String>) -> Kind {
        if crate::names::is_tunnel(key) {
            Kind::Vpn
        } else if !crate::firewall::blockable(key) {
            Kind::System // "System" or a process that ended before it was named
        } else if key.contains('|') {
            Kind::Service
        } else if windowed.contains(key) {
            Kind::App
        } else {
            Kind::Background
        }
    }
    fn label(self) -> (&'static str, &'static str) {
        match self {
            Kind::App => ("App", "Has a window open"),
            Kind::Background => ("Background", "No window: a helper, updater or tray program"),
            Kind::Service => ("Service", "A Windows service running inside svchost.exe"),
            Kind::Vpn => ("VPN", "Carries the other programs' traffic, so it is not added to the totals"),
            Kind::System => ("System", "Windows itself, or a program that ended before it could be named"),
        }
    }
}

struct Row {
    key: Arc<str>,
    name: String,
    up_s: u64,
    down_s: u64,
    up: u64,
    down: u64,
    kind: Kind,
}

type Sort = Option<(usize, bool)>; // (column, descending)
/// What a cached History view depends on: report generation, view, filter, sort.
type ViewKey = (u64, View, String, Sort);

pub struct App {
    backend: Arc<Backend>,
    live: Arc<Mutex<Live>>,
    capture_error: Option<String>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    tab: Tab,
    status: String,
    // Names
    labels: HashMap<Arc<str>, String>,
    renames: HashMap<String, String>,
    renaming: Option<(String, String)>,
    // Firewall: NetStop's rule names (the source of truth for "blocked") and changes in flight.
    fw_rules: HashSet<String>,
    fw_error: Option<String>,
    changing: HashSet<String>,
    // Now (rebuilt once a second)
    tick: Instant,
    prev: HashMap<Arc<str>, (u64, u64)>,
    rows: Vec<Row>,
    rate: (u64, u64),
    other: (u64, u64),
    adapter_prev: Option<(u64, u64)>,
    selected: Option<Arc<str>>,
    now_filter: String,
    // Live feed: a snapshot taken once a second (not while paused), and the filtered view of it
    feed_raw: Vec<FeedRow>,
    feed: Vec<(FeedRow, String)>,
    feed_filter: String,
    feed_small: bool,
    feed_paused: bool,
    feed_dirty: bool,
    // History
    day_idx: usize,
    day: Option<Result<Day, String>>,
    day_gen: u64,
    loading: Option<String>,
    loaded_at: Instant,
    view: View,
    hist_filter: String,
    sorts: [Sort; 4],
    view_rows: Option<(ViewKey, Vec<usize>)>,
}

impl App {
    pub fn new(backend: Backend, live: Arc<Mutex<Live>>, capture_error: Option<String>, renames: HashMap<String, String>) -> Self {
        let (tx, rx) = channel();
        let app = App {
            backend: Arc::new(backend),
            live,
            capture_error,
            tx,
            rx,
            tab: Tab::Now,
            status: String::new(),
            labels: HashMap::new(),
            renames,
            renaming: None,
            fw_rules: HashSet::new(),
            fw_error: None,
            changing: HashSet::new(),
            tick: Instant::now() - Duration::from_secs(2),
            prev: HashMap::new(),
            rows: Vec::new(),
            rate: (0, 0),
            other: (0, 0),
            adapter_prev: None,
            selected: None,
            now_filter: String::new(),
            feed_raw: Vec::new(),
            feed: Vec::new(),
            feed_filter: String::new(),
            feed_small: false,
            feed_paused: false,
            feed_dirty: true,
            day_idx: 0,
            day: None,
            day_gen: 0,
            loading: None,
            loaded_at: Instant::now(),
            view: View::Programs,
            hist_filter: String::new(),
            sorts: [None; 4],
            view_rows: None,
        };
        app.refresh_rules(None);
        app
    }

    // ---- background work -------------------------------------------------------------------

    fn spawn(&self, ctx: Option<&egui::Context>, job: impl FnOnce(&Backend) -> Vec<Msg> + Send + 'static) {
        let (b, tx, ctx) = (self.backend.clone(), self.tx.clone(), ctx.cloned());
        std::thread::spawn(move || {
            for m in job(&b) {
                let _ = tx.send(m);
            }
            if let Some(c) = ctx {
                c.request_repaint();
            }
        });
    }

    fn refresh_rules(&self, ctx: Option<&egui::Context>) {
        self.spawn(ctx, |b| vec![Msg::Rules((b.fw_rules)())]);
    }

    fn toggle_block(&mut self, ctx: &egui::Context, app: &str) {
        if !self.changing.insert(app.to_string()) {
            return; // already changing: a double click must not undo itself
        }
        let block = !crate::firewall::is_blocked(&self.fw_rules, app);
        self.status = format!("{} {}…", if block { "Blocking" } else { "Unblocking" }, self.name(&Arc::from(app)));
        let app = app.to_string();
        self.spawn(Some(ctx), move |b| {
            let result = (b.set_blocked)(&app, block);
            vec![Msg::Block { app, block, result, rules: (b.fw_rules)() }]
        });
    }

    fn poll(&mut self) {
        while let Ok(m) = self.rx.try_recv() {
            match m {
                Msg::Day(date, r) => {
                    if self.loading.as_deref() == Some(date.as_str()) {
                        self.loading = None;
                    }
                    // A reply for a day that is no longer shown is dropped.
                    if date == report::last_7_days()[self.day_idx] {
                        self.day = Some(r);
                        self.day_gen += 1;
                        self.loaded_at = Instant::now();
                    }
                }
                Msg::Rules(r) => self.set_rules(r),
                Msg::Block { app, block, result, rules } => {
                    self.changing.remove(&app);
                    self.set_rules(rules);
                    let n = self.name(&Arc::from(app.as_str()));
                    self.status = match result {
                        Ok(()) => format!("{} {n}", if block { "Blocked" } else { "Unblocked" }),
                        Err(e) => format!("Could not {} {n}: {e}", if block { "block" } else { "unblock" }),
                    };
                }
                Msg::Saved(Err(e)) => self.status = format!("Could not save the name: {e}"),
                Msg::Saved(Ok(())) => {}
            }
        }
    }

    fn set_rules(&mut self, r: Rules) {
        match r {
            Ok(r) => (self.fw_rules, self.fw_error) = (r, None),
            Err(e) => self.fw_error = Some(format!("Could not read Windows Firewall rules: {e}")),
        }
    }

    // ---- names -----------------------------------------------------------------------------

    fn name(&mut self, key: &Arc<str>) -> String {
        if let Some(n) = self.renames.get(&**key) {
            return n.clone();
        }
        self.labels.entry(key.clone()).or_insert_with(|| crate::procinfo::label(key)).clone()
    }

    /// History rows carry the name the report found; a rename made since then wins.
    fn report_name<'a>(&'a self, app: &str, name: &'a str) -> &'a str {
        self.renames.get(app).map_or(name, String::as_str)
    }

    fn name_button(&mut self, ui: &mut egui::Ui, key: &str, name: &str, selected: bool) -> egui::Response {
        let path = key.split('|').next().unwrap_or(key);
        let r = ui.add(egui::Button::selectable(selected, name).truncate()).on_hover_text(format!("{key}\nRight-click to rename or copy the path"));
        r.context_menu(|ui| {
            if ui.button("Rename…").clicked() {
                self.renaming = Some((key.to_string(), name.to_string()));
                ui.close();
            }
            if ui.button("Copy path").clicked() {
                ui.ctx().copy_text(path.to_string());
                ui.close();
            }
        });
        r
    }

    fn block_button(&mut self, ui: &mut egui::Ui, key: &str) {
        if !crate::firewall::blockable(key) {
            ui.weak("—").on_hover_text("Windows itself, or a program that already ended: can't be blocked by program");
            return;
        }
        if self.changing.contains(key) {
            ui.add_enabled(false, egui::Button::new("…").small()).on_disabled_hover_text("Changing the firewall rule");
            return;
        }
        let blocked = crate::firewall::is_blocked(&self.fw_rules, key);
        let (text, tip) = if blocked { ("Unblock", "Allow this program to use the internet again") } else { ("Block", "Stop this program sending anything (Windows Firewall rule)") };
        if ui.small_button(text).on_hover_text(tip).clicked() {
            self.toggle_block(&ui.ctx().clone(), key);
        }
    }

    // ---- once a second ---------------------------------------------------------------------

    fn every_second(&mut self) {
        let secs = self.tick.elapsed().as_secs_f64();
        if secs < 1.0 {
            return;
        }
        self.tick = Instant::now();
        let windowed = crate::procinfo::windowed_exes();
        let snap: Vec<(Arc<str>, u64, u64)> = {
            let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            if !self.feed_paused {
                self.feed_raw = live.feed.iter().cloned().collect();
                self.feed_dirty = true;
            }
            live.apps.iter().map(|(k, a)| (k.clone(), a.up, a.down)).collect()
        };
        let mut rows = Vec::with_capacity(snap.len());
        let (mut au, mut ad) = (0, 0);
        for (key, up, down) in snap {
            let (pu, pd) = self.prev.insert(key.clone(), (up, down)).unwrap_or((up, down));
            let (up_s, down_s) = ((up.saturating_sub(pu) as f64 / secs) as u64, (down.saturating_sub(pd) as f64 / secs) as u64);
            let kind = Kind::of(&key, &windowed);
            if kind != Kind::Vpn {
                au += up_s; // a VPN's own traffic is the wrapped copy of the rows it carries
                ad += down_s;
            }
            let name = self.name(&key);
            rows.push(Row { key, name, up_s, down_s, up, down, kind });
        }
        // By total, not by this second's rate: rows that reshuffle every second put the wrong
        // program under the cursor when you click Block.
        rows.sort_by(|a, b| (b.up + b.down).cmp(&(a.up + a.down)).then_with(|| a.key.cmp(&b.key)));
        let renamed = crate::names::distinct_names(rows.iter().map(|r| (&*r.key, r.name.as_str())));
        for r in &mut rows {
            if let Some(n) = renamed.get(&*r.key) {
                r.name.clone_from(n);
            }
        }
        self.rows = rows;
        let (rx, tx) = crate::procinfo::adapter_totals();
        if let Some((prx, ptx)) = self.adapter_prev.replace((rx, tx)) {
            let wire = ((tx.saturating_sub(ptx) as f64 / secs) as u64, (rx.saturating_sub(prx) as f64 / secs) as u64);
            self.other = (wire.0.saturating_sub(au), wire.1.saturating_sub(ad));
        }
        self.rate = (au + self.other.0, ad + self.other.1);
    }

    // ---- Now -------------------------------------------------------------------------------

    fn tab_now(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            filter_box(ui, &mut self.now_filter, "now_filter", "program or path");
            ui.weak(format!("{} programs since this window opened. Click one to see its connections.", self.rows.len()));
        });
        ui.add_space(4.0);
        let f = self.now_filter.to_lowercase();
        let rows = std::mem::take(&mut self.rows);
        let shown: Vec<&Row> = rows.iter().filter(|r| f.is_empty() || r.name.to_lowercase().contains(&f) || r.key.to_lowercase().contains(&f)).collect();
        let mut clicked = None;
        TableBuilder::new(ui)
            .id_salt("now")
            .striped(true)
            .auto_shrink(false)
            .max_scroll_height(f32::INFINITY)
            .column(Column::remainder().at_least(220.0).clip(true))
            .columns(Column::exact(86.0), 4)
            .column(Column::exact(92.0))
            .column(Column::exact(70.0))
            .header(20.0, |mut h| {
                for (t, tip) in [
                    ("Program", "Right-click a name to rename it"),
                    ("Upload", "Sent in the last second"),
                    ("Download", "Received in the last second"),
                    ("Sent", "Since this window opened"),
                    ("Received", "Since this window opened"),
                    ("Kind", "App, background program, Windows service, VPN or Windows itself"),
                    ("", ""),
                ] {
                    h.col(|ui| {
                        let r = ui.strong(t);
                        if !tip.is_empty() {
                            r.on_hover_text(tip);
                        }
                    });
                }
            })
            .body(|body| {
                body.rows(22.0, shown.len() + 1, |mut row| {
                    let i = row.index();
                    let Some(r) = shown.get(i) else {
                        // What the adapters carried that no program accounts for.
                        row.col(|ui| {
                            ui.weak("Not from a program: headers, ping, ARP…").on_hover_text("Wi-Fi/Ethernet adapter total minus every program above. Mostly TCP/IP packet headers.");
                        });
                        rate(&mut row, self.other.0);
                        rate(&mut row, self.other.1);
                        return;
                    };
                    let sel = self.selected.as_deref() == Some(&*r.key);
                    row.col(|ui| {
                        if self.name_button(ui, &r.key, &r.name, sel).clicked() {
                            clicked = Some(r.key.clone());
                        }
                    });
                    rate(&mut row, r.up_s);
                    rate(&mut row, r.down_s);
                    bytes(&mut row, r.up);
                    bytes(&mut row, r.down);
                    row.col(|ui| {
                        let (t, tip) = r.kind.label();
                        let l = if r.kind == Kind::App { ui.label(t) } else { ui.weak(t) };
                        l.on_hover_text(tip);
                    });
                    row.col(|ui| self.block_button(ui, &r.key));
                });
            });
        self.rows = rows;
        if let Some(k) = clicked {
            self.selected = if self.selected.as_ref() == Some(&k) { None } else { Some(k) };
        }
    }

    fn connections(&mut self, ui: &mut egui::Ui, key: &Arc<str>) {
        let name = self.name(key);
        let (mut conns, mut pids): (Vec<_>, Vec<u32>) = {
            let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            match live.apps.get(key) {
                Some(a) => (a.conns.iter().map(|((h, p, pr), c)| (h.clone(), *p, *pr, c.up, c.down, c.last_ms)).collect(), a.pids.iter().copied().collect()),
                None => (Vec::new(), Vec::new()),
            }
        };
        conns.sort_by_key(|c| std::cmp::Reverse(c.5));
        pids.sort_unstable();
        ui.add_space(14.0); // clear of the panel's drag-to-resize edge (egui grabs 5 px around it)
        ui.horizontal(|ui| {
            if ui.button("Close").on_hover_text("Hide these connections (or press Esc, or click the program again)").clicked() {
                self.selected = None;
            }
            ui.strong(&name);
            ui.weak(format!("{} connections · process {}", conns.len(), pids.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")));
        });
        ui.weak(key.split('|').next().unwrap_or(key));
        let table_h = (ui.available_height() - 20.0).max(40.0);
        TableBuilder::new(ui)
            .id_salt("conns")
            .striped(true)
            .auto_shrink(false)
            // Fit the panel: egui's default minimum of 200 points made the panel grow on its 2nd
            // frame, so it jumped 43 points as it opened and a click in that moment missed.
            .min_scrolled_height(0.0)
            .max_scroll_height(table_h)
            .column(Column::remainder().at_least(200.0).clip(true))
            .column(Column::exact(90.0))
            .columns(Column::exact(86.0), 2)
            .column(Column::exact(80.0))
            .header(20.0, |mut h| {
                for t in ["Site or address", "Port", "Sent", "Received", "Last seen"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, conns.len(), |mut row| {
                    let c = &conns[row.index()];
                    row.col(|ui| {
                        ui.label(&*c.0);
                    });
                    row.col(|ui| {
                        ui.monospace(port(c.1, c.2));
                    });
                    bytes(&mut row, c.3);
                    bytes(&mut row, c.4);
                    row.col(|ui| {
                        ui.monospace(clock(c.5 / 1000));
                    });
                });
            });
    }

    // ---- Live feed -------------------------------------------------------------------------

    fn tab_feed(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if filter_box(ui, &mut self.feed_filter, "feed_filter", "program, site or IP").changed() {
                self.feed_dirty = true;
            }
            if ui.checkbox(&mut self.feed_small, "Only small (1 KB or less)").changed() {
                self.feed_dirty = true;
            }
            let label = if self.feed_paused { "Resume" } else { "Pause" };
            if ui.button(label).on_hover_text("Freeze the list to read it").clicked() {
                self.feed_paused = !self.feed_paused;
                self.tick = Instant::now() - Duration::from_secs(2); // resume shows new lines at once
            }
        });
        if self.feed_dirty {
            self.feed_dirty = false;
            let f = self.feed_filter.to_lowercase();
            let raw = std::mem::take(&mut self.feed_raw);
            let mut shown = Vec::with_capacity(raw.len());
            for r in raw.iter().rev() {
                // newest first
                let name = self.name(&r.app);
                let hit = f.is_empty() || name.to_lowercase().contains(&f) || r.host.to_lowercase().contains(&f) || r.app.to_lowercase().contains(&f);
                if hit && (!self.feed_small || r.bytes <= 1024) {
                    shown.push((r.clone(), name));
                }
            }
            self.feed_raw = raw;
            self.feed = shown;
        }
        ui.weak(format!(
            "{} line{}, newest first{}. Bursts to the same place within a second are one line.",
            self.feed.len(),
            if self.feed.len() == 1 { "" } else { "s" },
            if self.feed_paused { " (paused)" } else { "" }
        ));
        let feed = &self.feed;
        TableBuilder::new(ui)
            .id_salt("feed")
            .striped(true)
            .auto_shrink(false)
            .max_scroll_height(f32::INFINITY)
            .column(Column::exact(96.0))
            .column(Column::initial(240.0).clip(true))
            .column(Column::exact(70.0))
            .column(Column::exact(86.0))
            .column(Column::exact(60.0))
            .column(Column::remainder().clip(true))
            .header(20.0, |mut h| {
                for t in ["Time", "Program", "Direction", "Bytes", "Packets", "Site or address"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, feed.len(), |mut row| {
                    let (r, name) = &feed[row.index()];
                    row.col(|ui| {
                        ui.monospace(clock_ms(r.ms));
                    });
                    row.col(|ui| {
                        ui.label(name).on_hover_text(&*r.app);
                    });
                    row.col(|ui| {
                        match r.dir {
                            Dir::Up => ui.colored_label(up_color(ui), "sent"),
                            Dir::Down => ui.label("received"),
                        };
                    });
                    bytes(&mut row, r.bytes);
                    row.col(|ui| {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| ui.monospace(r.packets.to_string()));
                    });
                    row.col(|ui| {
                        ui.label(format!("{}  {}", r.host, port(r.port, r.proto)));
                    });
                });
            });
    }

    // ---- History ---------------------------------------------------------------------------

    fn tab_history(&mut self, ui: &mut egui::Ui) {
        let days = report::last_7_days();
        let shown_date = &days[self.day_idx];
        // Midnight shifts every tab by a day, so a loaded report can belong to another date.
        let wrong_date = matches!(&self.day, Some(Ok(d)) if &d.date != shown_date);
        let today_old = self.day_idx == 0 && self.loaded_at.elapsed() > Duration::from_secs(30);
        let mut reload = self.day.is_none() || wrong_date || today_old;
        ui.horizontal(|ui| {
            for (i, d) in days.iter().enumerate() {
                if ui.selectable_label(self.day_idx == i, day_label(i, d)).on_hover_text(d.as_str()).clicked() && self.day_idx != i {
                    self.day_idx = i;
                    self.day = None;
                    reload = true;
                }
            }
            ui.separator();
            if ui.button("Refresh").clicked() {
                reload = true;
            }
        });
        let date = days[self.day_idx].clone();
        if reload && self.loading.as_deref() != Some(date.as_str()) {
            self.loading = Some(date.clone());
            self.loaded_at = Instant::now(); // a failed load retries in 30 s, not every frame
            let ctx = ui.ctx().clone();
            self.spawn(Some(&ctx), move |b| vec![Msg::Day(date.clone(), (b.load_day)(&date))]);
        }
        let day = match self.day.take() {
            None => {
                ui.add_space(20.0);
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Loading…");
                });
                return;
            }
            Some(Err(e)) => {
                ui.add_space(20.0);
                ui.colored_label(ui.visuals().error_fg_color, &e);
                self.day = Some(Err(e));
                return;
            }
            Some(Ok(d)) => d,
        };
        self.history_body(ui, &day);
        if self.day.is_none() {
            self.day = Some(Ok(day));
        }
    }

    fn history_body(&mut self, ui: &mut egui::Ui, day: &Day) {
        match day.recorder_last_write.map(|t| chrono::Utc::now().timestamp() - t) {
            Some(ago) if ago > 120 => {
                ui.colored_label(ui.visuals().warn_fg_color, format!("The recorder last saved {} ago. Is it still running? Reinstalling restarts it.", ago_text(ago)));
            }
            None => {
                ui.colored_label(ui.visuals().warn_fg_color, "The recorder hasn't saved anything yet. Install NetStop to start it (netstop install, as admin).");
            }
            _ => {}
        }
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("Total {}", human(day.up + day.down))).strong().size(16.0));
            ui.label(RichText::new(format!("Sent {}", human(day.up))).monospace());
            ui.label(RichText::new(format!("Received {}", human(day.down))).monospace());
            if day.apps.iter().any(|a| a.tunnel) {
                ui.weak("VPN traffic not counted twice").on_hover_text("A VPN carries the other programs' traffic, so its own rows are listed but not added to the totals");
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Export CSV").on_hover_text("Every connection of this day, saved to your Downloads folder").clicked() {
                    self.status = match export_csv(day) {
                        Ok(p) => format!("Saved {p}"),
                        Err(e) => format!("Export failed: {e}"),
                    };
                }
            });
        });
        hours_strip(ui, &day.hours);
        ui.add_space(4.0);

        let night_n = day.night.iter().filter(|a| a.up + a.down > 0).count();
        ui.horizontal(|ui| {
            for (v, label) in [
                (View::Programs, format!("Programs ({})", day.apps.len())),
                (View::Sites, format!("Sites ({})", day.hosts.len())),
                (View::Connections, format!("Connections ({})", day.conns_total)),
                (View::Night, format!("00:00 to 06:00 ({night_n})")),
            ] {
                ui.selectable_value(&mut self.view, v, label);
            }
            ui.separator();
            filter_box(ui, &mut self.hist_filter, "hist_filter", "program, site or IP");
            if day.has_history {
                let new_apps = day.apps.iter().filter(|a| a.is_new).count();
                if new_apps + day.new_hosts > 0 {
                    ui.weak(format!("New this week: {new_apps} programs, {} sites", day.new_hosts)).on_hover_text("Not seen on any earlier day in the last 7");
                }
            }
        });
        if self.view == View::Connections && (day.conns.len() as u64) < day.conns_total {
            ui.weak(format!("Showing the {} biggest of {} connections.", day.conns.len(), day.conns_total));
        }

        let idx = self.view_rows(day);
        let v = self.view as usize;
        let mut sort = self.sorts[v];
        match self.view {
            View::Programs => self.app_table(ui, "r_apps", &day.apps, &idx, &mut sort, day.has_history),
            View::Night => self.app_table(ui, "r_night", &day.night, &idx, &mut sort, day.has_history),
            View::Sites => site_table(ui, &day.hosts, &idx, &mut sort, day.has_history),
            View::Connections => self.conn_table(ui, &day.conns, &idx, &mut sort),
        }
        if sort != self.sorts[v] {
            self.sorts[v] = sort;
        }
    }

    /// Filtered + sorted row indices for the current view, cached until something changes.
    fn view_rows(&mut self, day: &Day) -> Vec<usize> {
        let key = (self.day_gen, self.view, self.hist_filter.to_lowercase(), self.sorts[self.view as usize]);
        if let Some((k, rows)) = &self.view_rows
            && *k == key
        {
            return rows.clone();
        }
        let f = &key.2;
        let has = |s: &str| f.is_empty() || s.to_lowercase().contains(f.as_str());
        let sort = key.3;
        let rows: Vec<usize> = match self.view {
            View::Programs | View::Night => {
                let list = if self.view == View::Night { &day.night } else { &day.apps };
                let mut v: Vec<usize> = (0..list.len()).filter(|&i| (self.view != View::Night || list[i].up + list[i].down > 0) && (has(&list[i].name) || has(&list[i].app))).collect();
                sorted(&mut v, sort, |&a, &b, c| cmp_app(&list[a], &list[b], c));
                v
            }
            View::Sites => {
                let mut v: Vec<usize> = (0..day.hosts.len()).filter(|&i| has(&day.hosts[i].host)).collect();
                sorted(&mut v, sort, |&a, &b, c| cmp_host(&day.hosts[a], &day.hosts[b], c));
                v
            }
            View::Connections => {
                let mut v: Vec<usize> = (0..day.conns.len()).filter(|&i| has(&day.conns[i].name) || has(&day.conns[i].app) || has(&day.conns[i].host)).collect();
                sorted(&mut v, sort, |&a, &b, c| cmp_conn(&day.conns[a], &day.conns[b], c));
                v
            }
        };
        self.view_rows = Some((key, rows.clone()));
        rows
    }

    fn app_table(&mut self, ui: &mut egui::Ui, id: &str, apps: &[AppRow], idx: &[usize], sort: &mut Sort, has_history: bool) {
        if idx.is_empty() {
            ui.weak(if apps.is_empty() { "Nothing recorded." } else { "Nothing matches the filter." });
            return;
        }
        TableBuilder::new(ui)
            .id_salt(id)
            .striped(true)
            .auto_shrink(false)
            .max_scroll_height(f32::INFINITY)
            .column(Column::remainder().at_least(220.0).clip(true))
            .columns(Column::exact(86.0), 2)
            .column(Column::exact(50.0))
            .column(Column::exact(110.0))
            .column(Column::exact(44.0))
            .column(Column::exact(70.0))
            .header(20.0, |mut h| {
                for (i, t) in ["Program", "Sent", "Received", "Sites", "Active"].into_iter().enumerate() {
                    h.col(|ui| sort_header(ui, t, i, i == 0, sort));
                }
                h.col(|_| {});
                h.col(|_| {});
            })
            .body(|body| {
                body.rows(22.0, idx.len(), |mut row| {
                    let a = &apps[idx[row.index()]];
                    let name = self.report_name(&a.app, &a.name).to_string();
                    row.col(|ui| {
                        self.name_button(ui, &a.app, &name, false);
                    });
                    bytes(&mut row, a.up);
                    bytes(&mut row, a.down);
                    row.col(|ui| {
                        ui.monospace(a.hosts.to_string());
                    });
                    row.col(|ui| {
                        ui.monospace(format!("{}–{}", clock(a.first), clock(a.last + 59)));
                    });
                    row.col(|ui| {
                        if a.tunnel {
                            ui.weak("VPN").on_hover_text(Kind::Vpn.label().1);
                        } else if a.is_new && has_history {
                            ui.label("new").on_hover_text("Not seen on any earlier day in the last 7");
                        }
                    });
                    row.col(|ui| self.block_button(ui, &a.app));
                });
            });
    }

    fn conn_table(&self, ui: &mut egui::Ui, conns: &[ConnRow], idx: &[usize], sort: &mut Sort) {
        if idx.is_empty() {
            ui.weak(if conns.is_empty() { "Nothing recorded." } else { "Nothing matches the filter." });
            return;
        }
        let renames = &self.renames;
        TableBuilder::new(ui)
            .id_salt("r_conns")
            .striped(true)
            .auto_shrink(false)
            .max_scroll_height(f32::INFINITY)
            .column(Column::initial(200.0).clip(true))
            .column(Column::remainder().at_least(200.0).clip(true))
            .column(Column::exact(80.0))
            .columns(Column::exact(86.0), 2)
            .column(Column::exact(110.0))
            .header(20.0, |mut h| {
                for (i, t) in ["Program", "Site or address", "Port", "Sent", "Received", "Active"].into_iter().enumerate() {
                    h.col(|ui| sort_header(ui, t, i, i < 2, sort));
                }
            })
            .body(|body| {
                body.rows(20.0, idx.len(), |mut row| {
                    let c = &conns[idx[row.index()]];
                    row.col(|ui| {
                        ui.label(renames.get(&c.app).unwrap_or(&c.name)).on_hover_text(&c.app);
                    });
                    row.col(|ui| {
                        ui.label(&c.host);
                    });
                    row.col(|ui| {
                        ui.monospace(format!("{} {}", c.port, c.proto));
                    });
                    bytes(&mut row, c.up);
                    bytes(&mut row, c.down);
                    row.col(|ui| {
                        ui.monospace(format!("{}–{}", clock(c.first), clock(c.last + 59)));
                    });
                });
            });
    }

    // ---- Blocked ---------------------------------------------------------------------------

    fn tab_blocked(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("Refresh").clicked() {
                self.refresh_rules(Some(ui.ctx()));
            }
            ui.weak("These are Windows Firewall rules named \"NetStop block: …\". Removing one in Windows Firewall unblocks it here too.");
        });
        if let Some(e) = &self.fw_error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
        // Rule names are "NetStop block: <path>" or "...: <svchost path>|<one service>".
        let mut list: Vec<String> = self.fw_rules.iter().filter_map(|r| r.strip_prefix("NetStop block: ").map(str::to_string)).collect();
        list.sort_by_cached_key(|k| k.to_lowercase());
        if list.is_empty() {
            ui.add_space(12.0);
            ui.label("Nothing is blocked. Use Block next to a program in Now or History.");
            return;
        }
        let names: Vec<String> = list.iter().map(|k| self.name(&Arc::from(k.as_str()))).collect();
        TableBuilder::new(ui)
            .id_salt("blocked")
            .striped(true)
            .auto_shrink(false)
            .max_scroll_height(f32::INFINITY)
            .column(Column::exact(80.0))
            .column(Column::initial(260.0).clip(true))
            .column(Column::remainder().clip(true))
            .header(20.0, |mut h| {
                for t in ["", "Program", "Path"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(22.0, list.len(), |mut row| {
                    let i = row.index();
                    row.col(|ui| self.block_button(ui, &list[i]));
                    row.col(|ui| {
                        ui.label(&names[i]);
                    });
                    row.col(|ui| {
                        ui.weak(&list[i]);
                    });
                });
            });
    }

    // ---- rename dialog ---------------------------------------------------------------------

    fn rename_window(&mut self, ctx: &egui::Context) {
        let Some((key, mut text)) = self.renaming.take() else { return };
        let (mut open, mut save) = (true, false);
        egui::Window::new("Rename").collapsible(false).resizable(false).open(&mut open).show(ctx, |ui| {
            ui.weak(&key);
            let label = ui.label("Name");
            let r = ui.text_edit_singleline(&mut text).labelled_by(label.id);
            r.request_focus();
            ui.horizontal(|ui| {
                if ui.button("Save").clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    save = true;
                }
                if ui.button("Use default name").clicked() {
                    text.clear();
                    save = true;
                }
            });
        });
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            return;
        }
        if save {
            let name = text.trim().chars().take(200).collect::<String>();
            if name.is_empty() {
                self.renames.remove(&key);
            } else {
                self.renames.insert(key.clone(), name.clone());
            }
            self.labels.remove(&*key);
            self.tick = Instant::now() - Duration::from_secs(2); // show it in Now at once
            self.view_rows = None;
            self.spawn(Some(ctx), move |b| vec![Msg::Saved((b.save_name)(&key, &name))]);
        } else if open {
            self.renaming = Some((key, text));
        }
    }

    /// One frame. Separate from eframe so tests can drive it without a window.
    pub fn show(&mut self, ui: &mut egui::Ui) {
        self.poll();
        self.every_second();
        egui::Panel::top("tabs").show(ui, |ui| {
            ui.horizontal(|ui| {
                for (t, label) in [(Tab::Now, "Now"), (Tab::Feed, "Live feed"), (Tab::History, "History"), (Tab::Blocked, "Blocked")] {
                    ui.selectable_value(&mut self.tab, t, label);
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(RichText::new(format!("Down {}/s", human(self.rate.1))).monospace().strong()).on_hover_text("Everything this PC is receiving right now");
                    ui.label(RichText::new(format!("Up {}/s", human(self.rate.0))).monospace().strong().color(up_color(ui))).on_hover_text("Everything this PC is sending right now");
                });
            });
        });
        egui::Panel::bottom("status").show(ui, |ui| {
            ui.horizontal(|ui| {
                match &self.capture_error {
                    Some(e) => ui.colored_label(ui.visuals().error_fg_color, e),
                    None => ui.weak("Live capture on"),
                };
                if let Some(e) = &self.fw_error {
                    ui.separator();
                    ui.colored_label(ui.visuals().warn_fg_color, e);
                }
                ui.separator();
                ui.label(&self.status);
            });
        });
        if self.selected.is_some() && self.renaming.is_none() && !ui.ctx().egui_wants_keyboard_input() && ui.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.selected = None;
        }
        // Before the central panel, so the program table ends where the connections begin.
        if let (Tab::Now, Some(key)) = (self.tab, self.selected.clone()) {
            egui::Panel::bottom("detail").resizable(true).default_size(240.0).min_size(120.0).show(ui, |ui| self.connections(ui, &key));
        }
        egui::CentralPanel::default().show(ui, |ui| match self.tab {
            Tab::Now => self.tab_now(ui),
            Tab::Feed => self.tab_feed(ui),
            Tab::History => self.tab_history(ui),
            Tab::Blocked => self.tab_blocked(ui),
        });
        let ctx = ui.ctx().clone();
        self.rename_window(&ctx);
        ctx.request_repaint_after(Duration::from_millis(1000));
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.show(ui);
    }
}

// ---- small helpers ------------------------------------------------------------------------

fn filter_box(ui: &mut egui::Ui, text: &mut String, id: &str, hint: &str) -> egui::Response {
    let label = ui.label("Filter");
    let r = ui.add(egui::TextEdit::singleline(text).id_salt(id).hint_text(hint).desired_width(220.0)).labelled_by(label.id);
    if !text.is_empty() && ui.small_button("×").on_hover_text("Clear the filter").clicked() {
        text.clear();
        let mut r = r;
        r.mark_changed();
        return r;
    }
    r
}

fn sort_header(ui: &mut egui::Ui, label: &str, col: usize, text: bool, sort: &mut Sort) {
    let r = ui.add(egui::Button::new(RichText::new(label).strong()).frame(false)).on_hover_text("Sort by this column");
    match *sort {
        // The arrows exist only in egui's monospace font.
        Some((c, d)) if c == col => drop(ui.monospace(if d { "↓" } else { "↑" })),
        _ => {}
    }
    if r.clicked() {
        // Text columns start A to Z, number columns biggest first; the 2nd click flips, the 3rd
        // restores the report's order (biggest total first).
        *sort = match *sort {
            Some((c, d)) if c == col && d != text => Some((col, !d)),
            Some((c, _)) if c == col => None,
            _ => Some((col, !text)),
        };
    }
}

fn sorted<T>(v: &mut [T], sort: Sort, cmp: impl Fn(&T, &T, usize) -> Ordering) {
    if let Some((col, desc)) = sort {
        v.sort_by(|a, b| if desc { cmp(b, a, col) } else { cmp(a, b, col) });
    }
}

fn text_cmp(a: &str, b: &str) -> Ordering {
    a.to_lowercase().cmp(&b.to_lowercase())
}

fn cmp_app(a: &AppRow, b: &AppRow, col: usize) -> Ordering {
    match col {
        0 => text_cmp(&a.name, &b.name),
        1 => a.up.cmp(&b.up),
        2 => a.down.cmp(&b.down),
        3 => a.hosts.cmp(&b.hosts),
        _ => a.first.cmp(&b.first),
    }
}

fn cmp_host(a: &HostRow, b: &HostRow, col: usize) -> Ordering {
    match col {
        0 => text_cmp(&a.host, &b.host),
        1 => a.up.cmp(&b.up),
        2 => a.down.cmp(&b.down),
        _ => a.apps.cmp(&b.apps),
    }
}

fn cmp_conn(a: &ConnRow, b: &ConnRow, col: usize) -> Ordering {
    match col {
        0 => text_cmp(&a.name, &b.name),
        1 => text_cmp(&a.host, &b.host),
        2 => a.port.cmp(&b.port),
        3 => a.up.cmp(&b.up),
        4 => a.down.cmp(&b.down),
        _ => a.first.cmp(&b.first),
    }
}

fn site_table(ui: &mut egui::Ui, hosts: &[HostRow], idx: &[usize], sort: &mut Sort, has_history: bool) {
    if idx.is_empty() {
        ui.weak(if hosts.is_empty() { "Nothing recorded." } else { "Nothing matches the filter." });
        return;
    }
    TableBuilder::new(ui)
        .id_salt("r_hosts")
        .striped(true)
        .auto_shrink(false)
        .max_scroll_height(f32::INFINITY)
        .column(Column::remainder().at_least(240.0).clip(true))
        .columns(Column::exact(86.0), 2)
        .column(Column::exact(76.0))
        .column(Column::exact(50.0))
        .header(20.0, |mut h| {
            for (i, t) in ["Site or address", "Sent", "Received", "Programs"].into_iter().enumerate() {
                h.col(|ui| sort_header(ui, t, i, i == 0, sort));
            }
            h.col(|_| {});
        })
        .body(|body| {
            body.rows(20.0, idx.len(), |mut row| {
                let h = &hosts[idx[row.index()]];
                row.col(|ui| {
                    ui.label(&h.host);
                });
                bytes(&mut row, h.up);
                bytes(&mut row, h.down);
                row.col(|ui| {
                    ui.monospace(h.apps.to_string());
                });
                row.col(|ui| {
                    if h.is_new && has_history {
                        ui.label("new").on_hover_text("Not seen on any earlier day in the last 7");
                    }
                });
            });
        });
}

fn up_color(ui: &egui::Ui) -> Color32 {
    if ui.visuals().dark_mode { Color32::from_rgb(255, 170, 90) } else { Color32::from_rgb(170, 80, 0) }
}

fn bytes(row: &mut egui_extras::TableRow<'_, '_>, v: u64) {
    row.col(|ui| {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| ui.monospace(human(v)));
    });
}

/// A per-second figure: "–" when idle, so busy rows stand out.
fn rate(row: &mut egui_extras::TableRow<'_, '_>, v: u64) {
    row.col(|ui| {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| if v == 0 { ui.weak("–") } else { ui.monospace(format!("{}/s", human(v))) });
    });
}

fn port(port: u16, proto: u8) -> String {
    format!("{port} {}", if proto == 17 { "UDP" } else { "TCP" })
}

fn day_label(i: usize, date: &str) -> String {
    match i {
        0 => "Today".into(),
        1 => "Yesterday".into(),
        _ => chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").map(|d| d.format("%a %-d %b").to_string()).unwrap_or_else(|_| date.to_string()),
    }
}

fn ago_text(secs: i64) -> String {
    match secs {
        ..120 => format!("{secs} s"),
        120..7200 => format!("{} min", secs / 60),
        7200..172_800 => format!("{} hours", secs / 3600),
        _ => format!("{} days", secs / 86_400),
    }
}

fn clock(unix: i64) -> String {
    use chrono::TimeZone;
    chrono::Local.timestamp_opt(unix, 0).single().map(|t| t.format("%H:%M").to_string()).unwrap_or_default()
}

fn clock_ms(ms: i64) -> String {
    use chrono::TimeZone;
    chrono::Local.timestamp_millis_opt(ms).single().map(|t| t.format("%H:%M:%S%.3f").to_string()).unwrap_or_default()
}

fn hours_strip(ui: &mut egui::Ui, hours: &[[u64; 2]]) {
    let max = hours.iter().map(|h| h[0] + h[1]).max().unwrap_or(0).max(1) as f32;
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 72.0), Sense::hover());
    let p = ui.painter_at(rect);
    let w = rect.width() / 24.0;
    p.hline(rect.x_range(), rect.bottom() - 13.0, ui.visuals().widgets.noninteractive.bg_stroke);
    let (down_c, up_c) = (ui.visuals().selection.bg_fill, up_color(ui));
    for (i, h) in hours.iter().enumerate() {
        let x = rect.left() + i as f32 * w;
        let col = egui::Rect::from_min_max(egui::pos2(x + 1.0, rect.top()), egui::pos2(x + w - 1.0, rect.bottom() - 13.0));
        let hd = col.height() * h[1] as f32 / max;
        let hu = col.height() * h[0] as f32 / max;
        p.rect_filled(egui::Rect::from_min_max(egui::pos2(col.left(), col.bottom() - hd), col.max), 0.0, down_c);
        p.rect_filled(egui::Rect::from_min_max(egui::pos2(col.left(), col.bottom() - hd - hu), egui::pos2(col.right(), col.bottom() - hd)), 0.0, up_c);
        if i % 6 == 0 {
            p.text(egui::pos2(x + 1.0, rect.bottom()), egui::Align2::LEFT_BOTTOM, format!("{i:02}:00"), egui::FontId::monospace(10.0), ui.visuals().weak_text_color());
        }
    }
    if let Some(pos) = resp.hover_pos() {
        let i = (((pos.x - rect.left()) / w) as usize).min(23);
        resp.on_hover_text(format!("{i:02}:00–{i:02}:59  sent {}  received {}", human(hours[i][0]), human(hours[i][1])));
    }
}

/// Spreadsheet-safe CSV: quoted fields, and a leading ' on anything a spreadsheet would run as a formula.
fn csv_field(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{s}") } else { s.to_string() };
    format!("\"{}\"", s.replace('"', "\"\""))
}

fn csv(day: &Day) -> String {
    let mut out = String::from("program,path,site,port,protocol,sent_bytes,received_bytes,first_minute,last_minute\n");
    for c in &day.conns {
        let row = [csv_field(&c.name), csv_field(&c.app), csv_field(&c.host), c.port.to_string(), c.proto.to_string(), c.up.to_string(), c.down.to_string(), clock(c.first), clock(c.last)];
        out.push_str(&row.join(","));
        out.push('\n');
    }
    out
}

fn export_csv(day: &Day) -> Result<String, String> {
    let path = crate::winutil::downloads().join(format!("netstop-{}.csv", day.date));
    std::fs::write(&path, csv(day)).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

const DEFAULT_SIZE: egui::Vec2 = egui::vec2(1040.0, 620.0);
const MIN_SIZE: egui::Vec2 = egui::vec2(760.0, 420.0);
const TITLE_BAR: f32 = 32.0;

/// The default size, shrunk to fit the screen above the taskbar and centred there. Windows' own
/// placement (and egui's "centered", which uses the whole monitor) left the status bar under the
/// taskbar on a 1080p screen at 150% scaling.
fn initial_window(work: Option<[f32; 4]>) -> (Option<egui::Pos2>, egui::Vec2) {
    let Some([x, y, w, h]) = work else { return (None, DEFAULT_SIZE) };
    let size = egui::vec2(DEFAULT_SIZE.x.min(w - 24.0), DEFAULT_SIZE.y.min(h - TITLE_BAR - 24.0)).max(MIN_SIZE);
    let pos = egui::pos2(x + ((w - size.x) / 2.0).max(0.0), y + ((h - size.y - TITLE_BAR) / 2.0).max(0.0));
    (Some(pos), size)
}

pub fn run() -> Result<(), String> {
    // One window per logon session (they would fight over the live-capture session name). Local\,
    // not Global\: other accounts can create Global\ names first and keep the window from opening.
    let Some(_one) = crate::winutil::single_instance(r"Local\NetStopWindow") else {
        return Err("NetStop is already open.".into());
    };
    let live: Arc<Mutex<Live>> = Arc::default();
    let l = live.clone();
    let sink: crate::capture::Sink = Arc::new(move |e| l.lock().unwrap_or_else(|e| e.into_inner()).add(e));
    let (trace, capture_error) = match crate::capture::start(&format!("NetStop-Live-{}", crate::winutil::session_id()), sink) {
        Ok(t) => (Some(t), None),
        Err(e) => (None, Some(format!("Live capture failed to start: {e}"))),
    };
    let renames = crate::db::open_ro().map(|c| crate::db::names(&c)).unwrap_or_default();
    let (pos, size) = initial_window(crate::winutil::work_area_points());
    let mut viewport = egui::ViewportBuilder::default().with_title("NetStop").with_inner_size(size).with_min_inner_size(MIN_SIZE);
    if let Some(p) = pos {
        viewport = viewport.with_position(p);
    }
    let opts = eframe::NativeOptions { viewport, ..Default::default() };
    let r = eframe::run_native("NetStop", opts, Box::new(|_| Ok(Box::new(App::new(Backend::real(), live, capture_error, renames))))).map_err(|e| e.to_string());
    drop(trace); // stop the live capture session before the process exits
    r
}

#[cfg(test)]
#[path = "gui_tests.rs"]
mod tests;
