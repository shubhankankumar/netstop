//! The window. Runs its own live capture (separate from the recorder) and reads the
//! 7-day store for reports. Redraws once a second unless you interact.

use crate::capture::{self, Dir, Event};
use crate::report::{self, Day, human};
use eframe::egui::{self, Align, Color32, Layout, RichText, Sense};
use egui_extras::{Column, TableBuilder};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const FEED_MAX: usize = 5000;

#[derive(Default)]
struct ConnLive {
    up: u64,
    down: u64,
    last_ms: i64,
}

#[derive(Default)]
struct AppLive {
    up: u64,
    down: u64,
    last_ms: i64,
    pids: HashSet<u32>,
    conns: HashMap<(Arc<str>, u16, u8), ConnLive>,
}

#[derive(Clone)]
struct FeedRow {
    ms: i64,
    app: Arc<str>,
    dir: Dir,
    bytes: u64,
    packets: u32,
    host: Arc<str>,
    port: u16,
    proto: u8,
}

#[derive(Default)]
struct Live {
    apps: HashMap<Arc<str>, AppLive>,
    feed: VecDeque<FeedRow>,
}

impl Live {
    fn add(&mut self, e: Event) {
        let host = e.host_or_ip();
        let a = self.apps.entry(e.app.clone()).or_default();
        a.pids.insert(e.pid);
        a.last_ms = e.unix_ms;
        let c = a.conns.entry((host.clone(), e.port, e.proto)).or_default();
        c.last_ms = e.unix_ms;
        match e.dir {
            Dir::Up => (a.up += e.bytes as u64, c.up += e.bytes as u64),
            Dir::Down => (a.down += e.bytes as u64, c.down += e.bytes as u64),
        };
        // Merge bursts (same program, host, direction, within 1 s) into one feed line.
        if let Some(last) = self.feed.back_mut() {
            if last.app == e.app && last.host == host && last.port == e.port && last.dir == e.dir && e.unix_ms - last.ms < 1000 {
                last.bytes += e.bytes as u64;
                last.packets += 1;
                return;
            }
        }
        if self.feed.len() >= FEED_MAX {
            self.feed.pop_front();
        }
        self.feed.push_back(FeedRow { ms: e.unix_ms, app: e.app, dir: e.dir, bytes: e.bytes as u64, packets: 1, host, port: e.port, proto: e.proto });
    }
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Now,
    Feed,
    Report,
    Blocked,
}

struct Row {
    key: Arc<str>,
    name: String,
    up_s: u64,
    down_s: u64,
    up: u64,
    down: u64,
    background: bool,
}

pub struct App {
    live: Arc<Mutex<Live>>,
    _trace: Option<ferrisetw::UserTrace>,
    capture_error: Option<String>,
    db: Option<rusqlite::Connection>,
    tab: Tab,
    // once-a-second snapshot
    tick: Instant,
    prev: HashMap<Arc<str>, (u64, u64)>,
    rows: Vec<Row>,
    adapter_prev: (u64, u64),
    other: (u64, u64),
    attributed_s: (u64, u64),
    windowed: HashSet<String>,
    labels: HashMap<Arc<str>, String>,
    renames: HashMap<String, String>,
    selected: Option<Arc<str>>,
    /// Names of NetStop's rules in Windows Firewall (the source of truth for "blocked").
    fw_rules: HashSet<String>,
    // feed
    filter: String,
    small_only: bool,
    paused: Option<Vec<FeedRow>>,
    // report
    day_idx: usize,
    day: Option<Result<Day, String>>,
    day_at: Instant,
    day_job: Option<Receiver<Result<Day, String>>>,
    // misc
    renaming: Option<(String, String)>,
    status: String,
    jobs: (Sender<BlockJob>, Receiver<BlockJob>),
}

/// (app, block?, result, firewall rules afterwards)
type BlockJob = (String, bool, Result<(), String>, Option<HashSet<String>>);

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let live: Arc<Mutex<Live>> = Arc::default();
        let l = live.clone();
        let _ = cc;
        let (trace, capture_error) = match capture::start(
            &format!("NetStop-Live-{}", crate::winutil::session_id()),
            Arc::new(move |e| {
                l.lock().unwrap_or_else(|e| e.into_inner()).add(e);
            }),
        ) {
            Ok(t) => (Some(t), None),
            Err(e) => (None, Some(format!("Live capture failed to start: {e}"))),
        };
        let db = crate::db::open_rw().ok();
        let renames = db.as_ref().map(crate::db::names).unwrap_or_default();
        let fw_rules = crate::firewall::rules().unwrap_or_default();
        App {
            live,
            _trace: trace,
            capture_error,
            db,
            tab: Tab::Now,
            tick: Instant::now() - Duration::from_secs(2),
            prev: HashMap::new(),
            rows: Vec::new(),
            adapter_prev: crate::procinfo::adapter_totals(),
            other: (0, 0),
            attributed_s: (0, 0),
            windowed: HashSet::new(),
            labels: HashMap::new(),
            renames,
            selected: None,
            fw_rules,
            filter: String::new(),
            small_only: false,
            paused: None,
            day_idx: 0,
            day: None,
            day_at: Instant::now(),
            day_job: None,
            renaming: None,
            status: String::new(),
            jobs: channel(),
        }
    }

    fn name(&mut self, key: &Arc<str>) -> String {
        if let Some(n) = self.renames.get(&**key) {
            return n.clone();
        }
        self.labels.entry(key.clone()).or_insert_with(|| crate::procinfo::label(key)).clone()
    }

    fn every_second(&mut self) {
        if self.tick.elapsed() < Duration::from_secs(1) {
            return;
        }
        let secs = self.tick.elapsed().as_secs_f64().max(1.0);
        self.tick = Instant::now();
        self.windowed = crate::procinfo::windowed_exes();
        let snap: Vec<(Arc<str>, u64, u64, bool)> = {
            let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            live.apps
                .iter()
                .map(|(k, a)| (k.clone(), a.up, a.down, k.contains('|') || !self.windowed.contains(&**k)))
                .collect()
        };
        let mut rows = Vec::with_capacity(snap.len());
        let (mut au, mut ad) = (0, 0);
        for (key, up, down, background) in snap {
            let (pu, pd) = self.prev.get(&key).copied().unwrap_or((up, down));
            let (up_s, down_s) = (((up - pu) as f64 / secs) as u64, ((down - pd) as f64 / secs) as u64);
            if !crate::names::is_tunnel(&key) {
                au += up_s; // a VPN's own traffic is the wrapped copy of the rows it carries
                ad += down_s;
            }
            self.prev.insert(key.clone(), (up, down));
            let name = self.name(&key);
            rows.push(Row { key, name, up_s, down_s, up, down, background });
        }
        // By total, not by this second's rate: rows that reshuffle every second put the wrong
        // program under the cursor when you click Block.
        rows.sort_by(|a, b| (b.up + b.down).cmp(&(a.up + a.down)).then_with(|| a.key.cmp(&b.key)));
        self.rows = rows;
        self.attributed_s = (au, ad);
        let (rx, tx) = crate::procinfo::adapter_totals();
        let (prx, ptx) = self.adapter_prev;
        self.adapter_prev = (rx, tx);
        let wire = ((tx.saturating_sub(ptx) as f64 / secs) as u64, (rx.saturating_sub(prx) as f64 / secs) as u64);
        self.other = (wire.0.saturating_sub(au), wire.1.saturating_sub(ad));

        while let Ok((app, block, res, rules)) = self.jobs.1.try_recv() {
            if let Some(r) = rules {
                self.fw_rules = r;
            }
            match res {
                Ok(()) => {
                    let n = self.name(&Arc::from(app.as_str()));
                    self.status = format!("{} {n}", if block { "Blocked" } else { "Unblocked" });
                }
                Err(e) => self.status = format!("Could not change block: {e}"),
            }
        }
    }

    fn toggle_block(&mut self, app: &str) {
        let block = !crate::firewall::is_blocked(&self.fw_rules, app);
        let tx = self.jobs.0.clone();
        let app = app.to_string();
        self.status = format!("{}…", if block { "Blocking" } else { "Unblocking" });
        std::thread::spawn(move || {
            let r = crate::firewall::set_blocked(&app, block);
            let _ = tx.send((app, block, r, crate::firewall::rules().ok()));
        });
    }

    fn block_button(&mut self, ui: &mut egui::Ui, key: &str) {
        if !crate::firewall::blockable(key) {
            ui.weak("—").on_hover_text("Windows itself, or a program that already closed");
            return;
        }
        let blocked = crate::firewall::is_blocked(&self.fw_rules, key);
        let text = if blocked { "Unblock" } else { "Block" };
        if ui.small_button(text).on_hover_text(if blocked { "Allow internet again" } else { "Stop this program sending anything" }).clicked() {
            self.toggle_block(key);
        }
    }

    fn name_label(&mut self, ui: &mut egui::Ui, key: &Arc<str>, name: &str, selected: bool) -> egui::Response {
        let r = ui.add(egui::Button::selectable(selected, name).truncate()).on_hover_text(&**key);
        r.context_menu(|ui| {
            if ui.button("Rename…").clicked() {
                self.renaming = Some((key.to_string(), name.to_string()));
                ui.close();
            }
            if ui.button("Copy path").clicked() {
                ui.ctx().copy_text(key.split('|').next().unwrap_or(key).to_string());
                ui.close();
            }
        });
        r
    }

    fn tab_now(&mut self, ui: &mut egui::Ui) {
        let (au, ad) = self.attributed_s;
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("Up {}/s", human(au + self.other.0))).strong().monospace());
            ui.label(RichText::new(format!("Down {}/s", human(ad + self.other.1))).strong().monospace());
            ui.weak(format!("{} programs since this window opened", self.rows.len()));
        });
        ui.add_space(4.0);

        let detail_h = if self.selected.is_some() { 220.0 } else { 0.0 };
        let rows = std::mem::take(&mut self.rows);
        let avail = ui.available_height() - detail_h - 28.0;
        let mut clicked = None;
        TableBuilder::new(ui)
            .id_salt("now")
            .striped(true)
            .max_scroll_height(avail.max(120.0))
            .column(Column::remainder().at_least(220.0).clip(true))
            .columns(Column::exact(86.0), 4)
            .column(Column::exact(92.0))
            .column(Column::exact(70.0))
            .header(20.0, |mut h| {
                for t in ["Program", "Up /s", "Down /s", "Sent", "Received", "Runs as", ""] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(22.0, rows.len() + 1, |mut row| {
                    let i = row.index();
                    if i == rows.len() {
                        // The part Windows can't attribute to a program.
                        row.col(|ui| {
                            ui.weak("Headers, ping, ARP and other non-program traffic").on_hover_text(
                                "Wi-Fi/Ethernet adapter total minus everything above. Includes TCP/IP packet headers.",
                            );
                        });
                        num(&mut row, self.other.0, true);
                        num(&mut row, self.other.1, true);
                        row.col(|_| {});
                        row.col(|_| {});
                        row.col(|_| {});
                        row.col(|_| {});
                        return;
                    }
                    let r = &rows[i];
                    let sel = self.selected.as_deref() == Some(&*r.key);
                    row.col(|ui| {
                        if self.name_label(ui, &r.key, &r.name, sel).clicked() {
                            clicked = Some(r.key.clone());
                        }
                    });
                    num(&mut row, r.up_s, true);
                    num(&mut row, r.down_s, true);
                    num(&mut row, r.up, false);
                    num(&mut row, r.down, false);
                    row.col(|ui| {
                        if crate::names::is_tunnel(&r.key) {
                            ui.label("VPN tunnel").on_hover_text("Carries the other programs' traffic, so it is not added to the totals");
                        } else if r.background {
                            ui.label("Background");
                        } else {
                            ui.weak("Window");
                        }
                    });
                    row.col(|ui| self.block_button(ui, &r.key));
                });
            });
        self.rows = rows;
        if let Some(k) = clicked {
            self.selected = if self.selected.as_ref() == Some(&k) { None } else { Some(k) };
        }
        if let Some(key) = self.selected.clone() {
            ui.separator();
            self.connections(ui, &key);
        }
    }

    fn connections(&mut self, ui: &mut egui::Ui, key: &Arc<str>) {
        let name = self.name(key);
        let (mut conns, pids): (Vec<(String, u16, u8, u64, u64, i64)>, Vec<u32>) = {
            let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            match live.apps.get(key) {
                Some(a) => (
                    a.conns.iter().map(|((h, p, pr), c)| (h.to_string(), *p, *pr, c.up, c.down, c.last_ms)).collect(),
                    a.pids.iter().copied().collect(),
                ),
                None => (Vec::new(), Vec::new()),
            }
        };
        conns.sort_by(|a, b| b.5.cmp(&a.5));
        ui.horizontal(|ui| {
            ui.strong(&name);
            ui.weak(format!("PID {}", pids.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")));
            ui.weak(key.split('|').next().unwrap_or(key));
        });
        TableBuilder::new(ui)
            .id_salt("conns")
            .striped(true)
            .max_scroll_height(180.0)
            .column(Column::remainder().at_least(200.0).clip(true))
            .column(Column::exact(60.0))
            .column(Column::exact(50.0))
            .columns(Column::exact(86.0), 2)
            .column(Column::exact(80.0))
            .header(20.0, |mut h| {
                for t in ["Site / address", "Port", "Proto", "Sent", "Received", "Last"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, conns.len(), |mut row| {
                    let c = &conns[row.index()];
                    row.col(|ui| {
                        ui.label(&c.0);
                    });
                    row.col(|ui| {
                        ui.monospace(c.1.to_string());
                    });
                    row.col(|ui| {
                        ui.label(if c.2 == 17 { "UDP" } else { "TCP" });
                    });
                    num(&mut row, c.3, false);
                    num(&mut row, c.4, false);
                    row.col(|ui| {
                        ui.monospace(clock(c.5 / 1000));
                    });
                });
            });
    }

    fn tab_feed(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Filter");
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("program, site or IP").desired_width(240.0));
            ui.checkbox(&mut self.small_only, "Only small (1 KB or less)");
            let paused = self.paused.is_some();
            if ui.button(if paused { "Resume" } else { "Pause" }).clicked() {
                self.paused = if paused { None } else { Some(self.live.lock().unwrap_or_else(|e| e.into_inner()).feed.iter().cloned().collect()) };
            }
        });
        let all: Vec<FeedRow> = match &self.paused {
            Some(v) => v.clone(),
            None => self.live.lock().unwrap_or_else(|e| e.into_inner()).feed.iter().cloned().collect(),
        };
        let f = self.filter.to_lowercase();
        let mut shown = Vec::with_capacity(all.len());
        for r in all.into_iter().rev() {
            if self.small_only && r.bytes > 1024 {
                continue;
            }
            let name = self.name(&r.app);
            if !f.is_empty() && !name.to_lowercase().contains(&f) && !r.host.to_lowercase().contains(&f) && !r.app.to_lowercase().contains(&f) {
                continue;
            }
            shown.push((r, name));
        }
        ui.weak(format!("{} lines, newest first. Bursts within 1 second are merged into one line.", shown.len()));
        TableBuilder::new(ui)
            .id_salt("feed")
            .striped(true)
            .max_scroll_height(f32::INFINITY) // default cap is 800 px, leaving the bottom of the window empty
            .column(Column::exact(96.0))
            .column(Column::initial(240.0).clip(true))
            .column(Column::exact(44.0))
            .column(Column::exact(86.0))
            .column(Column::exact(60.0))
            .column(Column::remainder().clip(true))
            .header(20.0, |mut h| {
                for t in ["Time", "Program", "", "Bytes", "Packets", "Site / address"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, shown.len(), |mut row| {
                    let (r, name) = &shown[row.index()];
                    row.col(|ui| {
                        ui.monospace(clock_ms(r.ms));
                    });
                    row.col(|ui| {
                        ui.label(name).on_hover_text(&*r.app);
                    });
                    row.col(|ui| {
                        match r.dir {
                            Dir::Up => ui.colored_label(up_color(ui), "up"),
                            Dir::Down => ui.label("down"),
                        };
                    });
                    num(&mut row, r.bytes, false);
                    row.col(|ui| {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| ui.monospace(r.packets.to_string()));
                    });
                    row.col(|ui| {
                        ui.label(format!("{}:{} {}", r.host, r.port, if r.proto == 17 { "UDP" } else { "TCP" }));
                    });
                });
            });
    }

    fn tab_report(&mut self, ui: &mut egui::Ui) {
        let days = report::last_7_days();
        ui.horizontal(|ui| {
            for (i, d) in days.iter().enumerate() {
                let label = if i == 0 { "Today".to_string() } else if i == 1 { "Yesterday".to_string() } else { d.clone() };
                if ui.selectable_label(self.day_idx == i, label).clicked() && self.day_idx != i {
                    self.day_idx = i;
                    self.day = None;
                    self.day_job = None; // drop a result for the previous day
                }
            }
            if ui.button("Refresh").clicked() {
                self.day = None;
            }
        });
        if let Some(rx) = &self.day_job {
            if let Ok(d) = rx.try_recv() {
                self.day = Some(d);
                self.day_job = None;
            }
        }
        let stale = self.day.is_none() || (self.day_idx == 0 && self.day_at.elapsed() > Duration::from_secs(30));
        if stale && self.day_job.is_none() {
            // Built on a worker thread with its own read-only connection, so the window never stalls.
            let (tx, rx) = channel();
            let date = days[self.day_idx].clone();
            let ctx = ui.ctx().clone();
            std::thread::spawn(move || {
                let r = crate::db::open_ro()
                    .map_err(|_| "No history yet. Install the recorder: run `netstop install` as admin.".to_string())
                    .and_then(|c| report::day(&c, &date, 100_000));
                let _ = tx.send(r);
                ctx.request_repaint();
            });
            self.day_job = Some(rx);
            self.day_at = Instant::now();
        }
        if self.day.is_none() {
            ui.spinner();
            return;
        }
        let day = match self.day.take() {
            Some(Ok(d)) => d,
            Some(Err(e)) => {
                ui.colored_label(ui.visuals().error_fg_color, &e);
                self.day = Some(Err(e));
                return;
            }
            None => return,
        };
        self.report_body(ui, &day);
        if self.day.is_none() {
            self.day = Some(Ok(day));
        }
    }

    fn report_body(&mut self, ui: &mut egui::Ui, day: &Day) {
        if let Some(t) = day.recorder_last_write {
            let ago = chrono::Utc::now().timestamp() - t;
            if ago > 120 {
                ui.colored_label(ui.visuals().warn_fg_color, format!("Recorder last saved {} min ago. Is it installed and running? (netstop install)", ago / 60));
            }
        } else {
            ui.colored_label(ui.visuals().warn_fg_color, "The recorder hasn't saved anything yet. Run `netstop install` as admin.");
        }
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("Sent {}", human(day.up))).strong().monospace());
            ui.label(RichText::new(format!("Received {}", human(day.down))).strong().monospace());
            ui.weak(format!("{} programs, {} sites, {} connections", day.apps.len(), day.hosts.len(), day.conns_total));
            if ui.button("Export CSV").clicked() {
                self.status = match export_csv(day) {
                    Ok(p) => format!("Saved {p}"),
                    Err(e) => format!("Export failed: {e}"),
                };
            }
        });
        hours_strip(ui, &day.hours);

        egui::ScrollArea::vertical().id_salt("report").show(ui, |ui| {
            let new_apps: Vec<_> = day.apps.iter().filter(|a| a.is_new).collect();
            let new_hosts = day.hosts.iter().filter(|h| h.is_new).count();
            if day.has_history && (!new_apps.is_empty() || new_hosts > 0) {
                ui.label(format!(
                    "New this day (not seen in the days before): {} programs, {} sites",
                    new_apps.len(),
                    new_hosts
                ));
            }
            egui::CollapsingHeader::new(format!("Programs ({})", day.apps.len())).default_open(true).show(ui, |ui| {
                self.app_table(ui, "r_apps", &day.apps);
            });
            egui::CollapsingHeader::new(format!("Between midnight and 6 am ({})", day.night.len())).show(ui, |ui| {
                self.app_table(ui, "r_night", &day.night);
            });
            egui::CollapsingHeader::new(format!("Sites ({})", day.hosts.len())).show(ui, |ui| {
                TableBuilder::new(ui)
                    .id_salt("r_hosts")
                    .striped(true)
                    .max_scroll_height(360.0)
                    .column(Column::remainder().at_least(240.0).clip(true))
                    .columns(Column::exact(86.0), 2)
                    .column(Column::exact(70.0))
                    .column(Column::exact(50.0))
                    .header(20.0, |mut h| {
                        for t in ["Site / address", "Sent", "Received", "Programs", ""] {
                            h.col(|ui| {
                                ui.strong(t);
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(20.0, day.hosts.len(), |mut row| {
                            let h = &day.hosts[row.index()];
                            row.col(|ui| {
                                ui.label(&h.host);
                            });
                            num(&mut row, h.up, false);
                            num(&mut row, h.down, false);
                            row.col(|ui| {
                                ui.monospace(h.apps.to_string());
                            });
                            row.col(|ui| {
                                if h.is_new {
                                    ui.label("new");
                                }
                            });
                        });
                    });
            });
            egui::CollapsingHeader::new(format!("Every connection ({})", day.conns_total)).show(ui, |ui| {
                TableBuilder::new(ui)
                    .id_salt("r_conns")
                    .striped(true)
                    .max_scroll_height(420.0)
                    .column(Column::initial(200.0).clip(true))
                    .column(Column::remainder().at_least(200.0).clip(true))
                    .column(Column::exact(80.0))
                    .columns(Column::exact(86.0), 2)
                    .column(Column::exact(110.0))
                    .header(20.0, |mut h| {
                        for t in ["Program", "Site / address", "Port", "Sent", "Received", "Active"] {
                            h.col(|ui| {
                                ui.strong(t);
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(20.0, day.conns.len(), |mut row| {
                            let c = &day.conns[row.index()];
                            row.col(|ui| {
                                ui.label(&c.name).on_hover_text(&c.app);
                            });
                            row.col(|ui| {
                                ui.label(&c.host);
                            });
                            row.col(|ui| {
                                ui.monospace(format!("{} {}", c.port, c.proto));
                            });
                            num(&mut row, c.up, false);
                            num(&mut row, c.down, false);
                            row.col(|ui| {
                                ui.monospace(format!("{}–{}", clock(c.first), clock(c.last + 59)));
                            });
                        });
                    });
            });
        });
    }

    fn app_table(&mut self, ui: &mut egui::Ui, id: &str, apps: &[report::AppRow]) {
        let h = ui.available_height().max(360.0);
        TableBuilder::new(ui)
            .id_salt(id)
            .striped(true)
            .max_scroll_height(h)
            .column(Column::remainder().at_least(220.0).clip(true))
            .columns(Column::exact(86.0), 2)
            .column(Column::exact(50.0))
            .column(Column::exact(110.0))
            .column(Column::exact(40.0))
            .column(Column::exact(70.0))
            .header(20.0, |mut h| {
                for t in ["Program", "Sent", "Received", "Sites", "Active", "", ""] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(22.0, apps.len(), |mut row| {
                    let a = &apps[row.index()];
                    let key: Arc<str> = Arc::from(a.app.as_str());
                    let name = self.renames.get(&a.app).cloned().unwrap_or_else(|| a.name.clone());
                    row.col(|ui| {
                        self.name_label(ui, &key, &name, false);
                    });
                    num(&mut row, a.up, false);
                    num(&mut row, a.down, false);
                    row.col(|ui| {
                        ui.monospace(a.hosts.to_string());
                    });
                    row.col(|ui| {
                        ui.monospace(format!("{}–{}", clock(a.first), clock(a.last + 59)));
                    });
                    row.col(|ui| {
                        if a.tunnel {
                            ui.weak("VPN").on_hover_text("Carries the other programs' traffic, so it is not added to the totals");
                        } else if a.is_new {
                            ui.label("new").on_hover_text("Not seen on any earlier day this week");
                        }
                    });
                    row.col(|ui| self.block_button(ui, &a.app));
                });
            });
    }

    fn tab_blocked(&mut self, ui: &mut egui::Ui) {
        if ui.button("Refresh").clicked() {
            self.fw_rules = crate::firewall::rules().unwrap_or_default();
        }
        // Rule names are "NetStop block: <path>" or "...: <svchost path>|<one service>".
        let mut list: Vec<String> = self.fw_rules.iter().filter_map(|r| r.strip_prefix("NetStop block: ").map(str::to_string)).collect();
        if list.is_empty() {
            ui.label("Nothing is blocked. Use Block next to a program in Now or Last 7 days.");
            return;
        }
        ui.weak("These are Windows Firewall rules named \"NetStop block: …\". You can also remove them in Windows Firewall.");
        list.sort();
        for app in list {
            let key: Arc<str> = Arc::from(app.as_str());
            let name = self.name(&key);
            ui.horizontal(|ui| {
                self.block_button(ui, &app);
                ui.label(&name);
                ui.weak(&app);
            });
        }
    }

    fn rename_window(&mut self, ctx: &egui::Context) {
        let Some((key, mut text)) = self.renaming.take() else { return };
        let mut open = true;
        let mut done = false;
        egui::Window::new("Rename").collapsible(false).resizable(false).open(&mut open).show(ctx, |ui| {
            ui.weak(&key);
            let r = ui.text_edit_singleline(&mut text);
            r.request_focus();
            ui.horizontal(|ui| {
                if ui.button("Save").clicked() || (r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
                    done = true;
                }
                if ui.button("Use default name").clicked() {
                    text.clear();
                    done = true;
                }
            });
        });
        if done {
            if let Some(c) = &self.db {
                let _ = crate::db::set_name(c, &key, &text);
            }
            let t = text.trim().to_string();
            if t.is_empty() {
                self.renames.remove(&key);
            } else {
                self.renames.insert(key.clone(), t);
            }
            self.day = None;
            self.tick = Instant::now() - Duration::from_secs(2);
        } else if open {
            self.renaming = Some((key, text));
        }
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.every_second();
        ctx.request_repaint_after(Duration::from_millis(1000));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Panel::top("tabs").show(ui, |ui| {
            ui.horizontal(|ui| {
                for (t, label) in [(Tab::Now, "Now"), (Tab::Feed, "Live feed"), (Tab::Report, "Last 7 days"), (Tab::Blocked, "Blocked")] {
                    ui.selectable_value(&mut self.tab, t, label);
                }
            });
        });
        egui::Panel::bottom("status").show(ui, |ui| {
            ui.horizontal(|ui| {
                if let Some(e) = &self.capture_error {
                    ui.colored_label(ui.visuals().error_fg_color, e);
                } else {
                    ui.weak("Live capture on");
                }
                ui.separator();
                ui.label(&self.status);
            });
        });
        egui::CentralPanel::default().show(ui, |ui| match self.tab {
            Tab::Now => self.tab_now(ui),
            Tab::Feed => self.tab_feed(ui),
            Tab::Report => self.tab_report(ui),
            Tab::Blocked => self.tab_blocked(ui),
        });
        let ctx = ui.ctx().clone();
        self.rename_window(&ctx);
    }
}

fn up_color(ui: &egui::Ui) -> Color32 {
    if ui.visuals().dark_mode { Color32::from_rgb(255, 170, 90) } else { Color32::from_rgb(170, 80, 0) }
}

fn num(row: &mut egui_extras::TableRow<'_, '_>, v: u64, rate: bool) {
    row.col(|ui| {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if v == 0 && rate {
                ui.weak("0");
            } else {
                ui.monospace(human(v));
            }
        });
    });
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
    let axis = ui.visuals().widgets.noninteractive.bg_stroke;
    p.hline(rect.x_range(), rect.bottom() - 12.0, axis);
    let down_c = ui.visuals().selection.bg_fill;
    let up_c = up_color(ui);
    for (i, h) in hours.iter().enumerate() {
        let x = rect.left() + i as f32 * w;
        let col = egui::Rect::from_min_max(egui::pos2(x + 1.0, rect.top()), egui::pos2(x + w - 1.0, rect.bottom() - 12.0));
        let hd = col.height() * h[1] as f32 / max;
        let hu = col.height() * h[0] as f32 / max;
        p.rect_filled(egui::Rect::from_min_max(egui::pos2(col.left(), col.bottom() - hd), col.max), 0.0, down_c);
        p.rect_filled(egui::Rect::from_min_max(egui::pos2(col.left(), col.bottom() - hd - hu), egui::pos2(col.right(), col.bottom() - hd)), 0.0, up_c);
        if i % 6 == 0 {
            p.text(egui::pos2(x + 1.0, rect.bottom()), egui::Align2::LEFT_BOTTOM, format!("{i:02}"), egui::FontId::monospace(10.0), ui.visuals().weak_text_color());
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

fn export_csv(day: &Day) -> Result<String, String> {
    let mut out = String::from("program,path,site,port,protocol,sent_bytes,received_bytes,first_minute,last_minute\n");
    for c in &day.conns {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{}\n",
            csv_field(&c.name),
            csv_field(&c.app),
            csv_field(&c.host),
            c.port,
            c.proto,
            c.up,
            c.down,
            clock(c.first),
            clock(c.last)
        ));
    }
    let path = crate::winutil::downloads().join(format!("netstop-{}.csv", day.date));
    std::fs::write(&path, out).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

pub fn run() -> Result<(), String> {
    // One window per logon session (they would fight over the live-capture session name). Local\,
    // not Global\: other accounts can create Global\ names first and keep the window from opening.
    let Some(_one) = crate::winutil::single_instance(r"Local\NetStopWindow") else {
        return Err("NetStop is already open.".into());
    };
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_title("NetStop").with_inner_size([1040.0, 700.0]).with_min_inner_size([720.0, 420.0]),
        ..Default::default()
    };
    eframe::run_native("NetStop", opts, Box::new(|cc| Ok(Box::new(App::new(cc))))).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn csv_is_safe() {
        assert_eq!(super::csv_field("=cmd|x"), "\"'=cmd|x\"");
        assert_eq!(super::csv_field("a\"b"), "\"a\"\"b\"");
    }
}
