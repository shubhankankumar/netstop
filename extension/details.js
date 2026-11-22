"use strict";

// View state lives in the URL: ?date=YYYY-MM-DD&q=text&app=key&hour=N
const params = new URLSearchParams(location.search);
const state = {
  date: /^\d{4}-\d{2}-\d{2}$/.test(params.get("date") || "") ? params.get("date") : todayStr(),
  q: params.get("q") || "",
  app: params.get("app") || "",
  hour: /^(1?\d|2[0-3])$/.test(params.get("hour") || "") ? Number(params.get("hour")) : null,
};
const sorts = {}; // table id -> { key, desc }
const MAX_ROWS = 5000; // per table, so a day with huge site lists still renders quickly
let day = null;
const $ = (id) => document.getElementById(id);

function saveUrl() {
  const p = new URLSearchParams({ date: state.date });
  if (state.q) p.set("q", state.q);
  if (state.app) p.set("app", state.app);
  if (state.hour !== null) p.set("hour", state.hour);
  history.replaceState(null, "", `?${p}`);
}

async function load() {
  $("main").replaceChildren(el("div", { class: "state skeleton" }, el("span"), el("span"), el("span")));
  day = await ask(state.date, true);
  if (day.error) { $("main").replaceChildren(el("p", { class: "state error" }, day.error)); return; }
  $("days").replaceChildren(...day.days.map((d) =>
    el("a", { href: `?date=${d}`, "aria-current": d === state.date ? "page" : null, on: { click: (e) => { e.preventDefault(); state.date = d; state.app = ""; state.hour = null; saveUrl(); load(); } } }, dayLabel(d, day.days))));
  render();
}

function matches(text) {
  return !state.q || text.toLowerCase().includes(state.q.toLowerCase());
}

function inHour(first, last) {
  if (state.hour === null) return true;
  const d = new Date(state.date + "T00:00:00");
  d.setHours(state.hour);
  const s = d.getTime() / 1000;
  return first < s + 3600 && last + 60 > s;
}

// Sortable table. cols: [label, key, kind("text"|"num"|"bytes"|"time"), render?]
function table(id, cols, rows, opts = {}) {
  const sort = sorts[id] || {};
  const sorted = !sort.key ? rows : [...rows].sort((a, b) => {
    const x = a[sort.key], y = b[sort.key];
    const r = typeof x === "string" ? x.localeCompare(y) : x - y;
    return sort.desc ? -r : r;
  });
  const head = el("tr", {}, ...cols.map(([label, key, kind]) => {
    const active = sort.key === key;
    return el("th", { scope: "col", class: kind === "text" ? null : "num", "aria-sort": active ? (sort.desc ? "descending" : "ascending") : null },
      el("button", { type: "button", class: "sort", on: { click: () => { sorts[id] = { key, desc: active ? !sort.desc : kind !== "text" }; render(); } } },
        label, active ? (sort.desc ? " ↓" : " ↑") : ""));
  }));
  const body = sorted.slice(0, MAX_ROWS).map((r) => el("tr", { class: opts.rowClass ? opts.rowClass(r) : null },
    ...cols.map(([, key, kind, fn]) => {
      const v = fn ? fn(r) : kind === "bytes" ? bytes(r[key]) : kind === "time" ? clock(r[key]) : r[key];
      return el("td", { class: kind === "text" ? null : "num" }, v);
    })));
  const cut = rows.length > MAX_ROWS ? el("caption", {}, `Showing ${MAX_ROWS} of ${rows.length} rows. Filter to narrow it down.`) : null;
  return el("table", { class: "grid", id }, cut, el("thead", {}, head), el("tbody", {}, ...body));
}

function section(title, count, content, note) {
  return el("section", { class: "card" },
    el("div", { class: "card-head" }, el("h2", {}, title), el("span", { class: "count num" }, count)),
    note ? el("p", { class: "note" }, note) : null,
    content);
}

function appCell(a) {
  const pick = el("button", { type: "button", class: "link", title: a.app, on: { click: () => { state.app = state.app === a.app ? "" : a.app; saveUrl(); render(); } } }, a.name);
  return el("span", { class: "cell" }, pick, ...tags(a, day));
}

function render() {
  const main = $("main");
  const apps = day.apps.filter((a) => matches(a.name + " " + a.app) && inHour(a.first, a.last));
  const conns = day.conns.filter((c) => (!state.app || c.app === state.app) && matches(`${c.name} ${c.app} ${c.host}`) && inHour(c.first, c.last));
  const hostSet = state.app ? new Set(conns.map((c) => c.host)) : null;
  const hosts = day.hosts.filter((h) => (!hostSet || hostSet.has(h.host)) && matches(h.host));
  const appName = state.app ? (day.apps.find((a) => a.app === state.app) || {}).name || state.app : "";

  const strip = hourStrip(day.hours, (i) => { state.hour = state.hour === i ? null : i; saveUrl(); render(); });
  if (state.hour !== null) strip.querySelector(`[data-hour="${state.hour}"]`)?.setAttribute("aria-pressed", "true");

  const summary = el("div", { class: "summary" },
    totalsBlock(day, [["Programs", String(day.apps.length)], ["Sites", String(day.hosts.length)]]),
    statusLine(day.recorder_last_write));
  const facts = notes(day);
  const chart = el("section", { class: "card chart" },
    el("div", { class: "card-head" }, el("h2", {}, "By hour"), el("span", { class: "note" }, "Click an hour to narrow the tables")), strip);
  const factList = facts.length ? el("section", { class: "card" }, el("div", { class: "card-head" }, el("h2", {}, "Worth a look")), notesBlock(facts)) : null;

  const filters = el("div", { class: "filters" },
    el("label", { for: "q" }, "Filter"),
    el("input", { id: "q", type: "search", value: state.q, placeholder: "program, site or IP", autocomplete: "off",
      on: { input: (e) => { state.q = e.target.value; saveUrl(); clearTimeout(render.t); render.t = setTimeout(() => { render(); $("q").focus(); $("q").setSelectionRange(state.q.length, state.q.length); }, 150); } } }),
    state.app ? el("button", { type: "button", class: "key chip", on: { click: () => { state.app = ""; saveUrl(); render(); } } }, `Program: ${appName} ×`) : null,
    state.hour !== null ? el("button", { type: "button", class: "key chip", on: { click: () => { state.hour = null; saveUrl(); render(); } } }, `Hour: ${String(state.hour).padStart(2, "0")}:00 ×`) : null);

  const active = (r) => `${clock(r.first)} to ${clock(r.last + 59)}`;
  const appCols = [["Program", "name", "text", appCell], ["Sent", "up", "bytes"], ["Received", "down", "bytes"], ["Sites", "hosts", "num"], ["Active", "first", "time", active]];
  const truncated = day.conns_total > day.conns.length ? `Showing the ${day.conns.length} biggest of ${day.conns_total}. Use the NetStop window for all of them.` : null;

  main.replaceChildren(
    summary,
    el("div", { class: "pair" }, chart, factList),
    filters,
    section("Programs", apps.length, table("t-apps", appCols, apps, { rowClass: (a) => (a.app === state.app ? "picked" : null) })),
    section("Sites", hosts.length, table("t-hosts", [["Site or address", "host", "text", (h) => el("span", { class: "cell" }, h.host, h.is_new && day.has_history ? el("span", { class: "tag" }, "new") : null)], ["Sent", "up", "bytes"], ["Received", "down", "bytes"], ["Programs", "apps", "num"]], hosts)),
    section("00:00 to 06:00", day.night.length, day.night.length ? table("t-night", appCols, day.night) : el("p", { class: "note" }, "Nothing used the network overnight.")),
    section("Every connection", conns.length, table("t-conns", [["Program", "name", "text", (c) => el("span", { title: c.app }, c.name)], ["Site or address", "host", "text"], ["Port", "port", "num", (c) => `${c.port} ${c.proto}`], ["Sent", "up", "bytes"], ["Received", "down", "bytes"], ["Active", "first", "time", active]], conns), truncated),
  );
}

// CSV, with a leading ' on anything a spreadsheet would run as a formula.
function csvField(s) {
  s = String(s);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return `"${s.replace(/"/g, '""')}"`;
}

$("csv").addEventListener("click", () => {
  if (!day || day.error) return;
  const lines = ["program,path,site,port,protocol,sent_bytes,received_bytes,first,last"];
  for (const c of day.conns) lines.push([c.name, c.app, c.host, c.port, c.proto, c.up, c.down, clock(c.first), clock(c.last)].map(csvField).join(","));
  const url = URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/csv" }));
  el("a", { href: url, download: `netstop-${state.date}.csv` }).click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

load();
