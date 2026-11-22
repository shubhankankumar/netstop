// Shared helpers. Every string from the report (program names, domains) is untrusted:
// it is only ever placed with textContent, never parsed as HTML.
"use strict";

const HOST = "com.netstop.host";

function ask(date, detail) {
  return new Promise((resolve) => {
    chrome.runtime.sendNativeMessage(HOST, { cmd: "day", date, detail }, (reply) => {
      if (chrome.runtime.lastError || !reply) {
        resolve({ error: "NetStop isn't installed for this browser. In an Administrator terminal run: netstop install" });
      } else {
        resolve(reply);
      }
    });
  });
}

// el("td", { class: "num", title: "x" }, "text", childNode, ...)
function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "on") for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
    else n.setAttribute(k, v === true ? "" : String(v));
  }
  for (const k of kids) if (k !== null && k !== undefined && k !== false) n.append(k instanceof Node ? k : String(k));
  return n;
}

function bytes(b) {
  if (b < 1024) return `${b} B`;
  const u = ["KB", "MB", "GB", "TB"];
  let v = b / 1024, i = 0;
  while (v >= 1023.95 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`;
}

function clock(unix) {
  return new Date(unix * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hourCycle: "h23" });
}

function dayLabel(date, days) {
  const i = days.indexOf(date);
  if (i === 0) return "Today";
  if (i === 1) return "Yesterday";
  return new Date(date + "T12:00:00").toLocaleDateString([], { weekday: "long", day: "numeric", month: "short" });
}

function todayStr() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

function recorderStatus(lastWrite) {
  if (!lastWrite) return { text: "Recorder has not saved anything yet", warn: true };
  const ago = Math.round(Date.now() / 1000 - lastWrite);
  if (ago > 120) return { text: `Recorder last saved ${Math.round(ago / 60)} min ago`, warn: true };
  return { text: `Recorder saved ${Math.max(ago, 1)} s ago`, warn: false };
}

// 24 bars, upload stacked on download. Height via CSSOM (allowed under the page's CSP).
function hourStrip(hours, onPick) {
  const peak = Math.max(0, ...hours.map((h) => h[0] + h[1]));
  const max = Math.max(1, peak);
  const strip = el("div", { class: "hours", role: "group", "aria-label": "Traffic by hour" });
  hours.forEach((h, i) => {
    const hh = String(i).padStart(2, "0");
    const label = `${hh}:00 to ${hh}:59: sent ${bytes(h[0])}, received ${bytes(h[1])}`;
    const stack = el("span", { class: "stack" }, el("span", { class: "bar-up" }), el("span", { class: "bar-down" }));
    stack.style.height = h[0] + h[1] ? `max(2px, ${((h[0] + h[1]) / max) * 100}%)` : "0";
    stack.firstChild.style.flexGrow = h[0];
    stack.lastChild.style.flexGrow = h[1];
    const col = onPick
      ? el("button", { class: "hour", type: "button", title: label, "aria-label": label, on: { click: () => onPick(i) } }, stack)
      : el("span", { class: "hour", title: label }, stack);
    col.dataset.hour = i;
    strip.append(col);
  });
  const ticks = el("div", { class: "ticks", "aria-hidden": "true" }, ...["00:00", "06:00", "12:00", "18:00", ""].map((t) => el("span", {}, t)));
  return el("div", { class: "hours-wrap" }, el("span", { class: "peak", "aria-hidden": "true" }, `peak ${bytes(peak)}/h`), strip, ticks);
}

// Sent + received as one figure, with the split as a thin two-part bar.
function totalsBlock(day, extra = []) {
  const all = day.up + day.down;
  const split = el("div", { class: "split", "aria-hidden": "true" }, el("span", { class: "bar-up" }), el("span", { class: "bar-down" }));
  split.firstChild.style.flexGrow = day.up;
  split.lastChild.style.flexGrow = day.down;
  return el("div", { class: "totals" },
    el("div", { class: "total" }, el("span", { class: "figure" }, bytes(all)), el("span", { class: "cap" }, "used in total")),
    split,
    el("div", { class: "legend" },
      el("span", {}, el("i", { class: "dot up" }), "Sent ", el("b", { class: "num" }, bytes(day.up))),
      el("span", {}, el("i", { class: "dot down" }), "Received ", el("b", { class: "num" }, bytes(day.down))),
      ...extra.map(([k, v]) => el("span", {}, `${k} `, el("b", { class: "num" }, v)))));
}

function statusLine(lastWrite) {
  const st = recorderStatus(lastWrite);
  return el("p", { class: `status${st.warn ? " warn" : ""}` }, el("i", { class: "pulse" }), st.text);
}

// "new" / "VPN" badges after a program name.
function tags(a, day) {
  return [
    a.tunnel ? el("span", { class: "tag muted", title: "A VPN carries the other programs' traffic, so it isn't added to the totals" }, "VPN, not in totals") : null,
    a.is_new && day.has_history ? el("span", { class: "tag" }, "new") : null,
  ];
}

function notesBlock(facts) {
  if (!facts.length) return null;
  return el("ul", { class: "notes" }, ...facts.map(([k, v, n]) =>
    el("li", {}, el("span", { class: "k" }, k), el("span", { class: "who", title: v }, v), el("span", { class: "n num" }, n))));
}

// Short factual notes worth a look. Never alarmist: just what happened.
function notes(day) {
  const out = [];
  const topUp = day.apps.filter((a) => !a.tunnel).sort((a, b) => b.up - a.up)[0];
  if (topUp && topUp.up > 0) out.push(["Sent the most", `${topUp.name}`, bytes(topUp.up)]);
  if (day.has_history) {
    const newApps = day.apps.filter((a) => a.is_new);
    const isIp = (h) => /^[\d.]+$|:/.test(h);
    const newHosts = day.hosts.filter((h) => h.is_new).sort((a, b) => isIp(a.host) - isIp(b.host));
    if (newApps.length) out.push(["First time this week", newApps.slice(0, 3).map((a) => a.name).join(", ") + (newApps.length > 3 ? ` and ${newApps.length - 3} more` : ""), `${newApps.length} program${newApps.length > 1 ? "s" : ""}`]);
    const nNew = day.new_hosts ?? newHosts.length;
    if (nNew) out.push(["New sites", newHosts.slice(0, 2).map((h) => h.host).join(", ") + (nNew > 2 ? ` and ${nNew - 2} more` : ""), `${nNew}`]);
  }
  const night = day.night.filter((a) => a.up + a.down > 0 && !a.tunnel);
  if (night.length) {
    const t = night.reduce((s, a) => s + a.up + a.down, 0);
    out.push(["00:00 to 06:00", night.slice(0, 2).map((a) => a.name).join(", ") + (night.length > 2 ? ` and ${night.length - 2} more` : ""), bytes(t)]);
  }
  return out;
}
