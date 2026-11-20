"use strict";

let days = [];
let date = todayStr();
const $ = (id) => document.getElementById(id);

async function load() {
  $("main").replaceChildren(el("div", { class: "state skeleton" }, el("span"), el("span"), el("span")));
  const day = await ask(date, false);
  const main = $("main");
  if (day.error) {
    main.replaceChildren(el("p", { class: "state error" }, day.error));
    $("status").textContent = "";
    return;
  }
  days = day.days;
  $("day").textContent = dayLabel(date, days);
  $("prev").disabled = days.indexOf(date) >= days.length - 1;
  $("next").disabled = days.indexOf(date) <= 0;
  const st = recorderStatus(day.recorder_last_write);
  $("status").textContent = st.text;
  $("status").classList.toggle("warn", st.warn);

  if (day.up + day.down === 0) {
    main.replaceChildren(el("p", { class: "state" }, "Nothing recorded on this day."));
    return;
  }

  const totals = el("div", { class: "totals" },
    el("div", {}, el("span", { class: "figure up" }, bytes(day.up)), el("span", { class: "cap" }, "sent")),
    el("div", {}, el("span", { class: "figure" }, bytes(day.down)), el("span", { class: "cap" }, "received")));

  const facts = notes(day);
  const list = facts.length
    ? el("dl", { class: "notes" }, ...facts.flatMap(([k, v, n]) => [el("dt", {}, k), el("dd", {}, el("span", { class: "who" }, v), el("span", { class: "num" }, n))]))
    : null;

  const rows = day.apps.slice(0, 6).map((a) =>
    el("tr", {},
      el("td", { class: "name", title: a.app }, a.name, a.is_new && day.has_history ? el("span", { class: "tag" }, "new") : null),
      el("td", { class: "num up" }, bytes(a.up)),
      el("td", { class: "num" }, bytes(a.down))));
  const table = el("table", { class: "grid" },
    el("thead", {}, el("tr", {}, el("th", { scope: "col" }, "Program"), el("th", { scope: "col", class: "num" }, "Sent"), el("th", { scope: "col", class: "num" }, "Received"))),
    el("tbody", {}, ...rows));

  const more = day.apps.length > 6 ? el("p", { class: "more" }, `${day.apps.length - 6} more programs, ${day.hosts_total} sites in the full report`) : null;
  main.replaceChildren(totals, hourStrip(day.hours), list, table, more);
}

function shift(by) {
  const i = days.indexOf(date) + by;
  if (i >= 0 && i < days.length) { date = days[i]; load(); }
}

$("prev").addEventListener("click", () => shift(1));
$("next").addEventListener("click", () => shift(-1));
$("open").addEventListener("click", () => {
  chrome.tabs.create({ url: chrome.runtime.getURL(`details.html?date=${encodeURIComponent(date)}`) });
  window.close();
});
load();
