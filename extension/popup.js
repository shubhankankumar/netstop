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
  $("status").replaceWith(Object.assign(statusLine(day.recorder_last_write), { id: "status" }));

  if (day.up + day.down === 0) {
    main.replaceChildren(el("p", { class: "state" }, "Nothing recorded on this day."));
    return;
  }

  const top = day.apps.slice(0, 6);
  const biggest = Math.max(1, ...top.map((a) => a.up + a.down));
  const list = el("ol", { class: "apps" }, ...top.map((a) => {
    const bar = el("span", { class: "share", "aria-hidden": "true" }, el("span", { class: "bar-up" }), el("span", { class: "bar-down" }));
    bar.style.width = `${((a.up + a.down) / biggest) * 100}%`;
    bar.firstChild.style.flexGrow = a.up;
    bar.lastChild.style.flexGrow = a.down;
    return el("li", { title: a.app },
      el("span", { class: "name" }, a.name, ...tags(a, day)),
      el("span", { class: "n num" }, bytes(a.up + a.down)),
      bar,
      el("span", { class: "sub num" }, `↑ ${bytes(a.up)}  ↓ ${bytes(a.down)}`));
  }));

  const more = day.apps.length > 6 ? el("p", { class: "more" }, `${day.apps.length - 6} more programs and ${day.hosts_total} sites in the full report`) : null;
  const facts = notes(day);
  main.replaceChildren(
    totalsBlock(day),
    el("h2", { class: "label" }, "By hour"), hourStrip(day.hours),
    facts.length ? el("h2", { class: "label" }, "Worth a look") : null, notesBlock(facts),
    el("h2", { class: "label" }, "Top programs"), list, more);
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
