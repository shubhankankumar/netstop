// Unit tests for the extension's pure helpers (no browser needed): node --test tests/extension.test.js
"use strict";
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ctx = vm.createContext({});
vm.runInContext(fs.readFileSync(path.join(__dirname, "../extension/shared.js"), "utf8"), ctx);
const { bytes, notes, recorderStatus, dayLabel, clock } = ctx;

test("clock is 24-hour", () => {
  assert.strictEqual(clock(new Date(2026, 0, 1, 0, 5).getTime() / 1000), "00:05");
  assert.strictEqual(clock(new Date(2026, 0, 1, 23, 59).getTime() / 1000), "23:59");
});

test("bytes", () => {
  assert.strictEqual(bytes(0), "0 B");
  assert.strictEqual(bytes(1023), "1023 B");
  assert.strictEqual(bytes(1536), "1.5 KB");
  assert.strictEqual(bytes(1024 * 1024 - 1), "1.0 MB"); // not "1024 KB"
  assert.strictEqual(bytes(5 * 1024 ** 4), "5.0 TB");
  assert.strictEqual(bytes(5000 * 1024 ** 4), "5000 TB");
});

test("recorderStatus", () => {
  const now = Date.now() / 1000;
  assert.ok(recorderStatus(null).warn);
  assert.deepStrictEqual({ ...recorderStatus(now - 3) }, { text: "Recorder saved 3 s ago", warn: false });
  assert.ok(recorderStatus(now - 600).warn);
  assert.strictEqual(recorderStatus(now + 30).text, "Recorder saved 1 s ago"); // clock skew: never "-30 s"
});

test("dayLabel", () => {
  const days = ["2026-11-22", "2026-11-21", "2026-11-20"];
  assert.strictEqual(dayLabel("2026-11-22", days), "Today");
  assert.strictEqual(dayLabel("2026-11-21", days), "Yesterday");
  assert.match(dayLabel("2026-11-20", days), /20/);
});

const app = (name, up, down, extra = {}) => ({ name, app: `C:\\${name}.exe`, up, down, is_new: false, tunnel: false, ...extra });

test("notes: tunnel never 'sent the most', night counts every program", () => {
  const day = {
    has_history: true,
    apps: [app("vpn", 900, 900, { tunnel: true }), app("a", 10, 0), app("b", 50, 0, { is_new: true }), app("b2", 1, 0, { is_new: true })],
    hosts: [{ host: "1.2.3.4", is_new: true }, { host: "new.com", is_new: true }],
    new_hosts: 2,
    night: [app("vpn", 5, 5, { tunnel: true }), app("a", 1, 0), app("b", 2, 0), app("c", 3, 0)],
  };
  const out = Object.fromEntries(notes(day).map(([k, v, n]) => [k, [v, n]]));
  assert.deepStrictEqual(out["Sent the most"], ["b", "50 B"]);
  assert.deepStrictEqual(out["First time this week"], ["b, b2", "2 programs"]);
  assert.deepStrictEqual(out["New sites"], ["new.com, 1.2.3.4", "2"]); // names before bare IPs
  assert.deepStrictEqual(out["00:00 to 06:00"], ["a, b and 1 more", "6 B"]);
});

test("notes: first recorded day has nothing to call new", () => {
  const day = { has_history: false, apps: [app("a", 0, 0, { is_new: true })], hosts: [], new_hosts: 0, night: [] };
  assert.strictEqual(notes(day).length, 0);
});
