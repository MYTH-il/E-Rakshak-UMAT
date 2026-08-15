import assert from "node:assert/strict";
import test from "node:test";

import { runtimeObservationRows } from "../../src/umat/web/static/runtime-observations.js";

test("expands runtime arrays and keyed MobSF sections into individual rows", () => {
  const rows = runtimeObservationRows({
    api_monitor: [
      { class: "android.content.ContentResolver", method: "query", arguments: ["contacts"] },
      { name: "Device Data", class: "android.telephony.TelephonyManager", method: "getDeviceId" },
    ],
    domains: {
      "c2.example.test": { geolocation: { ip: "203.0.113.8" } },
    },
    urls: ["https://c2.example.test/checkin", "https://c2.example.test/upload"],
  });

  assert.equal(rows.length, 5);
  assert.deepEqual(rows.map((row) => row.section), [
    "api_monitor", "api_monitor", "domains", "urls", "urls",
  ]);
  assert.equal(rows[0].observation, "android.content.ContentResolver.query");
  assert.equal(rows[1].observation, "Device Data");
  assert.equal(rows[2].observation, "c2.example.test");
  assert.match(rows[2].details, /203\.0\.113\.8/);
  assert.equal(rows[3].observation, "https://c2.example.test/checkin");
});

test("unwraps event containers, preserves metadata, and enforces the row limit", () => {
  const rows = runtimeObservationRows({
    traffic: {
      events: [{ event: "connect", host: "c2.example.test" }, { event: "send", bytes: 42 }],
      parser_status: "partial",
    },
    empty: [],
  }, 2);

  assert.equal(rows.length, 2);
  assert.deepEqual(rows.map((row) => row.observation), ["connect", "send"]);
});

test("ignores scalar report metadata and empty collections", () => {
  assert.deepEqual(runtimeObservationRows({ package: "example.app", version: "1", urls: [] }), []);
  assert.deepEqual(runtimeObservationRows(null), []);
});
