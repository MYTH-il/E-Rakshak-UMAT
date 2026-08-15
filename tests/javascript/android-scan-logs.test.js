import assert from "node:assert/strict";
import test from "node:test";

import { androidScanLogRows } from "../../src/umat/web/static/android-scan-logs.js";

test("expands the MobSF logs wrapper into individual scan events", () => {
  const rows = androidScanLogRows({
    logs: [
      { timestamp: "2026-08-15 09:00:49", status: "Generating Hashes", exception: null },
      { timestamp: "2026-08-15 09:00:50", status: "Manifest Analysis Started", exception: null },
    ],
  });
  assert.deepEqual(rows, [
    { stage: "logs", timestamp: "2026-08-15 09:00:49", status: "Generating Hashes", exception: "—" },
    { stage: "logs", timestamp: "2026-08-15 09:00:50", status: "Manifest Analysis Started", exception: "—" },
  ]);
});

test("preserves scan exceptions and enforces the display limit", () => {
  const rows = androidScanLogRows([
    { status: "First", exception: { message: "failure" } },
    { status: "Second", exception: null },
  ], 1);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].exception, '{"message":"failure"}');
});
