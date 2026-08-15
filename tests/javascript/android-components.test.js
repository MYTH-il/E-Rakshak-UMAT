import assert from "node:assert/strict";
import test from "node:test";

import { androidComponentItems, readableAndroidFinding } from "../../src/umat/web/static/android-components.js";

test("leaves conventional Android component names readable", () => {
  const [item] = androidComponentItems(["androidx.core.content.FileProvider"]);
  assert.equal(item.display, "androidx.core.content.FileProvider");
  assert.equal(item.obfuscated, false);
});

test("aliases long adversarial Unicode names and retains raw evidence", () => {
  const raw = `glasgow.pl.${"བཀྵུར".repeat(35)}72_SCA`;
  const [item] = androidComponentItems([raw]);
  assert.equal(item.display, "glasgow.pl.‹obfuscated component 1›.72_SCA");
  assert.equal(item.raw, raw);
  assert.equal(item.raw_character_count, [...raw].length);
  assert.equal(item.obfuscated, true);
});

test("renders control and bidi characters as explicit code points", () => {
  const [item] = androidComponentItems(["com.example.Safe\u202Eexe"]);
  assert.equal(item.raw, "com.example.Safe\\u{202E}exe");
});

test("aliases an obfuscated component embedded inside a finding", () => {
  const component = `glasgow.pl.${"བཀྵུར".repeat(20)}14_CA`;
  const finding = readableAndroidFinding(`Activity (${component}) is not Protected. [android:exported=true]`);
  assert.equal(finding.changed, true);
  assert.match(finding.display, /glasgow\.pl\.‹obfuscated component 1›\.14_CA/);
  assert.match(finding.raw, /android:exported=true/);
});

test("removes MobSF formatting tags from display but retains the raw finding", () => {
  const finding = readableAndroidFinding("Protection should be checked. <strong>Permission:</strong> android.permission.BIND_JOB_SERVICE");
  assert.equal(finding.display, "Protection should be checked. Permission: android.permission.BIND_JOB_SERVICE");
  assert.match(finding.raw, /<strong>Permission:<\/strong>/);
  assert.equal(finding.changed, true);
});
