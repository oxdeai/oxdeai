// SPDX-License-Identifier: Apache-2.0
// #344: the release-critical toolchain is pinned to exact versions in the
// repository and checked against what actually runs before anything is packed.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ROOT } from "./orchestrator.mjs";
import { readReleaseToolchain, assertReleaseToolchain } from "./toolchain.mjs";

function fixtureRoot({ nodeVersion = "22.9.0\n", packageManager = "pnpm@10.34.5", engines = { node: ">=20", pnpm: ">=10.34.5 <11" } } = {}) {
  const root = mkdtempSync(path.join(tmpdir(), "oxdeai-toolchain-"));
  if (nodeVersion !== null) writeFileSync(path.join(root, ".node-version"), nodeVersion);
  // null means "field absent" (undefined would fall back to the default above).
  writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "fixture", ...(packageManager === null ? {} : { packageManager }), engines }));
  return root;
}

test("the repository pins exact release Node and pnpm versions", () => {
  const pinned = readReleaseToolchain(ROOT);
  assert.match(pinned.node, /^\d+\.\d+\.\d+$/);
  assert.match(pinned.pnpm, /^\d+\.\d+\.\d+$/);
  const pkg = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8"));
  assert.equal(`pnpm@${pinned.pnpm}`, pkg.packageManager, "pnpm pin is the root packageManager");
});

test("ranged, missing or inconsistent pins fail closed", () => {
  for (const nodeVersion of ["22\n", ">=22\n", "lts/*\n", "v22.x\n", "", null]) {
    assert.throws(() => readReleaseToolchain(fixtureRoot({ nodeVersion })), /\.node-version/, JSON.stringify(nodeVersion));
  }
  for (const packageManager of [null, "pnpm@10", "pnpm@^10.34.5", "npm@10.0.0"]) {
    assert.throws(() => readReleaseToolchain(fixtureRoot({ packageManager })), /packageManager/, String(packageManager));
  }
  // A pin outside the declared engines range is inconsistent, not a choice.
  assert.throws(() => readReleaseToolchain(fixtureRoot({ nodeVersion: "18.20.0\n" })), /engines\.node/);
  assert.throws(() => readReleaseToolchain(fixtureRoot({ packageManager: "pnpm@11.0.0" })), /engines\.pnpm/);
  assert.deepEqual(readReleaseToolchain(fixtureRoot()), { node: "22.9.0", pnpm: "10.34.5" });
});

test("the observed toolchain must equal the pin exactly", () => {
  const pinned = { node: "22.9.0", pnpm: "10.34.5" };
  assert.doesNotThrow(() => assertReleaseToolchain({ node: "v22.9.0", pnpm: "10.34.5" }, pinned));
  assert.throws(() => assertReleaseToolchain({ node: "v22.22.0", pnpm: "10.34.5" }, pinned), /Node v22\.22\.0.*22\.9\.0/);
  assert.throws(() => assertReleaseToolchain({ node: "v22.9.0", pnpm: "9.12.0" }, pinned), /pnpm 9\.12\.0.*10\.34\.5/);
  assert.throws(() => assertReleaseToolchain({ node: "v22.9.0", pnpm: "" }, pinned), /pnpm/);
});

test("release-critical CI jobs run on the pinned Node, not a floating major", () => {
  const ci = readFileSync(path.join(ROOT, ".github/workflows/ci.yml"), "utf8");
  for (const job of ["packed-artifact-consumer-gate", "release-reproducibility"]) {
    const start = ci.indexOf(`\n  ${job}:\n`);
    assert.notEqual(start, -1, `CI job ${job} missing`);
    const next = ci.slice(start + 1).search(/\n  [a-z0-9-]+:\n/);
    const body = next === -1 ? ci.slice(start) : ci.slice(start, start + 1 + next);
    assert.match(body, /node-version-file: \.node-version/, `${job} must use .node-version`);
    assert.doesNotMatch(body, /node-version: "22"/, `${job} must not float on Node 22`);
  }
});
