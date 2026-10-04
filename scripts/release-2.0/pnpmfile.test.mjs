// SPDX-License-Identifier: Apache-2.0
// #344: pnpm rewrites workspace: specifiers concurrently and inserts the
// rewritten keys in completion order, so a manifest with two workspace
// dependencies could be packed as {core, guard} or {guard, core}. The root
// .pnpmfile.cjs `beforePacking` hook restores the source manifest's key order.
// These tests drive the hook directly with the out-of-order input pnpm can
// produce, so they are deterministic rather than depending on the race.
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ROOT } from "./orchestrator.mjs";

const require = createRequire(import.meta.url);
const PNPMFILE = path.join(ROOT, ".pnpmfile.cjs");

function packageDir(manifest) {
  const dir = mkdtempSync(path.join(tmpdir(), "oxdeai-pnpmfile-"));
  writeFileSync(path.join(dir, "package.json"), JSON.stringify(manifest, null, 2));
  return dir;
}

function hook() {
  const pnpmfile = require(PNPMFILE);
  assert.equal(typeof pnpmfile?.hooks?.beforePacking, "function", ".pnpmfile.cjs must export hooks.beforePacking");
  return pnpmfile.hooks.beforePacking;
}

const SOURCE = {
  name: "@oxdeai/example-adapter",
  version: "2.0.0",
  dependencies: { "@oxdeai/core": "workspace:^", "@oxdeai/guard": "workspace:^", "zod": "^3.0.0" },
  devDependencies: { "@oxdeai/sdk": "workspace:*", "typescript": "5.9.3" },
  peerDependencies: { "@oxdeai/core": "workspace:^" },
};

test("beforePacking restores the source key order of every dependency field", () => {
  const dir = packageDir(SOURCE);
  // Completion order as pnpm can produce it: reversed relative to the source.
  const packed = {
    name: SOURCE.name,
    version: SOURCE.version,
    dependencies: { "zod": "^3.0.0", "@oxdeai/guard": "^2.0.2", "@oxdeai/core": "^2.0.1" },
    devDependencies: { "typescript": "5.9.3", "@oxdeai/sdk": "2.0.1" },
    peerDependencies: { "@oxdeai/core": "^2.0.1" },
  };
  const out = hook()(structuredClone(packed), dir);
  assert.deepEqual(Object.keys(out.dependencies), Object.keys(SOURCE.dependencies));
  assert.deepEqual(Object.keys(out.devDependencies), Object.keys(SOURCE.devDependencies));
  // Only order changes: every rewritten value is preserved exactly.
  for (const f of ["dependencies", "devDependencies", "peerDependencies"]) {
    for (const [k, v] of Object.entries(packed[f])) assert.equal(out[f][k], v, `${f}.${k}`);
  }
});

test("beforePacking makes every completion order serialize to identical bytes", () => {
  const dir = packageDir(SOURCE);
  const orders = [
    { "@oxdeai/core": "^2.0.1", "@oxdeai/guard": "^2.0.2", "zod": "^3.0.0" },
    { "@oxdeai/guard": "^2.0.2", "@oxdeai/core": "^2.0.1", "zod": "^3.0.0" },
    { "zod": "^3.0.0", "@oxdeai/guard": "^2.0.2", "@oxdeai/core": "^2.0.1" },
  ];
  const bytes = orders.map((dependencies) =>
    JSON.stringify(hook()({ name: SOURCE.name, version: SOURCE.version, dependencies }, dir), null, 2));
  assert.equal(new Set(bytes).size, 1);
});

test("beforePacking leaves non-dependency fields and absent fields untouched", () => {
  const dir = packageDir({ name: "x", version: "1.0.0", dependencies: { a: "1" } });
  const pkg = { name: "x", version: "1.0.0", files: ["dist"], dependencies: { a: "1" } };
  const out = hook()(structuredClone(pkg), dir);
  assert.deepEqual(out, pkg);
  assert.equal("devDependencies" in out, false);
});

test("beforePacking fails closed when the packed dependency names differ from the source", () => {
  const dir = packageDir(SOURCE);
  const h = hook();
  // A dependency added or dropped during packing must never be silently reordered away.
  assert.throws(() => h({ dependencies: { "@oxdeai/core": "^2.0.1", "zod": "^3.0.0" } }, dir), /dependencies/);
  assert.throws(() => h({ dependencies: { ...SOURCE.dependencies, extra: "1.0.0" } }, dir), /dependencies/);
  assert.throws(() => h({ devDependencies: { "@oxdeai/sdk": "2.0.1" }, dependencies: SOURCE.dependencies }, dir), /devDependencies/);
});

test("the committed lockfile records the checksum of this .pnpmfile.cjs", () => {
  // pnpm refuses a frozen install when the hook changes without the lockfile,
  // so a stale or missing hook cannot silently reach a release build.
  const digest = createHash("sha256").update(readFileSync(PNPMFILE)).digest("base64");
  const lock = readFileSync(path.join(ROOT, "pnpm-lock.yaml"), "utf8");
  assert.match(lock, new RegExp(`^pnpmfileChecksum: sha256-${digest.replace(/[+/=]/g, "\\$&")}$`, "m"));
});
