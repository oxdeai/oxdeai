// SPDX-License-Identifier: Apache-2.0
// #344 reproducibility harness: N packs per publishable package from one clean
// revision must be byte-identical. Hermetic: pack/source/toolchain are injected.
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { compareReports, runReproducibilityCheck } from "./reproducible-pack.mjs";

const SHA = "a".repeat(40);
const TOOLCHAIN = { pinned: { node: "22.9.0", pnpm: "10.34.5" }, observed: { node: "v22.9.0", pnpm: "10.34.5" } };
const discovered = ["@oxdeai/core", "@oxdeai/guard", "@oxdeai/crewai"].map((name) => ({
  name, dir: `/fake/${name.slice(8)}`, manifest: { name, version: "2.0.0" },
}));

function freshOut() {
  return path.join(mkdtempSync(path.join(tmpdir(), "oxdeai-repro-test-")), "out");
}
function source(sequence = [{ root: "/fake", revision: SHA, clean: true }]) {
  let i = 0;
  return { snapshot: () => ({ ...sequence[Math.min(i++, sequence.length - 1)] }) };
}
function packer(bytesFor = (pkg) => `TARBALL:${pkg.name}`) {
  const calls = [];
  return {
    calls,
    packToDir(pkg, destDir) {
      calls.push(pkg.name);
      const run = calls.filter((n) => n === pkg.name).length;
      const file = path.join(destDir, `${pkg.name.slice(8)}.tgz`);
      writeFileSync(file, bytesFor(pkg, run));
      return file;
    },
  };
}
const run = (over = {}) => runReproducibilityCheck({
  discovered, runs: 3, outDir: freshOut(), sourceTransport: source(), packTransport: packer(), toolchain: TOOLCHAIN, ...over,
});

test("identical bytes across N packs: reproducible, with a package -> hash mapping", () => {
  const outDir = freshOut();
  const p = packer();
  const r = run({ outDir, packTransport: p });
  assert.equal(r.ok, true);
  assert.equal(r.sourceRevision, SHA);
  assert.equal(r.runs, 3);
  assert.equal(p.calls.length, 9);
  for (const entry of r.packages) {
    assert.equal(entry.reproducible, true);
    assert.equal(entry.hashes.length, 3);
    assert.match(entry.sha256, /^[0-9a-f]{64}$/);
  }
  assert.deepEqual(r.packages.map((e) => e.package), discovered.map((d) => d.name));
  assert.deepEqual(readdirSync(outDir).sort(), ["run-1", "run-2", "run-3"]);
});

test("one package differing in one run fails the check and names the package", () => {
  const r = run({ packTransport: packer((pkg, n) => pkg.name === "@oxdeai/crewai" && n === 2 ? "REORDERED" : `T:${pkg.name}`) });
  assert.equal(r.ok, false);
  assert.deepEqual(r.failures.map((f) => f.package), ["@oxdeai/crewai"]);
  const crewai = r.packages.find((e) => e.package === "@oxdeai/crewai");
  assert.equal(crewai.reproducible, false);
  assert.equal(crewai.sha256, null, "no hash is reported for a non-reproducible package");
  assert.equal(new Set(crewai.hashes).size, 2);
});

test("a dirty or malformed source is refused before anything is packed", () => {
  for (const observed of [{ root: "/fake", revision: SHA, clean: false }, { root: "/fake", revision: "short", clean: true }, null]) {
    const p = packer();
    assert.throws(() => run({ sourceTransport: { snapshot: () => observed }, packTransport: p }), /source/);
    assert.equal(p.calls.length, 0);
  }
});

test("a source that changes during the runs fails closed", () => {
  const changed = source([{ root: "/fake", revision: SHA, clean: true }, { root: "/fake", revision: SHA, clean: false }]);
  assert.throws(() => run({ sourceTransport: changed }), /source changed/);
});

test("an existing output directory is never written to (frozen artifacts stay untouched)", () => {
  const outDir = freshOut();
  mkdirSync(outDir, { recursive: true });
  writeFileSync(path.join(outDir, "oxdeai-core-2.0.1.tgz"), "FROZEN");
  const p = packer();
  assert.throws(() => run({ outDir, packTransport: p }), /already exists/);
  assert.equal(p.calls.length, 0);
  assert.equal(readFileSync(path.join(outDir, "oxdeai-core-2.0.1.tgz"), "utf8"), "FROZEN");
});

test("fewer than two runs proves nothing and is refused", () => {
  for (const runs of [0, 1, 1.5, "3"]) assert.throws(() => run({ runs }), /runs/);
});

test("a toolchain that differs from the pin is refused before packing", () => {
  const p = packer();
  assert.throws(() => run({ packTransport: p, toolchain: { ...TOOLCHAIN, observed: { node: "v22.22.0", pnpm: "10.34.5" } } }), /Node/);
  assert.equal(p.calls.length, 0);
});

test("the harness cannot publish: no registry-mutating command appears in its source", () => {
  const src = readFileSync(fileURLToPath(new URL("./reproducible-pack.mjs", import.meta.url)), "utf8");
  for (const cmd of ["publish", "dist-tag", "unpublish", "deprecate"]) {
    assert.doesNotMatch(src, new RegExp(`["'\`]${cmd}["'\`]`), cmd);
  }
  assert.equal(existsSync(fileURLToPath(new URL("./reproducible-pack.mjs", import.meta.url))), true);
});

test("cross-environment comparison requires the same revision and identical bytes for every package", () => {
  const report = (rev, pairs) => ({ sourceRevision: rev, packages: pairs.map(([pkg, sha256]) => ({ package: pkg, sha256 })) });
  const a = report(SHA, [["@oxdeai/core", "1".repeat(64)], ["@oxdeai/guard", "2".repeat(64)]]);
  assert.deepEqual(compareReports(a, structuredClone(a)), []);
  assert.equal(compareReports(a, report("b".repeat(40), [["@oxdeai/core", "1".repeat(64)], ["@oxdeai/guard", "2".repeat(64)]])).length, 1);
  assert.match(compareReports(a, report(SHA, [["@oxdeai/core", "1".repeat(64)], ["@oxdeai/guard", "3".repeat(64)]]))[0], /@oxdeai\/guard/);
  assert.match(compareReports(a, report(SHA, [["@oxdeai/core", "1".repeat(64)]]))[0], /@oxdeai\/guard.*missing/);
  // A non-reproducible package (sha256 null) can never compare equal.
  assert.match(compareReports(report(SHA, [["@oxdeai/core", null]]), report(SHA, [["@oxdeai/core", null]]))[0], /@oxdeai\/core/);
});
