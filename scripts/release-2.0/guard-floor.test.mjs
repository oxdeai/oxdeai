// SPDX-License-Identifier: Apache-2.0
// R3 F-02: the adapters' Guard security floor is enforced on manifests
// extracted from the packed tarballs, before any consumer install. Hermetic:
// synthetic tarballs built with `tar`, no registry, no package manager.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  POLICY, GateFailure, GUARD_PACKAGE, GUARD_SECURITY_FLOOR, GUARD_FLOOR_PACKAGES,
  assertGuardFloorPolicy, assertGuardSecurityFloor, scanPackedTarballs, verifyPackedTarballs,
} from "../verify-packed-artifacts.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const FLOOR_ERROR = (pkg) => (e) => e instanceof GateFailure && /phase\s+: guard-floor/.test(e.message) &&
  (pkg === undefined || e.message.includes(pkg));

function packedManifest(name, overrides = {}) {
  const p = POLICY[name];
  return {
    name, version: p.version,
    ...(p.expectMain ? { main: "index.js" } : {}),
    ...(p.expectTypes ? { types: "index.d.ts" } : {}),
    ...(p.expectExports ? { exports: { ".": "./index.js" } } : {}),
    ...(p.expectBin ? { bin: { [p.expectBin]: "bin.js" } } : {}),
    ...(name === "@oxdeai/core" ? {} : { dependencies: {
      "@oxdeai/core": p.kind === "adapter" ? "^2.0.3" : "2.0.3",
      ...(p.kind === "adapter" ? { [GUARD_PACKAGE]: GUARD_SECURITY_FLOOR.range } : {}),
    } }),
    ...overrides,
  };
}

function writeTarball(base, manifest) {
  const dir = path.join(base, "src", manifest.name.replace("/", "_"));
  mkdirSync(path.join(dir, "package"), { recursive: true });
  writeFileSync(path.join(dir, "package", "package.json"), JSON.stringify(manifest));
  const tarballPath = path.join(base, `${manifest.name.replace("/", "_")}.tgz`);
  const r = spawnSync("tar", ["-czf", tarballPath, "-C", dir, "package"], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  return { name: manifest.name, tarballPath };
}

function tempBase(t) {
  const base = mkdtempSync(path.join(tmpdir(), "oxdeai-guard-floor-"));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  return base;
}

// ── Policy binding ──────────────────────────────────────────────────────────

test("floor constants: ^2.0.5 over exactly the five POLICY adapters, satisfied by the released Guard", () => {
  assert.deepEqual(GUARD_SECURITY_FLOOR, { version: "2.0.5", range: "^2.0.5" });
  assert.deepEqual([...GUARD_FLOOR_PACKAGES].sort(),
    Object.entries(POLICY).filter(([, m]) => m.kind === "adapter").map(([n]) => n).sort());
  assert.equal(GUARD_FLOOR_PACKAGES.length, 5);
  assert.doesNotThrow(() => assertGuardFloorPolicy(POLICY));
});

for (const [label, mutate, pattern] of [
  ["Guard 2.0.4 below the floor", (p) => { p[GUARD_PACKAGE].version = "2.0.4"; }, /does not satisfy the Guard security floor/],
  ["Guard 2.0.3 below the floor", (p) => { p[GUARD_PACKAGE].version = "2.0.3"; }, /does not satisfy/],
  ["Guard 1.9.9 other major", (p) => { p[GUARD_PACKAGE].version = "1.9.9"; }, /does not satisfy/],
  ["Guard 3.0.0 other major", (p) => { p[GUARD_PACKAGE].version = "3.0.0"; }, /does not satisfy/],
  ["Guard prerelease of the floor", (p) => { p[GUARD_PACKAGE].version = "2.0.5-rc.1"; }, /does not satisfy/],
  ["Guard missing from policy", (p) => { delete p[GUARD_PACKAGE]; }, /does not satisfy/],
  ["new adapter not covered by the floor", (p) => { p["@oxdeai/new-adapter"] = { ...p["@oxdeai/langgraph"] }; }, /must equal POLICY adapters/],
  ["adapter reclassified out of the floor", (p) => { p["@oxdeai/openclaw"].kind = "library"; }, /must equal POLICY adapters/],
]) {
  test(`floor policy fails closed: ${label}`, () => {
    const policy = structuredClone(POLICY);
    mutate(policy);
    assert.throws(() => assertGuardFloorPolicy(policy), pattern);
  });
}

test("source manifests declare workspace:^2.0.5 for every adapter (packed as ^2.0.5)", () => {
  for (const name of GUARD_FLOOR_PACKAGES) {
    const m = JSON.parse(readFileSync(path.join(ROOT, "packages", name.slice("@oxdeai/".length), "package.json"), "utf8"));
    assert.equal(m.dependencies?.[GUARD_PACKAGE], `workspace:${GUARD_SECURITY_FLOOR.range}`, name);
    for (const field of ["peerDependencies", "optionalDependencies"]) assert.ok(!m[field] || !Object.hasOwn(m[field], GUARD_PACKAGE), `${name} ${field}`);
  }
});

// ── Manifest-level negatives ────────────────────────────────────────────────

const BAD_MANIFESTS = [
  ["dependency missing", (m) => { delete m.dependencies[GUARD_PACKAGE]; }],
  ["dependencies object missing", (m) => { delete m.dependencies; }],
  ["dependencies is an array", (m) => { m.dependencies = [GUARD_PACKAGE]; }],
  ["^2.0.4", (m) => { m.dependencies[GUARD_PACKAGE] = "^2.0.4"; }],
  ["exact 2.0.4", (m) => { m.dependencies[GUARD_PACKAGE] = "2.0.4"; }],
  ["~2.0.4", (m) => { m.dependencies[GUARD_PACKAGE] = "~2.0.4"; }],
  ["^2.0.0 (the published 2.0.0 adapter range)", (m) => { m.dependencies[GUARD_PACKAGE] = "^2.0.0"; }],
  [">=2.0.0", (m) => { m.dependencies[GUARD_PACKAGE] = ">=2.0.0"; }],
  ["*", (m) => { m.dependencies[GUARD_PACKAGE] = "*"; }],
  ["latest tag", (m) => { m.dependencies[GUARD_PACKAGE] = "latest"; }],
  ["union admitting 2.0.4", (m) => { m.dependencies[GUARD_PACKAGE] = "^2.0.5 || ^2.0.0"; }],
  ["leaked workspace protocol", (m) => { m.dependencies[GUARD_PACKAGE] = "workspace:^2.0.5"; }],
  ["file: tarball", (m) => { m.dependencies[GUARD_PACKAGE] = "file:../guard.tgz"; }],
  ["trailing whitespace", (m) => { m.dependencies[GUARD_PACKAGE] = "^2.0.5 "; }],
  ["non-string range", (m) => { m.dependencies[GUARD_PACKAGE] = 205; }],
  ["stricter range not yet reviewed", (m) => { m.dependencies[GUARD_PACKAGE] = "^2.0.6"; }],
  ["optionalDependencies override to ^2.0.0", (m) => { m.optionalDependencies = { [GUARD_PACKAGE]: "^2.0.0" }; }],
  ["optionalDependencies repeating the floor", (m) => { m.optionalDependencies = { [GUARD_PACKAGE]: "^2.0.5" }; }],
  ["peerDependencies ^2.0.0", (m) => { m.peerDependencies = { [GUARD_PACKAGE]: "^2.0.0" }; }],
  ["bundleDependencies lists Guard", (m) => { m.bundleDependencies = [GUARD_PACKAGE]; }],
  ["bundledDependencies = true", (m) => { m.bundledDependencies = true; }],
  ["bundleDependencies malformed", (m) => { m.bundleDependencies = GUARD_PACKAGE; }],
];

for (const name of GUARD_FLOOR_PACKAGES) {
  test(`${name}: packed manifest with Guard ${GUARD_SECURITY_FLOOR.range} is accepted`, () => {
    assert.equal(assertGuardSecurityFloor(name, packedManifest(name)), GUARD_SECURITY_FLOOR.range);
  });
  test(`${name}: every non-floor Guard declaration is rejected`, () => {
    for (const [label, mutate] of BAD_MANIFESTS) {
      const m = structuredClone(packedManifest(name));
      mutate(m);
      assert.throws(() => assertGuardSecurityFloor(name, m), FLOOR_ERROR(name), label);
    }
  });
}

test("non-adapter packages: no Guard dependency is fine, a weaker Guard dependency is not", () => {
  assert.equal(assertGuardSecurityFloor("@oxdeai/core", packedManifest("@oxdeai/core")), null);
  assert.equal(assertGuardSecurityFloor("@oxdeai/cli", packedManifest("@oxdeai/cli")), null);
  const weak = packedManifest("@oxdeai/sdk"); weak.dependencies[GUARD_PACKAGE] = "^2.0.0";
  assert.throws(() => assertGuardSecurityFloor("@oxdeai/sdk", weak), FLOOR_ERROR("@oxdeai/sdk"));
  const peer = packedManifest("@oxdeai/conformance"); peer.peerDependencies = { [GUARD_PACKAGE]: "^2.0.5" };
  assert.throws(() => assertGuardSecurityFloor("@oxdeai/conformance", peer), FLOOR_ERROR("@oxdeai/conformance"));
});

// ── Tarball-level: manifests are read from the packed bytes ─────────────────

test("scanPackedTarballs verifies the floor from all five real adapter tarballs", (t) => {
  const base = tempBase(t);
  const packed = Object.keys(POLICY).map((name) => writeTarball(base, packedManifest(name)));
  const { guardFloor } = scanPackedTarballs(packed, path.join(base, "scan"));
  assert.deepEqual(Object.keys(guardFloor).sort(), [...GUARD_FLOOR_PACKAGES].sort());
  for (const name of GUARD_FLOOR_PACKAGES) assert.equal(guardFloor[name], "^2.0.5");
});

for (const name of GUARD_FLOOR_PACKAGES) {
  test(`scanPackedTarballs rejects a ${name} tarball that packs @oxdeai/guard ^2.0.4`, (t) => {
    const base = tempBase(t);
    const packed = Object.keys(POLICY).map((n) => {
      const m = packedManifest(n);
      if (n === name) m.dependencies[GUARD_PACKAGE] = "^2.0.4";
      return writeTarball(base, m);
    });
    assert.throws(() => scanPackedTarballs(packed, path.join(base, "scan")), FLOOR_ERROR(name));
  });
}

test("scanPackedTarballs fails when an adapter tarball is absent (floor is mandatory)", (t) => {
  const base = tempBase(t);
  const packed = Object.keys(POLICY).filter((n) => n !== "@oxdeai/crewai").map((n) => writeTarball(base, packedManifest(n)));
  assert.throws(() => scanPackedTarballs(packed, path.join(base, "scan")), FLOOR_ERROR("@oxdeai/crewai"));
});

test("scanPackedTarballs reads the tarball, not the source: a source-correct manifest cannot hide a bad pack", (t) => {
  const base = tempBase(t);
  // Source manifests in this repository are correct (asserted above); the
  // packed bytes are what consumers install, so a bad packed range must fail.
  const packed = Object.keys(POLICY).map((n) => {
    const m = packedManifest(n);
    if (n === "@oxdeai/langgraph") m.dependencies[GUARD_PACKAGE] = "^2.0.0";
    return writeTarball(base, m);
  });
  assert.throws(() => scanPackedTarballs(packed, path.join(base, "scan")), FLOOR_ERROR("@oxdeai/langgraph"));
});

// Round 3 (M09): every per-manifest rule must also hold at tarball level. The
// coverage backstop in scanPackedTarballs only sees `dependencies` ranges, so
// these cases fail only if assertGuardSecurityFloor runs on each extracted
// manifest — including packages that are not adapters.
const TARBALL_ONLY_PER_MANIFEST_CASES = [
  ["@oxdeai/crewai", "adapter also declares Guard in optionalDependencies", (m) => { m.optionalDependencies = { [GUARD_PACKAGE]: "^2.0.0" }; }],
  ["@oxdeai/autogen", "adapter also declares Guard in peerDependencies", (m) => { m.peerDependencies = { [GUARD_PACKAGE]: "^2.0.5" }; }],
  ["@oxdeai/openclaw", "adapter bundles Guard (bundledDependencies)", (m) => { m.bundledDependencies = [GUARD_PACKAGE]; }],
  ["@oxdeai/langgraph", "adapter bundles everything (bundleDependencies: true)", (m) => { m.bundleDependencies = true; }],
  ["@oxdeai/sdk", "non-adapter declares a weaker Guard range", (m) => { m.dependencies[GUARD_PACKAGE] = "^2.0.0"; }],
  ["@oxdeai/conformance", "non-adapter declares Guard as a peer", (m) => { m.peerDependencies = { [GUARD_PACKAGE]: "^2.0.5" }; }],
];
for (const [target, label, mutate] of TARBALL_ONLY_PER_MANIFEST_CASES) {
  test(`scanPackedTarballs rejects a packed tarball where ${label} (${target})`, (t) => {
    const base = tempBase(t);
    const packed = Object.keys(POLICY).map((n) => {
      const m = packedManifest(n);
      if (n === target) mutate(m);
      return writeTarball(base, m);
    });
    assert.throws(() => scanPackedTarballs(packed, path.join(base, "scan")), FLOOR_ERROR(target));
  });
}

// Round 3 (M16): the floor policy is asserted when the module is LOADED, so a
// gate run with a below-floor Guard or an exempted adapter cannot start. This
// imports a byte-copy of the real module (with its one relative import) from
// a temporary directory; a control copy must load, so a broken harness cannot
// pass as a rejection.
function importModuleCopy(t, rewrite) {
  const base = tempBase(t);
  mkdirSync(path.join(base, "scripts", "release-2.0"), { recursive: true });
  const source = readFileSync(path.join(ROOT, "scripts", "verify-packed-artifacts.mjs"), "utf8");
  const rewritten = rewrite(source);
  writeFileSync(path.join(base, "scripts", "verify-packed-artifacts.mjs"), rewritten);
  writeFileSync(path.join(base, "scripts", "release-2.0", "artifact-paths.mjs"),
    readFileSync(path.join(ROOT, "scripts", "release-2.0", "artifact-paths.mjs")));
  return { changed: rewritten !== source,
    load: () => import(pathToFileURL(path.join(base, "scripts", "verify-packed-artifacts.mjs")).href) };
}
const GUARD_POLICY_VERSION = /("@oxdeai\/guard": \{[^}]*?version: ")2\.0\.5(")/;

test("module load: an unmodified copy of the gate module loads (harness control)", async (t) => {
  const copy = importModuleCopy(t, (s) => s);
  const mod = await copy.load();
  assert.deepEqual(mod.GUARD_SECURITY_FLOOR, GUARD_SECURITY_FLOOR);
});

for (const [label, rewrite, pattern] of [
  ["POLICY releases Guard 2.0.4, below the floor", (s) => s.replace(GUARD_POLICY_VERSION, "$12.0.4$2"), /does not satisfy the Guard security floor/],
  ["an adapter is dropped from GUARD_FLOOR_PACKAGES", (s) => s.replace('"@oxdeai/autogen", "@oxdeai/crewai",', '"@oxdeai/crewai",'), /must equal POLICY adapters/],
]) {
  test(`module load fails closed when ${label}`, async (t) => {
    const copy = importModuleCopy(t, rewrite);
    assert.equal(copy.changed, true, "rewrite must apply to the real module source");
    await assert.rejects(copy.load(), pattern);
  });
}

// ── Gate-level: failure precedes every install, so no override can mask it ──

test("verifyPackedTarballs fails on the Guard floor before the conformance baseline and any npm/pnpm consumer", (t) => {
  const base = tempBase(t);
  const packed = Object.keys(POLICY).map((n) => {
    const m = packedManifest(n);
    if (n === "@oxdeai/openai-agents") m.dependencies[GUARD_PACKAGE] = "^2.0.4";
    return writeTarball(base, m);
  });
  const gateDir = path.join(base, "gate");
  const discovered = Object.keys(POLICY).map((name) => ({ name }));
  assert.throws(() => verifyPackedTarballs(discovered, packed, { baseDir: gateDir }), FLOOR_ERROR("@oxdeai/openai-agents"));
  assert.equal(existsSync(path.join(gateDir, "npm-consumer")), false, "npm consumer must not be created");
  assert.equal(existsSync(path.join(gateDir, "pnpm-consumer")), false, "pnpm consumer (and its overrides) must not be created");
});

test("verifyPackedTarballs fails when the discovered set itself omits an adapter", (t) => {
  const base = tempBase(t);
  const names = Object.keys(POLICY).filter((n) => n !== "@oxdeai/autogen");
  const packed = names.map((n) => writeTarball(base, packedManifest(n)));
  const gateDir = path.join(base, "gate");
  assert.throws(() => verifyPackedTarballs(names.map((name) => ({ name })), packed, { baseDir: gateDir }), FLOOR_ERROR("@oxdeai/autogen"));
  assert.equal(existsSync(path.join(gateDir, "pnpm-consumer")), false);
});
