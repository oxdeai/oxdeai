// SPDX-License-Identifier: Apache-2.0
// Published-version floor: PRECHECK refuses to reuse or downgrade a version
// that is already on the npm registry (R3 reconciliation).
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { POLICY } from "../verify-packed-artifacts.mjs";
import { ROOT, precheck } from "./orchestrator.mjs";
import { fixturePackages, PRE_R3_PUBLISHED_BASELINE } from "./precheck-fixture.mjs";
import {
  compareVersions, loadPublishedBaseline, publishedVersionBlockers, validatePublishedBaseline,
} from "./published-baseline.mjs";

const NPM_PUBLISHED = Object.freeze({
  "@oxdeai/core": "2.0.3", "@oxdeai/guard": "2.0.5", "@oxdeai/sdk": "2.0.3", "@oxdeai/conformance": "2.0.4",
  "@oxdeai/autogen": "2.0.1", "@oxdeai/crewai": "2.0.1", "@oxdeai/langgraph": "2.0.1",
  "@oxdeai/openai-agents": "2.0.1", "@oxdeai/openclaw": "2.0.1", "@oxdeai/cli": "0.3.3",
});

const discovered = () => Object.entries(POLICY).map(([name, meta]) => ({
  name, dir: `/fake/${name.split("/")[1]}`,
  manifest: { name, version: meta.version, private: false, publishConfig: { access: "public" } },
}));
const run = (overrides) => {
  const releaseDir = path.join(mkdtempSync(path.join(tmpdir(), "oxdeai-baseline-")), "release");
  try {
    const receipt = precheck({ discovered: discovered(), releaseDir, sourceRevision: "a".repeat(40),
      gitTransport: { isClean: () => true }, sourceTransport: { snapshot: () => ({ root: "/fake", revision: "a".repeat(40), clean: true }) },
      packageTransport: fixturePackages, ...overrides });
    return { receipt, written: readdirSync(releaseDir) };
  } catch (error) {
    return { error, written: existsSync(releaseDir) ? readdirSync(releaseDir) : [] };
  } finally {
    rmSync(path.dirname(releaseDir), { recursive: true, force: true });
  }
};
const bump = (baseline, name, version) => structuredClone({ ...baseline, packages: { ...baseline.packages, [name]: { ...baseline.packages[name], version } } });

test("committed baseline is valid and records exactly the ten published npm versions", () => {
  const baseline = loadPublishedBaseline();
  assert.deepEqual(Object.fromEntries(Object.entries(baseline.packages).map(([n, e]) => [n, e.version])), NPM_PUBLISHED);
  assert.deepEqual(Object.keys(baseline.packages).sort(), Object.keys(POLICY).sort());
});

test("repository POLICY and package versions equal the published baseline (reconciled main)", () => {
  for (const [name, meta] of Object.entries(POLICY)) assert.equal(meta.version, NPM_PUBLISHED[name], name);
});

test("default PRECHECK refuses every already-published version and writes nothing", () => {
  const { error, written } = run({});
  assert.ok(error, "PRECHECK must fail");
  assert.deepEqual(written, []);
  for (const [name, version] of Object.entries(NPM_PUBLISHED)) {
    assert.ok(error.blockers.includes(error.blockers.find(b => b.startsWith(`RELEASE_VERSION_ALREADY_PUBLISHED: ${name}@${version} `))), `${name}@${version}`);
  }
});

test("a single reused version is enough to refuse PRECHECK", () => {
  const baseline = bump(PRE_R3_PUBLISHED_BASELINE, "@oxdeai/guard", "2.0.5");
  const { error, written } = run({ publishedBaseline: baseline });
  assert.deepEqual(error.blockers.filter(b => b.startsWith("RELEASE_VERSION_")),
    [`RELEASE_VERSION_ALREADY_PUBLISHED: @oxdeai/guard@2.0.5 is already published (${baseline.packages["@oxdeai/guard"].integrity}); choose a new version`]);
  assert.deepEqual(written, []);
});

test("a downgrade below the published version is refused", () => {
  const baseline = bump(PRE_R3_PUBLISHED_BASELINE, "@oxdeai/cli", "0.4.0");
  const { error } = run({ publishedBaseline: baseline });
  assert.deepEqual(error.blockers.filter(b => b.startsWith("RELEASE_VERSION_")),
    ["RELEASE_VERSION_DOWNGRADE: @oxdeai/cli@0.3.3 is lower than the published 0.4.0"]);
});

test("a package missing from the baseline is refused", () => {
  const baseline = structuredClone(PRE_R3_PUBLISHED_BASELINE);
  delete baseline.packages["@oxdeai/openclaw"];
  const { error } = run({ publishedBaseline: baseline });
  assert.ok(error.blockers.some(b => b.startsWith("RELEASE_VERSION_BASELINE_MISSING: @oxdeai/openclaw ")));
});

test("versions strictly above the baseline pass the floor (pre-R3 registry state)", () => {
  const { receipt, error } = run({ publishedBaseline: PRE_R3_PUBLISHED_BASELINE });
  assert.equal(error, undefined, error?.message);
  assert.equal(receipt.ok, true);
});

test("malformed baselines fail closed", () => {
  const good = PRE_R3_PUBLISHED_BASELINE;
  const cases = [
    null, [], {},
    { ...good, extra: 1 },
    { ...good, baselineVersion: 2 },
    { ...good, registry: "https://example.invalid/" },
    { ...good, packages: {} },
    bump(good, "@oxdeai/core", "2.0"),
    bump(good, "@oxdeai/core", "^2.0.3"),
    { ...good, packages: { ...good.packages, "@oxdeai/core": { ...good.packages["@oxdeai/core"], integrity: "sha1-x" } } },
    { ...good, packages: { ...good.packages, "@oxdeai/core": { ...good.packages["@oxdeai/core"], extra: true } } },
  ];
  for (const c of cases) {
    assert.throws(() => validatePublishedBaseline(c), /invalid published-version baseline/);
    const { error, written } = run({ publishedBaseline: c });
    assert.ok(error, JSON.stringify(c)?.slice(0, 80));
    assert.deepEqual(written, []);
  }
});

test("SemVer precedence used by the floor", () => {
  const ordered = ["0.3.3", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "2.0.5", "2.0.6-rc.1", "2.0.6", "2.1.0", "10.0.0"];
  for (let i = 0; i < ordered.length; i++) {
    for (let j = 0; j < ordered.length; j++) assert.equal(compareVersions(ordered[i], ordered[j]), Math.sign(i - j), `${ordered[i]} vs ${ordered[j]}`);
  }
  assert.equal(compareVersions("2.0.5+build.1", "2.0.5"), 0);
  assert.throws(() => compareVersions("2.0", "2.0.5"));
  assert.deepEqual(publishedVersionBlockers({ "@oxdeai/guard": { version: "2.0.6-rc.1" } }, bump(PRE_R3_PUBLISHED_BASELINE, "@oxdeai/guard", "2.0.5")).length, 0);
});

test("real CLI precheck on this checkout refuses the already-published versions and creates no release directory", () => {
  const releaseDir = path.join(mkdtempSync(path.join(tmpdir(), "oxdeai-baseline-cli-")), "release");
  try {
    const r = spawnSync(process.execPath, [path.join(ROOT, "scripts/release-2.0/orchestrator.mjs"), "precheck", "--release-dir", releaseDir], { encoding: "utf8", cwd: ROOT });
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stderr, /RELEASE_VERSION_ALREADY_PUBLISHED: @oxdeai\/guard@2\.0\.5 /);
    assert.equal(existsSync(releaseDir), false);
  } finally {
    rmSync(path.dirname(releaseDir), { recursive: true, force: true });
  }
});
