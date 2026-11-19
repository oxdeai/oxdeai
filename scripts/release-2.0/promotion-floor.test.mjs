// SPDX-License-Identifier: Apache-2.0
// `latest` promotion floor (R3 reconciliation). Hermetic: real frozen tarballs
// on disk, an in-memory dist-tag registry behind an injected transport. No npm,
// no subprocess, no network. Every refusal is checked for zero effects and an
// unchanged persisted state.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { POLICY } from "../verify-packed-artifacts.mjs";
import { RELEASE_REGISTRY_REQUIREMENTS } from "./auth-precheck.mjs";
import { persistFixturePrecheck } from "./precheck-fixture.mjs";
import {
  MANIFEST_FILENAME, MANIFEST_VERSION, STATE_FILENAME, STATE_VERSION,
  computeManifestIntegrity, computeSriIntegrity, publicationPackages, validateState,
} from "./orchestrator.mjs";
import { promoteLatest } from "./release-finalization.mjs";
import { assertLatestPromotionAllowed, readPackedPackageJson, PromotionFloorError } from "./promotion-floor.mjs";
import { makePackedTarball, makeTarball } from "./tarball-fixture.mjs";

const REGISTRY = RELEASE_REGISTRY_REQUIREMENTS.registry;
const GUARD = "@oxdeai/guard";

// `tarballVersion` lets a test freeze a tarball whose package.json disagrees with
// the manifest (the manifest records that tarball's real integrity).
function fixture(t, { latest = {}, tarballVersion = {} } = {}) {
  const releaseDir = fs.mkdtempSync(path.join(tmpdir(), "oxdeai-promotion-floor-"));
  t.after(() => fs.rmSync(releaseDir, { recursive: true, force: true }));
  const revision = "b".repeat(40);
  const discovered = Object.entries(POLICY).map(([name, p]) => ({ name, dir: `/fake/${name.slice(8)}`,
    manifest: { name, version: p.version } }));
  const precheck = persistFixturePrecheck(discovered, path.join(releaseDir, "precheck"), revision, "/fake");
  fs.mkdirSync(path.join(releaseDir, "tarballs"));
  const packages = discovered.map((d) => {
    const p = POLICY[d.name];
    const bytes = makePackedTarball({ name: d.name, version: tarballVersion[d.name] ?? p.version });
    const tarball = `tarballs/${d.name.slice(8)}.tgz`;
    fs.writeFileSync(path.join(releaseDir, tarball), bytes);
    return { package: d.name, version: p.version, releaseLine: p.releaseLine, publishOrder: p.publishOrder,
      tarball, integrity: computeSriIntegrity(bytes) };
  });
  const manifest = { manifestVersion: MANIFEST_VERSION, releaseId: revision, sourceRevision: revision,
    createdAt: "2026-11-18T00:00:00.000Z", packages, precheck };
  manifest.manifestIntegrity = computeManifestIntegrity(manifest);
  const state = { stateVersion: STATE_VERSION, releaseId: revision, phase: "READY_TO_PROMOTE",
    history: [{ phase: "PRECHECK", at: precheck.observedAt, receiptDigest: precheck.receiptDigest },
      ...["PACKED", "VERIFIED_LOCAL", "PUBLISHING_NEXT", "PUBLISHED_NEXT", "REGISTRY_VERIFIED",
        "EXTERNAL_INSTALL_VERIFIED", "READY_TO_PROMOTE"].map((phase) => ({ phase, at: manifest.createdAt }))],
    packages: Object.fromEntries(packages.map((p) => [p.package,
      { publishStatus: "published", registryIntegrity: p.integrity, registryVerified: true, externalInstallVerified: true }])) };
  validateState(manifest, state);
  fs.writeFileSync(path.join(releaseDir, MANIFEST_FILENAME), JSON.stringify(manifest));
  fs.writeFileSync(path.join(releaseDir, STATE_FILENAME), JSON.stringify(state));
  const tags = new Map(packages.map((p) => [p.package, { latest: latest[p.package] ?? "1.9.9", next: p.version }]));
  const f = { manifest, state, releaseDir, tags, effects: [], observations: [] };
  f.distTagTransport = {
    observeDistTag({ registry, package: name, tag }) {
      f.observations.push([name, tag]);
      if (f.onObserve) return f.onObserve({ registry, name, tag });
      const version = f.tags.get(name)?.[tag];
      return version === undefined ? { registry, package: name, tag, present: false }
        : { registry, package: name, tag, present: true, version };
    },
    addDistTag(op) { f.effects.push(["add", op.package, op.version]); f.tags.get(op.package).latest = op.version; return { ok: true }; },
    removeDistTag(op) { f.effects.push(["rm", op.package]); delete f.tags.get(op.package).next; return { ok: true }; },
  };
  return f;
}
const entry = (f, name) => f.manifest.packages.find((p) => p.package === name);
const consent = (f, name, replaces) => ({ kind: "promotion-authorization", authorizationVersion: 1,
  releaseId: f.manifest.releaseId, manifestIntegrity: f.manifest.manifestIntegrity, package: name,
  version: entry(f, name).version, integrity: entry(f, name).integrity, registry: REGISTRY,
  tag: "latest", operation: "dist-tag-add", replaces });
const promote = (f, name, replaces) => promoteLatest({ manifest: f.manifest, state: f.state, releaseDir: f.releaseDir,
  registry: REGISTRY, distTagTransport: f.distTagTransport, package: name, authorization: consent(f, name, replaces) });
const stateBytes = (f) => fs.readFileSync(path.join(f.releaseDir, STATE_FILENAME), "utf8");

function assertRefused(f, name, replaces, code) {
  const before = stateBytes(f);
  assert.throws(() => promote(f, name, replaces), (e) => e.code === code || assert.fail(`${code} expected, got ${e.code}: ${e.message}`));
  assert.deepEqual(f.effects, [], "no dist-tag effect");
  assert.equal(stateBytes(f), before, "persisted state unchanged");
  assert.equal(f.state.phase, "READY_TO_PROMOTE");
}

// ── SemVer, not string order ──────────────────────────────────────────────

test("SemVer: 2.0.10 is promoted over latest 2.0.9 (string order would refuse it)", () => {
  const policy = { [GUARD]: { version: "2.0.10" } };
  const bytes = makePackedTarball({ name: GUARD, version: "2.0.10" });
  const p = { package: GUARD, version: "2.0.10", integrity: "sri", tarball: "tarballs/guard.tgz" };
  const args = { p, releaseDir: "/unused", readTarball: () => bytes, integrityOf: () => "sri", policy };
  assert.deepEqual(assertLatestPromotionAllowed({ ...args, current: "2.0.9" }), { candidate: "2.0.10", current: "2.0.9", alreadyCurrent: false });
  assert.equal(assertLatestPromotionAllowed({ ...args, current: "2.0.10" }).alreadyCurrent, true);
  assert.throws(() => assertLatestPromotionAllowed({ ...args, current: "2.0.11" }), { code: "LATEST_NOT_ADVANCING" });
  assert.throws(() => assertLatestPromotionAllowed({ ...args, current: "2.1.0" }), { code: "LATEST_NOT_ADVANCING" });
  const older = { ...args, policy: { [GUARD]: { version: "2.0.9" } }, p: { ...p, version: "2.0.9" },
    readTarball: () => makePackedTarball({ name: GUARD, version: "2.0.9" }) };
  assert.throws(() => assertLatestPromotionAllowed({ ...older, current: "2.0.10" }), { code: "LATEST_NOT_ADVANCING" });
});

test("promoteLatest: latest 2.0.40 is newer than 2.0.5 under SemVer and blocks the promotion despite consent", (t) => {
  const f = fixture(t, { latest: { [GUARD]: "2.0.40" } });
  assertRefused(f, GUARD, "2.0.40", "LATEST_NOT_ADVANCING");
});

test("promoteLatest: latest 2.0.4 is older than 2.0.5 and the promotion proceeds", (t) => {
  const f = fixture(t, { latest: { [GUARD]: "2.0.4" } });
  assert.equal(promote(f, GUARD, "2.0.4").effect, true);
  assert.deepEqual(f.effects, [["add", GUARD, "2.0.5"]]);
});

// ── explicit consent cannot override the floor ────────────────────────────

test("an explicit consent to replace a newer or equal-precedence latest is refused", (t) => {
  for (const latest of ["2.0.6", "2.1.0", "3.0.0"]) {
    const f = fixture(t, { latest: { [GUARD]: latest } });
    assertRefused(f, GUARD, latest, "LATEST_NOT_ADVANCING");
  }
  // Same precedence, different build metadata: not an advance either.
  const bytes = makePackedTarball({ name: GUARD, version: POLICY[GUARD].version });
  assert.throws(() => assertLatestPromotionAllowed({ p: { package: GUARD, version: POLICY[GUARD].version, integrity: "x" },
    current: `${POLICY[GUARD].version}+build.7`, releaseDir: "/unused", readTarball: () => bytes, integrityOf: () => "x" }),
  { code: "LATEST_NOT_ADVANCING" });
});

// ── registry changes between PRECHECK and promotion ───────────────────────

test("latest moved past the candidate after PRECHECK: promotion is refused with no effect", (t) => {
  const f = fixture(t, { latest: { [GUARD]: "2.0.3" } }); // state of the registry at PRECHECK
  f.tags.get(GUARD).latest = "2.0.6";                     // another release landed meanwhile
  assertRefused(f, GUARD, "2.0.6", "LATEST_NOT_ADVANCING");
  // The consent recorded for the PRECHECK-time value no longer matches either.
  assertRefused(f, GUARD, "2.0.3", "LATEST_NOT_ADVANCING");
});

test("latest observed at promotion time, not reused from an earlier observation", (t) => {
  const f = fixture(t, { latest: { [GUARD]: "2.0.3" } });
  let n = 0;
  f.onObserve = ({ registry, name, tag }) => ({ registry, package: name, tag, present: true,
    version: name === GUARD && tag === "latest" && ++n > 0 ? "2.0.7" : "1.0.0" });
  assertRefused(f, GUARD, "2.0.7", "LATEST_NOT_ADVANCING");
  assert.ok(n >= 1, "latest was re-read during promoteLatest");
});

test("latest already on the candidate (resumed run): converges with no effect", (t) => {
  const f = fixture(t, { latest: { [GUARD]: "2.0.5" } });
  assert.equal(promote(f, GUARD, "2.0.3").effect, false); // consent recorded the prior latest

  assert.deepEqual(f.effects, []);
  assert.equal(f.state.packages[GUARD].latestVerified, true);
});

// ── fail closed when latest cannot be established ─────────────────────────

test("registry unavailable or latest unverifiable: fail closed, no effect", (t) => {
  const cases = [
    ["throws", () => { throw new Error("ECONNRESET"); }],
    ["malformed", ({ registry, name, tag }) => ({ registry, package: name, tag, present: true })],
    ["wrong registry", ({ name, tag }) => ({ registry: "https://example.invalid/", package: name, tag, present: true, version: "1.0.0" })],
    ["not semver", ({ registry, name, tag }) => ({ registry, package: name, tag, present: true, version: "latest-ish" })],
    ["partial version", ({ registry, name, tag }) => ({ registry, package: name, tag, present: true, version: "2.0" })],
  ];
  for (const [label, onObserve] of cases) {
    const f = fixture(t);
    f.onObserve = onObserve;
    assertRefused(f, GUARD, "1.9.9", "DIST_TAG_STATE_UNDETERMINED");
    assert.ok(label);
  }
});

// ── candidate version comes from the frozen tarball ───────────────────────

test("tarball version differs from the manifest and POLICY: refused", (t) => {
  const f = fixture(t, { latest: { [GUARD]: "2.0.3" }, tarballVersion: { [GUARD]: "2.0.6" } });
  assertRefused(f, GUARD, "2.0.3", "TARBALL_VERSION_MISMATCH");
});

test("tarball replaced after the manifest was frozen: refused on integrity", (t) => {
  const f = fixture(t, { latest: { [GUARD]: "2.0.3" } });
  fs.writeFileSync(path.join(f.releaseDir, entry(f, GUARD).tarball), makePackedTarball({ name: GUARD, version: "2.0.5" }).subarray(0, 40));
  assertRefused(f, GUARD, "2.0.3", "TARBALL_INTEGRITY_MISMATCH");
});

test("tarball missing: refused", (t) => {
  const f = fixture(t, { latest: { [GUARD]: "2.0.3" } });
  fs.rmSync(path.join(f.releaseDir, entry(f, GUARD).tarball));
  assertRefused(f, GUARD, "2.0.3", "TARBALL_UNREADABLE");
});

test("manifest and tarball agree but POLICY differs: refused", () => {
  const bytes = makePackedTarball({ name: GUARD, version: "2.0.6" });
  assert.throws(() => assertLatestPromotionAllowed({ p: { package: GUARD, version: "2.0.6", integrity: "x" }, current: "2.0.5",
    releaseDir: "/unused", readTarball: () => bytes, integrityOf: () => "x" }), { code: "TARBALL_VERSION_MISMATCH" });
});

test("tarball and POLICY agree but the manifest records another version: refused", () => {
  const version = POLICY[GUARD].version;
  const bytes = makePackedTarball({ name: GUARD, version });
  assert.throws(() => assertLatestPromotionAllowed({ p: { package: GUARD, version: "2.0.6", integrity: "x" }, current: "2.0.3",
    releaseDir: "/unused", readTarball: () => bytes, integrityOf: () => "x" }), { code: "TARBALL_VERSION_MISMATCH" });
});

test("tarball declaring another package name: refused", () => {
  const bytes = makePackedTarball({ name: "@oxdeai/core", version: POLICY[GUARD].version });
  assert.throws(() => assertLatestPromotionAllowed({ p: { package: GUARD, version: POLICY[GUARD].version, integrity: "x" },
    current: null, releaseDir: "/unused", readTarball: () => bytes, integrityOf: () => "x" }), { code: "TARBALL_VERSION_MISMATCH" });
});

// ── prereleases never go to latest ────────────────────────────────────────

test("prerelease candidates are refused for latest, whatever the current latest", () => {
  for (const version of ["2.0.6-rc.1", "2.0.6-0", "3.0.0-beta"]) {
    const bytes = makePackedTarball({ name: GUARD, version });
    for (const current of [null, "2.0.5", "1.0.0"]) {
      assert.throws(() => assertLatestPromotionAllowed({ p: { package: GUARD, version, integrity: "x" }, current,
        releaseDir: "/unused", readTarball: () => bytes, integrityOf: () => "x", policy: { [GUARD]: { version } } }),
      { code: "LATEST_PRERELEASE_REFUSED" }, `${version} over ${current}`);
    }
  }
});

test("absent latest: a stable candidate may be promoted only with replaces: null consent", (t) => {
  const f = fixture(t);
  f.tags.get(GUARD).latest = undefined;
  assert.equal(promote(f, GUARD, null).effect, true);
  assert.deepEqual(f.effects, [["add", GUARD, "2.0.5"]]);
});

// ── tarball reader fails closed ───────────────────────────────────────────

test("tarball reader: only regular files, one package.json, valid archive", () => {
  const pj = JSON.stringify({ name: GUARD, version: "2.0.5" });
  assert.deepEqual(readPackedPackageJson(makeTarball([["package/package.json", pj]])), { name: GUARD, version: "2.0.5" });
  const bad = [
    ["symlink", makeTarball([["package/package.json", "", "2"]]), "TARBALL_UNSUPPORTED_ENTRY"],
    ["pax header", makeTarball([["PaxHeader", "30 path=package/package.json\n", "x"], ["package/x.json", pj]]), "TARBALL_UNSUPPORTED_ENTRY"],
    ["GNU long name", makeTarball([["././@LongLink", "package/package.json", "L"], ["package/x.json", pj]]), "TARBALL_UNSUPPORTED_ENTRY"],
    ["duplicate", makeTarball([["package/package.json", pj], ["package/package.json", pj]]), "TARBALL_UNSUPPORTED_ENTRY"],
    ["missing", makeTarball([["package/README.md", "x"]]), "TARBALL_UNREADABLE"],
    ["not json", makeTarball([["package/package.json", "{"]]), "TARBALL_UNREADABLE"],
    ["not gzip", Buffer.from("plain"), "TARBALL_UNREADABLE"],
  ];
  for (const [label, bytes, code] of bad) {
    assert.throws(() => readPackedPackageJson(bytes), (e) => e instanceof PromotionFloorError && e.code === code, label);
  }
});
