// SPDX-License-Identifier: Apache-2.0
// #343: the persisted PRECHECK receipt is the evidence PACK, VERIFY_LOCAL and
// readiness consume. Hermetic: package.json files and tarball bytes are local
// fixtures; git and the consumer-install gate are injected. No npm/registry.
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, unlinkSync } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { POLICY } from "../verify-packed-artifacts.mjs";
import {
  precheck, pack, verifyLocal, PRECHECK_FILENAME, MANIFEST_FILENAME, STATE_FILENAME,
  loadState, loadAndValidateManifest, validateState, evaluateReleaseReadiness,
  computeManifestIntegrity, computePrecheckReceiptDigest,
} from "./orchestrator.mjs";
import { observeRegistryPrecheck, RELEASE_REGISTRY_REQUIREMENTS } from "./auth-precheck.mjs";

const REVISION = "a".repeat(40);
const ORCHESTRATOR = new URL("./orchestrator.mjs", import.meta.url).href;

function writePackages(root) {
  return Object.entries(POLICY).map(([name, p]) => {
    const dir = path.join(root, name.slice(8)); mkdirSync(dir, { recursive: true });
    const manifest = { name, version: p.version };
    writeFileSync(path.join(dir, "package.json"), JSON.stringify(manifest));
    return { name, dir, manifest };
  });
}

function fixture(t, { persist = true } = {}) {
  const root = mkdtempSync(path.join(tmpdir(), "oxdeai-precheck-binding-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const releaseDir = path.join(root, "release");
  const discovered = writePackages(root);
  const source = { root, revision: REVISION, clean: true };
  const args = { discovered, releaseDir, sourceRevision: REVISION,
    gitTransport: { isClean: () => source.clean }, sourceTransport: { snapshot: () => ({ ...source }) } };
  let calls = 0, duringPack = () => {};
  const packTransport = { packToDir(d, dest) {
    calls++; duringPack(d);
    const file = path.join(dest, `${d.name.slice(8)}.tgz`); writeFileSync(file, d.name); return file;
  } };
  if (persist) precheck(args);
  const receiptFile = path.join(releaseDir, PRECHECK_FILENAME);
  return {
    args, source, root, receiptFile,
    get calls() { return calls; }, set duringPack(fn) { duringPack = fn; },
    run: () => pack({ ...args, packTransport }),
    receipt: () => JSON.parse(readFileSync(receiptFile, "utf8")),
    edit(mutate, { redigest = false } = {}) {
      const r = this.receipt(); mutate(r);
      if (redigest) r.receiptDigest = computePrecheckReceiptDigest(r);
      writeFileSync(receiptFile, JSON.stringify(r));
    },
  };
}

// ── PRECHECK persistence ─────────────────────────────────────────────────

test("PRECHECK persists the observations it actually made", t => {
  const f = fixture(t, { persist: false });
  const returned = precheck({ ...f.args, now: () => "2026-10-06T00:00:00.000Z" });
  const receipt = f.receipt();
  assert.deepEqual(receipt, returned);
  assert.equal(receipt.ok, true);
  assert.equal(receipt.sourceRevision, REVISION);
  assert.deepEqual(receipt.source, { root: f.root, revision: REVISION, clean: true });
  assert.equal(receipt.workingTreeClean, true);
  assert.equal(receipt.releaseDir, f.args.releaseDir);
  assert.equal(receipt.observedAt, "2026-10-06T00:00:00.000Z");
  assert.deepEqual(receipt.discovered.map(d => [d.name, d.manifest.version]),
    Object.entries(POLICY).map(([name, p]) => [name, p.version]).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
  for (const d of receipt.discovered) assert.match(d.packageJsonDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(receipt.receiptDigest, computePrecheckReceiptDigest(receipt));
  assert.ok(!Object.hasOwn(receipt, "signature"));
});

test("dirty PRECHECK persists no receipt", t => {
  const f = fixture(t, { persist: false }); f.source.clean = false;
  assert.throws(() => precheck(f.args), /dirty working tree/);
  assert.equal(existsSync(f.receiptFile), false);
});

test("PRECHECK fails closed when its receipt cannot be persisted", t => {
  const f = fixture(t, { persist: false });
  writeFileSync(f.args.releaseDir, "not a directory");
  assert.throws(() => precheck(f.args), /could not persist its receipt; PRECHECK did not pass/);
});

test("PRECHECK never replaces an existing receipt", t => {
  const f = fixture(t); const first = readFileSync(f.receiptFile);
  assert.throws(() => precheck(f.args), /refuses existing release evidence/);
  assert.deepEqual(readFileSync(f.receiptFile), first);
});

test("PRECHECK requires a release directory and an exact revision", t => {
  const f = fixture(t, { persist: false });
  assert.throws(() => precheck({ ...f.args, releaseDir: undefined }), /requires a releaseDir/);
  assert.throws(() => precheck({ ...f.args, sourceRevision: "HEAD" }), /40-hex sourceRevision/);
});

// ── PACK consumes the receipt, fail-closed ──────────────────────────────

for (const [label, mutate, expected] of [
  ["missing receipt", f => unlinkSync(f.receiptFile), /run PRECHECK for this release directory first/],
  ["malformed receipt JSON", f => writeFileSync(f.receiptFile, "{"), /receipt is invalid/],
  ["malformed receipt structure", f => f.edit(r => { delete r.discovered; }, { redigest: true }), /discovered packages/],
  ["unsupported receipt version", f => f.edit(r => { r.receiptVersion = 2; }, { redigest: true }), /receiptVersion/],
  ["tampered receipt", f => f.edit(r => { r.observedAt = "2020-01-01T00:00:00.000Z"; }), /receiptDigest does not match/],
  ["tampered clean-tree observation", f => f.edit(r => { r.workingTreeClean = false; }), /clean-tree observation/],
  ["internally inconsistent revision", f => f.edit(r => { r.source.revision = "b".repeat(40); }, { redigest: true }), /source observation/],
  ["recorded dirty source", f => f.edit(r => { r.source.clean = false; }, { redigest: true }), /source observation/],
  ["source revision mismatch", f => { f.source.revision = f.args.sourceRevision = "b".repeat(40); }, /source revision a{40} != b{40}/],
  ["another checkout", f => { f.source.root = path.dirname(f.root); },
    /PACK PRECHECK receipt does not match this candidate: checkout \S+ != \S+/],
  ["stale receipt from another release directory", f => {
    const other = path.join(f.root, "other-release"); mkdirSync(other);
    writeFileSync(path.join(other, PRECHECK_FILENAME), readFileSync(f.receiptFile)); f.args.releaseDir = other;
  }, /release directory/],
  ["stale receipt: package.json changed", f => {
    const d = f.args.discovered[0]; writeFileSync(path.join(d.dir, "package.json"), JSON.stringify(d.manifest) + "\n");
  }, /package\.json changed since PRECHECK/],
  ["package-set mismatch", f => f.edit(r => { r.discovered.pop(); }, { redigest: true }), /package set/],
  ["package-version mismatch", f => f.edit(r => { r.discovered[0].manifest.version = "9.9.9"; }, { redigest: true }), /version 9\.9\.9 !=/],
  ["dirty source at PACK (#344)", f => { f.source.clean = false; }, /not clean/],
]) {
  test(`PACK rejects ${label} before any packing`, t => {
    const f = fixture(t); mutate(f);
    assert.throws(f.run, expected);
    assert.equal(f.calls, 0);
    assert.equal(existsSync(path.join(f.args.releaseDir, MANIFEST_FILENAME)), false);
  });
}

test("PACK rejects package.json changes made while packing; no identity recorded", t => {
  const f = fixture(t);
  const d = f.args.discovered.at(-1);
  f.duringPack = () => writeFileSync(path.join(d.dir, "package.json"), JSON.stringify({ ...d.manifest, private: false }));
  assert.throws(f.run, /changed while packing.*package\.json changed since PRECHECK/s);
  assert.equal(existsSync(path.join(f.args.releaseDir, MANIFEST_FILENAME)), false);
});

test("PACK rejects a receipt produced under a different POLICY before packing", t => {
  const f = fixture(t);
  f.args.policy = structuredClone(POLICY);
  f.args.policy["@oxdeai/core"].expectedSymbols.push("ChangedAfterPrecheck");
  assert.throws(f.run, /^ReleaseOrchestratorError: PACK PRECHECK receipt does not match this candidate: release POLICY changed since PRECHECK$/);
  assert.equal(f.calls, 0);
  assert.equal(existsSync(path.join(f.args.releaseDir, MANIFEST_FILENAME)), false);
});

test("PACK rejects a POLICY change made while packing; no identity recorded", t => {
  const f = fixture(t);
  f.args.policy = structuredClone(POLICY); // same content and digest as at PRECHECK
  f.duringPack = () => { f.args.policy["@oxdeai/core"].expectedSymbols.push("ChangedWhilePacking"); };
  assert.throws(f.run, /changed while packing.*release POLICY changed since PRECHECK/s);
  assert.ok(f.calls > 0);
  assert.equal(existsSync(path.join(f.args.releaseDir, MANIFEST_FILENAME)), false);
});

test("PACK freezes the actual receipt and derives the PRECHECK history entry from it", t => {
  const f = fixture(t); const receipt = f.receipt();
  const { manifest, state } = f.run();
  assert.deepEqual(manifest.precheck, receipt);
  assert.deepEqual(state.history[0], { phase: "PRECHECK", at: receipt.observedAt, receiptDigest: receipt.receiptDigest });
  assert.deepEqual(loadAndValidateManifest(f.args.releaseDir), manifest);
});

// ── VERIFY_LOCAL preserves and checks the bound provenance ──────────────

// Each rejection below happens before the real consumer gate runs; there is
// no way to substitute that gate.
function packed(t) {
  const f = fixture(t); const result = f.run();
  return { f, ...result, verify: () => verifyLocal({ discovered: f.args.discovered, manifest: result.manifest,
    state: result.state, releaseDir: f.args.releaseDir }) };
}
for (const [label, mutate, expected] of [
  ["missing persisted receipt", p => unlinkSync(p.f.receiptFile), /persisted PRECHECK receipt .* is required/],
  ["tampered persisted receipt", p => p.f.edit(r => { r.observedAt = "2020-01-01T00:00:00.000Z"; }), /receiptDigest does not match/],
  ["persisted receipt replaced by another valid one", p => p.f.edit(r => { r.observedAt = "2020-01-01T00:00:00.000Z"; }, { redigest: true }),
    /differs from the one bound at PACK/],
  ["synthesized PRECHECK history", p => { p.state.history[0].at = p.manifest.createdAt; }, /PRECHECK evidence binding mismatch: release state PRECHECK history/],
  ["unbound PRECHECK history", p => { delete p.state.history[0].receiptDigest; }, /PRECHECK evidence binding mismatch/],
  ["manifest without PRECHECK evidence", p => {
    delete p.manifest.precheck; p.manifest.manifestIntegrity = computeManifestIntegrity(p.manifest);
  }, /VERIFY_LOCAL requires PRECHECK evidence/],
  ["manifest receipt bound to another revision", p => {
    p.manifest.precheck.sourceRevision = p.manifest.precheck.source.revision = "b".repeat(40);
    p.manifest.precheck.receiptDigest = computePrecheckReceiptDigest(p.manifest.precheck);
    p.state.history[0].receiptDigest = p.manifest.precheck.receiptDigest;
  }, /binding mismatch: source revision/],
]) {
  test(`VERIFY_LOCAL rejects ${label}`, t => {
    const p = packed(t); mutate(p);
    assert.throws(p.verify, expected);
    assert.equal(loadState(p.f.args.releaseDir).phase, "PACKED");
  });
}

// ── Legacy (pre-#343) frozen candidates ─────────────────────────────────
//
// A manifest frozen before #343 has no receipt. It stays loadable for
// historical inspection, can never become VERIFIED_LOCAL or READY, and
// PRECHECK/PACK refuse to regenerate it. Fixture only; no real release dir.

function legacyCandidate(t) {
  const f = fixture(t); const { manifest, state } = f.run();
  delete manifest.precheck; manifest.manifestIntegrity = computeManifestIntegrity(manifest);
  state.history[0] = { phase: "PRECHECK", at: manifest.createdAt }; // the pre-#343 shape
  unlinkSync(f.receiptFile);
  writeFileSync(path.join(f.args.releaseDir, MANIFEST_FILENAME), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(path.join(f.args.releaseDir, STATE_FILENAME), `${JSON.stringify(state, null, 2)}\n`);
  return f;
}

test("legacy manifest without PRECHECK evidence stays inspectable but never verifiable, ready or regenerable", t => {
  const f = legacyCandidate(t); const dir = f.args.releaseDir;
  const manifest = loadAndValidateManifest(dir), state = loadState(dir);
  assert.equal(manifest.precheck, undefined);
  assert.equal(validateState(manifest, state), state);
  // A later historical phase (the real frozen 2.0 candidate is PROMOTED) still validates.
  const promoted = { ...structuredClone(state), phase: "PROMOTED",
    packages: Object.fromEntries(manifest.packages.map(p => [p.package, { publishStatus: "published", registryVerified: true, externalInstallVerified: true }])) };
  assert.equal(validateState(manifest, promoted), promoted);

  const before = readFileSync(path.join(dir, STATE_FILENAME));
  assert.throws(() => verifyLocal({ discovered: f.args.discovered, manifest, state, releaseDir: dir }),
    /^ReleaseOrchestratorError: VERIFY_LOCAL requires PRECHECK evidence bound to the packed candidate$/);
  assert.deepEqual(readFileSync(path.join(dir, STATE_FILENAME)), before);

  const verified = { ...structuredClone(state), phase: "VERIFIED_LOCAL",
    history: [...state.history, { phase: "VERIFIED_LOCAL", at: manifest.createdAt }] };
  const result = evaluateReleaseReadiness({ manifest, state: verified, authPrecheck: positiveAuth(),
    localPrecheck: { ok: true, discovered: f.args.discovered } });
  assert.equal(result.kind, "not-ready");
  assert.ok(result.reasons.some(r => r.code === "LOCAL_PRECHECK_NOT_PASSED"), JSON.stringify(result));

  assert.throws(() => precheck(f.args), /PRECHECK refuses existing release evidence: release-manifest\.json/);
  assert.equal(existsSync(f.receiptFile), false);
  const packCalls = f.calls;
  assert.throws(f.run, /Repacking\/reconstruction of an existing release identity is forbidden/);
  assert.equal(f.calls, packCalls);
  assert.deepEqual(loadAndValidateManifest(dir), manifest);
});

// ── Lifecycle across process boundaries ─────────────────────────────────
//
// Each phase runs in its own Node process against the same release directory,
// so only persisted evidence crosses phases. Nothing here constructs
// localPrecheck or any PRECHECK/PACKED/VERIFIED_LOCAL history. Injected: the
// git observation (fixture checkout) and tarball bytes. A positive
// VERIFY_LOCAL needs the real consumer gate on real artifacts, which cannot
// be substituted; that path is orchestrator.local.test.mjs. Here readiness is
// evaluated on the persisted PACKED candidate: the receipt must be accepted
// and local verification must be the only thing missing.

function positiveAuth() {
  const registry = RELEASE_REGISTRY_REQUIREMENTS.registry, names = Object.keys(POLICY);
  return observeRegistryPrecheck({ discovered: names.map(name => ({ name })), authTransport: {
    whoami: () => ({ kind: "identity", registry, username: "maintainer" }),
    listPackageAccess: subject => ({ kind: "access", registry, subject, packages: Object.fromEntries(names.map(n => [n, "read-write"])) }),
    getPackageStatus: packageName => ({ kind: "existing", registry, packageName, visibility: "public" }),
  } });
}

function phase(root, body) {
  const script = `
    import { readdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
    import path from "node:path";
    import * as o from ${JSON.stringify(ORCHESTRATOR)};
    const root = ${JSON.stringify(root)}, releaseDir = path.join(root, "release"), sourceRevision = ${JSON.stringify(REVISION)};
    const discovered = readdirSync(root).filter(n => existsSync(path.join(root, n, "package.json"))).map(n => {
      const manifest = JSON.parse(readFileSync(path.join(root, n, "package.json"), "utf8"));
      return { name: manifest.name, dir: path.join(root, n), manifest };
    });
    const sourceTransport = { snapshot: () => ({ root, revision: sourceRevision, clean: true }) };
    const packTransport = { packToDir(d, dest) { const f = path.join(dest, d.name.slice(8) + ".tgz"); writeFileSync(f, d.name); return f; } };
    const out = v => process.stdout.write(JSON.stringify(v));
    ${body}`;
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout ? JSON.parse(r.stdout) : undefined;
}

test("lifecycle: PRECHECK -> PACK -> readiness consume the receipt PRECHECK persisted", t => {
  const root = mkdtempSync(path.join(tmpdir(), "oxdeai-precheck-e2e-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  writePackages(root);
  const releaseDir = path.join(root, "release");

  phase(root, `o.precheck({ discovered, releaseDir, sourceRevision, sourceTransport, gitTransport: { isClean: () => true } });`);
  const receipt = JSON.parse(readFileSync(path.join(releaseDir, PRECHECK_FILENAME), "utf8"));
  assert.equal(receipt.workingTreeClean, true);

  phase(root, `o.pack({ discovered, releaseDir, sourceRevision, sourceTransport, packTransport });`);
  const manifest = loadAndValidateManifest(releaseDir), state = loadState(releaseDir);
  assert.deepEqual(manifest.precheck, receipt);
  assert.deepEqual(state.history, [
    { phase: "PRECHECK", at: receipt.observedAt, receiptDigest: receipt.receiptDigest },
    { phase: "PACKED", at: state.history[1].at },
  ]);

  const authPrecheck = positiveAuth();
  const result = phase(root, `
    const authPrecheck = ${JSON.stringify(authPrecheck)};
    const manifest = o.loadAndValidateManifest(releaseDir), state = o.loadState(releaseDir);
    const persisted = o.evaluateReleaseReadiness({ manifest, state, authPrecheck });
    // Caller-asserted local evidence cannot replace the persisted receipt.
    const stripped = structuredClone(manifest); delete stripped.precheck;
    stripped.manifestIntegrity = o.computeManifestIntegrity(stripped);
    const substituted = o.evaluateReleaseReadiness({ manifest: stripped, state, authPrecheck, localPrecheck: { ok: true, discovered } });
    out({ persisted, substituted });`);

  // The persisted receipt is accepted; only the not-yet-run VERIFY_LOCAL blocks readiness.
  assert.equal(result.persisted.kind, "not-ready");
  assert.deepEqual([...new Set(result.persisted.reasons.map(r => r.code))].sort(),
    ["PACKED_ARTIFACTS_NOT_VERIFIED", "PUBLICATION_PLANNING_STATE_INVALID"], JSON.stringify(result.persisted));
  assert.ok(result.substituted.reasons.some(r => r.code === "LOCAL_PRECHECK_NOT_PASSED"));
  // Readiness is evaluation only: it persisted nothing.
  assert.deepEqual(loadState(releaseDir), state);
});
