// SPDX-License-Identifier: Apache-2.0
// R3 release completeness. For a release whose Guard carries the adapter
// security floor, a partial selection is refused at PRECHECK (Round 3) and,
// since R4 (F-R4-1), also by receipt validation (so PACK and VERIFY_LOCAL) and
// by publication planning. The receipt digest is not authentication, so a
// receipt edited to add a selection must not get past PRECHECK's absence. Full
// mode and pre-R3 (below-floor) policies are not affected.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { POLICY, GUARD_PACKAGE, GUARD_SECURITY_FLOOR, GUARD_FLOOR_PACKAGES, discoverPublishablePackages } from "../verify-packed-artifacts.mjs";
import { forgeSelectionReceipt, persistFixturePrecheck } from "./precheck-fixture.mjs";
import { fixturePlan } from "./publication-fixture.mjs";
import {
  F2_CLI1_SELECTION, MANIFEST_FILENAME, PRECHECK_FILENAME, ROOT, STATE_FILENAME, assertCompleteReleaseSelection,
  computeManifestIntegrity, computePrecheckReceiptDigest, loadAndValidateManifest, pack, publicationPackages,
  readPrecheckReceipt, releasesGuardSecurityFloor, validatePrecheckReceipt, validateState, verifyLocal,
} from "./orchestrator.mjs";

const COMPLETENESS = /R3 release completeness/;
const fullSelection = (policy = POLICY) => Object.entries(policy).map(([name, p]) => ({ package: name, version: p.version }));
const withGuard = (version) => { const p = structuredClone(POLICY); p[GUARD_PACKAGE].version = version; return p; };
function tempDir(t) {
  const dir = fs.mkdtempSync(path.join(tmpdir(), "oxdeai-completeness-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

// A pre-R3 (R2-era) policy: Guard 2.0.4 is below the floor; its adapters were 2.0.0.
const PRE_R3_POLICY = (() => {
  const p = withGuard("2.0.4");
  p["@oxdeai/conformance"].version = "2.0.3";
  for (const name of GUARD_FLOOR_PACKAGES) p[name].version = "2.0.0";
  return p;
})();
const PRE_R3_SELECTION = [["@oxdeai/core", "2.0.3"], ["@oxdeai/guard", "2.0.4"], ["@oxdeai/sdk", "2.0.3"],
  ["@oxdeai/conformance", "2.0.3"], ["@oxdeai/cli", "0.3.3"]].map(([n, v]) => ({ package: n, version: v }));

// ── Classification ──────────────────────────────────────────────────────────

test("this checkout's POLICY is an R3 release (Guard carries the security floor)", () => {
  assert.equal(POLICY[GUARD_PACKAGE].version, GUARD_SECURITY_FLOOR.version);
  assert.equal(releasesGuardSecurityFloor(POLICY), true);
});

for (const [version, expected] of [
  ["2.0.5", true], ["2.0.6", true], ["2.1.0", true], ["3.0.0", true],
  ["2.0.4", false], ["2.0.0", false], ["1.9.9", false], ["2.0.5-rc.1", false],
  ["not-a-version", true], ["", true], [undefined, true],
]) {
  test(`Guard ${JSON.stringify(version)} ${expected ? "is" : "is not"} treated as an R3 release${expected && !/^\d/.test(version ?? "") ? " (fail closed)" : ""}`, () => {
    assert.equal(releasesGuardSecurityFloor(withGuard(version)), expected);
  });
}

// ── Positive ────────────────────────────────────────────────────────────────

test("positive: full mode (no selection) passes the real PRECHECK and persists a receipt without selection", (t) => {
  const dir = tempDir(t);
  const receipt = persistFixturePrecheck(discoverPublishablePackages(), dir, "c".repeat(40), ROOT);
  assert.equal(receipt.selection, undefined);
  assert.deepEqual(receipt.discovered.map((d) => d.name).sort(), Object.keys(POLICY).sort());
  assert.ok(fs.existsSync(path.join(dir, PRECHECK_FILENAME)));
});

test("positive: a selection naming all ten packages at their POLICY versions satisfies the rule (any order)", () => {
  assert.doesNotThrow(() => assertCompleteReleaseSelection(undefined));
  assert.doesNotThrow(() => assertCompleteReleaseSelection(fullSelection()));
  assert.doesNotThrow(() => assertCompleteReleaseSelection(fullSelection().reverse()));
});

// ── Negative ────────────────────────────────────────────────────────────────

test("negative: the real PRECHECK refuses --selection=f2-cli1 and writes nothing", (t) => {
  const dir = tempDir(t);
  assert.throws(() => persistFixturePrecheck(discoverPublishablePackages(), dir, "c".repeat(40), ROOT, { selection: F2_CLI1_SELECTION }),
    (e) => COMPLETENESS.test(e.message) && GUARD_FLOOR_PACKAGES.every((n) => e.message.includes(`${n}@${POLICY[n].version}`)));
  assert.deepEqual(fs.readdirSync(dir), []);
});

for (const omitted of Object.keys(POLICY)) {
  test(`negative: a selection omitting ${omitted} is refused and names it`, () => {
    const selection = fullSelection().filter((e) => e.package !== omitted);
    assert.throws(() => assertCompleteReleaseSelection(selection),
      (e) => COMPLETENESS.test(e.message) && e.message.includes(`omits ${omitted}@${POLICY[omitted].version}.`));
  });
}

for (const [label, mutate] of [
  ["an adapter at its published 2.0.0", (s) => { s.find((e) => e.package === "@oxdeai/langgraph").version = "2.0.0"; }],
  ["Guard at the unpublished 2.0.4", (s) => { s.find((e) => e.package === GUARD_PACKAGE).version = "2.0.4"; }],
  ["an empty selection", (s) => { s.length = 0; }],
  ["a duplicated entry replacing an adapter", (s) => { s[s.findIndex((e) => e.package === "@oxdeai/crewai")] = { ...s[0] }; }],
]) {
  test(`negative: ${label} is refused`, () => {
    const selection = fullSelection();
    mutate(selection);
    assert.throws(() => assertCompleteReleaseSelection(selection), COMPLETENESS);
  });
}

test("negative: a non-array selection is refused", () => {
  for (const selection of [null, {}, "f2-cli1", 5]) {
    assert.throws(() => assertCompleteReleaseSelection(selection), COMPLETENESS);
  }
});

test("negative: a later Guard above the floor is still held to completeness", () => {
  for (const version of ["2.0.6", "2.1.0"]) {
    assert.throws(() => assertCompleteReleaseSelection(F2_CLI1_SELECTION, withGuard(version)), COMPLETENESS);
  }
});

test("negative: the real CLI `precheck --selection=f2-cli1` exits non-zero before persisting anything", (t) => {
  const dir = tempDir(t);
  const releaseDir = path.join(dir, "release");
  const r = spawnSync(process.execPath, [path.join(ROOT, "scripts/release-2.0/orchestrator.mjs"), "precheck",
    "--selection=f2-cli1", "--release-dir", releaseDir], { cwd: ROOT, encoding: "utf8" });
  assert.notEqual(r.status, 0);
  assert.match(r.stdout + r.stderr, COMPLETENESS);
  assert.doesNotMatch(r.stdout, /PRECHECK \(local\): PASS/);
  assert.equal(fs.existsSync(releaseDir), false);
});

// ── Backward compatibility ──────────────────────────────────────────────────

test("compat: a pre-R3 policy (Guard 2.0.4 below the floor) keeps its five-package selection behaviour", () => {
  assert.equal(releasesGuardSecurityFloor(PRE_R3_POLICY), false);
  assert.doesNotThrow(() => assertCompleteReleaseSelection(PRE_R3_SELECTION, PRE_R3_POLICY));
  assert.doesNotThrow(() => assertCompleteReleaseSelection(undefined, PRE_R3_POLICY));
});

test("compat: the fixed f2-cli1 profile itself is unchanged by the rule", () => {
  assert.deepEqual(F2_CLI1_SELECTION.map((e) => e.package),
    ["@oxdeai/core", "@oxdeai/guard", "@oxdeai/sdk", "@oxdeai/conformance", "@oxdeai/cli"]);
  assert.ok(Object.isFrozen(F2_CLI1_SELECTION));
});

test("compat: full-mode receipts and manifests are unaffected by the downstream checks", (t) => {
  const dir = tempDir(t);
  const receipt = persistFixturePrecheck(discoverPublishablePackages(), dir, "d".repeat(40), ROOT);
  assert.doesNotThrow(() => validatePrecheckReceipt(receipt));
  assert.deepEqual(readPrecheckReceipt(dir), receipt);
  const manifest = { packages: Object.entries(POLICY).map(([name, p]) => ({ package: name, version: p.version,
    releaseLine: p.releaseLine, publishOrder: p.publishOrder })), precheck: receipt };
  assert.equal(publicationPackages(manifest).length, 10);
});

test("compat: PRECHECK still reports an external-dependency selection error before completeness", (t) => {
  const dir = tempDir(t);
  const discovered = discoverPublishablePackages().map((d) => d.name !== "@oxdeai/sdk" ? d
    : { ...d, manifest: { ...d.manifest, dependencies: { ...d.manifest.dependencies, "left-pad": "1.3.0" } } });
  assert.throws(() => persistFixturePrecheck(discovered, dir, "e".repeat(40), ROOT, { selection: F2_CLI1_SELECTION }),
    /external dependency resolution required: left-pad@1\.3\.0/);
});

// ── Downstream enforcement (R4, F-R4-1) ─────────────────────────────────────
// A forged receipt is the real full-mode PRECHECK receipt with `selection`
// inserted and the consistency digest recomputed; nothing else differs.

const FAKE_ROOT = "/fake";
const REVISION = "f".repeat(40);
const hermeticDiscovered = () => Object.entries(POLICY).map(([name, p]) => ({ name, dir: `/fake/${name.slice(8)}`,
  manifest: { name, version: p.version, ...(name === "@oxdeai/core" ? {} : { dependencies: { "@oxdeai/core": "workspace:*" } }) } }));
const snapshot = { snapshot: () => ({ root: FAKE_ROOT, revision: REVISION, clean: true }) };
const listTree = (dir) => fs.readdirSync(dir, { recursive: true }).sort();
function fakePack(calls) {
  return { packToDir(d, dir) { calls.push(d.name); const file = path.join(dir, `${d.name.slice(8)}.tgz`); fs.writeFileSync(file, d.name); return file; } };
}
// Edits the persisted receipt in place (as an attacker with write access to the
// release directory could): selection inserted, digest recomputed.
function forgeInPlace(releaseDir) {
  const file = path.join(releaseDir, PRECHECK_FILENAME);
  const { receiptDigest, ...rest } = JSON.parse(fs.readFileSync(file, "utf8"));
  const forged = { ...rest, selection: structuredClone(F2_CLI1_SELECTION) };
  forged.receiptDigest = computePrecheckReceiptDigest(forged);
  fs.writeFileSync(file, `${JSON.stringify(forged, null, 2)}\n`);
  return forged;
}
function packFullMode(t) {
  const releaseDir = tempDir(t), discovered = hermeticDiscovered();
  persistFixturePrecheck(discovered, releaseDir, REVISION, FAKE_ROOT);
  const result = pack({ discovered, releaseDir, sourceRevision: REVISION, sourceTransport: snapshot,
    packageTransport: { read: (d) => Buffer.from(JSON.stringify(d.manifest)) }, packTransport: fakePack([]) });
  return { ...result, releaseDir, discovered };
}

test("negative: a forged receipt (selection inserted, digest recomputed) fails receipt validation on completeness alone", (t) => {
  const dir = tempDir(t);
  const forged = forgeSelectionReceipt(discoverPublishablePackages(), dir, "c".repeat(40), ROOT, { selection: F2_CLI1_SELECTION });
  assert.equal(forged.receiptDigest, computePrecheckReceiptDigest(forged), "digest is internally consistent");
  assert.throws(() => validatePrecheckReceipt(forged), COMPLETENESS);
  assert.throws(() => readPrecheckReceipt(dir), (e) => /persisted PRECHECK receipt is invalid/.test(e.message) && COMPLETENESS.test(e.message));
  const { selection, receiptDigest, ...full } = forged;
  assert.doesNotThrow(() => validatePrecheckReceipt({ ...full, receiptDigest: computePrecheckReceiptDigest(full) }),
    "the same receipt without the selection is valid");
});

test("negative: PACK refuses a forged partial-selection receipt before packing or writing any artifact", (t) => {
  const releaseDir = tempDir(t), discovered = hermeticDiscovered(), calls = [];
  forgeSelectionReceipt(discovered, releaseDir, REVISION, FAKE_ROOT, { selection: F2_CLI1_SELECTION });
  const before = listTree(releaseDir);
  assert.throws(() => pack({ discovered, releaseDir, sourceRevision: REVISION, sourceTransport: snapshot,
    packageTransport: { read: (d) => Buffer.from(JSON.stringify(d.manifest)) }, packTransport: fakePack(calls) }), COMPLETENESS);
  assert.deepEqual(calls, [], "no package was packed");
  assert.deepEqual(listTree(releaseDir), before, "no manifest, state or tarball was written");
  assert.deepEqual(before, [PRECHECK_FILENAME]);
});

test("positive control: the same hermetic PACK in full mode freezes all ten without a selection", (t) => {
  const { manifest, releaseDir } = packFullMode(t);
  assert.equal(manifest.selection, undefined);
  assert.equal(publicationPackages(manifest).length, 10);
  assert.ok(fs.existsSync(path.join(releaseDir, MANIFEST_FILENAME)));
});

test("negative: VERIFY_LOCAL refuses a receipt forged after PACK and leaves the release state PACKED", (t) => {
  const { manifest, state, releaseDir, discovered } = packFullMode(t);
  forgeInPlace(releaseDir);
  const stateBefore = fs.readFileSync(path.join(releaseDir, STATE_FILENAME), "utf8"), treeBefore = listTree(releaseDir);
  assert.throws(() => verifyLocal({ discovered, manifest, state, releaseDir }), COMPLETENESS);
  assert.equal(fs.readFileSync(path.join(releaseDir, STATE_FILENAME), "utf8"), stateBefore);
  assert.equal(JSON.parse(stateBefore).phase, "PACKED");
  assert.deepEqual(listTree(releaseDir), treeBefore, "nothing new written");
});

test("negative: a consistent partial-selection manifest (receipt and integrity recomputed) is refused by VERIFY_LOCAL and publication planning", (t) => {
  const { manifest, state, releaseDir, discovered } = packFullMode(t);
  manifest.precheck = forgeInPlace(releaseDir);
  manifest.selection = structuredClone(F2_CLI1_SELECTION);
  manifest.manifestIntegrity = computeManifestIntegrity(manifest);
  fs.writeFileSync(path.join(releaseDir, MANIFEST_FILENAME), JSON.stringify(manifest, null, 2));
  const stateBefore = fs.readFileSync(path.join(releaseDir, STATE_FILENAME), "utf8"), treeBefore = listTree(releaseDir);
  // The loader checks integrity only, so historical manifests keep loading;
  // every phase that acts on the loaded manifest refuses it.
  assert.doesNotThrow(() => loadAndValidateManifest(releaseDir));
  assert.throws(() => verifyLocal({ discovered, manifest, state, releaseDir }), COMPLETENESS);
  assert.throws(() => publicationPackages(manifest), COMPLETENESS);
  assert.equal(fs.readFileSync(path.join(releaseDir, STATE_FILENAME), "utf8"), stateBefore);
  assert.equal(state.phase, "PACKED");
  assert.deepEqual(listTree(releaseDir), treeBefore);
});

test("negative: direct publicationPackages() refuses the R3 partial selection even when manifest and receipt agree", () => {
  const packages = Object.entries(POLICY).map(([name, p]) => ({ package: name, version: p.version,
    releaseLine: p.releaseLine, publishOrder: p.publishOrder }));
  const precheck = { selection: structuredClone(F2_CLI1_SELECTION) };
  assert.throws(() => publicationPackages({ packages, precheck, selection: structuredClone(F2_CLI1_SELECTION) }),
    (e) => COMPLETENESS.test(e.message) && GUARD_FLOOR_PACKAGES.every((n) => e.message.includes(n)));
  // Any other selection still fails the exact-profile check first, as before.
  assert.throws(() => publicationPackages({ packages, precheck, selection: fullSelection() }), /exact ordered five-package selection/);
});

// ── Full-mode manifest tampering after PACK (R5) ────────────────────────────
// Regression for the full-mode check: a full-mode (no selection) R3 manifest
// edited after PACK to hold fewer, duplicated, unexpected or wrong-version
// packages, with manifestIntegrity recomputed by the release tool's own
// computeManifestIntegrity. It is refused at:
//   1. validateState -> assertPrecheckBinding: manifest packages must equal the
//      receipt's discovered set/versions (manifest-only or manifest+state edits);
//   2. verifyLocal -> assertPackedBijection: packed packages must be exactly the
//      packages discovered in the checkout (receipt also forged, digest recomputed);
//   3. evaluateReleaseReadiness (POLICY_RELEASE_STATE_MISMATCH): the receipt's
//      discovered set/versions must equal POLICY, so derivePublicationPlan
//      never yields a plan (receipt also forged).
// In every case the release state stays PACKED and nothing is written.

const ADAPTERS = new Set(GUARD_FLOOR_PACKAGES);
const TAMPER = {
  "five adapters removed": { manifest: (ps) => ps.filter((p) => !ADAPTERS.has(p.package)), receipt: (ds) => ds.filter((d) => !ADAPTERS.has(d.name)), state: (st) => { for (const n of ADAPTERS) delete st[n]; } },
  "one adapter removed": { manifest: (ps) => ps.filter((p) => p.package !== "@oxdeai/openclaw"), receipt: (ds) => ds.filter((d) => d.name !== "@oxdeai/openclaw"), state: (st) => { delete st["@oxdeai/openclaw"]; } },
  "duplicated package": { manifest: (ps) => [...ps, structuredClone(ps.find((p) => p.package === GUARD_PACKAGE))], receipt: (ds) => ds, state: () => {} },
  "unexpected package": {
    manifest: (ps) => [...ps, { ...structuredClone(ps[0]), package: "@oxdeai/extra", version: "1.0.0", publishOrder: 999, tarball: "tarballs/extra.tgz" }],
    receipt: (ds) => [...ds, { name: "@oxdeai/extra", dir: "/fake/extra", manifest: { name: "@oxdeai/extra", version: "1.0.0" }, packageJsonDigest: `sha256:${"0".repeat(64)}` }],
    state: (st) => { st["@oxdeai/extra"] = { publishStatus: "pending" }; },
    files: (releaseDir, manifest) => { fs.writeFileSync(path.join(releaseDir, "tarballs/extra.tgz"), "@oxdeai/core"); }, // a forger supplies the archive too
  },
  "wrong Guard version": {
    manifest: (ps) => ps.map((p) => p.package === GUARD_PACKAGE ? { ...p, version: "2.0.4" } : p),
    receipt: (ds) => ds.map((d) => d.name === GUARD_PACKAGE ? { ...d, manifest: { ...d.manifest, version: "2.0.4" } } : d), state: () => {},
  },
};
// scope: "manifest" | "manifest+state" | "full" (manifest + receipt + state, all digests recomputed)
function tamper(releaseDir, manifest, state, edit, scope) {
  const m = structuredClone(manifest), st = structuredClone(state);
  m.packages = edit.manifest(m.packages);
  edit.files?.(releaseDir, m);
  if (scope !== "manifest") edit.state(st.packages);
  if (scope === "full") {
    const file = path.join(releaseDir, PRECHECK_FILENAME);
    const { receiptDigest, ...r } = JSON.parse(fs.readFileSync(file, "utf8"));
    r.discovered = edit.receipt(r.discovered);
    r.receiptDigest = computePrecheckReceiptDigest(r);
    fs.writeFileSync(file, `${JSON.stringify(r, null, 2)}\n`);
    m.precheck = r;
    st.history[0].receiptDigest = r.receiptDigest;
  }
  m.manifestIntegrity = computeManifestIntegrity(m);
  fs.writeFileSync(path.join(releaseDir, MANIFEST_FILENAME), JSON.stringify(m, null, 2));
  fs.writeFileSync(path.join(releaseDir, STATE_FILENAME), JSON.stringify(st, null, 2));
  return { manifest: m, state: st };
}

test("positive control: the untampered full-mode PACK output plans all ten POLICY packages", (t) => {
  const { manifest, releaseDir } = packFullMode(t);
  assert.deepEqual(fixturePlan(manifest, releaseDir).operations.map((o) => o.package).sort(), Object.keys(POLICY).sort());
});

for (const [label, edit] of Object.entries(TAMPER)) {
  for (const scope of ["manifest", "manifest+state"]) {
    test(`full-mode tamper after PACK (${label}; ${scope} edited, integrity recomputed): refused by the PRECHECK binding`, (t) => {
      const packed = packFullMode(t);
      const { manifest, state } = tamper(packed.releaseDir, packed.manifest, packed.state, edit, scope);
      const stateBefore = fs.readFileSync(path.join(packed.releaseDir, STATE_FILENAME), "utf8"), treeBefore = listTree(packed.releaseDir);
      assert.doesNotThrow(() => loadAndValidateManifest(packed.releaseDir), "integrity alone is satisfied");
      assert.throws(() => validateState(manifest, state), /PRECHECK evidence binding mismatch: package set\/versions/);
      assert.throws(() => verifyLocal({ discovered: packed.discovered, manifest, state, releaseDir: packed.releaseDir }),
        /PRECHECK evidence binding mismatch: package set\/versions/);
      assert.throws(() => fixturePlan(manifest, packed.releaseDir));
      assert.equal(fs.readFileSync(path.join(packed.releaseDir, STATE_FILENAME), "utf8"), stateBefore);
      assert.equal(JSON.parse(stateBefore).phase, "PACKED");
      assert.deepEqual(listTree(packed.releaseDir), treeBefore);
    });
  }
  test(`full-mode tamper after PACK (${label}; manifest, receipt and state forged): refused by VERIFY_LOCAL and by readiness`, (t) => {
    const packed = packFullMode(t);
    const { manifest, state } = tamper(packed.releaseDir, packed.manifest, packed.state, edit, "full");
    const stateBefore = fs.readFileSync(path.join(packed.releaseDir, STATE_FILENAME), "utf8"), treeBefore = listTree(packed.releaseDir);
    if (label !== "wrong Guard version") {
      // Wrong version keeps the name bijection; it is refused by readiness below.
      assert.throws(() => verifyLocal({ discovered: packed.discovered, manifest, state, releaseDir: packed.releaseDir }),
        /packed bijection|PRECHECK evidence binding mismatch/);
    }
    assert.throws(() => fixturePlan(manifest, packed.releaseDir),
      (e) => /POLICY_RELEASE_STATE_MISMATCH|PRECHECK evidence binding mismatch|packed bijection/.test(e.message));
    assert.equal(fs.readFileSync(path.join(packed.releaseDir, STATE_FILENAME), "utf8"), stateBefore);
    assert.equal(JSON.parse(stateBefore).phase, "PACKED");
    assert.deepEqual(listTree(packed.releaseDir), treeBefore);
  });
}

test("full forgery that drops the five adapters is refused by readiness specifically (POLICY coverage)", (t) => {
  const packed = packFullMode(t);
  const { manifest } = tamper(packed.releaseDir, packed.manifest, packed.state, TAMPER["five adapters removed"], "full");
  assert.equal(publicationPackages(manifest).length, 5, "the full-mode publication set itself is manifest-derived");
  assert.throws(() => fixturePlan(manifest, packed.releaseDir), /POLICY_RELEASE_STATE_MISMATCH/);
});
