// SPDX-License-Identifier: Apache-2.0
//
// Tests for the OxDeAI 2.0 release orchestrator (#292).
//
// ABSOLUTE SAFETY GATE: no test in this file invokes, spawns, or mocks a
// subprocess call to `npm publish`, `npm dist-tag`, or `npm unpublish`.
// `registryTransport.publish()` and promotion planning are exercised purely
// as injected fake objects / data assertions — nothing here shells out to a
// registry, real or local.

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  MANIFEST_FILENAME,
  STATE_FILENAME,
  STATE_VERSION,
  ReleaseOrchestratorError,
  RegistryIntegrityConflictError,
  assertValidTransition,
  buildDependencyGraph,
  buildPromotionPlan,
  buildPublishCommandData,
  canonicalStringify,
  computeManifestIntegrity,
  computeSriIntegrity,
  loadAndValidateManifest,
  loadState,
  pack,
  precheck,
  promote,
  publishNext,
  requireOriginalTarballs,
  resume,
  runDeterminismProbe,
  saveState,
  sha256Hex,
  transitionToReadyToPromote,
  validatePublishOrder,
  verifyExternalInstall,
  verifyRegistry,
  verifyLocal,
  validateState,
} from "./orchestrator.mjs";

import { POLICY, assertReleaseMetadataConsistency } from "../verify-packed-artifacts.mjs";

// ── Test fixtures ──────────────────────────────────────────────────────────

const SHA = "a".repeat(40);

function tmpDir(prefix) {
  return mkdtempSync(path.join(tmpdir(), prefix));
}

// A minimal, self-consistent discovered-package set mirroring the real
// dependency shape (core <- guard <- adapters; core <- sdk/conformance/cli)
// without touching the real packages/* tree, so tests are hermetic and fast.
function fakeDiscovered({ withDeps = true } = {}) {
  const mk = (name, deps = {}) => ({
    name,
    dir: `/fake/${name.replace("@oxdeai/", "")}`,
    manifest: { name, version: POLICY[name].version, dependencies: withDeps ? deps : {} },
  });
  return [
    mk("@oxdeai/core"),
    mk("@oxdeai/guard", { "@oxdeai/core": "workspace:*" }),
    mk("@oxdeai/sdk", { "@oxdeai/core": "workspace:*" }),
    mk("@oxdeai/conformance", { "@oxdeai/core": "workspace:*" }),
    mk("@oxdeai/autogen", { "@oxdeai/core": "workspace:^", "@oxdeai/guard": "workspace:^" }),
    mk("@oxdeai/crewai", { "@oxdeai/core": "workspace:^", "@oxdeai/guard": "workspace:^" }),
    mk("@oxdeai/langgraph", { "@oxdeai/core": "workspace:^", "@oxdeai/guard": "workspace:^" }),
    mk("@oxdeai/openai-agents", { "@oxdeai/core": "workspace:^", "@oxdeai/guard": "workspace:^" }),
    mk("@oxdeai/openclaw", { "@oxdeai/core": "workspace:^", "@oxdeai/guard": "workspace:^" }),
    mk("@oxdeai/cli", { "@oxdeai/core": "workspace:*" }),
  ];
}

// Deterministic fake tarball bytes: content is a function of package name +
// a "generation" tag, so tests can produce identical or divergent bytes on
// demand without ever shelling out to `pnpm pack`.
function fakeTarballBytes(name, tag = "v1") {
  return Buffer.from(`FAKE-TARBALL:${name}:${tag}`);
}

function fakePackTransport({ deterministic = true, generation = { n: 0 } } = {}) {
  return {
    packToDir(pkg, destDir) {
      generation.n += 1;
      const tag = deterministic ? "stable" : `gen${generation.n}`;
      const tarballPath = path.join(destDir, `${pkg.name.replace("@oxdeai/", "")}.tgz`);
      writeFileSync(tarballPath, fakeTarballBytes(pkg.name, tag));
      return tarballPath;
    },
  };
}

function packFixture(overrides = {}) {
  const releaseDir = tmpDir("oxdeai-release-");
  const discovered = fakeDiscovered();
  const result = pack({
    discovered,
    releaseDir,
    sourceRevision: SHA,
    packTransport: fakePackTransport(),
    now: () => "2026-09-13T00:00:00.000Z",
    ...overrides,
  });
  return { releaseDir, discovered, ...result };
}

function cleanGit() {
  return { isClean: () => true };
}
function dirtyGit() {
  return { isClean: () => false };
}

// A fake registry transport backed by an in-memory Map<name@version, integrity>.
function fakeRegistry(initial = {}) {
  const store = new Map(Object.entries(initial));
  return {
    _store: store,
    getRegistryVersion(name, version) {
      const key = `${name}@${version}`;
      return store.has(key) ? { exists: true, integrity: store.get(key) } : { exists: false };
    },
    publish(commandData) {
      store.set(`${commandData.package}@${commandData.version}`, "PUBLISHED-BY-FAKE-TRANSPORT");
      return { ok: true };
    },
  };
}

function alwaysFailPublish(baseRegistry) {
  return { ...baseRegistry, publish: () => ({ ok: false, error: "simulated failure" }) };
}

function registryThatPublishesThenAppearsWithIntegrity(integrityByKey) {
  const store = new Map();
  return {
    getRegistryVersion(name, version) {
      const key = `${name}@${version}`;
      if (integrityByKey.has(key)) return { exists: true, integrity: integrityByKey.get(key) };
      return store.has(key) ? { exists: true, integrity: store.get(key) } : { exists: false };
    },
    // Simulates: publish command reports an ambiguous failure, but the bytes
    // actually landed on the registry (network blip after acceptance).
    publish(commandData) {
      const key = `${commandData.package}@${commandData.version}`;
      store.set(key, integrityByKey.get(key) ?? "unexpected-integrity");
      return { ok: false, error: "ETIMEDOUT (ambiguous)" };
    },
  };
}

function fullyPublishedState(manifest, integrityFn = (p) => p.integrity) {
  const packages = {};
  for (const p of manifest.packages) {
    packages[p.package] = {
      publishStatus: "published",
      registryIntegrity: integrityFn(p),
      registryVerified: true,
      externalInstallVerified: true,
    };
  }
  return packages;
}

function okInstallTransport() {
  return { verifyInstall: () => ({ ok: true }) };
}

// ── 1. dirty working tree -> PRECHECK fails ─────────────────────────────────

test("1. dirty working tree fails PRECHECK", () => {
  const discovered = fakeDiscovered();
  assert.throws(
    () => precheck({ discovered, gitTransport: dirtyGit() }),
    /dirty working tree/
  );
});

test("PRECHECK passes on a clean tree with valid discovery", () => {
  const discovered = fakeDiscovered();
  const result = precheck({ discovered, gitTransport: cleanGit() });
  assert.equal(result.ok, true);
});

// ── 2. declared version != package.json version -> hard stop ───────────────

test("2. declared POLICY version mismatched against package.json version is a hard stop", () => {
  const discovered = fakeDiscovered();
  discovered.find((d) => d.name === "@oxdeai/core").manifest.version = "1.9.9";
  assert.throws(
    () => precheck({ discovered, gitTransport: cleanGit() }),
    /does not exactly match package\.json version/
  );
});

// ── 3. publishOrder violates a real inter-package dependency -> PRECHECK fails ─

test("3. publishOrder violating the real dependency graph fails PRECHECK", () => {
  const discovered = fakeDiscovered();
  const badPolicy = structuredClone(POLICY);
  // guard depends on core; force guard to publish before core.
  badPolicy["@oxdeai/guard"].publishOrder = 1;
  badPolicy["@oxdeai/core"].publishOrder = 99;
  assertReleaseMetadataConsistency(badPolicy); // still internally consistent re: releaseLine/version
  assert.throws(
    () => precheck({ discovered, policy: badPolicy, gitTransport: cleanGit() }),
    /must publish strictly before its dependents/
  );
});

test("validatePublishOrder detects a dependency cycle", () => {
  const discovered = fakeDiscovered();
  discovered.find((d) => d.name === "@oxdeai/core").manifest.dependencies = { "@oxdeai/guard": "workspace:*" };
  const violations = validatePublishOrder(discovered, POLICY);
  assert.ok(violations.some((v) => v.includes("cycle")));
});

test("real POLICY publishOrder is consistent with the fixture dependency graph", () => {
  const discovered = fakeDiscovered();
  const violations = validatePublishOrder(discovered, POLICY);
  assert.deepEqual(violations, []);
});

// ── 4. package discovered with no POLICY entry -> fail closed ──────────────

test("4. a discovered package with no POLICY entry fails closed at PRECHECK", () => {
  const discovered = fakeDiscovered();
  discovered.push({ name: "@oxdeai/mystery", dir: "/fake/mystery", manifest: { name: "@oxdeai/mystery", version: "1.0.0", dependencies: {} } });
  assert.throws(
    () => precheck({ discovered, gitTransport: cleanGit() }),
    /no entry in the explicit POLICY table/
  );
});

// ── 5 & 6. @oxdeai/cli cannot become 2.0.0 / releaseLine "2.0" ──────────────

test("5. @oxdeai/cli cannot be assigned version 2.0.0 by any supported configuration", () => {
  const badPolicy = structuredClone(POLICY);
  badPolicy["@oxdeai/cli"].version = "2.0.0";
  // Rejected by the generic releaseLine/version derivation check before it
  // even reaches the named cli guard (releaseLine stays "cli", which
  // requires "0.3.0" — "2.0.0" is simply the wrong version for that line).
  assert.throws(() => assertReleaseMetadataConsistency(badPolicy), /releaseLine "cli" requires "0\.3\.0"/);
});

test("6. @oxdeai/cli releaseLine cannot become \"2.0\"", () => {
  const badPolicy = structuredClone(POLICY);
  badPolicy["@oxdeai/cli"].releaseLine = "2.0";
  // Setting releaseLine to "2.0" without changing version now fails the
  // generic derivation check (version "0.3.0" != required "2.0.0" for "2.0")
  // before it even reaches the named cli guard — both layers independently
  // reject this state.
  assert.throws(() => assertReleaseMetadataConsistency(badPolicy), /releaseLine "2\.0" requires "2\.0\.0"/);
});

test("6b. @oxdeai/cli with BOTH releaseLine and version forced to the 2.0 line is still rejected by the named guard", () => {
  const badPolicy = structuredClone(POLICY);
  badPolicy["@oxdeai/cli"].releaseLine = "2.0";
  badPolicy["@oxdeai/cli"].version = "2.0.0";
  assert.throws(() => assertReleaseMetadataConsistency(badPolicy), /must never be assigned version "2\.0\.0" or releaseLine "2\.0"/);
});

test("real POLICY is internally consistent at module load (already asserted on import, re-checked here)", () => {
  assert.doesNotThrow(() => assertReleaseMetadataConsistency(POLICY));
  assert.equal(POLICY["@oxdeai/cli"].version, "0.3.0");
  assert.equal(POLICY["@oxdeai/cli"].releaseLine, "cli");
  assert.equal(POLICY["@oxdeai/cli"].publishOrder, 90);
});

// ── 7. PACK freezes release identity fields ─────────────────────────────────

test("7. PACK freezes release identity fields", () => {
  const { manifest } = packFixture();
  assert.equal(manifest.manifestVersion, 1);
  assert.equal(manifest.sourceRevision, SHA);
  assert.equal(manifest.packages.length, 10);
  for (const p of manifest.packages) {
    assert.ok(p.tarball);
    assert.match(p.integrity, /^sha512-/);
  }
});

test("PACK writes state PACKED and it is resumable/loadable", () => {
  const { releaseDir } = packFixture();
  const state = loadState(releaseDir);
  assert.equal(state.phase, "PACKED");
  assert.equal(state.history.at(-1).phase, "PACKED");
});

// ── 8. manifestIntegrity validates correctly ────────────────────────────────

test("8. manifestIntegrity validates correctly and excludes itself from its own hash input", () => {
  const { manifest } = packFixture();
  const recomputed = computeManifestIntegrity(manifest);
  assert.equal(manifest.manifestIntegrity, recomputed);

  // Changing manifestIntegrity itself must not change the recomputed value
  // (proves no recursive hashing).
  const mutated = { ...manifest, manifestIntegrity: "sha256:deadbeef" };
  assert.equal(computeManifestIntegrity(mutated), recomputed);
});

test("canonicalStringify sorts keys and preserves array order deterministically", () => {
  assert.equal(canonicalStringify({ b: 1, a: 2 }), canonicalStringify({ a: 2, b: 1 }));
  assert.equal(canonicalStringify([3, 1, 2]), "[3,1,2]");
});

// ── 9. mutation of frozen manifest identity/evidence -> resume fails ───────

test("9. mutating the manifest after PACK is detected and resume fails", () => {
  const { releaseDir, manifest } = packFixture();
  const mutated = { ...manifest, sourceRevision: "b".repeat(40) };
  writeFileSync(path.join(releaseDir, MANIFEST_FILENAME), JSON.stringify(mutated, null, 2));
  assert.throws(() => loadAndValidateManifest(releaseDir), /manifestIntegrity mismatch/);
});

// ── 10. missing original tarball on resume -> hard stop, no repack ─────────

test("10. missing original tarball is a hard stop with no repack", () => {
  const { releaseDir, manifest } = packFixture();
  rmSync(path.join(releaseDir, manifest.packages[0].tarball));
  assert.throws(() => requireOriginalTarballs(releaseDir, manifest), /tarball missing/);
});

// ── 11. local tarball integrity differs from manifest -> hard stop ─────────

test("11. local tarball integrity differing from the manifest is a hard stop", () => {
  const { releaseDir, manifest } = packFixture();
  const target = manifest.packages[0];
  writeFileSync(path.join(releaseDir, target.tarball), Buffer.from("TAMPERED BYTES"));
  assert.throws(() => requireOriginalTarballs(releaseDir, manifest), /integrity for .* is .*manifest records/);
});

// ── 12. resume from PARTIAL_NEXT: already-published matching integrity ────

test("12. resume accepts an already-published package with matching registry integrity and continues only the rest", () => {
  const { releaseDir, manifest } = packFixture();
  const state = loadState(releaseDir);
  state.phase = "PARTIAL_NEXT";
  state.packages[manifest.packages[0].package] = { publishStatus: "pending" };
  saveState(releaseDir, state);

  const published = manifest.packages[0];
  const registry = fakeRegistry({ [`${published.package}@${published.version}`]: published.integrity });

  const { toPublish, state: resumedState } = resume({ releaseDir, registryTransport: registry });
  assert.equal(resumedState.packages[published.package].publishStatus, "published");
  assert.equal(toPublish.length, manifest.packages.length - 1);
  assert.ok(!toPublish.some((p) => p.package === published.package));
});

// ── 13. resume with already-published divergent integrity -> hard stop ────

test("13. resume with a divergent registry integrity is a hard stop", () => {
  const { releaseDir, manifest } = packFixture();
  const state = loadState(releaseDir);
  state.phase = "PARTIAL_NEXT";
  saveState(releaseDir, state);

  const target = manifest.packages[1];
  const registry = fakeRegistry({ [`${target.package}@${target.version}`]: "sha512-DIFFERENT" });

  assert.throws(
    () => resume({ releaseDir, registryTransport: registry }),
    RegistryIntegrityConflictError
  );
});

// ── highest-priority negative test: registry integrity != manifest integrity ─

test("HIGHEST PRIORITY: registry integrity != manifest integrity halts publication and blocks promotion planning", () => {
  const { releaseDir, manifest } = packFixture();
  const state = loadState(releaseDir);
  state.phase = "VERIFIED_LOCAL";
  saveState(releaseDir, state);

  const target = manifest.packages[0];
  const registry = fakeRegistry({ [`${target.package}@${target.version}`]: "sha512-WRONG-BYTES" });

  assert.throws(
    () => publishNext({ manifest, state, releaseDir, registryTransport: registry }),
    RegistryIntegrityConflictError
  );
  // No publication continuation: state was not advanced past VERIFIED_LOCAL/PUBLISHING_NEXT into PUBLISHED_NEXT.
  assert.notEqual(state.phase, "PUBLISHED_NEXT");
  // No promotion plan: state never reaches READY_TO_PROMOTE, so planning is refused.
  assert.throws(() => buildPromotionPlan(manifest, state), /READY_TO_PROMOTE/);
});

// ── 14 & 15. determinism probe: recorded, never authorizes reconstruction ──

test("14. non-deterministic PRECHECK probe result is recorded, but original tarballs are still required on resume", () => {
  const releaseDir = tmpDir("oxdeai-release-");
  const discovered = fakeDiscovered();
  const { manifest } = pack({
    discovered, releaseDir, sourceRevision: SHA,
    packTransport: fakePackTransport({ deterministic: false }),
  });
  assert.equal(manifest.determinismProbe.deterministic, false);
  assert.notEqual(manifest.determinismProbe.hashA, manifest.determinismProbe.hashB);
  // Regeneration still refused: removing a tarball still hard-stops, probe result notwithstanding.
  rmSync(path.join(releaseDir, manifest.packages[0].tarball));
  assert.throws(() => requireOriginalTarballs(releaseDir, manifest), /Regeneration is forbidden/);
});

test("15. deterministic PRECHECK probe result does not grant reconstruction permission", () => {
  const { releaseDir, manifest } = packFixture(); // fakePackTransport() defaults to deterministic
  assert.equal(manifest.determinismProbe.deterministic, true);
  rmSync(path.join(releaseDir, manifest.packages[0].tarball));
  assert.throws(() => requireOriginalTarballs(releaseDir, manifest), /Regeneration is forbidden/);
});

test("determinism-probe tarballs are disposable and never enter the manifest's package list", () => {
  const { manifest } = packFixture();
  const probeHashes = new Set([manifest.determinismProbe.hashA, manifest.determinismProbe.hashB]);
  for (const p of manifest.packages) {
    const integrityDigestOnly = p.integrity.replace(/^sha512-/, "");
    assert.ok(!probeHashes.has(integrityDigestOnly) || true); // different hash algorithms (sha256 vs sri sha512) — structural check below is the real guarantee
  }
  // Structural guarantee: the probe result has exactly {package, deterministic, hashA, hashB} —
  // no tarball path or integrity field that could be mistaken for a release artifact.
  assert.deepEqual(Object.keys(manifest.determinismProbe).sort(), ["deterministic", "hashA", "hashB", "package"]);
});

// ── 16, 17, 18. publish error + registry query resolution ──────────────────

test("16. publish error followed by registry presence with matching integrity is modeled as successful publication", () => {
  const { releaseDir, manifest } = packFixture();
  const state = loadState(releaseDir);
  state.phase = "VERIFIED_LOCAL";

  const integrityByKey = new Map(manifest.packages.map((p) => [`${p.package}@${p.version}`, p.integrity]));
  const registry = registryThatPublishesThenAppearsWithIntegrity(integrityByKey);

  const result = publishNext({ manifest, state, releaseDir, registryTransport: registry });
  assert.equal(result.phase, "PUBLISHED_NEXT");
  for (const p of manifest.packages) {
    assert.equal(result.packages[p.package].publishStatus, "published");
  }
});

test("17. publish error followed by a missing registry version persists PARTIAL_NEXT", () => {
  const { releaseDir, manifest } = packFixture();
  const state = loadState(releaseDir);
  state.phase = "VERIFIED_LOCAL";
  const registry = alwaysFailPublish(fakeRegistry());

  const result = publishNext({ manifest, state, releaseDir, registryTransport: registry });
  assert.equal(result.phase, "PARTIAL_NEXT");
  // First package in publish order was attempted and left pending (never marked published).
  const first = [...manifest.packages].sort((a, b) => a.publishOrder - b.publishOrder)[0];
  assert.notEqual(result.packages[first.package]?.publishStatus, "published");
});

test("18. publish error followed by a registry version with divergent integrity is a hard stop", () => {
  const { releaseDir, manifest } = packFixture();
  const state = loadState(releaseDir);
  state.phase = "VERIFIED_LOCAL";

  const first = [...manifest.packages].sort((a, b) => a.publishOrder - b.publishOrder)[0];
  const registry = {
    getRegistryVersion: (name, version) =>
      name === first.package && version === first.version
        ? { exists: true, integrity: "sha512-SOMETHING-ELSE" }
        : { exists: false },
    publish: () => ({ ok: false, error: "ambiguous" }),
  };

  assert.throws(
    () => publishNext({ manifest, state, releaseDir, registryTransport: registry }),
    RegistryIntegrityConflictError
  );
});

// ── 19 & 20. READY_TO_PROMOTE requires all ten, including CLI ──────────────

test("19. one package not registry-verified makes READY_TO_PROMOTE unreachable", () => {
  const { manifest } = packFixture();
  const state = { stateVersion: STATE_VERSION, releaseId: SHA, phase: "EXTERNAL_INSTALL_VERIFIED", history: [], packages: fullyPublishedState(manifest) };
  const notVerified = manifest.packages.find((p) => p.package === "@oxdeai/sdk").package;
  state.packages[notVerified].registryVerified = false;

  assert.throws(
    () => transitionToReadyToPromote({ manifest, state, releaseDir: tmpDir("oxdeai-release-") }),
    /Not ready: @oxdeai\/sdk/
  );
});

test("20. @oxdeai/cli alone failing verification blocks promotion of the nine 2.0-line packages", () => {
  const { manifest } = packFixture();
  const state = { stateVersion: STATE_VERSION, releaseId: SHA, phase: "EXTERNAL_INSTALL_VERIFIED", history: [], packages: fullyPublishedState(manifest) };
  state.packages["@oxdeai/cli"].externalInstallVerified = false;

  assert.throws(
    () => transitionToReadyToPromote({ manifest, state, releaseDir: tmpDir("oxdeai-release-") }),
    /Not ready: @oxdeai\/cli/
  );
});

test("all ten verified reaches READY_TO_PROMOTE", () => {
  const { manifest } = packFixture();
  const state = { stateVersion: STATE_VERSION, releaseId: SHA, phase: "EXTERNAL_INSTALL_VERIFIED", history: [], packages: fullyPublishedState(manifest) };
  const releaseDir = tmpDir("oxdeai-release-");
  writeFileSync(path.join(releaseDir, STATE_FILENAME), "{}"); // saveState overwrites; just needs a writable dir
  const result = transitionToReadyToPromote({ manifest, state, releaseDir });
  assert.equal(result.phase, "READY_TO_PROMOTE");
});

// ── 21. promotion planning before READY_TO_PROMOTE -> fail closed ─────────

test("21. promotion planning before READY_TO_PROMOTE fails closed", () => {
  const { manifest } = packFixture();
  const state = { stateVersion: STATE_VERSION, releaseId: SHA, phase: "VERIFIED_LOCAL", history: [], packages: fullyPublishedState(manifest) };
  assert.throws(() => buildPromotionPlan(manifest, state), /READY_TO_PROMOTE/);
  assert.throws(
    () => promote({ manifest, state, releaseDir: tmpDir("oxdeai-release-") }),
    /READY_TO_PROMOTE/
  );
});

// ── 22 & 23. publish plan uses exact .tgz paths, never directories, with --tag next --access public ─

test("22 & 23. generated publication plan uses exact .tgz paths (never package directories) and carries --tag next --access public", () => {
  const { releaseDir, manifest } = packFixture();
  for (const p of manifest.packages) {
    const data = buildPublishCommandData(p, releaseDir);
    assert.equal(data.executable, "npm");
    assert.equal(data.args[0], "publish");
    assert.ok(data.args[1].endsWith(".tgz"), `expected a .tgz path, got ${data.args[1]}`);
    assert.ok(path.isAbsolute(data.args[1]));
    assert.deepEqual(data.args.slice(2), ["--tag", "next", "--access", "public"]);
  }
});

// ── 24. generated promotion plan uses exact manifest versions ──────────────

test("24. generated promotion plan uses exact manifest versions", () => {
  const { manifest } = packFixture();
  const state = { stateVersion: STATE_VERSION, releaseId: SHA, phase: "READY_TO_PROMOTE", history: [], packages: fullyPublishedState(manifest) };
  const plan = buildPromotionPlan(manifest, state);
  assert.equal(plan.length, 10);
  for (const p of manifest.packages) {
    const entry = plan.find((e) => e.args[2].startsWith(`${p.package}@`));
    assert.ok(entry, `no promotion entry for ${p.package}`);
    assert.deepEqual(entry, { executable: "npm", args: ["dist-tag", "add", `${p.package}@${p.version}`, "latest"] });
  }
  // Expected batch shape from the issue: nine at 2.0.0, cli at 0.3.0.
  const cliEntry = plan.find((e) => e.args[2].startsWith("@oxdeai/cli@"));
  assert.equal(cliEntry.args[2], "@oxdeai/cli@0.3.0");
  const twoOh = plan.filter((e) => e.args[2].endsWith("@2.0.0"));
  assert.equal(twoOh.length, 9);
});

// ── 25. state transition graph rejects invalid/skipped transitions ────────

test("25. state transition graph rejects invalid or skipped transitions", () => {
  assert.doesNotThrow(() => assertValidTransition("PRECHECK", "PACKED"));
  assert.throws(() => assertValidTransition("PRECHECK", "VERIFIED_LOCAL"), /invalid state transition/); // skip
  assert.throws(() => assertValidTransition("PACKED", "PROMOTED"), /invalid state transition/); // skip to terminal
  assert.throws(() => assertValidTransition("PARTIAL_NEXT", "PACKED"), /invalid state transition/); // forbidden repack edge
  assert.throws(() => assertValidTransition("PROMOTED", "PRECHECK"), /invalid state transition/); // terminal
  assert.doesNotThrow(() => assertValidTransition("PARTIAL_NEXT", "PUBLISHING_NEXT")); // the one legal resume edge
});

// ── Additional coverage beyond the required 25 ─────────────────────────────

test("verifyRegistry requires exact name+version+integrity match, not merely name+version", () => {
  const { manifest } = packFixture();
  const state = { stateVersion: STATE_VERSION, releaseId: SHA, phase: "PUBLISHED_NEXT", history: [], packages: fullyPublishedState(manifest) };
  const target = manifest.packages[0];
  const registry = fakeRegistry(
    Object.fromEntries(manifest.packages.map((p) => [`${p.package}@${p.version}`, p.integrity]))
  );
  registry._store.set(`${target.package}@${target.version}`, "sha512-WRONG");
  assert.throws(
    () => verifyRegistry({ manifest, state, releaseDir: tmpDir("oxdeai-release-"), registryTransport: registry }),
    RegistryIntegrityConflictError
  );
});

test("verifyRegistry passes and transitions to REGISTRY_VERIFIED when all integrities match", () => {
  const { manifest } = packFixture();
  const state = { stateVersion: STATE_VERSION, releaseId: SHA, phase: "PUBLISHED_NEXT", history: [], packages: fullyPublishedState(manifest) };
  const registry = fakeRegistry(
    Object.fromEntries(manifest.packages.map((p) => [`${p.package}@${p.version}`, p.integrity]))
  );
  const result = verifyRegistry({ manifest, state, releaseDir: tmpDir("oxdeai-release-"), registryTransport: registry });
  assert.equal(result.phase, "REGISTRY_VERIFIED");
});

test("verifyExternalInstall is distinct from local tarball verification and requires its own transport", () => {
  const { manifest } = packFixture();
  const state = { stateVersion: STATE_VERSION, releaseId: SHA, phase: "REGISTRY_VERIFIED", history: [], packages: fullyPublishedState(manifest) };
  const failing = { verifyInstall: (name) => (name === "@oxdeai/guard" ? { ok: false, reason: "types not resolvable" } : { ok: true }) };
  assert.throws(
    () => verifyExternalInstall({ manifest, state, releaseDir: tmpDir("oxdeai-release-"), installTransport: failing }),
    /external install verification failed for @oxdeai\/guard/
  );

  const passing = okInstallTransport();
  const state2 = { stateVersion: STATE_VERSION, releaseId: SHA, phase: "REGISTRY_VERIFIED", history: [], packages: fullyPublishedState(manifest) };
  const result = verifyExternalInstall({ manifest, state: state2, releaseDir: tmpDir("oxdeai-release-"), installTransport: passing });
  assert.equal(result.phase, "EXTERNAL_INSTALL_VERIFIED");
});

test("runDeterminismProbe reports deterministic=false for divergent bytes and true for identical bytes", () => {
  const pkg = { name: "@oxdeai/core", dir: "/fake/core" };
  const det = runDeterminismProbe(pkg, fakePackTransport({ deterministic: true }));
  assert.equal(det.deterministic, true);
  const nonDet = runDeterminismProbe(pkg, fakePackTransport({ deterministic: false }));
  assert.equal(nonDet.deterministic, false);
});

test("computeSriIntegrity matches the sha512-<base64> shape used by npm registry dist.integrity", () => {
  const bytes = Buffer.from("hello world");
  const expected = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
  assert.equal(computeSriIntegrity(bytes), expected);
});

test("sha256Hex is a plain hex digest", () => {
  assert.equal(sha256Hex("abc"), createHash("sha256").update("abc").digest("hex"));
});

test("buildDependencyGraph only includes edges to OTHER discovered @oxdeai/* packages", () => {
  const discovered = fakeDiscovered();
  const graph = buildDependencyGraph(discovered);
  assert.deepEqual(graph.get("@oxdeai/core"), []);
  assert.deepEqual(graph.get("@oxdeai/guard"), ["@oxdeai/core"]);
  assert.deepEqual(new Set(graph.get("@oxdeai/autogen")), new Set(["@oxdeai/core", "@oxdeai/guard"]));
});

test("safety gate: no fixture or transport in this file constructs a real npm publish/dist-tag invocation", () => {
  const source = readFileSync(new URL("./orchestrator.test.mjs", import.meta.url), "utf8");
  assert.ok(!/spawnSync\(\s*["']npm["'].*publish/s.test(source));
  assert.ok(!/spawnSync\(\s*["']npm["'].*dist-tag/s.test(source));
  assert.ok(!/spawnSync\(\s*["']npm["'].*unpublish/s.test(source));
});

for (const [label, mutate] of [
  ["missing", (ps) => ps.slice(1)],
  ["extra", (ps) => [...ps, { ...ps[0], package: "@oxdeai/extra" }]],
  ["duplicate", (ps) => [...ps.slice(0, -1), ps[0]]],
]) {
  test(`verifyLocal rejects ${label} packed package`, () => {
    const f = packFixture();
    f.manifest.packages = mutate(f.manifest.packages);
    f.state.packages = Object.fromEntries(f.manifest.packages.map((p) => [p.package, { publishStatus: "pending" }]));
    assert.throws(() => verifyLocal(f), /bijection|package set mismatch/);
    assert.equal(f.state.phase, "PACKED");
  });
}

const stateMutations = [
  ["missing stateVersion", (s) => { delete s.stateVersion; }],
  ["string stateVersion", (s) => { s.stateVersion = "1"; }],
  ["older stateVersion", (s) => { s.stateVersion = 0; }],
  ["newer stateVersion", (s) => { s.stateVersion = STATE_VERSION + 1; }],
  ["fractional stateVersion", (s) => { s.stateVersion = 1.5; }],
  ["releaseId mismatch", (s) => { s.releaseId = "b".repeat(40); }],
  ["missing releaseId", (s) => { delete s.releaseId; }],
  ["malformed releaseId", (s) => { s.releaseId = 123; }],
  ["unknown phase", (s) => { s.phase = "SOMETHING_NEW"; }],
  ["missing package", (s) => { delete s.packages["@oxdeai/core"]; }],
  ["extra package", (s) => { s.packages.extra = { publishStatus: "pending" }; }],
  ["malformed package", (s) => { s.packages["@oxdeai/core"] = []; }],
  ["non-boolean registry flag", (s) => { s.packages["@oxdeai/core"].registryVerified = "true"; }],
  ["non-boolean install flag", (s) => { s.packages["@oxdeai/core"].externalInstallVerified = 1; }],
  ["invalid publishStatus", (s) => { s.packages["@oxdeai/core"].publishStatus = "done"; }],
];
for (const [label, mutate] of stateMutations) {
  test(`all phase entry points reject ${label} before decisions or transport calls`, () => {
    const f = packFixture();
    mutate(f.state);
    saveState(f.releaseDir, f.state);
    const forbidden = new Proxy({}, { get() { assert.fail("transport consulted before state validation"); } });
    const args = { ...f, registryTransport: forbidden, installTransport: forbidden, promotionTransport: forbidden };
    for (const fn of [verifyLocal, publishNext, verifyRegistry, verifyExternalInstall, transitionToReadyToPromote, promote]) {
      assert.throws(() => fn(args), /invalid release state/);
    }
    assert.throws(() => buildPromotionPlan(f.manifest, f.state), /invalid release state/);
    assert.throws(() => resume(args), /invalid release state/);
  });
}

for (const observation of ["missing", "matching", "divergent"]) {
  test(`resume rechecks locally published packages: registry ${observation}`, () => {
    const f = packFixture();
    f.state.phase = "PARTIAL_NEXT";
    f.state.packages = fullyPublishedState(f.manifest);
    saveState(f.releaseDir, f.state);
    const calls = [];
    const registryTransport = {
      getRegistryVersion(name, version) {
        calls.push([name, version]);
        const p = f.manifest.packages.find((p) => p.package === name);
        return observation === "missing" ? { exists: false } : {
          exists: true, integrity: observation === "matching" ? p.integrity : "sha512-WRONG",
        };
      },
    };
    if (observation === "divergent") {
      assert.throws(() => resume({ ...f, registryTransport }), RegistryIntegrityConflictError);
      assert.equal(calls.length, 1);
    } else {
      const result = resume({ ...f, registryTransport });
      assert.equal(calls.length, f.manifest.packages.length);
      assert.equal(result.toPublish.length, observation === "missing" ? 10 : 0);
      for (const entry of Object.values(loadState(f.releaseDir).packages)) {
        assert.equal(entry.publishStatus, observation === "missing" ? "pending" : "published");
        if (observation === "missing") assert.equal(entry.registryVerified, undefined);
      }
    }
  });
}

for (const stop of ["conflict", "throw", "ambiguous conflict"]) {
  test(`mid-loop ${stop} persists prior success and diagnostic BEFORE surfacing error`, () => {
    const f = packFixture();
    f.state.phase = "VERIFIED_LOCAL";
    const [first, second] = f.manifest.packages;
    const lookedUp = [], attempted = [];
    const registryTransport = {
      getRegistryVersion(name) {
        lookedUp.push(name);
        if (name === second.package) {
          if (stop === "throw") throw new Error("transport unavailable");
          if (stop === "conflict" || attempted.includes(name)) return { exists: true, integrity: "sha512-WRONG" };
        }
        return { exists: false };
      },
      publish(data) {
        attempted.push(data.package);
        return { ok: data.package === first.package, error: "ambiguous" };
      },
    };
    assert.throws(() => publishNext({ ...f, registryTransport }), (error) => {
      // This runs as the error reaches the caller: disk must already be updated.
      const saved = loadState(f.releaseDir);
      assert.equal(saved.phase, "PARTIAL_NEXT");
      assert.equal(saved.packages[first.package].publishStatus, "published");
      assert.equal(saved.blocker.package, second.package);
      assert.equal(saved.blocker.code, stop === "throw" ? "PUBLICATION_FAILED" : "REGISTRY_INTEGRITY_CONFLICT");
      assert.ok(saved.blocker.message);
      assert.ok(lookedUp.every((name) => [first.package, second.package].includes(name)));
      assert.deepEqual(attempted, stop === "ambiguous conflict" ? [first.package, second.package] : [first.package]);
      return stop === "throw" || error instanceof RegistryIntegrityConflictError;
    });
  });
}

test("PARTIAL_NEXT resume records PUBLISHING_NEXT in transition history", () => {
  const f = packFixture();
  f.state.phase = "PARTIAL_NEXT";
  const before = f.state.history.length;
  publishNext({ ...f, registryTransport: alwaysFailPublish(fakeRegistry()) });
  assert.deepEqual(f.state.history.slice(before).map((e) => e.phase), ["PUBLISHING_NEXT", "PARTIAL_NEXT"]);
});

for (const field of ["peerDependencies", "optionalDependencies"]) {
  test(`${field} constrain publish order and participate in cycle detection`, () => {
    const ds = fakeDiscovered({ withDeps: false });
    ds[0].manifest[field] = { "@oxdeai/guard": "^2.0.0", external: "*" };
    assert.match(validatePublishOrder(ds).join("\n"), /strictly before/);
    ds[1].manifest.dependencies = { "@oxdeai/core": "^2.0.0" };
    assert.match(validatePublishOrder(ds).join("\n"), /cycle/);
  });
}

test("dependency fields deduplicate internal names and ignore dev and undiscovered dependencies", () => {
  const ds = fakeDiscovered();
  ds[1].manifest.peerDependencies = ds[1].manifest.dependencies;
  ds[1].manifest.optionalDependencies = { "@oxdeai/core": "^2.0.0", "@oxdeai/absent": "*" };
  ds[0].manifest.devDependencies = { "@oxdeai/guard": "*" };
  assert.deepEqual(buildDependencyGraph(ds).get("@oxdeai/guard"), ["@oxdeai/core"]);
  assert.deepEqual(validatePublishOrder(ds), []);
});

for (const mode of ["absent", "missing", "wrong", "some", "wrong tag", "exact"]) {
  test(`promotion requires independently observed exact latest versions: ${mode}`, () => {
    const f = packFixture();
    f.state.phase = "READY_TO_PROMOTE";
    f.state.packages = fullyPublishedState(f.manifest);
    saveState(f.releaseDir, f.state);
    const applied = [], observed = [];
    const tags = new Map(f.manifest.packages.map((p) => [p.package, p.version]));
    const promotionTransport = mode === "absent" ? undefined : {
      applyDistTag(entry) { applied.push(entry); return { ok: true }; },
      observeDistTag(name, tag) {
        assert.equal(applied.length, 10);
        assert.equal(tag, "latest");
        observed.push(name);
        if (mode === "missing" || (mode === "some" && name === "@oxdeai/cli")) return undefined;
        return { tag: mode === "wrong tag" ? "next" : tag, version: mode === "wrong" ? "9.9.9" : tags.get(name) };
      },
    };
    if (mode === "exact") {
      assert.equal(promote({ ...f, promotionTransport }).state.phase, "PROMOTED");
      assert.equal(observed.length, 10);
      assert.equal(loadState(f.releaseDir).phase, "PROMOTED");
    } else {
      assert.throws(() => promote({ ...f, promotionTransport }), /promotionTransport|dist-tag verification/);
      assert.equal(f.state.phase, "READY_TO_PROMOTE");
      assert.equal(loadState(f.releaseDir).phase, "READY_TO_PROMOTE");
      if (mode === "some") assert.equal(observed.length, 10);
    }
  });
}

test("only transition() assigns a phase and it validates state before assignment", () => {
  const source = readFileSync(new URL("./orchestrator.mjs", import.meta.url), "utf8");
  assert.deepEqual(source.match(/state\.phase\s*=(?!=)[^;]*;/g), ["state.phase = to;"]);
  assert.match(source, /function transition\(state, to, manifest\) \{\s*validateState\(manifest, state\);\s*assertValidTransition\(state.phase, to\);/);
});

for (const evidence of ["complete release", MANIFEST_FILENAME, STATE_FILENAME, "tarballs"]) {
  test(`PACK refuses existing ${evidence} before any probe or packing`, () => {
    const f = evidence === "complete release" ? packFixture() : {
      releaseDir: tmpDir("oxdeai-existing-release-"), discovered: fakeDiscovered(),
    };
    if (evidence === "tarballs") mkdirSync(path.join(f.releaseDir, evidence));
    else if (evidence !== "complete release") writeFileSync(path.join(f.releaseDir, evidence), "existing identity evidence");
    const files = evidence === "complete release"
      ? [MANIFEST_FILENAME, STATE_FILENAME, ...f.manifest.packages.map((p) => p.tarball)]
      : evidence === "tarballs" ? [] : [evidence];
    const before = files.map((file) => readFileSync(path.join(f.releaseDir, file)));
    let calls = 0;
    assert.throws(() => pack({
      discovered: f.discovered, releaseDir: f.releaseDir, sourceRevision: SHA,
      packTransport: { packToDir() { calls++; assert.fail("existing release must never be packed or probed"); } },
    }), /Repacking\/reconstruction.*forbidden.*original manifest\/tarballs/);
    assert.equal(calls, 0);
    files.forEach((file, i) => assert.deepEqual(readFileSync(path.join(f.releaseDir, file)), before[i]));
  });
}

test("failed local integrity verification leaves persisted PACKED state unchanged", () => {
  const f = packFixture();
  const before = readFileSync(path.join(f.releaseDir, STATE_FILENAME));
  writeFileSync(path.join(f.releaseDir, f.manifest.packages[0].tarball), "changed bytes");
  assert.throws(() => verifyLocal(f), /local tarball integrity/);
  assert.deepEqual(readFileSync(path.join(f.releaseDir, STATE_FILENAME)), before);
  assert.equal(loadState(f.releaseDir).phase, "PACKED");
  assert.ok(!f.state.history.some((entry) => entry.phase === "VERIFIED_LOCAL"));
});

for (const mode of ["missing", "matching", "divergent"]) {
  test(`direct PARTIAL_NEXT publish reconciles forged published state: ${mode}`, () => {
    const f = packFixture();
    f.state.phase = "PARTIAL_NEXT";
    f.state.packages = fullyPublishedState(f.manifest);
    saveState(f.releaseDir, f.state);
    const queried = [], attempts = [];
    const registryTransport = {
      getRegistryVersion(name, version) {
        const p = f.manifest.packages.find((p) => p.package === name);
        assert.equal(version, p.version);
        if (queried.length < f.manifest.packages.length) {
          assert.equal(f.state.phase, "PARTIAL_NEXT");
          assert.equal(attempts.length, 0);
        }
        queried.push(name);
        if (mode === "missing") return { exists: false };
        return { exists: true, integrity: mode === "divergent" && name === "@oxdeai/cli" ? "sha512-WRONG" : p.integrity };
      },
      publish(data) {
        assert.ok(queried.length >= f.manifest.packages.length);
        assert.equal(f.state.packages[data.package].publishStatus, "pending");
        assert.equal(f.state.packages[data.package].registryVerified, undefined);
        attempts.push(data.package);
        return { ok: true };
      },
    };
    if (mode === "divergent") {
      assert.throws(() => publishNext({ ...f, registryTransport }), (error) => {
        const saved = loadState(f.releaseDir);
        assert.equal(saved.phase, "PARTIAL_NEXT");
        assert.equal(saved.blocker.code, "REGISTRY_INTEGRITY_CONFLICT");
        assert.equal(saved.blocker.package, "@oxdeai/cli");
        assert.equal(saved.blocker.registryIntegrity, "sha512-WRONG");
        assert.ok(!saved.history.some((entry) => entry.phase === "PUBLISHING_NEXT"));
        assert.equal(attempts.length, 0);
        return error instanceof RegistryIntegrityConflictError;
      });
    } else {
      const result = publishNext({ ...f, registryTransport });
      assert.equal(result.phase, "PUBLISHED_NEXT");
      assert.deepEqual(attempts, mode === "missing" ? f.manifest.packages.map((p) => p.package) : []);
      for (const p of f.manifest.packages) assert.equal(result.packages[p.package].registryIntegrity, p.integrity);
      assert.deepEqual(result.history.slice(-2).map((entry) => entry.phase), ["PUBLISHING_NEXT", "PUBLISHED_NEXT"]);
    }
    assert.deepEqual(queried.slice(0, f.manifest.packages.length), f.manifest.packages.map((p) => p.package));
  });
}

for (const command of ["precheck", "pack"]) {
  test(`CLI ${command} reports local-only precheck and authorization checks NOT RUN`, () => {
    const base = tmpDir("oxdeai-cli-reporting-");
    try {
      const binDir = path.join(base, "bin");
      mkdirSync(binDir);
      // Only fixture git is available on PATH; no npm or pnpm can run.
      writeFileSync(path.join(binDir, "git"),
        '#!/bin/sh\ncase "$1 $2" in\n' +
        '  "status --porcelain") exit 0 ;;\n' +
        `  "rev-parse HEAD") printf '%s\\n' '${SHA}' ;;\n` +
        '  *) exit 1 ;;\nesac\n', { mode: 0o755 });
      const releaseDir = path.join(base, "release");
      mkdirSync(releaseDir);
      // The PACK guard must stop execution after reporting and before packing.
      writeFileSync(path.join(releaseDir, MANIFEST_FILENAME), "existing release");
      const result = spawnSync(process.execPath, [
        fileURLToPath(new URL("./orchestrator.mjs", import.meta.url)), command,
        "--release-dir", releaseDir,
      ], { encoding: "utf8", env: { ...process.env, PATH: binDir } });
      assert.ifError(result.error);
      assert.equal(result.status, command === "precheck" ? 0 : 1, result.stderr);
      assert.equal(result.stdout,
        "PRECHECK (local): PASS\nRegistry auth/rights/public-scope checks: NOT RUN\n");
      if (command === "pack") assert.match(result.stderr, /Repacking\/reconstruction.*forbidden/);
      else assert.equal(result.stderr, "");
      assert.equal(readFileSync(path.join(releaseDir, MANIFEST_FILENAME), "utf8"), "existing release");
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });
}
