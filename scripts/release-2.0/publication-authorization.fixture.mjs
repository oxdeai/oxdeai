// SPDX-License-Identifier: Apache-2.0
// Test-only outer consent and process fixtures. No packing or real npm calls.
import assert from "node:assert/strict";
import { mock } from "node:test";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { POLICY } from "../verify-packed-artifacts.mjs";
import { fixturePlan } from "./publication-fixture.mjs";
import { computeManifestIntegrity, computeSriIntegrity, MANIFEST_VERSION, STATE_VERSION } from "./orchestrator.mjs";
import { publishAuthorizedOperation } from "./npm-publication-transport.mjs";

export function consent(f, index = f.operationIndex) {
  const p = f.plan.operations[index];
  return { kind: "publication-authorization", authorizationVersion: 1,
    releaseId: f.manifest.releaseId, manifestIntegrity: f.manifest.manifestIntegrity,
    operationIndex: index, package: p.package, version: p.version, tarball: p.tarball,
    integrity: p.integrity, registry: p.registry, tag: "next", access: "public" };
}
export function fixture(t) {
  const releaseDir = fs.mkdtempSync(path.join(tmpdir(), "oxdeai-consent-test-"));
  t.after(() => fs.rmSync(releaseDir, { recursive: true, force: true }));
  fs.mkdirSync(path.join(releaseDir, "tarballs"));
  const releaseId = "a".repeat(40), createdAt = "2026-09-13T00:00:00.000Z";
  const packages = Object.entries(POLICY).map(([name, p]) => {
    const tarball = `tarballs/${name.slice(8)}.tgz`, bytes = Buffer.from(name);
    fs.writeFileSync(path.join(releaseDir, tarball), bytes);
    return { package: name, version: p.version, releaseLine: p.releaseLine, publishOrder: p.publishOrder,
      tarball, integrity: computeSriIntegrity(bytes) };
  });
  const manifest = { manifestVersion: MANIFEST_VERSION, releaseId, sourceRevision: releaseId, createdAt, packages,
    determinismProbe: { package: packages[0].package, deterministic: false, hashA: "a".repeat(64), hashB: "b".repeat(64) } };
  manifest.manifestIntegrity = computeManifestIntegrity(manifest);
  const state = { stateVersion: STATE_VERSION, releaseId, phase: "VERIFIED_LOCAL",
    history: ["PRECHECK", "PACKED", "VERIFIED_LOCAL"].map(phase => ({ phase, at: createdAt })),
    packages: Object.fromEntries(packages.map(p => [p.package, { publishStatus: "pending" }])) };
  const f = { manifest, state, releaseDir, operationIndex: 0, plan: fixturePlan(manifest, releaseDir), calls: [] };
  f.authorization = consent(f);
  const registry = new Map();
  f.respond = (_exe, args) => {
    if (args[0] === "publish") {
      const p = f.plan.operations.find(p => p.command.args[1] === args[1]);
      assert.ok(p, "fixture publication must bind a planned tarball");
      registry.set(p.package, p);
      return { status: 0, stdout: "{}", stderr: "" };
    }
    const p = [...registry.values()].find(p => args[1] === p.package || args[1] === `${p.package}@${p.version}`);
    const body = args[2] === "versions" ? (p ? [p.version] : ["1.0.0"]) : p?.integrity;
    return { status: 0, stdout: JSON.stringify(body), stderr: "" };
  };
  mock.method(childProcess, "spawnSync", (...args) => { f.calls.push(args); return f.respond(...args); });
  syncBuiltinESMExports();
  t.after(() => { mock.restoreAll(); syncBuiltinESMExports(); });
  return f;
}
export const publications = f => f.calls.filter(([, args]) => args[0] === "publish");
export function invoke(f) {
  const before = publications(f).length;
  try { return publishAuthorizedOperation(f); }
  finally { assert.ok(publications(f).length - before <= 1, "one invocation must start at most one npm publication process"); }
}
