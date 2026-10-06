// SPDX-License-Identifier: Apache-2.0
// Hermetic PRECHECK inputs for unit tests. Receipts are always produced by the
// real precheck(); only git/package.json observations are injected.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { precheck, computeManifestIntegrity } from "./orchestrator.mjs";
export const fixturePackages = { read: d => Buffer.from(JSON.stringify(d.manifest)) };
export function persistFixturePrecheck(discovered, releaseDir, revision = "a".repeat(40), root = "/fake", overrides = {}) {
  return precheck({ discovered, releaseDir, sourceRevision: revision,
    gitTransport: { isClean: () => true }, sourceTransport: { snapshot: () => ({ root, revision, clean: true }) },
    packageTransport: fixturePackages, ...overrides });
}
// For unit tests of phases AFTER VERIFY_LOCAL that start from hand-built
// manifests/states. Not used by lifecycle tests (precheck-receipt.test.mjs,
// orchestrator.local.test.mjs), which run PRECHECK -> PACK -> VERIFY_LOCAL.
export function bindFixturePrecheck(manifest, state) {
  if (!manifest.precheck) {
    const dir = mkdtempSync(path.join(tmpdir(), "oxdeai-precheck-fixture-"));
    try {
      manifest.precheck = persistFixturePrecheck(manifest.packages.map(p => ({ name: p.package,
        dir: `/fake/${p.package.slice(8)}`, manifest: { name: p.package, version: p.version } })), dir, manifest.sourceRevision);
    } finally { rmSync(dir, { recursive: true, force: true }); }
    manifest.manifestIntegrity = computeManifestIntegrity(manifest);
  }
  state.history[0] = { phase: "PRECHECK", at: manifest.precheck.observedAt, receiptDigest: manifest.precheck.receiptDigest };
}
