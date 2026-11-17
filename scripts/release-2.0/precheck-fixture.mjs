// SPDX-License-Identifier: Apache-2.0
// Hermetic PRECHECK inputs for unit tests. Receipts are produced by the real
// precheck(); only git/package.json observations are injected. The single
// exception is forgeSelectionReceipt below, which exists only for negative tests.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { precheck, computeManifestIntegrity, computePrecheckReceiptDigest, PRECHECK_FILENAME } from "./orchestrator.mjs";
export const fixturePackages = { read: d => Buffer.from(JSON.stringify(d.manifest)) };
export function persistFixturePrecheck(discovered, releaseDir, revision = "a".repeat(40), root = "/fake", overrides = {}) {
  return precheck({ discovered, releaseDir, sourceRevision: revision,
    gitTransport: { isClean: () => true }, sourceTransport: { snapshot: () => ({ root, revision, clean: true }) },
    packageTransport: fixturePackages, ...overrides });
}
// NEGATIVE TESTS ONLY (R4, F-R4-1). Reproduces the forgery that bypassed the
// PRECHECK-only completeness rule: the real precheck() runs in full mode, then
// `selection` is inserted where PRECHECK would place it and the consistency
// digest (not an authentication) is recomputed. The forged receipt is written
// WITHOUT validation; every phase after PRECHECK must reject it on this R3
// checkout. It is never a valid receipt and is not a compatibility fixture.
export function forgeSelectionReceipt(discovered, releaseDir, revision = "a".repeat(40), root = "/fake", { selection, ...overrides } = {}) {
  if (selection === undefined) throw new Error("forgeSelectionReceipt requires a selection");
  const { receiptDigest, ...full } = persistFixturePrecheck(discovered, releaseDir, revision, root, overrides);
  const { receiptVersion, ok, sourceRevision, ...rest } = full;
  const receipt = { receiptVersion, ok, sourceRevision, selection: structuredClone(selection), ...rest };
  receipt.receiptDigest = computePrecheckReceiptDigest(receipt);
  writeFileSync(path.join(releaseDir, PRECHECK_FILENAME), `${JSON.stringify(receipt, null, 2)}\n`);
  return receipt;
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
