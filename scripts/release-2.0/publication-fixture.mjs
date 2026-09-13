// SPDX-License-Identifier: Apache-2.0
// Test receipts only: no real artifact verification or registry observation.
import assert from "node:assert/strict";
import { derivePublicationPlan, evaluateReleaseReadiness, STATE_VERSION } from "./orchestrator.mjs";
import { RELEASE_REGISTRY_REQUIREMENTS } from "./auth-precheck.mjs";

export function fixturePlan(manifest, releaseDir) {
  const registry = RELEASE_REGISTRY_REQUIREMENTS.registry;
  const packages = manifest.packages;
  const readiness = evaluateReleaseReadiness({
    manifest,
    localPrecheck: { ok: true, discovered: packages.map(p => ({ name: p.package, manifest: { version: p.version } })) },
    state: { stateVersion: STATE_VERSION, releaseId: manifest.releaseId, phase: "VERIFIED_LOCAL",
      history: ["PRECHECK", "PACKED", "VERIFIED_LOCAL"].map(phase => ({ phase, at: manifest.createdAt })),
      packages: Object.fromEntries(packages.map(p => [p.package, { publishStatus: "pending" }])) },
    authPrecheck: { blockers: [], observations: {
      identity: { kind: "identity", registry, username: "maintainer" },
      access: { kind: "access", registry, subject: "maintainer", packages: Object.fromEntries(packages.map(p => [p.package, "read-write"])) },
      packages: packages.map(p => ({ kind: "existing", registry, packageName: p.package, visibility: "public" })),
    } },
  });
  assert.equal(readiness.kind, "ready", JSON.stringify(readiness));
  return derivePublicationPlan({ readiness, releaseDir });
}
