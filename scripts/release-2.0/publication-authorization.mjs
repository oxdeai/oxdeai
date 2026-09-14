// SPDX-License-Identifier: Apache-2.0
import { isDeepStrictEqual } from "node:util";
import { computeManifestIntegrity, ReleaseOrchestratorError } from "./orchestrator.mjs";

// The outer operator/caller supplies this receipt as an explicit decision.
// There is deliberately no automatic issuer in readiness, planning or execution.
// This unsigned control-flow artifact neither authenticates its issuer nor proves
// freshness or consumption across restarts. Trusted calling code owns consent.
// It is not a protocol AuthorizationV1 or a substitute for credential controls.
export function validatePublicationAuthorization({ authorization, plan, operationIndex, manifest } = {}) {
  const object = v => v !== null && typeof v === "object" && !Array.isArray(v);
  const fail = (code, message) => { throw new ReleaseOrchestratorError(message, { code }); };
  if (authorization === undefined || authorization === null) {
    fail("PUBLICATION_AUTHORIZATION_REQUIRED", "explicit consent for one publication operation is required");
  }
  if (!object(authorization) || authorization.kind !== "publication-authorization" || authorization.authorizationVersion !== 1) {
    fail("PUBLICATION_AUTHORIZATION_INVALID", "unsupported publication authorization receipt");
  }
  if (!object(plan) || plan.kind !== "publication-plan" || !Array.isArray(plan.operations) ||
      !Number.isSafeInteger(operationIndex) || operationIndex < 0 || !object(plan.operations[operationIndex]) ||
      !object(manifest) || !Array.isArray(manifest.packages)) {
    fail("PUBLICATION_AUTHORIZATION_MISMATCH", "authorization requires an explicit frozen operation and manifest");
  }
  const op = plan.operations[operationIndex];
  const matches = manifest.packages.filter(p => p?.package === op.package);
  if (matches.length !== 1 || op.index !== operationIndex || op.releaseId !== plan.releaseId ||
      plan.releaseId !== manifest.releaseId || plan.evidence?.manifestIntegrity !== manifest.manifestIntegrity ||
      computeManifestIntegrity(manifest) !== manifest.manifestIntegrity ||
      op.registry !== plan.registry || op.tag !== "next" || plan.tag !== "next" ||
      op.access !== "public" || plan.access !== "public" ||
      ["version", "tarball", "integrity", "releaseLine", "publishOrder"].some(key => op[key] !== matches[0][key])) {
    fail("PUBLICATION_AUTHORIZATION_MISMATCH", "selected operation disagrees with the frozen release");
  }
  const expected = {
    kind: "publication-authorization", authorizationVersion: 1,
    releaseId: manifest.releaseId, manifestIntegrity: manifest.manifestIntegrity,
    operationIndex, package: op.package, version: op.version, tarball: op.tarball, integrity: op.integrity,
    registry: op.registry, tag: "next", access: "public",
  };
  if (!isDeepStrictEqual(authorization, expected)) {
    fail("PUBLICATION_AUTHORIZATION_MISMATCH", "consent must exactly bind one operation; no additional authority is accepted");
  }
  return structuredClone(op);
}
