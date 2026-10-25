// SPDX-License-Identifier: Apache-2.0
import { isDeepStrictEqual } from "node:util";
import { RELEASE_REGISTRY_REQUIREMENTS } from "./auth-precheck.mjs";
import { computeManifestIntegrity, publicationPackages, ReleaseOrchestratorError } from "./orchestrator.mjs";

// Outer consent receipts for dist-tag finalization (RELEASE-FINALIZATION-01).
// Like publication-authorization, these are unsigned control-flow artifacts a
// trusted caller supplies: they neither authenticate their issuer, prove
// freshness, nor prevent replay across restarts. They are not AuthorizationV1.
// Each receipt binds exactly one release, manifest digest, selected package,
// version, integrity, registry, tag and operation. Kinds never substitute for
// one another: a publication receipt cannot authorize promotion or removal.
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/;

function bind({ authorization, manifest, package: packageName, registry }, kind, codePrefix) {
  const object = v => v !== null && typeof v === "object" && !Array.isArray(v);
  const fail = (suffix, message) => { throw new ReleaseOrchestratorError(message, { code: `${codePrefix}_${suffix}` }); };
  if (authorization === undefined || authorization === null) {
    fail("AUTHORIZATION_REQUIRED", `explicit ${kind} for one selected package is required`);
  }
  if (!object(authorization) || authorization.kind !== kind || authorization.authorizationVersion !== 1) {
    fail("AUTHORIZATION_INVALID", `unsupported ${kind} receipt`);
  }
  if (!object(manifest) || !Array.isArray(manifest.packages) ||
      computeManifestIntegrity(manifest) !== manifest.manifestIntegrity) {
    fail("AUTHORIZATION_MISMATCH", `${kind} requires the frozen, unmodified manifest`);
  }
  if (registry !== RELEASE_REGISTRY_REQUIREMENTS.registry) {
    fail("AUTHORIZATION_MISMATCH", `${kind} requires the release registry`);
  }
  const matches = publicationPackages(manifest).filter(p => p.package === packageName);
  if (matches.length !== 1) fail("AUTHORIZATION_MISMATCH", `${kind} names a package outside the publication selection`);
  const p = matches[0];
  return {
    kind, authorizationVersion: 1, releaseId: manifest.releaseId, manifestIntegrity: manifest.manifestIntegrity,
    package: p.package, version: p.version, integrity: p.integrity, registry,
  };
}

function exact(authorization, expected, code) {
  if (!isDeepStrictEqual(authorization, expected)) {
    throw new ReleaseOrchestratorError("consent must exactly bind one operation; no additional authority is accepted", { code });
  }
  return structuredClone(expected);
}

// `replaces` is the explicit replacement policy: the exact prior `latest`
// version (or null for an absent tag) the operator consents to overwrite. Any
// other observed `latest` is a conflict.
export function validatePromotionAuthorization(inputs = {}) {
  const base = bind(inputs, "promotion-authorization", "PROMOTION");
  const replaces = inputs.authorization.replaces;
  if (!(replaces === null || (typeof replaces === "string" && VERSION.test(replaces) && replaces !== base.version))) {
    throw new ReleaseOrchestratorError("replaces must be null or an exact version other than the promoted one",
      { code: "PROMOTION_AUTHORIZATION_INVALID" });
  }
  return exact(inputs.authorization, { ...base, tag: "latest", operation: "dist-tag-add", replaces },
    "PROMOTION_AUTHORIZATION_MISMATCH");
}

export function validateNextRemovalAuthorization(inputs = {}) {
  const base = bind(inputs, "next-removal-authorization", "NEXT_REMOVAL");
  return exact(inputs.authorization, { ...base, tag: "next", operation: "dist-tag-rm" },
    "NEXT_REMOVAL_AUTHORIZATION_MISMATCH");
}
