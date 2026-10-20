// SPDX-License-Identifier: Apache-2.0
//
// Release finalization (RELEASE-FINALIZATION-01): per-package `latest`
// promotion and `next` removal for the selected publication set.
//
//   READY_TO_PROMOTE -> PROMOTING_LATEST -> PROMOTED -> REMOVING_NEXT -> FINALIZED
//
// promoteLatest()/removeNext() each perform at most one remote effect for one
// selected package, after its specific consent and an independent observation,
// and re-observe afterwards. verifyLatestPromotion()/verifyFinalization()
// independently observe the whole selected set before advancing the phase.
// Every phase change and in-flight effect is persisted, so an interrupted run
// resumes by re-observing the registry rather than trusting transport results.
//
// SAFETY GATE: there is no default transport. `distTagTransport` is injected by
// trusted calling code; this module never spawns npm or any other process, and
// command fields are data only. Excluded packages are never observed or changed.
//
// distTagTransport (synchronous):
//   observeDistTag({ registry, package, tag })
//     -> { registry, package, tag, present: false }
//      | { registry, package, tag, present: true, version }
//   addDistTag(operation)     // operation.operation === "promote-latest"
//   removeDistTag(operation)  // operation.operation === "remove-next"
// Return values of add/remove are ignored: only observations are evidence.

import path from "node:path";
import { RELEASE_REGISTRY_REQUIREMENTS } from "./auth-precheck.mjs";
import { validateNextRemovalAuthorization, validatePromotionAuthorization } from "./finalization-authorization.mjs";
import {
  FINALIZATION_RECORD_VERSION, ReleaseOrchestratorError, allPackagesReady, computeFinalizationDigest,
  computeManifestIntegrity, expectedFinalizationPackages, publicationPackages, saveState,
  transitionReleaseState, validateState,
} from "./orchestrator.mjs";

const object = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const fail = (code, message) => { throw new ReleaseOrchestratorError(message, { code }); };
const OBSERVATION_KEYS = ["registry", "package", "tag", "present", "version"];

export function buildDistTagOperation(operation, p, registry) {
  return operation === "promote-latest"
    ? { operation, registry, package: p.package, version: p.version, tag: "latest",
      command: { executable: "npm", args: ["dist-tag", "add", `${p.package}@${p.version}`, "latest", "--registry", registry] } }
    : { operation, registry, package: p.package, version: p.version, tag: "next",
      command: { executable: "npm", args: ["dist-tag", "rm", p.package, "next", "--registry", registry] } };
}

// Returns the observed version, or null for an absent tag. Anything malformed,
// attributed to another registry/package/tag, or thrown is indeterminate.
function observeTag(transport, registry, packageName, tag) {
  let o;
  try { o = transport.observeDistTag({ registry, package: packageName, tag }); }
  catch (error) { fail("DIST_TAG_STATE_UNDETERMINED", `${packageName} ${tag}: observation failed: ${error?.message ?? error}`); }
  if (!object(o) || Object.keys(o).some((k) => !OBSERVATION_KEYS.includes(k)) ||
      o.registry !== registry || o.package !== packageName || o.tag !== tag || typeof o.present !== "boolean" ||
      (o.present ? typeof o.version !== "string" || !o.version : Object.hasOwn(o, "version"))) {
    fail("DIST_TAG_STATE_UNDETERMINED", `${packageName} ${tag}: indeterminate or contradictory observation`);
  }
  return o.present ? o.version : null;
}

// Shared fail-closed gate: nothing here observes or mutates anything.
function prepare(inputs, { phases, operation, methods }) {
  if (!object(inputs)) fail("FINALIZATION_INPUT_INVALID", "finalization inputs must be an object");
  const { manifest, state, releaseDir, registry, distTagTransport } = inputs;
  if (typeof releaseDir !== "string" || !path.isAbsolute(releaseDir)) fail("FINALIZATION_INPUT_INVALID", "releaseDir must be absolute");
  if (!object(manifest) || computeManifestIntegrity(manifest) !== manifest.manifestIntegrity) {
    fail("MANIFEST_INTEGRITY_MISMATCH", "the frozen manifest has been modified");
  }
  try { validateState(manifest, state); }
  catch (error) { fail("FINALIZATION_STATE_INVALID", error.message); }
  if (!phases.includes(state.phase)) fail("FINALIZATION_PHASE_INVALID", `expected phase in [${phases.join(", ")}], got ${state.phase}`);
  if (!allPackagesReady(manifest, state)) fail("FINALIZATION_STATE_INVALID", "every selected package must be published and verified");
  if (registry !== RELEASE_REGISTRY_REQUIREMENTS.registry) fail("FINALIZATION_INPUT_INVALID", "registry must be the release registry");
  let p;
  if (operation) {
    const matches = publicationPackages(manifest).filter((s) => s.package === inputs.package);
    if (matches.length !== 1) fail("PACKAGE_NOT_SELECTED", `${inputs.package} is not in the publication selection`);
    p = matches[0];
    // An unresolved attempt or blocker may only be retried by the same operation.
    for (const field of ["finalizationAttempt", "finalizationBlocker"]) {
      if (Object.hasOwn(state, field) && (state[field].package !== p.package || state[field].operation !== operation)) {
        fail("FINALIZATION_BLOCKED", `unresolved ${field} for ${state[field].package} must be resolved first`);
      }
    }
  } else if (Object.hasOwn(state, "finalizationAttempt") || Object.hasOwn(state, "finalizationBlocker")) {
    fail("FINALIZATION_BLOCKED", "an unresolved finalization attempt or blocker remains");
  }
  if (!object(distTagTransport) || methods.some((m) => typeof distTagTransport[m] !== "function")) {
    fail("FINALIZATION_TRANSPORT_INVALID", `an injected distTagTransport with ${methods.join(", ")} is required`);
  }
  return p;
}

function block(state, p, operation, code, message) {
  state.finalizationBlocker = { code, operation, package: p.package, message: String(message) };
}

// One effect, then an independent re-observation. `expectedAfter` is the tag
// value that proves the effect; `before` means it is not (yet) visible.
function applyAndObserve({ inputs, state, p, operation, tag, before, expectedAfter, effect, now }) {
  const { manifest, releaseDir, registry, distTagTransport } = inputs;
  state.finalizationAttempt = { operation, package: p.package, version: p.version, startedAt: now() };
  saveState(releaseDir, state); // persisted before the effect: a crash leaves a visible in-flight record
  let effectError;
  try { distTagTransport[effect](buildDistTagOperation(operation, p, registry)); }
  catch (error) { effectError = error; }
  let after;
  try { after = observeTag(distTagTransport, registry, p.package, tag); }
  catch (error) {
    // Outcome unknown: keep the attempt so a restart reconciles by observation.
    block(state, p, operation, "DIST_TAG_STATE_UNDETERMINED", error.message);
    validateState(manifest, state); saveState(releaseDir, state);
    throw error;
  }
  delete state.finalizationAttempt;
  if (after === expectedAfter) return true;
  const conflict = after !== before;
  const code = conflict ? "DIST_TAG_CONFLICT" : `${operation === "promote-latest" ? "PROMOTION" : "NEXT_REMOVAL"}_NOT_OBSERVED`;
  const message = conflict ? `${p.package} ${tag} is ${after} after the effect; expected ${expectedAfter ?? "absent"}`
    : `${p.package} ${tag} unchanged after the effect${effectError ? `: ${effectError?.message ?? effectError}` : ""}`;
  block(state, p, operation, code, message);
  validateState(manifest, state); saveState(releaseDir, state);
  throw new ReleaseOrchestratorError(message, { code, cause: effectError });
}

// Promote one selected package's `latest` to its frozen version.
export function promoteLatest(inputs = {}) {
  const now = inputs?.now ?? (() => new Date().toISOString());
  const p = prepare(inputs, { phases: ["READY_TO_PROMOTE", "PROMOTING_LATEST"], operation: "promote-latest",
    methods: ["observeDistTag", "addDistTag"] });
  const { manifest, state, releaseDir, registry, distTagTransport } = inputs;
  const consent = validatePromotionAuthorization({ authorization: inputs.authorization, manifest, package: p.package, registry });
  const before = observeTag(distTagTransport, registry, p.package, "latest");
  if (before !== p.version && before !== consent.replaces) {
    // Pre-effect conflict: nothing is changed or persisted.
    fail("DIST_TAG_CONFLICT", `${p.package} latest is ${before ?? "absent"}; consent covers replacing ${consent.replaces ?? "absent"} only`);
  }
  if (state.phase === "READY_TO_PROMOTE") transitionReleaseState(state, "PROMOTING_LATEST", manifest);
  const effect = before !== p.version && applyAndObserve({ inputs, state, p, operation: "promote-latest", tag: "latest",
    before, expectedAfter: p.version, effect: "addDistTag", now });
  state.packages[p.package] = { ...state.packages[p.package], latestVerified: true };
  delete state.finalizationBlocker;
  delete state.finalizationAttempt;
  saveState(releaseDir, state);
  return { state, effect: Boolean(effect) };
}

function observeSelected(inputs, tag, expected) {
  const mismatches = [];
  for (const p of publicationPackages(inputs.manifest)) {
    const observed = observeTag(inputs.distTagTransport, inputs.registry, p.package, tag);
    if (observed !== expected(p)) mismatches.push(`${p.package} ${tag}=${observed ?? "absent"}`);
  }
  return mismatches;
}

// Independently observe every selected `latest` before declaring PROMOTED.
// Failures change nothing; promoteLatest() always re-observes, so a retry
// reconciles any drift under fresh consent.
export function verifyLatestPromotion(inputs = {}) {
  prepare(inputs, { phases: ["PROMOTING_LATEST"], methods: ["observeDistTag"] });
  const { manifest, state, releaseDir } = inputs;
  if (publicationPackages(manifest).some((p) => state.packages[p.package].latestVerified !== true)) {
    fail("PROMOTION_INCOMPLETE", "every selected package must be promoted before verification");
  }
  const mismatches = observeSelected(inputs, "latest", (p) => p.version);
  if (mismatches.length) fail("PROMOTION_VERIFICATION_FAILED", `latest verification failed: ${mismatches.join(", ")}`);
  transitionReleaseState(state, "PROMOTED", manifest);
  saveState(releaseDir, state);
  return state;
}

// Remove one selected package's `next` tag. Every invocation first re-verifies
// all selected `latest` tags, so removal never starts or continues on drift.
export function removeNext(inputs = {}) {
  const now = inputs?.now ?? (() => new Date().toISOString());
  const p = prepare(inputs, { phases: ["PROMOTED", "REMOVING_NEXT"], operation: "remove-next",
    methods: ["observeDistTag", "removeDistTag"] });
  const { manifest, state, releaseDir, registry, distTagTransport } = inputs;
  validateNextRemovalAuthorization({ authorization: inputs.authorization, manifest, package: p.package, registry });
  const drift = observeSelected(inputs, "latest", (s) => s.version);
  if (drift.length) fail("LATEST_NOT_VERIFIED", `next removal requires every selected latest: ${drift.join(", ")}`);
  const before = observeTag(distTagTransport, registry, p.package, "next");
  if (before !== null && before !== p.version) {
    fail("DIST_TAG_CONFLICT", `${p.package} next is ${before}; only ${p.version} may be removed`);
  }
  if (state.phase === "PROMOTED") {
    // Historical PROMOTED states carry no latestVerified flags; the
    // observation above is their independent verification.
    for (const s of publicationPackages(manifest)) state.packages[s.package] = { ...state.packages[s.package], latestVerified: true };
    transitionReleaseState(state, "REMOVING_NEXT", manifest);
  }
  const effect = before !== null && applyAndObserve({ inputs, state, p, operation: "remove-next", tag: "next",
    before, expectedAfter: null, effect: "removeDistTag", now });
  state.packages[p.package] = { ...state.packages[p.package], nextRemoved: true };
  delete state.finalizationBlocker;
  delete state.finalizationAttempt;
  saveState(releaseDir, state);
  return { state, effect: Boolean(effect) };
}

// The only path to FINALIZED: every selected package observed with
// latest = frozen version and no next tag, recorded as persistent evidence.
export function verifyFinalization(inputs = {}) {
  const now = inputs?.now ?? (() => new Date().toISOString());
  prepare(inputs, { phases: ["REMOVING_NEXT"], methods: ["observeDistTag"] });
  const { manifest, state, releaseDir, registry } = inputs;
  if (publicationPackages(manifest).some((p) => state.packages[p.package].nextRemoved !== true)) {
    fail("FINALIZATION_INCOMPLETE", "next must be removed for every selected package before verification");
  }
  const mismatches = [...observeSelected(inputs, "latest", (p) => p.version), ...observeSelected(inputs, "next", () => null)];
  if (mismatches.length) fail("FINALIZATION_VERIFICATION_FAILED", `finalization verification failed: ${mismatches.join(", ")}`);
  transitionReleaseState(state, "FINALIZED", manifest);
  const record = {
    kind: "release-finalization", finalizationVersion: FINALIZATION_RECORD_VERSION,
    releaseId: manifest.releaseId, manifestIntegrity: manifest.manifestIntegrity, registry,
    packages: expectedFinalizationPackages(manifest), verifiedAt: now(),
  };
  record.finalizationDigest = computeFinalizationDigest(record);
  state.finalization = record;
  validateState(manifest, state);
  saveState(releaseDir, state);
  return state;
}

// PROMOTED (historical or new) is never a complete finalization.
export function isReleaseFinalized(manifest, state) {
  try { return validateState(manifest, state).phase === "FINALIZED"; } catch { return false; }
}
