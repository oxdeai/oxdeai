#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// OxDeAI 2.0 release orchestrator (#292).
//
// Establishes the provenance chain:
//
//   source revision -> packed bytes -> integrity -> installation verification
//   -> npm artifact -> dist-tag
//
// EPISTEMIC BOUNDARY: the manifest this module produces records enough
// independently-checkable evidence to verify that the recorded source
// revision, packed bytes, integrity, local consumer verification, registry
// bytes and dist-tag promotion are ALL for the same artifact. It does NOT
// cryptographically prove that the packed bytes were produced from the
// recorded source revision — that would require reproducible, independently
// re-executed builds, which is out of scope here. A clean working tree, a
// recorded revision, a controlled PACK step that runs exactly once per
// tarball, retained tarballs, and integrity bindings across every later
// phase are PROCESS provenance, not independent cryptographic proof.
//
// ABSOLUTE SAFETY GATE: this module never calls, spawns, or wraps
//   npm publish / npm dist-tag / npm unpublish
// PUBLISH_NEXT and PROMOTE use only caller-INJECTED `registryTransport`
// and `promotionTransport` — there is no default transport in this file
// that shells out to a real registry. `buildPublishCommandData()` and
// `buildPromotionPlan()` return the intended command as DATA ONLY; nothing in
// this file shell-executes that data. A future, separately authorized change may
// wire a real transport; doing so is explicitly out of scope for this file.
//
// Single source of truth: package discovery and release metadata (version,
// releaseLine, publishOrder) come from `../verify-packed-artifacts.mjs`'s
// POLICY table — this module does not define a second publishable-package
// list.

import { createHash } from "node:crypto";
import { observeRegistryPrecheck, RELEASE_REGISTRY_REQUIREMENTS } from "./auth-precheck.mjs";
import { spawnSync } from "node:child_process";
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  POLICY,
  assertPackedBijection,
  discoverPublishablePackages,
  assertPolicyCoverage,
  assertReleaseMetadataConsistency,
  verifyPackedTarballs,
} from "../verify-packed-artifacts.mjs";

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const MANIFEST_FILENAME = "release-manifest.json";
export const STATE_FILENAME = "release-state.json";
export const MANIFEST_VERSION = 1;
export const STATE_VERSION = 1;

// ── State machine ─────────────────────────────────────────────────────────

export const PHASES = Object.freeze([
  "PRECHECK", "PACKED", "VERIFIED_LOCAL", "PUBLISHING_NEXT", "PARTIAL_NEXT",
  "PUBLISHED_NEXT", "REGISTRY_VERIFIED", "EXTERNAL_INSTALL_VERIFIED",
  "READY_TO_PROMOTE", "PROMOTED",
]);

// Explicit transition graph (#292 requirement: "state transition graph
// rejects invalid/skipped transitions"). PARTIAL_NEXT -> PUBLISHING_NEXT is
// the resume edge; there is no PARTIAL_NEXT -> PACKED edge, which is what
// makes "PARTIAL_NEXT -> pnpm pack again" structurally rejected, not merely
// discouraged.
const TRANSITIONS = Object.freeze({
  PRECHECK: ["PACKED"],
  PACKED: ["VERIFIED_LOCAL"],
  VERIFIED_LOCAL: ["PUBLISHING_NEXT"],
  PUBLISHING_NEXT: ["PUBLISHED_NEXT", "PARTIAL_NEXT"],
  PARTIAL_NEXT: ["PUBLISHING_NEXT"],
  PUBLISHED_NEXT: ["REGISTRY_VERIFIED"],
  REGISTRY_VERIFIED: ["EXTERNAL_INSTALL_VERIFIED"],
  EXTERNAL_INSTALL_VERIFIED: ["READY_TO_PROMOTE"],
  READY_TO_PROMOTE: ["PROMOTED"],
  PROMOTED: [],
});

export class ReleaseOrchestratorError extends Error {
  constructor(message, fields = {}) {
    super(message);
    this.name = "ReleaseOrchestratorError";
    Object.assign(this, fields);
  }
}

export class RegistryIntegrityConflictError extends ReleaseOrchestratorError {
  constructor(pkg, version, manifestIntegrity, registryIntegrity) {
    super(
      `STOP: registry already has ${pkg}@${version} with integrity ${registryIntegrity}, ` +
      `which differs from the manifest's ${manifestIntegrity}. npm cannot safely replace ` +
      `the same name@version with different bytes. This requires human intervention ` +
      `(e.g. a new version), never automatic unpublish/replace/reconstruction.`
    );
    this.name = "RegistryIntegrityConflictError";
    this.pkg = pkg;
    this.version = version;
    this.manifestIntegrity = manifestIntegrity;
    this.registryIntegrity = registryIntegrity;
  }
}

export function assertValidTransition(from, to) {
  const allowed = TRANSITIONS[from];
  if (!allowed) throw new ReleaseOrchestratorError(`unknown state "${from}"`);
  if (!allowed.includes(to)) {
    throw new ReleaseOrchestratorError(
      `invalid state transition ${from} -> ${to}; allowed from ${from}: [${allowed.join(", ") || "(terminal)"}]`
    );
  }
  return true;
}

function transition(state, to, manifest) {
  validateState(manifest, state);
  assertValidTransition(state.phase, to);
  state.phase = to;
  state.history.push({ phase: to, at: new Date().toISOString() });
  return state;
}

function assertPhase(state, ...expected) {
  if (!expected.includes(state.phase)) {
    throw new ReleaseOrchestratorError(
      `expected release-state phase in [${expected.join(", ")}], got "${state.phase}"`
    );
  }
}

// ── Canonicalization / digest ────────────────────────────────────────────
//
// Deliberately NOT the protocol's canonicalJson (@oxdeai/core): release
// tooling data is plain strings/numbers/booleans/arrays/objects only (no
// bigint anywhere in a manifest or plan), so a small self-contained
// canonicalizer keeps this file decoupled from protocol wire-format
// evolution and, not incidentally, has no exposure to the bigint/string
// canonicalization-collision class documented for `Intent` fields elsewhere
// in this codebase — there is nothing bigint-shaped here to collide.
//
// Algorithm: recursively sort object keys, preserve array order, JSON-encode
// leaves via JSON.stringify. sha256Hex hashes the resulting UTF-8 string.
export function canonicalStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalStringify).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalStringify(value[k])}`).join(",")}}`;
}

export function sha256Hex(data) {
  return createHash("sha256").update(data).digest("hex");
}

// npm-compatible SRI, matching what a real npm registry's `dist.integrity`
// uses (sha512-<base64>), so direct string equality against a registry
// response is possible without any transform.
export function computeSriIntegrity(bytes) {
  return `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
}

// manifestIntegrity = digest(canonical JSON of the manifest EXCLUDING
// manifestIntegrity itself) — avoids recursive hashing (the field is never
// part of its own input).
export function computeManifestIntegrity(manifest) {
  const { manifestIntegrity, ...rest } = manifest;
  return `sha256:${sha256Hex(canonicalStringify(rest))}`;
}

// ── Dependency graph / publish order ─────────────────────────────────────

export function buildDependencyGraph(discovered) {
  const names = new Set(discovered.map((d) => d.name));
  const graph = new Map();
  for (const d of discovered) {
    const deps = { ...d.manifest.dependencies, ...d.manifest.peerDependencies, ...d.manifest.optionalDependencies };
    graph.set(d.name, Object.keys(deps).filter((dep) => names.has(dep)));
  }
  return graph;
}

function findCycle(graph) {
  const WHITE = 0, GRAY = 1, BLACK = 2;
  const color = new Map([...graph.keys()].map((k) => [k, WHITE]));
  const stack = [];

  function visit(node) {
    color.set(node, GRAY);
    stack.push(node);
    for (const dep of graph.get(node) ?? []) {
      if (color.get(dep) === GRAY) {
        return [...stack.slice(stack.indexOf(dep)), dep];
      }
      if (color.get(dep) === WHITE) {
        const found = visit(dep);
        if (found) return found;
      }
    }
    stack.pop();
    color.set(node, BLACK);
    return null;
  }

  for (const node of graph.keys()) {
    if (color.get(node) === WHITE) {
      const found = visit(node);
      if (found) return found;
    }
  }
  return null;
}

// Validates declared publishOrder against the REAL @oxdeai/* dependency graph
// read from each package's own package.json — publishOrder is never trusted
// merely because POLICY declares it (#292: "Do not trust publishOrder merely
// because it is declared in POLICY").
export function validatePublishOrder(discovered, policy = POLICY) {
  const violations = [];
  const graph = buildDependencyGraph(discovered);

  const cycle = findCycle(graph);
  if (cycle) {
    violations.push(`dependency cycle detected: ${cycle.join(" -> ")}`);
    return violations;
  }

  for (const [pkg, deps] of graph) {
    for (const dep of deps) {
      if (!policy[pkg] || !policy[dep]) continue; // reported by assertPolicyCoverage separately
      if (policy[dep].publishOrder >= policy[pkg].publishOrder) {
        violations.push(
          `${pkg} (publishOrder ${policy[pkg].publishOrder}) depends on ${dep} ` +
          `(publishOrder ${policy[dep].publishOrder}); a dependency must publish ` +
          `strictly before its dependents`
        );
      }
    }
  }
  return violations;
}

// ── PRECHECK ──────────────────────────────────────────────────────────────
//
// Transports are injected and REQUIRED (no default that touches real git,
// npm auth, or a real registry) so PRECHECK is fully fixture-testable and
// never requires live credentials for this task.
//
//   gitTransport.isClean(): boolean
//   authTransport (optional): { whoami(), listPackageAccess(subject),
//                                getPackageStatus(packageName) }
// These methods return registry-attributed observations, never release verdicts.
// Omission retains explicitly local-only CLI behavior. Injected observations
// are checked against the explicit RELEASE_REGISTRY_REQUIREMENTS invariant.

export function precheck({ discovered, policy = POLICY, gitTransport, authTransport }) {
  assertReleaseMetadataConsistency(policy);
  const blockers = [];

  if (!gitTransport || typeof gitTransport.isClean !== "function") {
    throw new ReleaseOrchestratorError("precheck requires an injected gitTransport with isClean()");
  }
  if (!gitTransport.isClean()) {
    blockers.push(
      "dirty working tree: the source revision -> packed bytes provenance statement is " +
      "materially incomplete with uncommitted changes present. Hard stop, not a warning."
    );
  }

  try {
    assertPolicyCoverage(discovered);
  } catch (e) {
    blockers.push(e.message);
  }

  for (const d of discovered) {
    const p = policy[d.name];
    if (!p) continue; // already reported by assertPolicyCoverage above
    if (p.version !== d.manifest.version) {
      blockers.push(
        `declared release version "${p.version}" for ${d.name} does not exactly match ` +
        `package.json version "${d.manifest.version}". Mismatch is a hard stop.`
      );
    }
  }

  blockers.push(...validatePublishOrder(discovered, policy));

  let registryObservations;
  if (authTransport !== undefined) {
    const registryCheck = observeRegistryPrecheck({ discovered, authTransport });
    registryObservations = registryCheck.observations;
    blockers.push(...registryCheck.blockers);
  }

  if (blockers.length > 0) {
    throw new ReleaseOrchestratorError(`PRECHECK failed:\n  - ${blockers.join("\n  - ")}`, { blockers });
  }
  return { ok: true, discovered, ...(registryObservations ? { registryObservations } : {}) };
}

// ── Step 4: explicit, pure readiness evaluation ────────────────────────────
// READY_FOR_PUBLISH is derived evidence for the next planning step, not a new
// persisted phase, authorization, or execution. VERIFIED_LOCAL remains the
// existing state-machine prerequisite. No transport or filesystem is consulted.
// authPrecheck is the already-produced { observations, blockers } result of
// observeRegistryPrecheck(), NOT an authTransport. Raw npm errors are irrelevant.
// Receipt/manifest consistency is checked; artifacts are not rebuilt/reverified.
// Existing receipts do not establish freshness, authenticity, or an independent
// source-to-bytes proof. This evaluator does not invent such evidence.
/**
 * @typedef {{code: string, detail: string, package?: string}} ReadinessFailure
 * @typedef {{kind: "ready", state: "READY_FOR_PUBLISH", evidence: object} |
 * {kind: "not-ready", reasons: ReadinessFailure[]}} ReleaseReadiness
 */
/** @returns {ReleaseReadiness} */
export function evaluateReleaseReadiness(inputs = {}) {
  if (inputs === null || typeof inputs !== "object" || Array.isArray(inputs)) {
    return { kind: "not-ready", reasons: [{ code: "POLICY_RELEASE_STATE_MISMATCH", detail: "evidence inputs must be an object" }] };
  }
  const { policy = POLICY, localPrecheck, manifest, state, authPrecheck } = inputs;
  const reasons = [];
  const reject = (code, detail, pkg) => reasons.push({ code, detail, ...(pkg ? { package: pkg } : {}) });
  const object = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  const sameSet = (names, expected) => Array.isArray(names) && names.length === expected.length &&
    new Set(names).size === names.length && names.every((name) => expected.includes(name));
  const unresolved = (v) => Object.hasOwn(v, "blockers") && (!Array.isArray(v.blockers) || v.blockers.length !== 0);

  if (!object(localPrecheck) || localPrecheck.ok !== true || unresolved(localPrecheck)) {
    reject("LOCAL_PRECHECK_NOT_PASSED", "a successful local precheck receipt is required");
  }
  try {
    if (!object(policy) || Object.keys(policy).length === 0) throw new Error();
    assertReleaseMetadataConsistency(policy);
  } catch {
    reject("POLICY_RELEASE_STATE_MISMATCH", "invalid release POLICY");
    return { kind: "not-ready", reasons };
  }
  const names = Object.keys(policy).sort(); // Stable evidence ordering, not an execution plan.
  const candidates = localPrecheck?.discovered;
  if (!Array.isArray(candidates) || !sameSet(candidates.map((p) => p?.name), names) ||
      candidates.some((p) => p.manifest?.version !== policy[p.name].version)) {
    reject("POLICY_RELEASE_STATE_MISMATCH", "local precheck package set/versions differ from POLICY");
  }
  if (!object(manifest) || manifest.manifestVersion !== MANIFEST_VERSION ||
      !/^[0-9a-f]{40}$/.test(manifest.releaseId ?? "") || manifest.releaseId !== manifest.sourceRevision ||
      !Array.isArray(manifest.packages)) {
    reject("PACKED_ARTIFACTS_NOT_VERIFIED", "valid manifest identity and package records are required");
    return { kind: "not-ready", reasons };
  }
  if (!sameSet(manifest.packages.map((p) => p?.package), names)) {
    reject("POLICY_RELEASE_STATE_MISMATCH", "manifest package set differs from POLICY");
  }
  for (const p of manifest.packages) {
    const expected = policy[p?.package];
    if (!expected || p.version !== expected.version || p.releaseLine !== expected.releaseLine || p.publishOrder !== expected.publishOrder) {
      reject("POLICY_RELEASE_STATE_MISMATCH", "manifest release metadata differs from POLICY", p?.package);
    }
    if (!object(p) || typeof p.tarball !== "string" || !p.tarball ||
        typeof p.integrity !== "string" || !/^sha512-[A-Za-z0-9+/]{86}==$/.test(p.integrity)) {
      reject("PACKED_ARTIFACTS_NOT_VERIFIED", "missing or malformed recorded artifact identity", p?.package);
    }
  }
  try {
    if (manifest.manifestIntegrity !== computeManifestIntegrity(manifest)) throw new Error();
  } catch {
    reject("PACKED_ARTIFACTS_NOT_VERIFIED", "manifest digest does not bind the supplied manifest records");
  }
  try {
    validateState(manifest, state);
    if (state.phase !== "VERIFIED_LOCAL" || Object.values(state.packages).some((p) => p.publishStatus !== "pending") ||
        Object.hasOwn(state, "blocker")) {
      reject("PUBLICATION_PLANNING_STATE_INVALID", "publication planning requires VERIFIED_LOCAL with pending packages and no blocker");
    }
    if (state.history.at(-1)?.phase !== "VERIFIED_LOCAL") {
      reject("PACKED_ARTIFACTS_NOT_VERIFIED", "local artifact verification is not recorded in current state history");
    }
  } catch {
    reject("POLICY_RELEASE_STATE_MISMATCH", "state structure or release identity does not match the manifest");
    reject("PACKED_ARTIFACTS_NOT_VERIFIED", "valid local verification state is required");
  }

  if (!object(authPrecheck) || !Array.isArray(authPrecheck.blockers) || authPrecheck.blockers.length !== 0 ||
      (Object.hasOwn(authPrecheck, "ok") && authPrecheck.ok !== true)) {
    reject("AUTH_PRECHECK_NOT_PASSED", "auth precheck has missing, malformed, or unresolved blockers");
  }
  const observations = authPrecheck?.observations;
  const requirements = RELEASE_REGISTRY_REQUIREMENTS;
  const normalizedFailures = ["AUTH_UNAUTHENTICATED", "REGISTRY_UNAVAILABLE", "REGISTRY_ACCESS_INSUFFICIENT", "REGISTRY_STATE_UNDETERMINED"];
  const usable = (observation, label, pkg) => {
    if (!object(observation) || observation.registry !== requirements.registry) {
      reject(label === "identity" ? "AUTH_IDENTITY_NOT_ESTABLISHED" : "REGISTRY_STATE_UNDETERMINED",
        `${label}: missing observation or unexpected registry`, pkg);
      return false;
    }
    if (observation.kind === "unknown") {
      const code = normalizedFailures.includes(observation.reason?.code) ? observation.reason.code : "REGISTRY_STATE_UNDETERMINED";
      reject(code, `${label}: unknown observation`, pkg);
      return false;
    }
    return true;
  };
  const identity = observations?.identity;
  const identityUsable = usable(identity, "identity");
  if (identityUsable && (identity.kind !== "identity" || typeof identity.username !== "string" || !/^[a-z0-9][a-z0-9._-]*$/.test(identity.username))) {
    reject("AUTH_IDENTITY_NOT_ESTABLISHED", "normalized npm identity not established");
  }
  const access = observations?.access;
  let accessUsable = usable(access, "access");
  if (accessUsable && (access.kind !== "access" || !identityUsable || access.subject !== identity.username || !object(access.packages) ||
      Object.values(access.packages).some((right) => !["read-only", "read-write"].includes(right)))) {
    reject("REGISTRY_STATE_UNDETERMINED", "malformed or mismatched normalized access observation");
    accessUsable = false;
  }
  const statuses = observations?.packages;
  if (!Array.isArray(statuses) || !sameSet(statuses.map((p) => p?.packageName), names)) {
    reject("REGISTRY_STATE_UNDETERMINED", "required package observations must form an exact set, without duplicates");
  }
  for (const name of names) {
    const status = Array.isArray(statuses) ? statuses.find((p) => p?.packageName === name) : undefined;
    if (!usable(status, "package status", name)) continue;
    switch (status.kind) {
      case "missing":
        reject("PACKAGE_CREATION_AUTHORITY_NOT_ESTABLISHED", "missing package has no positive creation-authority evidence or current visibility", name);
        if (Object.hasOwn(status, "visibility")) reject("REGISTRY_STATE_UNDETERMINED", "missing package cannot have current visibility", name);
        break;
      case "existing":
        if (!["public", "private"].includes(status.visibility)) {
          reject("REGISTRY_STATE_UNDETERMINED", "unsupported current visibility", name);
        } else if (status.visibility !== requirements.existingPackageVisibility) {
          reject("PACKAGE_VISIBILITY_MISMATCH", "existing package does not have the required current public visibility", name);
        }
        if (accessUsable) {
          if (!Object.hasOwn(access.packages, name)) reject("REGISTRY_STATE_UNDETERMINED", "package access not positively observed", name);
          else if (access.packages[name] !== requirements.requiredRegistryAccess) {
            reject("REGISTRY_ACCESS_INSUFFICIENT", "observed read-only access does not satisfy required read-write", name);
          }
        }
        break;
      default:
        reject("REGISTRY_STATE_UNDETERMINED", "unsupported normalized package state", name);
    }
  }
  if (reasons.length) return { kind: "not-ready", reasons };
  return {
    kind: "ready", state: "READY_FOR_PUBLISH",
    evidence: structuredClone({
      requirements, registry: identity.registry, username: identity.username,
      localPrecheck, authPrecheck, manifest, releaseState: state,
      packagesEvaluated: names,
    }),
  };
}

// determinismProbe is diagnostic only and never authorizes reconstruction.
// Whether deterministic is true or false, resume MUST reuse the original
// retained tarballs; regeneration/repacking is forbidden in all cases.
// Pack destination is disposable diagnostic-only. Its tarballs are NEVER
// entered into the release manifest, never locally verified for
// publication, and never published — only the byte-equality RESULT is
// recorded. `packTransport.packToDir(pkg, destDir): tarballPath` is
// injected so tests never invoke real `pnpm pack`.
export function runDeterminismProbe(pkg, packTransport) {
  const base = mkdtempSync(path.join(tmpdir(), "oxdeai-determinism-probe-"));
  const destA = path.join(base, "a");
  const destB = path.join(base, "b");
  mkdirSync(destA, { recursive: true });
  mkdirSync(destB, { recursive: true });
  const tarballA = packTransport.packToDir(pkg, destA);
  const tarballB = packTransport.packToDir(pkg, destB);
  const hashA = sha256Hex(readFileSync(tarballA));
  const hashB = sha256Hex(readFileSync(tarballB));
  return {
    package: pkg.name,
    deterministic: hashA === hashB,
    hashA,
    hashB,
  };
}

// ── PACK ──────────────────────────────────────────────────────────────────
//
// Produces each release tarball EXACTLY ONCE, retains the files under
// `releaseDir/tarballs/`, computes npm-compatible SRI for each, and writes
// the frozen release-manifest.json. `packTransport.packToDir` is the same
// injectable shape used by the determinism probe; the default (real) CLI
// transport shells `pnpm pack` (packing is not a forbidden command — only
// npm publish/dist-tag/unpublish are).
export function defaultPackTransport() {
  return {
    packToDir(pkg, destDir) {
      const result = spawnSync("pnpm", ["pack", "--pack-destination", destDir], {
        cwd: pkg.dir, encoding: "utf8",
      });
      if (result.status !== 0) {
        throw new ReleaseOrchestratorError(
          `pnpm pack failed for ${pkg.name}: ${result.stderr || result.stdout}`
        );
      }
      const line = result.stdout.trim().split("\n").filter(Boolean).pop();
      const tarballPath = path.isAbsolute(line) ? line : path.join(destDir, line);
      if (!existsSync(tarballPath)) {
        throw new ReleaseOrchestratorError(`expected tarball not found at ${tarballPath} for ${pkg.name}`);
      }
      return tarballPath;
    },
  };
}

export function pack({
  discovered,
  policy = POLICY,
  releaseDir,
  sourceRevision,
  determinismProbePackage,
  packTransport = defaultPackTransport(),
  now = () => new Date().toISOString(),
}) {
  if (!/^[0-9a-f]{40}$/.test(sourceRevision ?? "")) {
    throw new ReleaseOrchestratorError("pack() requires an exact 40-hex sourceRevision");
  }
  for (const evidence of [MANIFEST_FILENAME, STATE_FILENAME, "tarballs"]) {
    if (existsSync(path.join(releaseDir, evidence))) {
      throw new ReleaseOrchestratorError(
        `Repacking/reconstruction of an existing release identity is forbidden: ${evidence} exists in ${releaseDir}. ` +
        `Resume must use the original manifest/tarballs; use a fresh release directory for a new release attempt.`
      );
    }
  }
  assertReleaseMetadataConsistency(policy);
  assertPolicyCoverage(discovered);

  const probeTarget = discovered.find((d) => d.name === (determinismProbePackage ?? discovered[0]?.name));
  if (!probeTarget) throw new ReleaseOrchestratorError("no package available for the determinism probe");
  const determinismProbe = runDeterminismProbe(probeTarget, packTransport);

  const tarballDir = path.join(releaseDir, "tarballs");
  mkdirSync(tarballDir, { recursive: true });

  const ordered = [...discovered].sort(
    (a, b) => policy[a.name].publishOrder - policy[b.name].publishOrder
  );

  const packages = ordered.map((d) => {
    const tarballPath = packTransport.packToDir(d, tarballDir);
    const integrity = computeSriIntegrity(readFileSync(tarballPath));
    return {
      package: d.name,
      version: policy[d.name].version,
      releaseLine: policy[d.name].releaseLine,
      publishOrder: policy[d.name].publishOrder,
      tarball: path.relative(releaseDir, tarballPath),
      integrity,
    };
  });

  const manifestSansIntegrity = {
    manifestVersion: MANIFEST_VERSION,
    releaseId: sourceRevision,
    sourceRevision,
    createdAt: now(),
    determinismProbe,
    packages,
  };
  const manifest = {
    ...manifestSansIntegrity,
    manifestIntegrity: computeManifestIntegrity(manifestSansIntegrity),
  };

  writeJson(path.join(releaseDir, MANIFEST_FILENAME), manifest);

  const state = {
    stateVersion: STATE_VERSION,
    releaseId: manifest.releaseId,
    phase: "PRECHECK",
    history: [{ phase: "PRECHECK", at: now() }],
    packages: Object.fromEntries(packages.map((p) => [p.package, { publishStatus: "pending" }])),
    updatedAt: now(),
  };
  transition(state, "PACKED", manifest);
  writeJson(path.join(releaseDir, STATE_FILENAME), state);

  return { manifest, state };
}

// ── Manifest / state loading + integrity validation ─────────────────────

function writeJson(file, obj) {
  writeFileSync(file, `${JSON.stringify(obj, null, 2)}\n`);
}

export function loadAndValidateManifest(releaseDir) {
  const manifestPath = path.join(releaseDir, MANIFEST_FILENAME);
  if (!existsSync(manifestPath)) {
    throw new ReleaseOrchestratorError(`no ${MANIFEST_FILENAME} found under ${releaseDir}`);
  }
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const expected = computeManifestIntegrity(manifest);
  if (manifest.manifestIntegrity !== expected) {
    throw new ReleaseOrchestratorError(
      `manifestIntegrity mismatch for ${manifestPath}: recorded ${manifest.manifestIntegrity}, ` +
      `recomputed ${expected}. The frozen release identity/evidence has been mutated after PACK ` +
      `— resume refuses to proceed from a mutated manifest.`
    );
  }
  return manifest;
}

// State is process bookkeeping, not authenticated registry evidence.
export function validateState(manifest, state) {
  const object = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  const invalid = (detail) => { throw new ReleaseOrchestratorError(`invalid release state: ${detail}`); };
  if (!object(state)) invalid("expected object");
  if (state.stateVersion !== STATE_VERSION) invalid("unsupported or missing stateVersion");
  if (typeof state.releaseId !== "string" || !/^[0-9a-f]{40}$/.test(state.releaseId) ||
      state.releaseId !== manifest.releaseId) invalid("releaseId missing, malformed or mismatched");
  if (!PHASES.includes(state.phase)) invalid("unknown phase");
  if (!Array.isArray(state.history)) invalid("history must be an array");
  if (!object(state.packages)) invalid("packages must be an object");
  const names = manifest.packages.map((p) => p.package);
  if (new Set(names).size !== names.length || Object.keys(state.packages).length !== names.length ||
      Object.keys(state.packages).some((name) => !names.includes(name))) invalid("package set mismatch");
  for (const name of names) {
    const entry = state.packages[name];
    if (!Object.hasOwn(state.packages, name) || !object(entry)) invalid(`malformed or missing package ${name}`);
    if (!["pending", "published"].includes(entry.publishStatus)) invalid(`invalid publishStatus for ${name}`);
    for (const flag of ["registryVerified", "externalInstallVerified"]) {
      if (Object.hasOwn(entry, flag) && typeof entry[flag] !== "boolean") invalid(`non-boolean ${flag} for ${name}`);
    }
    if (Object.hasOwn(entry, "registryIntegrity") && typeof entry.registryIntegrity !== "string") {
      invalid(`malformed registryIntegrity for ${name}`);
    }
  }
  return state;
}

export function loadState(releaseDir) {
  const statePath = path.join(releaseDir, STATE_FILENAME);
  if (!existsSync(statePath)) {
    throw new ReleaseOrchestratorError(`no ${STATE_FILENAME} found under ${releaseDir}`);
  }
  return JSON.parse(readFileSync(statePath, "utf8"));
}

export function saveState(releaseDir, state, { now = () => new Date().toISOString() } = {}) {
  state.updatedAt = now();
  writeJson(path.join(releaseDir, STATE_FILENAME), state);
  return state;
}

// Require the original tarball for every manifest package and verify its
// bytes still match the manifest's recorded integrity. Never reconstructs;
// throws (STOP) on any missing file or mismatch.
export function requireOriginalTarballs(releaseDir, manifest) {
  for (const p of manifest.packages) {
    const tarballPath = path.join(releaseDir, p.tarball);
    if (!existsSync(tarballPath)) {
      throw new ReleaseOrchestratorError(
        `STOP: original release tarball missing for ${p.package} at ${tarballPath}. ` +
        `Regeneration is forbidden — resume never repacks.`
      );
    }
    const actual = computeSriIntegrity(readFileSync(tarballPath));
    if (actual !== p.integrity) {
      throw new ReleaseOrchestratorError(
        `STOP: local tarball integrity for ${p.package} is ${actual}, manifest records ${p.integrity}. ` +
        `The tarball on disk no longer matches the frozen release identity.`
      );
    }
  }
  return true;
}

// ── VERIFY (VERIFIED_LOCAL) ──────────────────────────────────────────────
//
// Runs the EXACT existing packed-artifact consumer-verification semantics
// against the manifest's own tarballs — never a repack (verifyPackedTarballs
// takes already-built tarball paths).
export function verifyLocal({ discovered, manifest, state, releaseDir, baseDir } = {}) {
  validateState(manifest, state);
  assertPhase(state, "PACKED");
  const packed = manifest.packages.map((p) => ({
    name: p.package,
    tarballPath: path.join(releaseDir, p.tarball),
  }));
  assertPackedBijection(discovered, packed);
  requireOriginalTarballs(releaseDir, manifest);
  verifyPackedTarballs(discovered, packed, { baseDir });
  transition(state, "VERIFIED_LOCAL", manifest);
  saveState(releaseDir, state);
  return state;
}

// ── Resume from PARTIAL_NEXT ──────────────────────────────────────────────
//
// registryTransport.getRegistryVersion(name, version) -> { exists, integrity? }
function reconcileAgainstRegistry(p, registryTransport) {
  const reg = registryTransport.getRegistryVersion(p.package, p.version);
  if (!reg.exists) return { status: "missing" };
  if (reg.integrity === p.integrity) return { status: "already-published", integrity: reg.integrity };
  throw new RegistryIntegrityConflictError(p.package, p.version, p.integrity, reg.integrity);
}

export function resume({ releaseDir, registryTransport }) {
  const manifest = loadAndValidateManifest(releaseDir);
  const state = loadState(releaseDir);
  validateState(manifest, state);
  assertPhase(state, "PARTIAL_NEXT");
  requireOriginalTarballs(releaseDir, manifest);

  const toPublish = reconcilePartialNext({ manifest, state, releaseDir, registryTransport });
  return { manifest, state, toPublish };
}

// Explicit resume reconciles the full set without any publication effect.
function reconcilePartialNext({ manifest, state, releaseDir, registryTransport }) {
  validateState(manifest, state);
  assertPhase(state, "PARTIAL_NEXT");
  const toPublish = [];
  let activePackage;
  try {
    for (const p of manifest.packages) {
      activePackage = p.package;
      const result = reconcileAgainstRegistry(p, registryTransport);
      if (result.status === "already-published") {
        state.packages[p.package] = { publishStatus: "published", registryIntegrity: result.integrity };
      } else {
        state.packages[p.package] = { publishStatus: "pending" };
        toPublish.push(p);
      }
    }
  } catch (error) {
    persistPublicationBlocker({ manifest, state, releaseDir, error, activePackage });
    throw error;
  }
  delete state.blocker;
  saveState(releaseDir, state);
  return toPublish;
}

function persistPublicationBlocker({ manifest, state, releaseDir, error, activePackage }) {
  validateState(manifest, state);
  state.blocker = {
    code: error instanceof RegistryIntegrityConflictError ? "REGISTRY_INTEGRITY_CONFLICT" : "PUBLICATION_FAILED",
    package: activePackage,
    message: String(error?.message ?? error),
    ...(error instanceof RegistryIntegrityConflictError ? {
      manifestIntegrity: error.manifestIntegrity, registryIntegrity: error.registryIntegrity,
    } : {}),
  };
  if (state.phase !== "PARTIAL_NEXT") transition(state, "PARTIAL_NEXT", manifest);
  saveState(releaseDir, state);
}

// ── Publication command data ──────────────────────────────────────────

export function buildPublishCommandData(p, releaseDir, { registry } = {}) {
  return {
    executable: "npm",
    args: ["publish", path.resolve(releaseDir, p.tarball), "--tag", "next", "--access", "public",
      ...(registry === undefined ? [] : ["--registry", registry])],
    package: p.package,
    version: p.version,
  };
}

// ── Step 5: publication plan DATA ONLY ─────────────────────────────────────
// Consumes a Step 4 receipt, without re-evaluating readiness, recomputing its
// digest, observing authority, or verifying files. Receipt consistency is not
// receipt authenticity/freshness. Planning is neither authorization nor execution.
// No persisted phase, transport, or automatic execution is introduced here.
export function derivePublicationPlan(inputs = {}) {
  const object = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  const fail = (code, message) => { throw new ReleaseOrchestratorError(message, { code }); };
  if (!object(inputs)) fail("READINESS_NOT_ESTABLISHED", "planner inputs must be an object");
  const { readiness, releaseDir } = inputs;
  if (!object(readiness) || readiness.kind !== "ready" || readiness.state !== "READY_FOR_PUBLISH") {
    fail("READINESS_NOT_ESTABLISHED", "a successful READY_FOR_PUBLISH receipt is required");
  }
  // Absolute input prevents buildPublishCommandData/path.resolve consulting cwd.
  if (typeof releaseDir !== "string" || !path.isAbsolute(releaseDir) || /[\\\x00-\x1f\x7f]/.test(releaseDir)) {
    fail("INVALID_RELEASE_DIRECTORY", "releaseDir must be an explicit absolute path without backslashes/control characters");
  }
  const e = readiness.evidence;
  if (!object(e) || !object(e.requirements) || !object(e.localPrecheck) || !object(e.authPrecheck) ||
      e.localPrecheck.ok !== true || (Object.hasOwn(e.localPrecheck, "blockers") &&
        (!Array.isArray(e.localPrecheck.blockers) || e.localPrecheck.blockers.length !== 0)) ||
      !Array.isArray(e.authPrecheck.blockers) || e.authPrecheck.blockers.length !== 0 ||
      (Object.hasOwn(e.authPrecheck, "ok") && e.authPrecheck.ok !== true)) {
    fail("READINESS_EVIDENCE_INVALID", "readiness receipts/requirements must be present without unresolved failures");
  }
  const observations = e.authPrecheck.observations;
  if (!object(observations) || !object(observations.identity) || !object(observations.access) ||
      !Array.isArray(observations.packages) || observations.identity.kind !== "identity" ||
      observations.packages.some((p) => !object(p) || p.registry !== e.registry) ||
      observations.identity.username !== e.username || observations.identity.registry !== e.registry ||
      observations.access.kind !== "access" || observations.access.subject !== e.username ||
      observations.access.registry !== e.registry || !object(observations.access.packages) ||
      typeof e.username !== "string" || !/^[a-z0-9][a-z0-9._-]*$/.test(e.username) ||
      e.requirements.registry !== e.registry || e.requirements.requiredRegistryAccess !== "read-write" ||
      e.requirements.existingPackageVisibility !== "public") {
    fail("READINESS_EVIDENCE_INVALID", "readiness provenance is incomplete or contradictory");
  }
  try {
    const registry = new URL(e.registry);
    if (typeof e.registry !== "string" || registry.protocol !== "https:" || registry.username || registry.password ||
        registry.search || registry.hash || registry.href !== e.registry) throw new Error();
  } catch {
    fail("READINESS_EVIDENCE_INVALID", "readiness registry must be an explicit canonical HTTPS URL");
  }
  const manifest = e.manifest;
  if (!object(manifest) || manifest.manifestVersion !== MANIFEST_VERSION ||
      !Array.isArray(manifest.packages) || manifest.packages.length === 0) {
    fail("READINESS_EVIDENCE_INVALID", "a supported nonempty release manifest is required");
  }
  if (typeof manifest.releaseId !== "string" || !/^[0-9a-f]{40}$/.test(manifest.releaseId) ||
      manifest.sourceRevision !== manifest.releaseId || e.releaseState?.releaseId !== manifest.releaseId) {
    fail("RELEASE_IDENTITY_MISMATCH", "manifest/source/state release identities must agree");
  }
  if (typeof manifest.manifestIntegrity !== "string" || !/^sha256:[0-9a-f]{64}$/.test(manifest.manifestIntegrity)) {
    fail("READINESS_EVIDENCE_INVALID", "recorded manifest integrity is missing or malformed");
  }
  const names = manifest.packages.map((p) => p?.package);
  const sameSet = (other) => Array.isArray(other) && other.length === names.length &&
    new Set(other).size === other.length && other.every((name) => names.includes(name));
  if (new Set(names).size !== names.length || !sameSet(e.packagesEvaluated) ||
      !Array.isArray(e.localPrecheck.discovered) || !sameSet(e.localPrecheck.discovered.map((p) => p?.name)) ||
      !sameSet(observations.packages.map((p) => p?.packageName))) {
    fail("PACKAGE_SET_MISMATCH", "readiness and manifest must contain exactly the same unique package set");
  }
  const orders = new Set(), paths = new Set();
  for (const p of manifest.packages) {
    if (!object(p) || typeof p.package !== "string" || !/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(p.package) ||
        typeof p.version !== "string" || typeof p.releaseLine !== "string" ||
        typeof p.integrity !== "string" || !/^sha512-[A-Za-z0-9+/]{86}==$/.test(p.integrity) ||
        e.localPrecheck.discovered.find((d) => d.name === p.package)?.manifest?.version !== p.version) {
      fail("PACKAGE_METADATA_INVALID", "package identity/version/release line/integrity must match the supplied receipts");
    }
    if (!Number.isSafeInteger(p.publishOrder) || orders.has(p.publishOrder)) {
      fail("PUBLICATION_ORDER_INVALID", "publishOrder must be a unique safe integer for every package");
    }
    orders.add(p.publishOrder);
    // Lexical containment only. No filesystem lookup or symlink claim is made.
    // PACK produces relative paths; reject both POSIX and Windows escape forms.
    if (typeof p.tarball !== "string" || !p.tarball.endsWith(".tgz") ||
        path.isAbsolute(p.tarball) || path.win32.isAbsolute(p.tarball) || /[\\:\x00-\x1f\x7f]/.test(p.tarball) ||
        p.tarball.split("/").some((part) => !part || part === "." || part === "..")) {
      fail("UNSAFE_TARBALL_PATH", "tarball must be a contained relative .tgz path without traversal");
    }
    if (paths.has(p.tarball)) fail("PACKAGE_METADATA_INVALID", "distinct packages must not share a tarball reference");
    paths.add(p.tarball);
  }
  // Reuse the existing release-line/version invariant, solely over frozen
  // manifest metadata; do not discover packages or consult workspace manifests.
  try {
    assertReleaseMetadataConsistency(Object.fromEntries(manifest.packages.map((p) => [p.package, p])));
  } catch {
    fail("PACKAGE_METADATA_INVALID", "manifest release-line/version metadata is inconsistent");
  }
  try { validateState(manifest, e.releaseState); }
  catch { fail("PUBLICATION_PLANNING_STATE_INVALID", "release state is malformed or inconsistent"); }
  if (e.releaseState.phase !== "VERIFIED_LOCAL" || e.releaseState.history.at(-1)?.phase !== "VERIFIED_LOCAL" ||
      Object.values(e.releaseState.packages).some((p) => p.publishStatus !== "pending") || Object.hasOwn(e.releaseState, "blocker")) {
    fail("PUBLICATION_PLANNING_STATE_INVALID", "planning requires VERIFIED_LOCAL, all packages pending, and no blocker");
  }
  // Current publishOrder values are intentionally sparse. No contiguous-slot
  // rule exists. Sort only a copy; input array order must not influence output.
  const ordered = [...manifest.packages].sort((a, b) => a.publishOrder - b.publishOrder);
  return {
    kind: "publication-plan", releaseId: manifest.releaseId, registry: e.registry, tag: "next", access: "public",
    operations: ordered.map((p, index) => ({
      index, releaseId: manifest.releaseId, package: p.package, version: p.version,
      releaseLine: p.releaseLine, publishOrder: p.publishOrder, tarball: p.tarball, integrity: p.integrity,
      registry: e.registry, tag: "next", access: "public",
      command: buildPublishCommandData(p, releaseDir, { registry: e.registry }),
    })),
    evidence: {
      readinessState: readiness.state, manifestIntegrity: manifest.manifestIntegrity,
      sourceRevision: manifest.sourceRevision, packagesEvaluated: [...names].sort(),
      username: e.username, requirements: {
        registry: e.registry, requiredRegistryAccess: e.requirements.requiredRegistryAccess,
        existingPackageVisibility: e.requirements.existingPackageVisibility,
      },
    },
  };
}

// registryTransport: { getRegistryVersion(name, version), publish(commandData) }
// `publish()` returns { ok, error? } and MUST be supplied by the caller —
// there is no default implementation here that invokes a real `npm publish`.
export function publishNext() {
  throw new ReleaseOrchestratorError(
    "publishNext batch execution is retired; explicitly select one operation with publishPlannedOperation()",
    { code: "PUBLICATION_OPERATION_NOT_FOUND" }
  );
}

// Step 6: one explicit selection, at most one injected publish call. A plan
// binds data; it is neither real-effect authorization nor fresh auth evidence.
export function publishPlannedOperation(inputs = {}) {
  const object = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  const fail = (code, message) => { throw new ReleaseOrchestratorError(message, { code }); };
  if (!object(inputs)) fail("PUBLICATION_PLAN_INVALID", "publication inputs must be an object");
  const { plan, operationIndex, manifest, state, releaseDir, registryTransport } = inputs;
  if (!object(plan) || plan.kind !== "publication-plan" || !Array.isArray(plan.operations) ||
      !object(manifest) || manifest.manifestVersion !== MANIFEST_VERSION ||
      !Array.isArray(manifest.packages) || manifest.packages.length === 0 ||
      plan.operations.length !== manifest.packages.length || !object(plan.evidence)) {
    fail("PUBLICATION_PLAN_INVALID", "a complete publication plan and manifest are required");
  }
  if (!Number.isSafeInteger(operationIndex) || operationIndex < 0 || operationIndex >= plan.operations.length) {
    fail("PUBLICATION_OPERATION_NOT_FOUND", "an explicit valid operationIndex is required");
  }
  if (typeof releaseDir !== "string" || !path.isAbsolute(releaseDir) || /[\\\x00-\x1f\x7f]/.test(releaseDir)) {
    fail("UNSAFE_TARBALL_PATH", "releaseDir must be explicit and absolute");
  }
  const e = plan.evidence;
  if (typeof manifest.releaseId !== "string" || !/^[0-9a-f]{40}$/.test(manifest.releaseId) ||
      plan.releaseId !== manifest.releaseId || manifest.sourceRevision !== manifest.releaseId ||
      e.sourceRevision !== manifest.sourceRevision || e.manifestIntegrity !== manifest.manifestIntegrity ||
      computeManifestIntegrity(manifest) !== manifest.manifestIntegrity || e.readinessState !== "READY_FOR_PUBLISH" ||
      typeof e.username !== "string" || !/^[a-z0-9][a-z0-9._-]*$/.test(e.username) ||
      e.requirements?.registry !== plan.registry || e.requirements?.requiredRegistryAccess !== "read-write" ||
      e.requirements?.existingPackageVisibility !== "public" || plan.tag !== "next" || plan.access !== "public") {
    fail("PUBLICATION_PLAN_INVALID", "plan provenance, manifest digest and release identity must agree");
  }
  try {
    const registry = new URL(plan.registry);
    if (typeof plan.registry !== "string" || registry.protocol !== "https:" || registry.username || registry.password ||
        registry.search || registry.hash || registry.href !== plan.registry) throw new Error();
  } catch { fail("PUBLICATION_PLAN_INVALID", "registry must be a canonical HTTPS URL"); }
  const ordered = [...manifest.packages].sort((a, b) => a?.publishOrder - b?.publishOrder);
  const names = new Set(), orders = new Set(), paths = new Set();
  // Validate the complete data binding before effects, never execute the plan
  // as a batch. Command comparison rejects disagreement rather than repairing it.
  for (const [index, p] of ordered.entries()) {
    if (!object(p) || typeof p.package !== "string" || !/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(p.package) ||
        names.has(p.package) || !Number.isSafeInteger(p.publishOrder) || orders.has(p.publishOrder) ||
        typeof p.integrity !== "string" || !/^sha512-[A-Za-z0-9+/]{86}==$/.test(p.integrity)) {
      fail("PUBLICATION_PLAN_INVALID", "manifest package identities, orders and integrities must be unambiguous");
    }
    if (typeof p.tarball !== "string" || !p.tarball.endsWith(".tgz") ||
        path.isAbsolute(p.tarball) || path.win32.isAbsolute(p.tarball) || /[\\:\x00-\x1f\x7f]/.test(p.tarball) ||
        p.tarball.split("/").some(part => !part || part === "." || part === "..") || paths.has(p.tarball)) {
      fail("UNSAFE_TARBALL_PATH", "tarball must be a unique contained relative .tgz path");
    }
    names.add(p.package); orders.add(p.publishOrder); paths.add(p.tarball);
    const expected = {
      index, releaseId: manifest.releaseId, package: p.package, version: p.version,
      releaseLine: p.releaseLine, publishOrder: p.publishOrder, tarball: p.tarball, integrity: p.integrity,
      registry: plan.registry, tag: "next", access: "public",
      command: buildPublishCommandData(p, releaseDir, { registry: plan.registry }),
    };
    if (canonicalStringify(plan.operations[index]) !== canonicalStringify(expected)) {
      fail("PUBLICATION_OPERATION_MISMATCH", "operation and command must exactly match the frozen plan/manifest binding");
    }
  }
  if (!Array.isArray(e.packagesEvaluated) || e.packagesEvaluated.length !== names.size ||
      new Set(e.packagesEvaluated).size !== names.size || e.packagesEvaluated.some(name => !names.has(name))) {
    fail("PUBLICATION_PLAN_INVALID", "plan evidence package set must match the manifest");
  }
  try { assertReleaseMetadataConsistency(Object.fromEntries(ordered.map(p => [p.package, p]))); }
  catch { fail("PUBLICATION_PLAN_INVALID", "release metadata is inconsistent"); }
  // Explicit selection must respect the frozen plan order, using recorded
  // predecessor evidence only. Reject before reading artifacts or consulting a transport.
  for (let index = 0; index < operationIndex; index++) {
    const predecessor = plan.operations[index];
    const recorded = state?.packages?.[predecessor.package];
    if (!object(recorded) || recorded.publishStatus !== "published" ||
        recorded.registryIntegrity !== predecessor.integrity) {
      fail("PUBLICATION_ORDER_NOT_SATISFIED", `predecessor ${predecessor.package} must be published with its planned integrity`);
    }
  }
  try { validateState(manifest, state); }
  catch { fail("PUBLICATION_STATE_INVALID", "invalid release state"); }
  const p = structuredClone(plan.operations[operationIndex]);
  if (!["VERIFIED_LOCAL", "PARTIAL_NEXT"].includes(state.phase) ||
      Object.values(state.packages).some(s => s.registryVerified === true || s.externalInstallVerified === true) ||
      ordered.some(entry => {
        const s = state.packages[entry.package];
        return s.publishStatus === "published" ? s.registryIntegrity !== entry.integrity || state.phase === "VERIFIED_LOCAL"
          : s.registryIntegrity !== undefined;
      }) || (Object.hasOwn(state, "blocker") &&
        (state.phase !== "PARTIAL_NEXT" || !object(state.blocker) || state.blocker.package !== p.package))) {
    fail("PUBLICATION_STATE_INVALID", "publication state or unresolved blocker is incompatible with this selection");
  }
  if (!registryTransport || typeof registryTransport.getRegistryVersion !== "function" ||
      typeof registryTransport.publish !== "function") {
    fail("PUBLICATION_TRANSPORT_INVALID", "an injected synchronous observation and publication transport is required");
  }
  // Only the selected original artifact is read. No reconstruction or packing.
  requireOriginalTarballs(releaseDir, { packages: [p] });
  const observe = () => {
    const reg = registryTransport.getRegistryVersion(p.package, p.version);
    if (!object(reg) || typeof reg.exists !== "boolean" ||
        (reg.exists && (typeof reg.integrity !== "string" || !reg.integrity))) {
      fail("REGISTRY_STATE_UNDETERMINED", "selected registry observation is indeterminate");
    }
    if (reg.exists && reg.integrity !== p.integrity) {
      throw new RegistryIntegrityConflictError(p.package, p.version, p.integrity, reg.integrity);
    }
    return reg.exists;
  };
  transition(state, "PUBLISHING_NEXT", manifest);
  saveState(releaseDir, state);
  try {
    let published = observe();
    if (!published) {
      state.packages[p.package] = { publishStatus: "pending" };
      let result, publicationError;
      try { result = registryTransport.publish(structuredClone(p.command)); }
      catch (error) { publicationError = error; }
      published = (object(result) && result.ok === true) || observe();
      if (!published) {
        if (publicationError) throw publicationError;
        persistPublicationBlocker({ manifest, state, releaseDir, activePackage: p.package,
          error: new ReleaseOrchestratorError(String(result?.error ?? "registry version missing after publication")) });
        return state;
      }
    }
  } catch (error) {
    persistPublicationBlocker({ manifest, state, releaseDir, error, activePackage: p.package });
    throw error;
  }
  state.packages[p.package] = { publishStatus: "published", registryIntegrity: p.integrity };
  delete state.blocker;
  transition(state, ordered.every(entry => state.packages[entry.package].publishStatus === "published")
    ? "PUBLISHED_NEXT" : "PARTIAL_NEXT", manifest);
  saveState(releaseDir, state);
  return state;
}

// ── VERIFY_REGISTRY ───────────────────────────────────────────────────────
//
// Identity is name + version + integrity, never merely name + version.
export function verifyRegistry({ manifest, state, releaseDir, registryTransport }) {
  validateState(manifest, state);
  assertPhase(state, "PUBLISHED_NEXT");
  for (const p of manifest.packages) {
    const reg = registryTransport.getRegistryVersion(p.package, p.version);
    if (!reg.exists) {
      throw new ReleaseOrchestratorError(`registry verification failed: ${p.package}@${p.version} not present`);
    }
    if (reg.integrity !== p.integrity) {
      throw new RegistryIntegrityConflictError(p.package, p.version, p.integrity, reg.integrity);
    }
    state.packages[p.package] = { ...state.packages[p.package], registryVerified: true };
  }
  transition(state, "REGISTRY_VERIFIED", manifest);
  saveState(releaseDir, state);
  return state;
}

// ── EXTERNAL_INSTALL_VERIFIED ────────────────────────────────────────────
//
// installTransport.verifyInstall(pkgName, version, integrity) -> { ok, reason? }
// Distinct from local tarball consumer verification (VERIFIED_LOCAL): this
// installs from the published registry version, not the local tarball.
export function verifyExternalInstall({ manifest, state, releaseDir, installTransport }) {
  validateState(manifest, state);
  assertPhase(state, "REGISTRY_VERIFIED");
  for (const p of manifest.packages) {
    const result = installTransport.verifyInstall(p.package, p.version, p.integrity);
    if (!result.ok) {
      throw new ReleaseOrchestratorError(
        `external install verification failed for ${p.package}@${p.version}: ${result.reason ?? "(no reason given)"}`
      );
    }
    state.packages[p.package] = { ...state.packages[p.package], externalInstallVerified: true };
  }
  transition(state, "EXTERNAL_INSTALL_VERIFIED", manifest);
  saveState(releaseDir, state);
  return state;
}

// ── READY_TO_PROMOTE ──────────────────────────────────────────────────────
//
// Deliberate ALL-TEN invariant, checked explicitly rather than left as an
// accidental consequence of control flow: every manifest package —
// including @oxdeai/cli, whose releaseLine is "cli" rather than "2.0" — must
// be published, registry-verified, AND externally-install-verified. If the
// CLI alone fails, the nine 2.0-line packages are NOT promotable.
export function allPackagesReady(manifest, state) {
  validateState(manifest, state);
  return manifest.packages.every((p) => {
    const s = state.packages[p.package];
    return s?.publishStatus === "published" && s?.registryVerified === true && s?.externalInstallVerified === true;
  });
}

export function transitionToReadyToPromote({ manifest, state, releaseDir }) {
  validateState(manifest, state);
  assertPhase(state, "EXTERNAL_INSTALL_VERIFIED");
  if (!allPackagesReady(manifest, state)) {
    const notReady = manifest.packages
      .filter((p) => {
        const s = state.packages[p.package];
        return !(s?.publishStatus === "published" && s?.registryVerified === true && s?.externalInstallVerified === true);
      })
      .map((p) => p.package);
    throw new ReleaseOrchestratorError(
      `READY_TO_PROMOTE requires ALL ${manifest.packages.length} packages verified (published + registry + ` +
      `external-install), including @oxdeai/cli. Not ready: ${notReady.join(", ")}`
    );
  }
  transition(state, "READY_TO_PROMOTE", manifest);
  saveState(releaseDir, state);
  return state;
}

// ── PROMOTE (injected transport only; no default execution) ──────────────────────────────

export function buildPromotionPlan(manifest, state) {
  validateState(manifest, state);
  assertPhase(state, "READY_TO_PROMOTE");
  if (!allPackagesReady(manifest, state)) {
    throw new ReleaseOrchestratorError("promotion planning requires all ten packages verified");
  }
  return manifest.packages.map((p) => ({
    executable: "npm",
    args: ["dist-tag", "add", `${p.package}@${p.version}`, "latest"],
  }));
}

// Injected synchronous transport only. observeDistTag must independently read
// registry state and return { tag, version }; apply results are not evidence.
// partialDistTagRecovery: "registry-observed-idempotent-retry" declares that
// after partial application, retrying the same plan observes current tags and
// safely reapplies entries as needed to converge on the exact target versions.
// This is a required transport contract, not proof of its implementation.
export function promote({ manifest, state, releaseDir, promotionTransport }) {
  validateState(manifest, state);
  assertPhase(state, "READY_TO_PROMOTE");
  const plan = buildPromotionPlan(manifest, state); // throws if not ready
  if (!promotionTransport || typeof promotionTransport.applyDistTag !== "function" ||
      typeof promotionTransport.observeDistTag !== "function") {
    throw new ReleaseOrchestratorError("promote requires an injected promotionTransport");
  }
  if (promotionTransport.partialDistTagRecovery !== "registry-observed-idempotent-retry") {
    throw new ReleaseOrchestratorError(
      'promotionTransport must declare partialDistTagRecovery="registry-observed-idempotent-retry"; ' +
      'partial dist-tag recovery/resume semantics are otherwise undefined'
    );
  }
  for (const entry of plan) promotionTransport.applyDistTag(entry);
  for (const p of manifest.packages) {
    const observed = promotionTransport.observeDistTag(p.package, "latest");
    if (observed?.tag !== "latest" || observed.version !== p.version) {
      throw new ReleaseOrchestratorError(`dist-tag verification failed for ${p.package}: expected latest=${p.version}`);
    }
  }
  transition(state, "PROMOTED", manifest);
  saveState(releaseDir, state);
  return { state, plan };
}

// ── CLI (PRECHECK / PACK / VERIFY_LOCAL only — no publish/promote wiring) ─
//
// Deliberately does NOT wire a `publish-next` or `promote` subcommand to any
// real transport in this task: those phases require an explicitly-injected
// registryTransport/installTransport/promotionTransport supplied by CALLING CODE (a future,
// separately authorized change), never a default this file constructs.

function realGitTransport() {
  return {
    isClean() {
      const result = spawnSync("git", ["status", "--porcelain"], { cwd: ROOT, encoding: "utf8" });
      return result.status === 0 && result.stdout.trim().length === 0;
    },
  };
}

function currentSourceRevision() {
  const result = spawnSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" });
  if (result.status !== 0) throw new ReleaseOrchestratorError("git rev-parse HEAD failed");
  return result.stdout.trim();
}

function reportLocalPrecheck() {
  console.log("PRECHECK (local): PASS");
  console.log("Registry auth/rights/public-scope checks: NOT RUN");
}

async function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];
  const releaseDirArg = args.includes("--release-dir")
    ? args[args.indexOf("--release-dir") + 1]
    : path.join(ROOT, ".release-2.0");

  if (cmd === "precheck") {
    const discovered = discoverPublishablePackages();
    precheck({ discovered, gitTransport: realGitTransport() });
    reportLocalPrecheck();
    return;
  }

  if (cmd === "pack") {
    const discovered = discoverPublishablePackages();
    precheck({ discovered, gitTransport: realGitTransport() });
    reportLocalPrecheck();
    const sourceRevision = currentSourceRevision();
    const { manifest } = pack({ discovered, releaseDir: releaseDirArg, sourceRevision });
    console.log(`PACK (local): PASS — ${manifest.packages.length} package(s) recorded in ${releaseDirArg}/${MANIFEST_FILENAME}`);
    console.log("Registry auth/rights/public-scope checks: NOT RUN");
    return;
  }

  if (cmd === "verify-local") {
    const discovered = discoverPublishablePackages();
    const manifest = loadAndValidateManifest(releaseDirArg);
    const state = loadState(releaseDirArg);
    verifyLocal({ discovered, manifest, state, releaseDir: releaseDirArg });
    console.log("VERIFY_LOCAL: PASS");
    return;
  }

  console.error(
    "usage: node scripts/release-2.0/orchestrator.mjs <precheck|pack|verify-local> [--release-dir <path>]\n" +
    "publish-next / verify-registry / verify-external-install / ready-to-promote / promote are " +
    "library-only in this task: they require an explicitly injected registryTransport/installTransport " +
    "and are intentionally not wired to any CLI subcommand here."
  );
  process.exitCode = 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`\n${error.message}\n`);
    process.exitCode = 1;
  });
}
