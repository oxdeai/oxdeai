#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Security advisory gate: fails when audit findings lack a valid, non-expired
 * exception.
 *
 * This is freshness-dependent evidence: the external advisory database can
 * change while the commit and lockfile stay the same, so the same input can
 * produce a different decision on a later run. It is deliberately separate
 * from the reproducible policy-boundary check (`pnpm run security:policy-boundary`),
 * which depends only on repo state and inputs. Do not reintroduce that
 * harness here; run it as its own CI check instead.
 *
 * Usage: node scripts/security-gate.mjs audit.json security/vuln-policy.json
 *   [--artifact-out=path]        write a SecurityGateDecision artifact
 *   [--candidate-sha=sha]        pin the evaluated commit (else `git rev-parse HEAD`)
 *   [--lockfile=path]            pin the evaluated lockfile (else repo-root pnpm-lock.yaml)
 *   [--advisory-source=text]     pin the audit tool identity (else auto-detected pnpm version)
 *
 * The last three apply only with --artifact-out. See security/SECURITY-GATE-ARTIFACT.md.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

const args = process.argv.slice(2);
const [auditPath, policyPath] = args.filter((a) => !a.startsWith("--"));
const flag = (name) => args.find((a) => a.startsWith(`--${name}=`))?.split("=", 2)[1] ?? null;
const artifactOut = flag("artifact-out");
const candidateShaFlag = flag("candidate-sha");
const lockfileFlag = flag("lockfile");
const advisorySourceFlag = flag("advisory-source");

if (!auditPath || !policyPath) {
  console.error(
    "Usage: node scripts/security-gate.mjs <audit.json> <vuln-policy.json> [--artifact-out=path]"
  );
  process.exit(2);
}

const loadJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));

// ── Audit evidence validation ───────────────────────────────────────────────
//
// The only supported input is the `pnpm audit --json` report of the pinned
// pnpm (packageManager in package.json): { actions, advisories, muted,
// metadata }. Anything else - a registry/network failure ({ "error": ... }),
// another tool's format, missing fields - is not evidence of a clean audit,
// so it is rejected before findings are normalized, a decision is made, or an
// artifact is written.
//
// pnpm's own suppression (auditConfig.ignoreGhsas / ignoreCves, audit-level)
// deletes entries from `advisories` but leaves metadata.vulnerabilities
// untouched. A severity with a non-zero count and no advisory therefore means
// findings were hidden before reaching this gate; accepted risk must go
// through vuln-policy.json instead. Counts are not compared for exact equality
// with the number of advisories: their counting semantics are not established.
const SEVERITIES = ["info", "low", "moderate", "high", "critical"];
const plainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

function auditEvidenceProblem(a) {
  const invalid = (detail) => ({ code: "AUDIT_INPUT_INVALID", detail });
  if (!plainObject(a)) return invalid("audit report must be a JSON object");
  if (Object.hasOwn(a, "error")) return invalid(`audit command reported an error: ${JSON.stringify(a.error)}`);
  if (Object.hasOwn(a, "vulnerabilities")) return invalid("unsupported audit format (top-level vulnerabilities)");
  if (!plainObject(a.advisories)) return invalid("advisories must be an object keyed by advisory id");
  if (!plainObject(a.metadata) || !plainObject(a.metadata.vulnerabilities)) {
    return invalid("metadata.vulnerabilities must be an object");
  }
  const counts = a.metadata.vulnerabilities;
  const keys = Object.keys(counts);
  if (keys.length !== SEVERITIES.length || !SEVERITIES.every((s) => keys.includes(s))) {
    return invalid(`metadata.vulnerabilities must have exactly: ${SEVERITIES.join(", ")}`);
  }
  for (const s of SEVERITIES) {
    if (!Number.isInteger(counts[s]) || counts[s] < 0) {
      return invalid(`metadata.vulnerabilities.${s} must be a non-negative integer`);
    }
  }
  const advisorySeverities = new Set();
  for (const [key, adv] of Object.entries(a.advisories)) {
    if (!plainObject(adv)) return invalid(`advisory ${key} must be an object`);
    if (!((typeof adv.id === "string" && adv.id !== "") || Number.isInteger(adv.id))) {
      return invalid(`advisory ${key} must have an id`);
    }
    if (typeof adv.module_name !== "string" || adv.module_name === "") {
      return invalid(`advisory ${key} must have a string module_name`);
    }
    if (!SEVERITIES.includes(adv.severity)) return invalid(`advisory ${key} has unsupported severity`);
    if (!Array.isArray(adv.findings)) return invalid(`advisory ${key} findings must be an array`);
    for (const finding of adv.findings) {
      // Empty paths are valid: pnpm has emitted pathless findings.
      if (!plainObject(finding) || !Array.isArray(finding.paths) || !finding.paths.every((p) => typeof p === "string")) {
        return invalid(`advisory ${key} findings must be objects with string paths`);
      }
    }
    advisorySeverities.add(adv.severity);
  }
  for (const s of SEVERITIES) {
    if (counts[s] > 0 && !advisorySeverities.has(s)) {
      return {
        code: "AUDIT_EVIDENCE_INCONSISTENT",
        detail: `metadata reports ${counts[s]} ${s} vulnerabilities but no ${s} advisory is present ` +
          "(suppressed before the gate?); accept risk via vuln-policy.json, not pnpm audit configuration",
      };
    }
    if (counts[s] === 0 && advisorySeverities.has(s)) {
      return { code: "AUDIT_EVIDENCE_INCONSISTENT", detail: `${s} advisory present but metadata reports 0 ${s} vulnerabilities` };
    }
  }
  return null;
}

function rejectAuditEvidence({ code, detail }) {
  console.log("== Security Advisory Gate ==");
  console.log("Audit evidence: REJECTED (no decision made, no artifact written)");
  console.log(`Reason: ${code}: ${detail}`);
  process.exit(1);
}

let audit;
try {
  audit = loadJson(auditPath);
} catch (err) {
  rejectAuditEvidence({ code: "AUDIT_INPUT_INVALID", detail: `audit report is not readable JSON (${err.message})` });
}
const auditProblem = auditEvidenceProblem(audit);
if (auditProblem) rejectAuditEvidence(auditProblem);

const policy = loadJson(policyPath);
const exceptions = policy.exceptions ?? [];
const rules = policy.rules ?? {
  critical: "deny",
  high: "deny",
  moderate: "require_exception",
  medium: "require_exception",
  low: "warn"
};

const today = new Date();
today.setHours(0, 0, 0, 0);

const isExpired = (dateStr) => {
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) return true;
  d.setHours(0, 0, 0, 0);
  return d < today;
};

// Normalize validated pnpm audit JSON (see auditEvidenceProblem).
function normalizeFindings(a) {
  const findings = [];

  if (a.advisories) {
    for (const key of Object.keys(a.advisories)) {
      const adv = a.advisories[key];
      // Evaluate every reported dependency route independently. Keeping only
      // the first route would let a path-scoped exception hide other routes.
      const reported = adv.findings?.length ? adv.findings : [{ paths: [] }];
      const paths = reported.flatMap((finding) =>
        finding.paths?.length ? finding.paths : [""]
      );
      for (const findingPath of paths.length ? paths : [""]) {
        findings.push({
          id: adv.id ?? key,
          package: adv.module_name,
          severity: (adv.severity ?? "").toLowerCase(),
          path: findingPath,
        });
      }
    }
  }

  return findings;
}

const findings = normalizeFindings(audit);

const normSeverity = (s) => {
  const val = (s ?? "").toLowerCase();
  return val === "medium" ? "moderate" : val;
};

const stableStringify = (value) => {
  const sorter = (v) => {
    if (Array.isArray(v)) return v.map(sorter);
    if (v && typeof v === "object") {
      return Object.keys(v)
        .sort()
        .reduce((acc, k) => {
          acc[k] = sorter(v[k]);
          return acc;
        }, {});
    }
    return v;
  };
  return JSON.stringify(sorter(value));
};

const sha256 = (v) => crypto.createHash("sha256").update(stableStringify(v)).digest("hex");

function matchException(f) {
  return exceptions.filter((ex) => {
    const severityMatch = normSeverity(ex.severity) === normSeverity(f.severity);
    const idMatch = ex.id ? ex.id === f.id : true;
    const pkgMatch = ex.package ? ex.package === f.package : true;
    // scope remains descriptive. An optional path is an exact audit-path
    // constraint, never a glob/prefix; malformed constraints cannot match.
    const pathMatch = !Object.hasOwn(ex, "path") ||
      (typeof ex.path === "string" && ex.path.length > 0 &&
        ex.path.trim() === ex.path && ex.path === f.path);
    return severityMatch && idMatch && pkgMatch && pathMatch;
  });
}

const blocking = [];
const matched = [];
const expired = [];
const warnings = [];

for (const f of findings) {
  const sev = normSeverity(f.severity);
  const candidates = matchException(f);
  // Sort only for deterministic reporting; coverage considers every candidate.
  candidates.sort((a, b) => {
    const left = stableStringify(a);
    const right = stableStringify(b);
    return left < right ? -1 : left > right ? 1 : 0;
  });
  const valid = candidates.filter((ex) => !isExpired(ex.expires_on) && !!ex.reason);
  const ex = valid[0];
  const hasValidEx = valid.length > 0;

  for (const candidate of candidates.filter((ex) => isExpired(ex.expires_on))) {
    expired.push({ finding: f, exception: candidate, covered: hasValidEx });
  }
  if (hasValidEx) matched.push({ finding: f, exception: ex });

  // policy-driven action, fail-closed if missing
  let action = rules[sev] ?? "deny";
  // enforce invariant: high/critical always deny
  if (sev === "high" || sev === "critical") action = "deny";

  if (action === "deny") {
    blocking.push({ finding: f, exception: ex, reason: "policy denies this severity" });
  } else if (action === "require_exception") {
    if (!hasValidEx) {
      blocking.push({
        finding: f,
        exception: ex,
        reason: "moderate vulnerability without valid, non-expired exception"
      });
    }
  } else if (action === "warn") {
    warnings.push(f);
  } else {
    blocking.push({ finding: f, exception: ex, reason: `unknown action '${action}'` });
  }
}

const fmt = (f) =>
  `${f.severity || "unknown"} | ${f.package || "?"} | id=${f.id || "?"} | path=${f.path || "-"}`;

console.log("== Security Advisory Gate ==");
console.log(`Findings: ${findings.length}`);
console.log(`Blocking: ${blocking.length}`);
console.log(`Matched exceptions: ${matched.length}`);
console.log(`Expired exceptions: ${expired.length}`);
console.log(`Warnings: ${warnings.length}`);

if (blocking.length) {
  console.log("\nBlocking findings:");
  for (const b of blocking) console.log(` - ${fmt(b.finding)} (${b.reason})`);
}

if (expired.length) {
  console.log("\nExpired exceptions:");
  for (const e of expired) console.log(` - ${fmt(e.finding)} | exception expires_on=${e.exception.expires_on}${e.covered ? " (covered by another valid exception)" : ""}`);
}

if (!exceptions.length) console.log("\nNo exceptions configured.");

// Expired exceptions are diagnostics only: they never satisfy
// require_exception (see hasValidEx) and never change a policy action.
const ok = blocking.length === 0;
const decision = ok ? "ALLOW" : "DENY";
const reason = ok
  ? "no blocking findings"
  : blocking[0]
  ? blocking[0].reason
  : expired[0]
  ? "expired exception"
  : "unknown reason";

console.log(`\nDecision: ${decision}`);
console.log(`Reason: ${reason}`);

// ── Release-evidence provenance (#268) ──────────────────────────────────────
//
// Binds the decision artifact to the exact freeze candidate and dependency
// graph it was evaluated against. Only computed when an artifact is actually
// requested (--artifact-out): the plain advisory-check path (no artifact)
// keeps zero git/filesystem dependencies beyond audit.json and the policy
// file, exactly as before.
//
// candidateSha and lockfileHash are binding, not descriptive: a caller must
// be able to prove which commit and which exact pnpm-lock.yaml bytes were
// evaluated. Neither is inferred from a branch name or other mutable ref.
// If neither an explicit override nor ambient git/filesystem state can
// establish them, evidence generation fails loudly rather than emitting an
// artifact with absent or guessed provenance.
const SHA_RE = /^[0-9a-f]{7,40}$/i;

function resolveCandidateSha(explicit) {
  if (explicit !== null) {
    if (!SHA_RE.test(explicit)) {
      throw new Error(
        `--candidate-sha must be a hex git commit SHA (7-40 hex chars), got: ${JSON.stringify(explicit)}`
      );
    }
    return explicit.toLowerCase();
  }
  try {
    return execFileSync("git", ["rev-parse", "--verify", "HEAD"], {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    }).trim();
  } catch (err) {
    throw new Error(
      "candidateSha could not be determined: not resolvable via `git rev-parse --verify HEAD` " +
        `in ${repoRoot}. Pass --candidate-sha=<sha> explicitly for release/freeze tooling. (${err.message})`
    );
  }
}

function resolveLockfileHash(explicit) {
  const lockfilePath = explicit !== null ? explicit : path.join(repoRoot, "pnpm-lock.yaml");
  let bytes;
  try {
    bytes = fs.readFileSync(lockfilePath);
  } catch (err) {
    throw new Error(`lockfileHash could not be determined: cannot read ${lockfilePath} (${err.message})`);
  }
  return { lockfilePath, lockfileHash: crypto.createHash("sha256").update(bytes).digest("hex") };
}

function resolveAdvisorySource(explicit) {
  if (explicit !== null) return explicit;
  try {
    const pnpmVersion = execFileSync("pnpm", ["--version"], { encoding: "utf8" }).trim();
    return `pnpm audit --json (pnpm ${pnpmVersion})`;
  } catch {
    // Best-effort only: version detection is descriptive, not a binding
    // field, so its absence does not fail evidence generation.
    return "pnpm audit --json";
  }
}

let evidenceError = null;

if (artifactOut) {
  try {
    const candidateSha = resolveCandidateSha(candidateShaFlag);
    const { lockfileHash } = resolveLockfileHash(lockfileFlag);
    const advisorySource = resolveAdvisorySource(advisorySourceFlag);

    const artifactDir = path.dirname(artifactOut);
    fs.mkdirSync(artifactDir, { recursive: true });

    // Retain the raw advisory input alongside the decision artifact. A
    // findings hash alone is a commitment, not review evidence.
    const retainedAuditPath = path.join(artifactDir, "audit.json");
    if (path.resolve(retainedAuditPath) !== path.resolve(auditPath)) {
      fs.copyFileSync(auditPath, retainedAuditPath);
    }

    // Avoid silently overwriting unrelated prior evidence: if a decision
    // artifact for a different candidate already sits at this path, say so.
    if (fs.existsSync(artifactOut)) {
      try {
        const prior = JSON.parse(fs.readFileSync(artifactOut, "utf8"));
        if (prior.candidateSha && prior.candidateSha !== candidateSha) {
          console.log(`\nReplacing prior evidence at ${artifactOut}`);
          console.log(`  previous candidateSha: ${prior.candidateSha}`);
          console.log(`  new candidateSha:      ${candidateSha}`);
        }
      } catch {
        console.log(`\n${artifactOut} exists but is not a readable prior SecurityGateDecision; overwriting.`);
      }
    }

    const policyHash = sha256(rules);
    const exceptionsHash = sha256(exceptions);
    const findingsHash = sha256(findings);
    const inputHash = sha256({ policyHash, exceptionsHash, findingsHash, decision, reason });

    const artifact = {
      formatVersion: 2,
      type: "SecurityGateDecision",
      decision,
      reason,
      timestamp: new Date().toISOString(),
      candidateSha,
      lockfileHash,
      advisorySource,
      policyHash,
      exceptionsHash,
      findingsHash,
      inputHash
    };

    const artifactHash = sha256(artifact);
    artifact.artifactHash = artifactHash;

    fs.writeFileSync(artifactOut, stableStringify(artifact) + "\n", "utf8");
    console.log(`\nArtifact written to ${artifactOut}`);
    console.log(`Raw advisory input retained at ${retainedAuditPath}`);
    console.log(`candidateSha: ${candidateSha}`);
    console.log(`lockfileHash: ${lockfileHash}`);
    console.log(`advisorySource: ${advisorySource}`);
  } catch (err) {
    evidenceError = err;
    console.error(`\nEvidence generation failed: ${err.message}`);
  }
}

// Evidence-capture failure never downgrades a DENY to a pass, and never
// upgrades an ALLOW into a false "everything is fine": it is reported and
// fails the process independently of the advisory decision itself.
if (evidenceError) {
  process.exit(1);
}

process.exit(ok ? 0 : 1);
