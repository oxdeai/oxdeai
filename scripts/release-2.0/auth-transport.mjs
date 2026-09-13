// SPDX-License-Identifier: Apache-2.0
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

/** @typedef {'AUTH_UNAUTHENTICATED'|'REGISTRY_UNAVAILABLE'|'REGISTRY_ACCESS_INSUFFICIENT'|'REGISTRY_STATE_UNDETERMINED'} FailureCode */
/** @typedef {{code: FailureCode, detail: string}} RegistryObservationFailure */
/** @typedef {{kind: 'identity', registry: string, username: string}|{kind: 'unknown', registry: string, reason: RegistryObservationFailure}} IdentityObservation */
/** @typedef {{kind: 'access', registry: string, subject: string, packages: Record<string, 'read-only'|'read-write'>}|{kind: 'unknown', registry: string, reason: RegistryObservationFailure}} AccessObservation */
/**
 * @typedef {({kind: 'existing', visibility: 'public'|'private'}|
 * {kind: 'missing'}|{kind: 'unknown', reason: RegistryObservationFailure}) &
 * {registry: string, packageName: string}} PackageRegistryState
 *
 * Missing carries no visibility. Unknown always carries a failure.
 * IMPORTANT: npm CLI E404 is NOT an unambiguous absence contract: npm's
 * error-message.js explicitly says "not found or ... permission". The npm
 * visibility API documents 200/401, not a distinct confirmed-absence payload:
 * https://api-docs.npmjs.com/ (Get the visibility of a package).
 * Consequently this CLI adapter emits unknown for ALL E404 responses, even
 * "Not found" text. It currently cannot emit missing. The union retains that
 * distinct state for an observer with a documented, unambiguous absence
 * contract; never invent one from an ambiguous CLI message.
 */

const object = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const usernamePattern = /^[a-z0-9][a-z0-9._-]*$/;
const subjectPattern = /^@?[a-z0-9][a-z0-9._-]*(?::[a-z0-9][a-z0-9._-]*)?$/;
const packagePattern = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const unavailableCodes = new Set([
  "ENOTFOUND", "EAI_AGAIN", "ETIMEDOUT", "ESOCKETTIMEDOUT", "ECONNRESET",
  "ECONNREFUSED", "ECONNABORTED", "ENETUNREACH", "EHOSTUNREACH", "EPIPE",
  "CERT_HAS_EXPIRED", "DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "ERR_TLS_CERT_ALTNAME_INVALID", "EPROTO",
]);
const parse = (text) => { try { return JSON.parse(text); } catch { return undefined; } };

// Internal only. No caller-supplied command or args API is returned.
function execute(args) {
  // Isolate npm's cache/log files from the user's cache, do not persist them.
  // Credentials are read by npm from existing configuration; never written.
  const cache = mkdtempSync(path.join(tmpdir(), "oxdeai-auth-observation-"));
  try {
    return spawnSync("npm", [...args, `--cache=${cache}`], {
      encoding: "utf8", shell: false, timeout: 20000, maxBuffer: 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, CI: "true" },
    });
  } finally {
    rmSync(cache, { recursive: true, force: true });
  }
}

/**
 * Caller explicitly supplies the expected registry; no configuration discovery,
 * registry switching or .npmrc writes. subprocess is a fixture seam, private to
 * this closure. The frozen returned object exposes only three read operations.
 * Observations are npm reports, not release decisions or proof of token powers.
 */
export function createNpmAuthTransport({ registry, subprocess = execute }) {
  const url = new URL(registry);
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    throw new TypeError("registry must be an explicit HTTPS URL without credentials/query/fragment");
  }
  const target = url.href.endsWith("/") ? url.href : `${url.href}/`;
  const flags = [
    "--json", `--registry=${target}`, "--ignore-scripts", "--logs-max=0",
    "--update-notifier=false", "--color=false", "--fetch-retries=0",
    "--fetch-timeout=15000", "--offline=false", "--prefer-offline=false", "--prefer-online=true",
  ];
  const unknown = (code, detail) => ({ kind: "unknown", registry: target, reason: { code, detail } });
  function observe(args) {
    let result;
    try { result = subprocess([...args, ...flags]); }
    catch { return { failure: unknown("REGISTRY_STATE_UNDETERMINED", "observer execution failed") }; }
    if (!object(result)) return { failure: unknown("REGISTRY_STATE_UNDETERMINED", "invalid process result") };
    const body = parse(result.stdout);
    if (result.status === 0 && !result.error && !result.signal) return { body };
    const error = object(body?.error) ? body.error : parse(result.stderr)?.error;
    const code = result.error?.code ?? error?.code;
    if (unavailableCodes.has(code) || /^E5\d\d$/.test(code ?? "") || code === "E429" || result.signal) {
      return { failure: unknown("REGISTRY_UNAVAILABLE", "network/server/TLS failure or timeout") };
    }
    if (["ENEEDAUTH", "E401", "EAUTH", "EOTP"].includes(code)) {
      return { failure: unknown("AUTH_UNAUTHENTICATED", "npm did not establish identity/authentication") };
    }
    // A refusal does not establish the subject's package access level.
    if (code === "E403") return { failure: unknown("REGISTRY_STATE_UNDETERMINED", "npm refused the operation; precise access state not established") };
    // No raw stderr, summaries or credentials are returned in diagnostics.
    return { failure: unknown("REGISTRY_STATE_UNDETERMINED",
      code === "E404" ? "E404 cannot distinguish absence from inaccessible package/endpoint" : "unrecognized npm failure") };
  }
  return Object.freeze({
    /** @returns {IdentityObservation} */
    whoami() {
      const { body, failure } = observe(["whoami"]);
      if (failure) return failure;
      if (typeof body !== "string" || !usernamePattern.test(body)) {
        return unknown("REGISTRY_STATE_UNDETERMINED", "unsupported whoami JSON");
      }
      return { kind: "identity", registry: target, username: body };
    },
    /** @returns {AccessObservation} */
    listPackageAccess(subject) {
      if (typeof subject !== "string" || !subjectPattern.test(subject)) throw new TypeError("invalid access subject");
      const { body, failure } = observe(["access", "list", "packages", subject]);
      if (failure) return failure;
      if (!object(body) || Object.entries(body).some(([name, right]) =>
        !packagePattern.test(name) || !["read-only", "read-write"].includes(right))) {
        return unknown("REGISTRY_STATE_UNDETERMINED", "unsupported package-access JSON");
      }
      return { kind: "access", registry: target, subject, packages: body };
    },
    /** @returns {PackageRegistryState} */
    getPackageStatus(packageName) {
      if (typeof packageName !== "string" || !packagePattern.test(packageName)) throw new TypeError("invalid package name");
      const { body, failure } = observe(["access", "get", "status", packageName]);
      if (failure) return { ...failure, packageName };
      if (!object(body) || Object.keys(body).length !== 1 || !Object.hasOwn(body, packageName) ||
          !["public", "private"].includes(body[packageName])) {
        return { ...unknown("REGISTRY_STATE_UNDETERMINED", "unsupported package-status JSON"), packageName };
      }
      return { kind: "existing", registry: target, packageName, visibility: body[packageName] };
    },
  });
}
