// SPDX-License-Identifier: Apache-2.0
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { RELEASE_REGISTRY_REQUIREMENTS } from "./auth-precheck.mjs";
import { validatePublicationAuthorization } from "./publication-authorization.mjs";
import { publishPlannedOperation, buildPublishCommandData, ReleaseOrchestratorError } from "./orchestrator.mjs";

const REGISTRY = "https://registry.npmjs.org/";
const object = v => v !== null && typeof v === "object" && !Array.isArray(v);
const invalid = () => { throw new ReleaseOrchestratorError("invalid bound live publication command", { code: "LIVE_PUBLICATION_TRANSPORT_INVALID" }); };

// Pure validator, not an execution capability. The private transport calls this
// independently even though Step 6 has already validated the command binding.
export function validateNpmPublicationCommand({ command, operation, releaseDir } = {}) {
  if (!object(operation) || operation.registry !== REGISTRY || RELEASE_REGISTRY_REQUIREMENTS.registry !== REGISTRY ||
      operation.tag !== "next" || operation.access !== "public" ||
      typeof operation.package !== "string" || !/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(operation.package) ||
      typeof operation.version !== "string" || !/^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(operation.version) ||
      typeof releaseDir !== "string" || !path.isAbsolute(releaseDir) || /[\\\x00-\x1f\x7f]/.test(releaseDir) ||
      typeof operation.tarball !== "string" || !operation.tarball.endsWith(".tgz") ||
      path.isAbsolute(operation.tarball) || /[\\:\x00-\x1f\x7f]/.test(operation.tarball) ||
      operation.tarball.split("/").some(part => !part || part === "." || part === "..")) invalid();
  const expected = buildPublishCommandData(operation, releaseDir, { registry: REGISTRY });
  if (!isDeepStrictEqual(command, expected)) invalid();
  return structuredClone(expected.args);
}

// Not exported: callers cannot acquire a live capability to bypass Step 6.
// Only the authorized wrapper below creates this invocation-local closure.
function createNpmPublicationTransport(operation, releaseDir) {
  let attempted = false;
  function run(args) {
    const cache = mkdtempSync(path.join(tmpdir(), "oxdeai-npm-publication-"));
    try {
      const config = {
        cache, "logs-max": "0", "update-notifier": "false", "ignore-scripts": "true",
        "fetch-retries": "0", "fetch-timeout": "15000", offline: "false", "prefer-online": "true",
      };
      if (operation.package.startsWith("@")) config[`${operation.package.split("/")[0]}:registry`] = REGISTRY;
      const env = { ...process.env, CI: "true" };
      // Override conflicting case/underscore spellings without persisting any
      // environment/configuration. Existing operator credentials remain in npm's
      // normal user config/environment; raw output never leaves this closure.
      for (const key of Object.keys(env)) {
        if (/^npm_config_/i.test(key) && Object.hasOwn(config, key.slice(11).replace(/_/g, "-").toLowerCase())) delete env[key];
      }
      for (const [key, value] of Object.entries(config)) env[`npm_config_${key}`] = value;
      return spawnSync("npm", args, {
        shell: false, encoding: "utf8", timeout: 60000, maxBuffer: 1024 * 1024,
        stdio: ["ignore", "pipe", "pipe"], cwd: cache, env,
      });
    } finally { rmSync(cache, { recursive: true, force: true }); }
  }
  function read(args) {
    try {
      const result = run([...args, "--json", "--registry", REGISTRY]);
      if (!object(result) || result.status !== 0 || result.error || result.signal) return undefined;
      return JSON.parse(result.stdout);
    } catch { return undefined; }
  }
  return Object.freeze({
    getRegistryVersion(name, version) {
      if (name !== operation.package || version !== operation.version) invalid();
      // Step 3's access transport has no version/integrity observation. npm
      // view's successful versions array lists the known published versions.
      // Only positive list evidence can establish this VERSION as absent;
      // E404/E403, malformed output and execution errors remain unknown.
      const versions = read(["view", name, "versions"]);
      if (!Array.isArray(versions) || versions.length === 0 || new Set(versions).size !== versions.length ||
          versions.some(v => typeof v !== "string" || !/^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(v))) return {};
      if (!versions.includes(version)) return { exists: false };
      const integrity = read(["view", `${name}@${version}`, "dist.integrity"]);
      if (typeof integrity !== "string" || !/^sha512-[A-Za-z0-9+/]{86}==$/.test(integrity)) return {};
      return { exists: true, integrity };
    },
    publish(command) {
      const args = validateNpmPublicationCommand({ command, operation, releaseDir });
      if (attempted) invalid();
      attempted = true;
      try {
        run(args);
      } catch { /* Process failure, like success, requires registry reconciliation. */ }
      // A zero exit (including ambient dry-run) is process evidence only.
      // Always let Step 6 reobserve the selected version and planned integrity.
      return { ok: false, error: "npm publication attempted; registry reconciliation required" };
    },
  });
}

// Explicit outer call + supplied consent, then the unchanged Step 6 boundary.
// No authorization builder, default transport on Step 6, CLI or batch runner.
// Reusing a receipt requires another explicit call; receipts are not globally
// one-use tokens. Neither this call nor its observations refresh global rights.
export function publishAuthorizedOperation(inputs = {}) {
  const { authorization, plan, operationIndex, manifest, state, releaseDir } = inputs ?? {};
  const operation = validatePublicationAuthorization({ authorization, plan, operationIndex, manifest });
  validateNpmPublicationCommand({ command: operation.command, operation, releaseDir });
  return publishPlannedOperation({ plan, operationIndex, manifest, state, releaseDir,
    registryTransport: createNpmPublicationTransport(operation, releaseDir) });
}
