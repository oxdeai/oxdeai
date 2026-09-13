// SPDX-License-Identifier: Apache-2.0
// Release requirements belong here, never in the observation transport.
export const RELEASE_REGISTRY_REQUIREMENTS = Object.freeze({
  registry: "https://registry.npmjs.org/",
  requiredRegistryAccess: "read-write",
  existingPackageVisibility: "public",
});
const failureCodes = new Set([
  "AUTH_UNAUTHENTICATED", "REGISTRY_UNAVAILABLE", "REGISTRY_ACCESS_INSUFFICIENT", "REGISTRY_STATE_UNDETERMINED",
]);
const object = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// Missing packages cannot establish current visibility or creation authority.
// Step 3 deliberately refuses them; a future policy must establish creation
// authority separately. No future visibility assertion is made here.
export function observeRegistryPrecheck({ discovered, authTransport }) {
  const observations = { identity: undefined, access: undefined, packages: [] };
  const blockers = [];
  const reject = (code, detail) => blockers.push(`${code}: ${detail}`);
  const read = (fn) => { try { return fn(); } catch { return undefined; } };
  const usable = (observation, label) => {
    if (!object(observation) || observation.registry !== RELEASE_REGISTRY_REQUIREMENTS.registry) {
      reject("REGISTRY_STATE_UNDETERMINED", `${label}: malformed observation or unexpected registry`);
      return false;
    }
    if (observation.kind === "unknown") {
      const code = failureCodes.has(observation.reason?.code) ? observation.reason.code : "REGISTRY_STATE_UNDETERMINED";
      reject(code, `${label}: observation unavailable`);
      return false;
    }
    return true;
  };
  observations.identity = read(() => authTransport.whoami());
  const identity = observations.identity;
  if (!usable(identity, "identity")) return { observations, blockers };
  if (identity.kind !== "identity" || typeof identity.username !== "string" || !/^[a-z0-9][a-z0-9._-]*$/.test(identity.username)) {
    reject("AUTH_UNAUTHENTICATED", "identity not positively established");
    return { observations, blockers };
  }
  observations.access = read(() => authTransport.listPackageAccess(identity.username));
  const access = observations.access;
  if (!usable(access, "access")) return { observations, blockers };
  if (access.kind !== "access" || access.subject !== identity.username || !object(access.packages) ||
      Object.values(access.packages).some((right) => !["read-only", "read-write"].includes(right))) {
    reject("REGISTRY_STATE_UNDETERMINED", "unsupported or mismatched access observation");
    return { observations, blockers };
  }
  for (const { name } of discovered) {
    const status = read(() => authTransport.getPackageStatus(name));
    observations.packages.push(status);
    if (!usable(status, name)) continue;
    if (status.packageName !== name) {
      reject("REGISTRY_STATE_UNDETERMINED", `${name}: mismatched package observation`);
      continue;
    }
    switch (status.kind) {
      case "missing":
        if (Object.hasOwn(status, "visibility")) {
          reject("REGISTRY_STATE_UNDETERMINED", `${name}: missing package cannot have visibility`);
        } else {
          reject("REGISTRY_ACCESS_INSUFFICIENT", `${name}: missing package; creation authority not established, no current visibility`);
        }
        break;
      case "existing":
        if (!["public", "private"].includes(status.visibility)) {
          reject("REGISTRY_STATE_UNDETERMINED", `${name}: unsupported visibility`);
          break;
        }
        if (status.visibility !== RELEASE_REGISTRY_REQUIREMENTS.existingPackageVisibility) {
          reject("REGISTRY_ACCESS_INSUFFICIENT", `${name}: current visibility is private; release requires public`);
        }
        if (!Object.hasOwn(access.packages, name) || access.packages[name] !== RELEASE_REGISTRY_REQUIREMENTS.requiredRegistryAccess) {
          reject("REGISTRY_ACCESS_INSUFFICIENT", `${name}: required ${RELEASE_REGISTRY_REQUIREMENTS.requiredRegistryAccess} not observed`);
        }
        break;
      default:
        reject("REGISTRY_STATE_UNDETERMINED", `${name}: unsupported existence discriminant`);
    }
  }
  return { observations, blockers };
}
