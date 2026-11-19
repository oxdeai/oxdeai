// SPDX-License-Identifier: Apache-2.0
// Published-version floor (R3 reconciliation).
//
// `published-baseline.json` records, for every release package, the latest
// version published on the npm registry. PRECHECK refuses a release whose POLICY
// version for any package is not strictly greater than that recorded version:
// an equal version would try to republish an existing name@version, a lower one
// would publish a downgrade. Both are refused before any receipt is written.
//
// The baseline is committed data, not a live registry observation. It is
// updated in a reviewed change after a publication has been verified on the
// registry. The registry-side checks at publication (RegistryIntegrityConflict)
// remain in place; this floor stops the release earlier, offline.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const PUBLISHED_BASELINE_FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), "published-baseline.json");

const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const INTEGRITY = /^sha512-[A-Za-z0-9+/]{86}==$/;
const PACKAGE_KEYS = ["integrity", "publishedAt", "version"];
const ROOT_KEYS = ["$comment", "baselineVersion", "packages", "recordedAt", "registry"];

function parseVersion(v) {
  const m = typeof v === "string" ? VERSION.exec(v) : null;
  if (!m) return null;
  return { core: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] === undefined ? [] : m[4].split(".") };
}

// SemVer 2.0.0 precedence. Build metadata is ignored. Returns -1, 0 or 1.
export function compareVersions(a, b) {
  const pa = parseVersion(a), pb = parseVersion(b);
  if (!pa || !pb) throw new Error(`not a SemVer version: ${JSON.stringify(pa ? b : a)}`);
  for (let i = 0; i < 3; i++) if (pa.core[i] !== pb.core[i]) return pa.core[i] < pb.core[i] ? -1 : 1;
  if (pa.pre.length === 0 || pb.pre.length === 0) return pa.pre.length === pb.pre.length ? 0 : (pa.pre.length === 0 ? 1 : -1);
  for (let i = 0; i < Math.max(pa.pre.length, pb.pre.length); i++) {
    if (i >= pa.pre.length) return -1;
    if (i >= pb.pre.length) return 1;
    const x = pa.pre[i], y = pb.pre[i], nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    if (x === y) continue;
    if (nx && ny) return Number(x) < Number(y) ? -1 : 1;
    if (nx !== ny) return nx ? -1 : 1;
    return x < y ? -1 : 1;
  }
  return 0;
}

const plainObject = v => v !== null && typeof v === "object" && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
const exactKeys = (o, keys) => { const k = Object.keys(o).sort(); return k.length === keys.length && k.every((x, i) => x === keys[i]); };

// Strict shape check. Fails closed on anything unexpected.
export function validatePublishedBaseline(baseline) {
  const fail = (detail) => { throw new Error(`invalid published-version baseline: ${detail}`); };
  if (!plainObject(baseline) || !exactKeys(baseline, ROOT_KEYS)) fail("unexpected or missing top-level fields");
  if (baseline.baselineVersion !== 1) fail("baselineVersion must be 1");
  if (baseline.registry !== "https://registry.npmjs.org/") fail("registry must be https://registry.npmjs.org/");
  if (!plainObject(baseline.packages) || Object.keys(baseline.packages).length === 0) fail("packages must be a non-empty object");
  for (const [name, entry] of Object.entries(baseline.packages)) {
    if (!/^@oxdeai\/[a-z0-9-]+$/.test(name)) fail(`unexpected package name ${JSON.stringify(name)}`);
    if (!plainObject(entry) || !exactKeys(entry, PACKAGE_KEYS)) fail(`${name}: unexpected or missing fields`);
    if (!parseVersion(entry.version)) fail(`${name}: version is not an exact SemVer version`);
    if (typeof entry.integrity !== "string" || !INTEGRITY.test(entry.integrity)) fail(`${name}: integrity must be an npm sha512 SRI string`);
    if (typeof entry.publishedAt !== "string" || Number.isNaN(Date.parse(entry.publishedAt))) fail(`${name}: publishedAt must be an ISO timestamp`);
  }
  return baseline;
}

export function loadPublishedBaseline(file = PUBLISHED_BASELINE_FILE) {
  return validatePublishedBaseline(JSON.parse(readFileSync(file, "utf8")));
}

// Returns PRECHECK blocker strings; an empty array means every POLICY version is
// strictly greater than the recorded published version of the same package.
export function publishedVersionBlockers(policy, baseline) {
  validatePublishedBaseline(baseline);
  const blockers = [];
  for (const [name, meta] of Object.entries(policy)) {
    const published = baseline.packages[name];
    if (!published) {
      blockers.push(`RELEASE_VERSION_BASELINE_MISSING: ${name} has no recorded published version; add it to published-baseline.json in a reviewed change`);
      continue;
    }
    const order = compareVersions(meta.version, published.version);
    if (order === 0) {
      blockers.push(`RELEASE_VERSION_ALREADY_PUBLISHED: ${name}@${meta.version} is already published (${published.integrity}); choose a new version`);
    } else if (order < 0) {
      blockers.push(`RELEASE_VERSION_DOWNGRADE: ${name}@${meta.version} is lower than the published ${published.version}`);
    }
  }
  return blockers;
}
