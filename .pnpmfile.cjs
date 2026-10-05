// SPDX-License-Identifier: Apache-2.0
//
// Deterministic packed manifests (#344).
//
// pnpm 10 rewrites `workspace:` specifiers concurrently and inserts each
// rewritten dependency in completion order (p-map-values), and each workspace
// specifier waits on an async read of that dependency's manifest. A package
// with two workspace dependencies (every adapter: core + guard) was therefore
// packed as either {core, guard} or {guard, core}: same values, different
// bytes. `beforePacking` runs after that rewrite and before the tarball is
// written; it restores the key order of the package's own source manifest.
//
// It only reorders. Values come from pnpm unchanged, and any difference
// between the packed and source dependency names fails the pack instead of
// being reordered away.
//
// pnpm records this file's checksum in pnpm-lock.yaml (pnpmfileChecksum), so
// `pnpm install --frozen-lockfile` refuses a modified hook until the lockfile
// is updated with it.

const { readFileSync } = require("node:fs");
const path = require("node:path");

const DEPENDENCY_FIELDS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];

function beforePacking(pkg, dir) {
  const source = JSON.parse(readFileSync(path.join(dir, "package.json"), "utf8"));
  for (const field of DEPENDENCY_FIELDS) {
    if (pkg[field] == null) continue;
    const order = Object.keys(source[field] ?? {});
    const packed = Object.keys(pkg[field]);
    if (packed.length !== order.length || !order.every((name) => Object.hasOwn(pkg[field], name))) {
      throw new Error(
        `beforePacking: packed ${field} of ${source.name} (${packed.join(", ")}) ` +
        `differ from the source manifest (${order.join(", ")})`
      );
    }
    pkg[field] = Object.fromEntries(order.map((name) => [name, pkg[field][name]]));
  }
  return pkg;
}

module.exports = { hooks: { beforePacking } };
