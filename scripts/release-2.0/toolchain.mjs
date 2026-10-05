// SPDX-License-Identifier: Apache-2.0
//
// Release-critical toolchain pin (#344).
//
//   Node: exact version in `.node-version` (also read by actions/setup-node)
//   pnpm: exact version in the root `packageManager` (also read by
//         pnpm/action-setup and corepack)
//
// Both pins must lie inside the root `engines` ranges. Release packing and the
// reproducibility harness refuse to run unless the Node executing them and the
// `pnpm` resolved from PATH are exactly these versions. The PATH pnpm matters
// because it is what the pack transport spawns and what every package's
// `prepack: pnpm build` runs.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const EXACT = /^(\d+)\.(\d+)\.(\d+)$/;

function parts(version) {
  return version.split(".").map((n) => Number(n));
}

function compare(a, b) {
  const [x, y] = [parts(a), parts(b)];
  for (let i = 0; i < 3; i++) {
    if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) < (y[i] ?? 0) ? -1 : 1;
  }
  return 0;
}

// Supports the comparator sets used in `engines` here: space-separated
// >=, >, <=, <, = with full or partial versions (e.g. ">=10.34.5 <11").
function satisfies(version, range) {
  const comparators = String(range).trim().split(/\s+/);
  return comparators.length > 0 && comparators.every((c) => {
    const m = /^(>=|<=|>|<|=)?(\d+(?:\.\d+){0,2})$/.exec(c);
    if (!m) throw new Error(`unsupported engines comparator "${c}"`);
    const cmp = compare(version, m[2]);
    switch (m[1] ?? "=") {
      case ">=": return cmp >= 0;
      case "<=": return cmp <= 0;
      case ">": return cmp > 0;
      case "<": return cmp < 0;
      default: return cmp === 0;
    }
  });
}

export function readReleaseToolchain(root) {
  const nodeFile = path.join(root, ".node-version");
  const node = existsSync(nodeFile) ? readFileSync(nodeFile, "utf8").trim() : "";
  if (!EXACT.test(node)) {
    throw new Error(`.node-version must contain one exact Node version (X.Y.Z); found ${JSON.stringify(node)}`);
  }
  const pkg = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
  const pm = /^pnpm@(\d+\.\d+\.\d+)(?:\+[\w.-]+)?$/.exec(pkg.packageManager ?? "");
  if (!pm) {
    throw new Error(`root packageManager must pin an exact pnpm version (pnpm@X.Y.Z); found ${JSON.stringify(pkg.packageManager)}`);
  }
  const pnpm = pm[1];
  for (const [tool, version] of [["node", node], ["pnpm", pnpm]]) {
    const range = pkg.engines?.[tool];
    if (range === undefined || !satisfies(version, range)) {
      throw new Error(`pinned ${tool} ${version} is outside engines.${tool} ${JSON.stringify(range)}`);
    }
  }
  return { node, pnpm };
}

export function observeReleaseToolchain(cwd) {
  const pnpm = spawnSync("pnpm", ["--version"], { cwd, encoding: "utf8" });
  return { node: process.version, pnpm: pnpm.status === 0 ? pnpm.stdout.trim() : "" };
}

export function assertReleaseToolchain(observed, pinned) {
  const node = String(observed?.node ?? "").replace(/^v/, "");
  if (node !== pinned.node) {
    throw new Error(`release toolchain: running Node v${node}, but .node-version pins ${pinned.node}`);
  }
  if (observed?.pnpm !== pinned.pnpm) {
    throw new Error(
      `release toolchain: pnpm ${observed?.pnpm || "(unavailable)"} on PATH, but packageManager pins ${pinned.pnpm} ` +
      `(the PATH pnpm runs every prepack build)`
    );
  }
  return true;
}
