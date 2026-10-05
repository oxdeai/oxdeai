#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Reproducible pack check (#344).
//
// From one clean source revision, packs every publishable package N times with
// the release pack transport (`pnpm pack`, prepack builds included), hashes the
// exact tarball bytes and fails if any package produced more than one hash.
//
// It only packs into a NEW output directory and never touches a release
// directory, a release manifest or a frozen artifact. It has no publish path.
// Its tarballs are evidence of reproducibility, not release artifacts: a
// release is still packed exactly once by `orchestrator.mjs pack`.
//
//   node scripts/release-2.0/reproducible-pack.mjs [--runs N] [--out DIR]
//        [--report FILE] [--compare OTHER_REPORT.json]
//
// --compare checks this run's package -> sha256 map against a report produced
// in another environment and fails on any difference.

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { assertPolicyCoverage, discoverPublishablePackages } from "../verify-packed-artifacts.mjs";
import { ROOT, defaultPackTransport, gitSourceTransport } from "./orchestrator.mjs";
import { assertReleaseToolchain, observeReleaseToolchain, readReleaseToolchain } from "./toolchain.mjs";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function observeSource(sourceTransport) {
  const s = sourceTransport.snapshot();
  if (!s || typeof s.root !== "string" || !path.isAbsolute(s.root) || !/^[0-9a-f]{40}$/.test(s.revision ?? "") || typeof s.clean !== "boolean") {
    throw new Error("reproducibility source: malformed source observation");
  }
  if (!s.clean) throw new Error(`reproducibility source: ${s.root} is not clean at ${s.revision}`);
  return s;
}

export function runReproducibilityCheck({ discovered, runs, outDir, packTransport, sourceTransport, toolchain }) {
  if (!Number.isInteger(runs) || runs < 2) throw new Error(`runs must be an integer >= 2; got ${JSON.stringify(runs)}`);
  if (!outDir || existsSync(outDir)) {
    throw new Error(`output directory ${outDir} already exists; the check only writes to a new directory`);
  }
  assertReleaseToolchain(toolchain.observed, toolchain.pinned);
  const before = observeSource(sourceTransport);

  mkdirSync(outDir, { recursive: true });
  const hashes = new Map(discovered.map((d) => [d.name, []]));
  for (let i = 1; i <= runs; i++) {
    const runDir = path.join(outDir, `run-${i}`);
    mkdirSync(runDir);
    for (const d of discovered) hashes.get(d.name).push(sha256(readFileSync(packTransport.packToDir(d, runDir))));
  }

  let after;
  try {
    after = observeSource(sourceTransport);
  } catch (error) {
    throw new Error(`reproducibility source changed during the runs: ${error.message}`);
  }
  if (after.root !== before.root || after.revision !== before.revision) {
    throw new Error(`reproducibility source changed during the runs: ${before.root}@${before.revision} -> ${after.root}@${after.revision}`);
  }

  const packages = discovered.map((d) => {
    const hs = hashes.get(d.name);
    const reproducible = new Set(hs).size === 1;
    return { package: d.name, version: d.manifest.version, reproducible, sha256: reproducible ? hs[0] : null, hashes: hs };
  });
  const failures = packages.filter((p) => !p.reproducible).map((p) => ({ package: p.package, hashes: [...new Set(p.hashes)] }));
  return { ok: failures.length === 0, sourceRevision: before.revision, toolchain: toolchain.pinned, runs, packages, failures };
}

export function compareReports(a, b) {
  const differences = [];
  if (a.sourceRevision !== b.sourceRevision) differences.push(`sourceRevision ${a.sourceRevision} != ${b.sourceRevision}`);
  const map = (r) => new Map(r.packages.map((p) => [p.package, p.sha256]));
  const [ma, mb] = [map(a), map(b)];
  for (const name of new Set([...ma.keys(), ...mb.keys()])) {
    if (!ma.get(name) || ma.get(name) !== mb.get(name)) differences.push(`${name}: ${ma.get(name) ?? "missing"} != ${mb.get(name) ?? "missing"}`);
  }
  return differences;
}

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i === -1 ? fallback : process.argv[i + 1];
}

function main() {
  const discovered = discoverPublishablePackages();
  assertPolicyCoverage(discovered);
  const outDir = arg("--out", path.join(mkdtempSync(path.join(tmpdir(), "oxdeai-reproducible-pack-")), "packs"));
  const reportFile = arg("--report", path.join(path.dirname(outDir), "reproducible-pack-report.json"));
  if (existsSync(reportFile)) throw new Error(`report ${reportFile} already exists`);

  const report = runReproducibilityCheck({
    discovered,
    runs: Number(arg("--runs", "3")),
    outDir,
    packTransport: defaultPackTransport(),
    sourceTransport: gitSourceTransport(ROOT),
    toolchain: { observed: observeReleaseToolchain(ROOT), pinned: readReleaseToolchain(ROOT) },
  });
  writeFileSync(reportFile, `${JSON.stringify(report, null, 2)}\n`);

  console.log(`source ${report.sourceRevision}  node ${report.toolchain.node}  pnpm ${report.toolchain.pnpm}  runs ${report.runs}`);
  for (const p of report.packages) {
    console.log(`${p.reproducible ? "OK  " : "FAIL"} ${`${p.package}@${p.version}`.padEnd(32)} ${p.sha256 ?? [...new Set(p.hashes)].join(" | ")}`);
  }
  console.log(`report: ${reportFile}`);
  let ok = report.ok;
  if (!ok) console.error(`NOT REPRODUCIBLE: ${report.failures.map((f) => f.package).join(", ")}`);

  const compare = arg("--compare");
  if (compare) {
    const differences = compareReports(report, JSON.parse(readFileSync(compare, "utf8")));
    if (differences.length) {
      ok = false;
      console.error(`CROSS-ENVIRONMENT MISMATCH vs ${compare}:\n  ${differences.join("\n  ")}`);
    } else {
      console.log(`cross-environment: byte-identical to ${compare}`);
    }
  }
  console.log(ok ? "REPRODUCIBLE PACK: PASS" : "REPRODUCIBLE PACK: FAIL");
  process.exitCode = ok ? 0 : 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
