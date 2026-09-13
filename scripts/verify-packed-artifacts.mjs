#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Packed Artifact Consumer Gate
//
// Validates that every publishable OxDeAI package, once `pnpm pack`ed into a
// tarball, is actually installable and consumable from a clean external
// project — not merely that it builds and links correctly inside the
// monorepo workspace. This is the automated form of the manual validation
// that fixed `@oxdeai/conformance` (no workspace:/file:/link: leakage in the
// packed manifest, no monorepo-relative runtime path, external npm AND pnpm
// install, root import, strict TypeScript consumption, CLI execution).
//
// Design constraints (see the reviewed design report):
//   - Publishable packages are discovered dynamically from `packages/*`
//     manifests (private !== true).
//   - The EXPECTED test surface per package is NOT inferred from that same
//     manifest — it comes from the explicit POLICY table below. A
//     discovered package with no POLICY entry fails closed rather than
//     being silently skipped or silently tested with a default surface.
//   - Everything happens under a single temporary directory; nothing is
//     ever written into the repository tree.
//   - No registry publish, no lockfile mutation, no workspace manifest
//     mutation. A pnpm-only, /tmp-scoped `pnpm.overrides` is used solely to
//     let the pnpm consumer resolve not-yet-published internal versions
//     from the co-installed local tarballs — this override never touches a
//     repository file.

import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// ── Explicit expected-surface policy ─────────────────────────────────────────
//
// Keyed by package name. A publishable package discovered under `packages/*`
// that has no entry here is a FAIL-CLOSED condition (see `assertPolicyCoverage`)
// — it must be added deliberately, not inferred.
//
//   kind            — informational grouping, drives which checks apply
//   expectMain      — packed manifest MUST have a truthy `main`
//   expectTypes     — packed manifest MUST have a truthy `types`
//   expectExports   — packed manifest MUST have a truthy `exports`
//   expectBin       — packed manifest MUST have `bin[<name>]`, or null
//   expectedSymbols — root import MUST expose at least these (non-exhaustive
//                     on purpose: catches "nothing resolves" and "the one
//                     symbol everyone depends on vanished", not every export)
//   cliCheck        — "help" | "conformance-count" | null
//
// Release metadata (#292) — extends this SAME table rather than maintaining a
// second publishable-package list that could drift independently:
//   releaseLine     — "2.0" (the nine 2.0.0 packages) | "cli" (@oxdeai/cli,
//                     which tracks its own pre-1.0 contract, not the 2.0 line)
//   version         — the declared release version for this package. NEVER
//                     hardcoded per-entry: derived from RELEASE_LINE_VERSIONS
//                     so a package's version and its release-line membership
//                     cannot be edited independently into an inconsistent pair.
//   publishOrder    — declared publish order. assertPublishOrderMatchesDependencyGraph()
//                     (scripts/release-2.0/orchestrator.mjs) validates this against
//                     the REAL @oxdeai/* dependency graph; it is never trusted
//                     on its own.
const RELEASE_LINE_VERSIONS = Object.freeze({
  "2.0": "2.0.0",
  "cli": "0.3.0",
});

export const POLICY = {
  "@oxdeai/core": {
    kind: "library",
    expectMain: true, expectTypes: true, expectExports: true, expectBin: null,
    expectedSymbols: ["PolicyEngine", "verifyAuthorization", "verifyTrustedTime"],
    cliCheck: null,
    releaseLine: "2.0", version: RELEASE_LINE_VERSIONS["2.0"], publishOrder: 10,
  },
  "@oxdeai/guard": {
    kind: "library",
    expectMain: true, expectTypes: true, expectExports: false, expectBin: null,
    expectedSymbols: ["OxDeAIGuard"],
    cliCheck: null,
    releaseLine: "2.0", version: RELEASE_LINE_VERSIONS["2.0"], publishOrder: 20,
  },
  "@oxdeai/sdk": {
    kind: "library",
    expectMain: true, expectTypes: true, expectExports: false, expectBin: null,
    expectedSymbols: ["buildState"],
    cliCheck: null,
    releaseLine: "2.0", version: RELEASE_LINE_VERSIONS["2.0"], publishOrder: 30,
  },
  "@oxdeai/conformance": {
    kind: "library+cli",
    expectMain: true, expectTypes: true, expectExports: true, expectBin: "oxdeai-conformance",
    expectedSymbols: ["runTrustedTimeConformance", "parseTrustedTimeFile", "trustedTimeExitCode"],
    cliCheck: "conformance-count",
    releaseLine: "2.0", version: RELEASE_LINE_VERSIONS["2.0"], publishOrder: 40,
  },
  "@oxdeai/autogen": {
    kind: "adapter",
    expectMain: true, expectTypes: true, expectExports: false, expectBin: null,
    expectedSymbols: ["createAutoGenGuard"],
    cliCheck: null,
    releaseLine: "2.0", version: RELEASE_LINE_VERSIONS["2.0"], publishOrder: 50,
  },
  "@oxdeai/crewai": {
    kind: "adapter",
    expectMain: true, expectTypes: true, expectExports: false, expectBin: null,
    expectedSymbols: ["createCrewAIGuard"],
    cliCheck: null,
    releaseLine: "2.0", version: RELEASE_LINE_VERSIONS["2.0"], publishOrder: 60,
  },
  "@oxdeai/langgraph": {
    kind: "adapter",
    expectMain: true, expectTypes: true, expectExports: false, expectBin: null,
    expectedSymbols: ["createLangGraphGuard"],
    cliCheck: null,
    releaseLine: "2.0", version: RELEASE_LINE_VERSIONS["2.0"], publishOrder: 70,
  },
  "@oxdeai/openai-agents": {
    kind: "adapter",
    expectMain: true, expectTypes: true, expectExports: false, expectBin: null,
    expectedSymbols: ["createOpenAIAgentsGuard"],
    cliCheck: null,
    releaseLine: "2.0", version: RELEASE_LINE_VERSIONS["2.0"], publishOrder: 80,
  },
  "@oxdeai/openclaw": {
    kind: "adapter",
    expectMain: true, expectTypes: true, expectExports: false, expectBin: null,
    expectedSymbols: ["createOpenClawGuard"],
    cliCheck: null,
    releaseLine: "2.0", version: RELEASE_LINE_VERSIONS["2.0"], publishOrder: 85,
  },
  // @oxdeai/cli is at 0.3.0 and stays there: its published history is 0.2.x
  // and its own CHANGELOG declares a pre-1.0 SemVer regime. Its version
  // reflects the stability of its own public/operator contract, not
  // membership in the OxDeAI 2.0 release line. It is still part of the same
  // publication batch (publishOrder 90 — after core, which it depends on).
  "@oxdeai/cli": {
    kind: "cli",
    expectMain: false, expectTypes: false, expectExports: false, expectBin: "oxdeai",
    expectedSymbols: [],
    cliCheck: "help",
    releaseLine: "cli", version: RELEASE_LINE_VERSIONS["cli"], publishOrder: 90,
  },
};

// Fail-closed, load-time invariant: makes "@oxdeai/cli@2.0.0" (or any
// releaseLine/version pair that doesn't match RELEASE_LINE_VERSIONS)
// unrepresentable the moment this module is imported by ANYTHING — the CLI,
// the orchestrator, or a test — rather than relying on POLICY merely being
// configured correctly today. Three independent layers guard this invariant:
//   1. version is DERIVED from releaseLine via RELEASE_LINE_VERSIONS above,
//      not duplicated per package, so the two fields can't drift by a typo;
//   2. this function re-checks that derivation and throws on any mismatch;
//   3. an explicit, named guard for @oxdeai/cli specifically — independent of
//      the generic derivation — so the one state this table must never
//      represent is checked by name, not only inferred.
export function assertReleaseMetadataConsistency(policy) {
  for (const [name, meta] of Object.entries(policy)) {
    if (!meta.releaseLine || !(meta.releaseLine in RELEASE_LINE_VERSIONS)) {
      throw new Error(`POLICY['${name}'].releaseLine must be one of: ${Object.keys(RELEASE_LINE_VERSIONS).join(", ")}`);
    }
    const requiredVersion = RELEASE_LINE_VERSIONS[meta.releaseLine];
    if (meta.version !== requiredVersion) {
      throw new Error(`POLICY['${name}'] declares version "${meta.version}" but releaseLine "${meta.releaseLine}" requires "${requiredVersion}"`);
    }
    if (!Number.isInteger(meta.publishOrder)) {
      throw new Error(`POLICY['${name}'].publishOrder must be an integer`);
    }
  }
  const cli = policy["@oxdeai/cli"];
  if (cli && (cli.version === "2.0.0" || cli.releaseLine === "2.0")) {
    throw new Error(`@oxdeai/cli must never be assigned version "2.0.0" or releaseLine "2.0" — its release line is "cli" at ${RELEASE_LINE_VERSIONS.cli}.`);
  }
}
assertReleaseMetadataConsistency(POLICY);

// ── Structured failure ───────────────────────────────────────────────────────

export class GateFailure extends Error {
  constructor({ pkg, phase, pm, command, exitCode, detail }) {
    super(
      `Packed Artifact Consumer Gate FAILURE\n` +
      `  package    : ${pkg ?? "(n/a)"}\n` +
      `  phase      : ${phase}\n` +
      `  pm         : ${pm ?? "(n/a)"}\n` +
      `  command    : ${command ?? "(n/a)"}\n` +
      `  exit code  : ${exitCode ?? "(n/a)"}\n` +
      `  detail     : ${detail}`
    );
    this.name = "GateFailure";
  }
}

function fail(fields) {
  throw new GateFailure(fields);
}

function run(command, args, opts = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", ...opts });
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    error: result.error,
  };
}

function runOrFail({ pkg = null, phase, pm = null, command, args, opts = {} }) {
  const label = `${command} ${args.join(" ")}`;
  const result = run(command, args, opts);
  if (result.error || result.status !== 0) {
    fail({
      pkg, phase, pm, command: label,
      exitCode: result.status ?? "(spawn error)",
      detail: [result.stdout, result.stderr, result.error?.message].filter(Boolean).join("\n").trim() || "(no output)",
    });
  }
  return result;
}

// ── Discovery ─────────────────────────────────────────────────────────────────

export function discoverPublishablePackages() {
  const packagesDir = path.join(repoRoot, "packages");
  const discovered = [];
  for (const entry of readdirSync(packagesDir).sort()) {
    const dir = path.join(packagesDir, entry);
    const manifestPath = path.join(dir, "package.json");
    if (!statSync(dir).isDirectory() || !existsSync(manifestPath)) continue;
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (manifest.private === true) continue;
    discovered.push({ name: manifest.name, dir, manifest });
  }
  return discovered;
}

// Amendment 2: a discovered publishable package with no explicit policy is a
// fail-closed condition, not a silent skip and not a dynamically-inferred
// default surface.
export function assertPolicyCoverage(discovered) {
  for (const { name } of discovered) {
    if (!POLICY[name]) {
      fail({
        pkg: name,
        phase: "policy-coverage",
        command: null,
        exitCode: null,
        detail:
          `'${name}' is publishable (private!==true under packages/*) but has no entry in the ` +
          `explicit POLICY table in scripts/verify-packed-artifacts.mjs. Add a deliberate test-policy ` +
          `entry for this package before it can pass this gate — the gate does not infer an expected ` +
          `surface from the package's own manifest.`,
      });
    }
  }
}

// ── Build ─────────────────────────────────────────────────────────────────────

function buildPublishablePackages(discovered) {
  const filterArgs = discovered.flatMap(({ name }) => ["--filter", `${name}...`]);
  runOrFail({
    phase: "build",
    command: "pnpm",
    args: [...filterArgs, "build"],
    opts: { cwd: repoRoot },
  });
}

// ── Pack ──────────────────────────────────────────────────────────────────────

export function packPublishablePackages(discovered, tarballDir) {
  const packed = [];
  for (const { name, dir } of discovered) {
    const result = runOrFail({
      pkg: name,
      phase: "pack",
      command: "pnpm",
      args: ["pack", "--pack-destination", tarballDir],
      opts: { cwd: dir },
    });
    const tarballLine = result.stdout.trim().split("\n").filter(Boolean).pop();
    const tarballPath = path.isAbsolute(tarballLine) ? tarballLine : path.join(tarballDir, tarballLine);
    if (!existsSync(tarballPath)) {
      fail({ pkg: name, phase: "pack", command: "pnpm pack", exitCode: 0, detail: `expected tarball not found at ${tarballPath}` });
    }
    packed.push({ name, dir, tarballPath });
  }
  return packed;
}

// ── Artifact integrity: packed manifest + shipped-JS scans ──────────────────

const FORBIDDEN_DEP_PROTOCOLS = ["workspace:", "file:", "link:"];
// Matched only against shipped `.js` (never `.map`, never `.d.ts`): a
// monorepo-relative reference in compiled, executed code is load-bearing at
// runtime. The same substring in a `.d.ts` comment or a `.js.map`'s embedded
// original source is not something that executes.
const MONOREPO_PATH_PATTERNS = [/packages\/core\//, /\.\.\/\.\.\/packages\//, /\.\.\/core\//];

function extractTarball(tarballPath, destDir) {
  mkdirSync(destDir, { recursive: true });
  runOrFail({ phase: "extract", command: "tar", args: ["-xzf", tarballPath, "-C", destDir] });
  return path.join(destDir, "package");
}

function scanPackedManifest(name, packageDir) {
  const manifest = JSON.parse(readFileSync(path.join(packageDir, "package.json"), "utf8"));
  const policy = POLICY[name];

  // Forbidden dependency protocols.
  for (const field of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
    const deps = manifest[field] ?? {};
    for (const [depName, spec] of Object.entries(deps)) {
      if (FORBIDDEN_DEP_PROTOCOLS.some((proto) => String(spec).startsWith(proto))) {
        fail({
          pkg: name, phase: "manifest-scan", command: null, exitCode: null,
          detail: `${field}.${depName} = "${spec}" survived packing — forbidden protocol leaked into the published manifest.`,
        });
      }
    }
  }

  // Expected-surface enforcement (Amendment 2): a policy-declared surface
  // field that is absent from the packed manifest is a failure, not a
  // silently-skipped smoke test.
  if (policy.expectMain && !manifest.main) {
    fail({ pkg: name, phase: "manifest-scan", detail: `policy requires 'main'; packed manifest has none.` });
  }
  if (policy.expectTypes && !manifest.types) {
    fail({ pkg: name, phase: "manifest-scan", detail: `policy requires 'types'; packed manifest has none.` });
  }
  if (policy.expectExports && !manifest.exports) {
    fail({ pkg: name, phase: "manifest-scan", detail: `policy requires 'exports'; packed manifest has none.` });
  }
  if (policy.expectBin && !(manifest.bin && manifest.bin[policy.expectBin])) {
    fail({ pkg: name, phase: "manifest-scan", detail: `policy requires bin["${policy.expectBin}"]; packed manifest lacks it.` });
  }

  return manifest;
}

function walkJsFiles(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walkJsFiles(full, out);
    else if (entry.isFile() && entry.name.endsWith(".js") && !entry.name.endsWith(".map")) out.push(full);
  }
  return out;
}

function scanShippedRuntimePaths(name, packageDir) {
  const distDir = path.join(packageDir, "dist");
  if (!existsSync(distDir)) return;
  for (const file of walkJsFiles(distDir)) {
    const content = readFileSync(file, "utf8");
    for (const pattern of MONOREPO_PATH_PATTERNS) {
      const match = content.match(pattern);
      if (match) {
        const line = content.slice(0, match.index).split("\n").length;
        fail({
          pkg: name, phase: "runtime-path-scan", command: null, exitCode: null,
          detail: `${path.relative(packageDir, file)}:${line} contains monorepo-relative pattern "${match[0]}" in shipped JS.`,
        });
      }
    }
  }
}

// ── Consumer construction ────────────────────────────────────────────────────

function writeJson(file, obj) {
  writeFileSync(file, JSON.stringify(obj, null, 2));
}

// npm co-installs the supplied tarballs; the focused H2 test checks that
// satisfying internal semver ranges resolve to these local bytes (no overrides).
export function installNpmConsumer(consumerDir, packed) {
  mkdirSync(consumerDir, { recursive: true });
  writeJson(path.join(consumerDir, "package.json"), { name: "packed-gate-npm-consumer", version: "1.0.0", private: true, type: "module" });
  runOrFail({
    phase: "external-install", pm: "npm",
    command: "npm",
    args: ["install", "--no-audit", "--no-fund", ...packed.map((p) => p.tarballPath)],
    opts: { cwd: consumerDir },
  });
}

// The strict-TypeScript check needs `typescript` + `@types/node` available in
// the consumer. Installed with the SAME package manager that installed the
// packages under test, so the npm consumer is never touched by pnpm (or vice
// versa) — each consumer's toolchain stays single-package-manager throughout,
// strictly inside its own temporary directory.
// Release-gate evidence only; exact versions match the repository lockfile.
const TYPESCRIPT_TOOLING = ["typescript@5.9.3", "@types/node@22.19.17"];

export function installTypeScriptTooling(consumerDir, pm, runTool = runOrFail) {
  if (pm === "npm") {
    runTool({
      phase: "typescript-tooling-setup", pm,
      command: "npm",
      args: ["install", "--save-dev", "--save-exact", "--no-audit", "--no-fund", ...TYPESCRIPT_TOOLING],
      opts: { cwd: consumerDir },
    });
  } else if (pm === "pnpm") {
    runTool({
      phase: "typescript-tooling-setup", pm,
      command: "pnpm",
      args: ["add", "-D", "--save-exact", "--ignore-workspace", "--no-lockfile", ...TYPESCRIPT_TOOLING],
      opts: { cwd: consumerDir },
    });
  } else {
    fail({ phase: "typescript-tooling-setup", pm, detail: `unknown package manager "${pm}"` });
  }
}

function installPnpmConsumer(consumerDir, packed) {
  mkdirSync(consumerDir, { recursive: true });
  const deps = {};
  const overrides = {};
  for (const { name, tarballPath } of packed) {
    deps[name] = `file:${tarballPath}`;
    overrides[name] = `file:${tarballPath}`;
  }
  // pnpm resolves an internal package's own semver dependency range (e.g.
  // "^2.0.0") against the real registry even when a same-named tarball is
  // co-installed. Because the internal packages under test are not yet
  // published, a consumer-local override is required to bind that range to
  // the local tarball for this test only. This file lives entirely under
  // /tmp; no repository manifest is touched.
  writeJson(path.join(consumerDir, "package.json"), {
    name: "packed-gate-pnpm-consumer", version: "1.0.0", private: true, type: "module",
    dependencies: deps,
    pnpm: { overrides },
  });
  runOrFail({
    phase: "external-install", pm: "pnpm",
    command: "pnpm",
    args: ["install", "--no-lockfile"],
    opts: { cwd: consumerDir },
  });
}

// ── Smoke tests (shared between npm and pnpm consumers) ──────────────────────

function checkRootImportAndSymbols(pkg, consumerDir, pm) {
  const { name, expectedSymbols } = pkg;
  const script = `
    import(${JSON.stringify(name)}).then((m) => {
      const missing = ${JSON.stringify(expectedSymbols)}.filter((s) => typeof m[s] === "undefined");
      if (missing.length > 0) { console.error("MISSING:" + missing.join(",")); process.exit(1); }
      console.log("OK");
    }).catch((e) => { console.error("IMPORT_FAILED:" + e.message); process.exit(1); });
  `;
  const result = run(process.execPath, ["-e", script], { cwd: consumerDir });
  if (result.status !== 0) {
    fail({
      pkg: name, phase: "root-import", pm, command: `node -e "import('${name}')..."`,
      exitCode: result.status, detail: [result.stdout, result.stderr].filter(Boolean).join("\n"),
    });
  }
}

function checkStrictTypeScript(pkg, consumerDir) {
  const { name, expectedSymbols } = pkg;
  const safe = name.replace(/[^a-zA-Z0-9]/g, "_");
  const tsFile = path.join(consumerDir, `check_${safe}.ts`);
  const importList = expectedSymbols.join(", ");
  writeFileSync(
    tsFile,
    `import { ${importList} } from ${JSON.stringify(name)};\n` +
    expectedSymbols.map((s) => `void ${s};\n`).join("")
  );
}

function runStrictTypeScriptBatch(consumerDir, checkedFiles) {
  if (checkedFiles.length === 0) return;
  const tsconfigPath = path.join(consumerDir, "tsconfig.json");
  writeJson(tsconfigPath, {
    compilerOptions: {
      strict: true, module: "NodeNext", moduleResolution: "NodeNext",
      target: "ES2022", types: ["node"], noEmit: true, skipLibCheck: false,
    },
    include: checkedFiles.map((f) => path.basename(f)),
  });
  runOrFail({
    phase: "typescript",
    command: "tsc",
    args: ["-p", "tsconfig.json"],
    opts: { cwd: consumerDir, env: { ...process.env, PATH: `${path.join(consumerDir, "node_modules", ".bin")}:${process.env.PATH}` } },
  });
}

function checkCliHelp(pkg, consumerDir, pm) {
  const { name, expectBin } = pkg;
  const binPath = path.join(consumerDir, "node_modules", ".bin", expectBin);
  if (!existsSync(binPath)) {
    fail({ pkg: name, phase: "cli-bin-presence", pm, detail: `expected bin "${expectBin}" not found at ${binPath}` });
  }
  // Execute the bin directly via its own shebang, not `node <path>`: pnpm's
  // .bin shim is a shell-script wrapper (needed to resolve through its
  // symlinked node_modules layout), not a plain JS file, and parsing it as
  // JavaScript fails. npm's plain symlink also executes fine this way.
  const result = run(binPath, ["--help"], { cwd: consumerDir });
  if (result.status !== 0 || !/usage/i.test(result.stdout)) {
    fail({
      pkg: name, phase: "cli-execution", pm, command: `${expectBin} --help`,
      exitCode: result.status, detail: [result.stdout, result.stderr].filter(Boolean).join("\n"),
    });
  }
}

function runExternalConformanceCli(pkg, consumerDir, pm) {
  const { name, expectBin } = pkg;
  const binPath = path.join(consumerDir, "node_modules", ".bin", expectBin);
  if (!existsSync(binPath)) {
    fail({ pkg: name, phase: "cli-bin-presence", pm, detail: `expected bin "${expectBin}" not found at ${binPath}` });
  }
  // Executed from the consumer root, deliberately NOT from inside
  // node_modules — this is the exact condition that broke before the
  // conformance package-boundary fix (loadJson resolved vectors via
  // process.cwd() instead of the module's own location). Direct execution
  // via the bin's own shebang, same reasoning as checkCliHelp above.
  const result = run(binPath, [], { cwd: consumerDir });
  const text = result.stdout + result.stderr;
  const match = text.match(/Conformance passed: (\d+) assertions/);
  if (result.status !== 0 || !match) {
    fail({
      pkg: name, phase: "cli-execution", pm, command: expectBin,
      exitCode: result.status, detail: text || "(no output; expected 'Conformance passed: N assertions')",
    });
  }
  return Number(match[1]);
}

export function getMonorepoConformanceCount() {
  const result = runOrFail({
    phase: "monorepo-baseline",
    command: "pnpm",
    args: ["-C", "packages/conformance", "validate"],
    opts: { cwd: repoRoot },
  });
  const match = result.stdout.match(/Conformance passed: (\d+) assertions/);
  if (!match) {
    fail({ pkg: "@oxdeai/conformance", phase: "monorepo-baseline", detail: "monorepo run did not print an assertion count to compare against." });
  }
  return Number(match[1]);
}

// ── Per-consumer orchestration ───────────────────────────────────────────────

function runSmokeTestsForConsumer(packed, consumerDir, pm, monorepoConformanceCount) {
  const tsCheckFiles = [];
  for (const { name } of packed) {
    const policy = POLICY[name];

    if (policy.expectedSymbols.length > 0) {
      checkRootImportAndSymbols({ name, expectedSymbols: policy.expectedSymbols }, consumerDir, pm);
      if (policy.expectTypes) {
        checkStrictTypeScript({ name, expectedSymbols: policy.expectedSymbols }, consumerDir);
        tsCheckFiles.push(`check_${name.replace(/[^a-zA-Z0-9]/g, "_")}.ts`);
      }
    }

    if (policy.cliCheck === "help") {
      checkCliHelp({ name, expectBin: policy.expectBin }, consumerDir, pm);
    } else if (policy.cliCheck === "conformance-count") {
      const externalCount = runExternalConformanceCli({ name, expectBin: policy.expectBin }, consumerDir, pm);
      if (externalCount !== monorepoConformanceCount) {
        fail({
          pkg: name, phase: "conformance-equivalence", pm,
          detail: `external ${pm} run reported ${externalCount} assertions; monorepo run reported ${monorepoConformanceCount}.`,
        });
      }
      console.log(`  [${pm}] ${name}: external=${externalCount} monorepo=${monorepoConformanceCount} (match)`);
    }
  }
  runStrictTypeScriptBatch(consumerDir, tsCheckFiles);
}

// ── Main ──────────────────────────────────────────────────────────────────────
//
// No `--package` targeted mode: the gate always validates the full
// publishable set together. A single target (e.g. an adapter) packed in
// isolation would supply the external consumer with that one tarball while
// silently omitting its own unpublished internal dependencies (@oxdeai/core,
// @oxdeai/guard) from the packed-artifact set — the build filter resolves
// those dependencies for building, but packing did not, which is exactly the
// class of gap this gate exists to catch, not to reintroduce for itself.

// Verifies an already-packed tarball set (manifest scan + shipped-JS scan +
// external npm/pnpm consumer install + smoke tests) WITHOUT packing anything
// itself. `packed` must be `[{ name, tarballPath }]` for exactly the
// discovered set. Extracted from `main()` (#292) so a caller that already
// produced its own tarballs — e.g. the release orchestrator's PACK phase —
// can run the identical consumer-verification semantics against those EXACT
// files, never a repack. `main()` below calls this immediately after its own
// `packPublishablePackages()` call, so default CLI behavior is unchanged.
export function assertPackedBijection(discovered, packed) {
  const expected = new Set(discovered.map((p) => p.name));
  const seen = new Set();
  for (const { name } of packed) {
    if (seen.has(name)) throw new Error(`packed bijection: duplicate package ${name}`);
    if (!expected.has(name)) throw new Error(`packed bijection: extra package ${name}`);
    seen.add(name);
  }
  const missing = [...expected].filter((name) => !seen.has(name));
  if (missing.length || packed.length !== discovered.length || expected.size !== discovered.length) {
    throw new Error(`packed bijection: missing package or cardinality mismatch: ${missing.join(", ")}`);
  }
}

export function verifyPackedTarballs(discovered, packed, { baseDir } = {}) {
  assertPackedBijection(discovered, packed);
  assertPolicyCoverage(discovered);

  console.log("Establishing monorepo conformance baseline...");
  const monorepoConformanceCount = getMonorepoConformanceCount();
  console.log(`  monorepo conformance: ${monorepoConformanceCount} assertions\n`);

  const base = baseDir ?? mkdtempSync(path.join(tmpdir(), "oxdeai-packed-gate-"));
  mkdirSync(base, { recursive: true });

  console.log("Scanning packed manifests and shipped runtime JS...");
  for (const { name, tarballPath } of packed) {
    const extractDir = path.join(base, "extracted", name.replace("/", "_"));
    const packageDir = extractTarball(tarballPath, extractDir);
    scanPackedManifest(name, packageDir);
    scanShippedRuntimePaths(name, packageDir);
  }
  console.log("  no forbidden dependency protocol or monorepo-relative runtime path found.\n");

  console.log("Installing packed tarballs into a clean external npm consumer...");
  const npmConsumer = path.join(base, "npm-consumer");
  installNpmConsumer(npmConsumer, packed);
  installTypeScriptTooling(npmConsumer, "npm");
  runSmokeTestsForConsumer(packed, npmConsumer, "npm", monorepoConformanceCount);
  console.log("  npm consumer: all checks passed.\n");

  console.log("Installing packed tarballs into a clean external pnpm consumer...");
  const pnpmConsumer = path.join(base, "pnpm-consumer");
  installPnpmConsumer(pnpmConsumer, packed);
  installTypeScriptTooling(pnpmConsumer, "pnpm");
  runSmokeTestsForConsumer(packed, pnpmConsumer, "pnpm", monorepoConformanceCount);
  console.log("  pnpm consumer: all checks passed.\n");

  return { base, monorepoConformanceCount };
}

async function main() {
  console.log("Discovering publishable packages...");
  const discovered = discoverPublishablePackages();
  if (discovered.length === 0) {
    fail({ phase: "discovery", detail: "no publishable packages discovered under packages/*" });
  }
  console.log(discovered.map((p) => `  ${p.name}`).join("\n"));

  assertPolicyCoverage(discovered);
  console.log("Policy coverage OK for all discovered packages.\n");

  console.log("Building publishable packages (and their workspace dependencies)...");
  buildPublishablePackages(discovered);

  const base = mkdtempSync(path.join(tmpdir(), "oxdeai-packed-gate-"));
  const tarballDir = path.join(base, "tarballs");
  mkdirSync(tarballDir, { recursive: true });

  console.log(`Packing ${discovered.length} package(s) into ${tarballDir} ...`);
  const packed = packPublishablePackages(discovered, tarballDir);

  const { base: verifiedBase } = verifyPackedTarballs(discovered, packed, { baseDir: base });

  console.log(`Packed Artifact Consumer Gate: PASS (${discovered.length} package(s), npm + pnpm, temp dir: ${verifiedBase})`);
}

// Guard so this module can be `import`ed for its exports (POLICY,
// discoverPublishablePackages, verifyPackedTarballs, ...) — by the release
// orchestrator (#292) or by tests — without unconditionally running the full
// build+pack+verify CLI flow as a side effect of import. Running the file
// directly (`node scripts/verify-packed-artifacts.mjs`) is unaffected.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    if (error instanceof GateFailure) {
      console.error(`\n${error.message}\n`);
    } else {
      console.error("\nPacked Artifact Consumer Gate: unexpected error\n", error);
    }
    process.exit(1);
  });
}
