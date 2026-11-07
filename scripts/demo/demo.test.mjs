// Regression tests for the root executable demo (`pnpm demo`, demo.mjs).
//
// Requires built packages: run `pnpm build:protocol` (or `pnpm build`) first.
// The tests run real copies of demo.mjs: from the repository root, from
// directories whose names contain a space or `%`, and from deliberately broken
// copies that must fail. They never change the demo's security semantics.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));
const DEMO = join(ROOT, "demo.mjs");
const REQUIRED = [
  "packages/core/package.json",
  "packages/core/dist/index.js",
  "packages/guard/package.json",
  "packages/guard/dist/index.js",
  "examples/non-bypassable-demo/auth-fixture.mjs",
];
const SCENARIOS = ["ALLOW", "NOT_COVERED", "REPLAY", "BYPASS"];

for (const rel of REQUIRED) {
  if (!existsSync(join(ROOT, rel))) {
    throw new Error(`missing ${rel}: run \`pnpm build:protocol\` before these tests`);
  }
}

function runDemo(file, cwd = dirname(file)) {
  const r = spawnSync(process.execPath, [file], { cwd, encoding: "utf8", timeout: 30_000 });
  return { status: r.status, out: `${r.stdout}${r.stderr}`, error: r.error };
}

function assertAllPassed(r) {
  assert.equal(r.error, undefined, String(r.error));
  assert.equal(r.status, 0, r.out);
  for (const name of SCENARIOS) {
    assert.match(r.out, new RegExp(`^${name}\\s+\\d{3}\\s.*side effects \\+[01]\\s+✓$`, "m"), `${name} line missing:\n${r.out}`);
  }
  assert.match(r.out, /All 4 scenarios behaved as expected\. Total side effects: 1/);
}

/** Copy the files demo.mjs needs into `dir`, laid out as in the repository. */
function stageCopy(dir, transform = (s) => s) {
  for (const rel of ["packages/core", "packages/guard"]) {
    mkdirSync(join(dir, rel), { recursive: true });
    cpSync(join(ROOT, rel, "package.json"), join(dir, rel, "package.json"));
    cpSync(join(ROOT, rel, "dist"), join(dir, rel, "dist"), { recursive: true });
  }
  // @oxdeai/guard imports the bare specifier "@oxdeai/core" (a workspace link in pnpm).
  mkdirSync(join(dir, "packages/guard/node_modules/@oxdeai"), { recursive: true });
  symlinkSync(join(dir, "packages/core"), join(dir, "packages/guard/node_modules/@oxdeai/core"), "junction");
  mkdirSync(join(dir, "examples/non-bypassable-demo"), { recursive: true });
  cpSync(join(ROOT, "examples/non-bypassable-demo/auth-fixture.mjs"), join(dir, "examples/non-bypassable-demo/auth-fixture.mjs"));
  writeFileSync(join(dir, "demo.mjs"), transform(readFileSync(DEMO, "utf8")));
  return join(dir, "demo.mjs");
}

function withTempDir(name, fn) {
  const parent = mkdtempSync(join(tmpdir(), "oxdeai-demo-"));
  const dir = join(parent, name);
  mkdirSync(dir);
  try {
    return fn(dir);
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
}

/** Replace exactly one occurrence; fail loudly if the demo source changed shape. */
function replaceOnce(src, from, to) {
  const n = src.split(from).length - 1;
  assert.equal(n, 1, `expected exactly one occurrence of ${JSON.stringify(from)} in demo.mjs, found ${n}`);
  return src.replace(from, to);
}

test("demo runs all four scenarios from the repository root", () => {
  assertAllPassed(runDemo(DEMO, ROOT));
});

test("demo resolves its root when the path contains a space", () => {
  withTempDir("repo with space", (dir) => assertAllPassed(runDemo(stageCopy(dir))));
});

test("demo resolves its root when the path contains '%' sequences", () => {
  // Both a bare '%' and a sequence that looks percent-encoded must survive.
  withTempDir("repo%20literal%x", (dir) => assertAllPassed(runDemo(stageCopy(dir))));
});

test("demo derives its root with fileURLToPath, not URL.pathname (Windows-compatible)", (t) => {
  const src = readFileSync(DEMO, "utf8");
  assert.match(src, /fileURLToPath\(new URL\("\.", import\.meta\.url\)\)/);
  assert.doesNotMatch(src, /import\.meta\.url\)\.pathname/);
  // The same conversion on a Windows file URL: drive letter, backslashes, decoding.
  const probe = (() => {
    try { return fileURLToPath("file:///C:/x", { windows: true }); } catch { return undefined; }
  })();
  if (process.platform !== "win32" && probe !== "C:\\x") {
    t.skip("this Node.js version has no fileURLToPath({ windows }) option");
    return;
  }
  const url = new URL(".", "file:///C:/Users/dev/repo%20with%20space/o%25x/demo.mjs");
  assert.equal(fileURLToPath(url, { windows: true }), "C:\\Users\\dev\\repo with space\\o%x\\");
});

test("demo exits nonzero when a bypass unexpectedly executes", () => {
  withTempDir("negative-bypass", (dir) => {
    const file = stageCopy(dir, (s) => replaceOnce(s,
      'post(upstreamPort, "/charge", ACTION.params)',
      'post(gatewayPort, "/execute", { action: ACTION, authorization: makeAuthorization({ action: ACTION, authId: "negative-bypass", audience: AUDIENCE }) })'));
    const r = runDemo(file);
    assert.equal(r.status, 1, r.out);
    assert.match(r.out, /^BYPASS\s+FAIL/m);
    assert.match(r.out, /FAILED: 1 scenario\(s\) failed, total side effects 2 \(expected 1\)/);
  });
});

test("demo exits nonzero when a not-covered action unexpectedly executes", () => {
  withTempDir("negative-not-covered", (dir) => {
    const file = stageCopy(dir, (s) => replaceOnce(s,
      "post(gatewayPort, \"/execute\", { action: altered, authorization:",
      "post(gatewayPort, \"/execute\", { action: ACTION, authorization:"));
    const r = runDemo(file);
    assert.equal(r.status, 1, r.out);
    assert.match(r.out, /^NOT_COVERED\s+FAIL/m);
  });
});
