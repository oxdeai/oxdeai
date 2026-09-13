// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { verifyPackedTarballs, installTypeScriptTooling, installNpmConsumer } from "./verify-packed-artifacts.mjs";

for (const [label, names] of [
  ["missing", ["@oxdeai/core"]],
  ["extra", ["@oxdeai/core", "@oxdeai/guard", "@oxdeai/extra"]],
  ["duplicate", ["@oxdeai/core", "@oxdeai/core"]],
]) {
  test(`packed bijection rejects ${label} before subprocess or filesystem work`, () => {
    const ds = ["@oxdeai/core", "@oxdeai/guard"].map((name) => ({ name }));
    assert.throws(() => verifyPackedTarballs(ds, names.map((name) => ({ name, tarballPath: "/nonexistent" }))), new RegExp(`bijection: ${label}`));
  });
}

for (const pm of ["npm", "pnpm"]) {
  test(`${pm} external TypeScript install arguments pin identical exact versions`, () => {
    const calls = [];
    installTypeScriptTooling("/consumer", pm, (data) => calls.push(data));
    assert.equal(calls.length, 1);
    assert.equal(calls[0].command, pm);
    assert.ok(calls[0].args.includes("--save-exact"));
    assert.deepEqual(calls[0].args.slice(-2), ["typescript@5.9.3", "@types/node@22.19.17"]);
  });
}

// H2 observation only: use the production npm install path, an empty cache,
// offline mode and local marker bytes. No registry or resolution overrides.
// Test both tarball orders and inspect the lockfile plus dependency resolution.
for (const reverse of [false, true]) {
  test(`H2 npm satisfies ^2.0.0 from co-supplied local tarballs (reverse=${reverse})`, () => {
    const base = mkdtempSync(path.join(tmpdir(), "oxdeai-h2-"));
    const saved = { ...process.env };
    try {
      process.env.npm_config_offline = "true";
      process.env.npm_config_cache = path.join(base, "empty-cache");
      const packed = [];
      for (const name of ["core", "guard"]) {
        const dir = path.join(base, name), pkgDir = path.join(dir, "package");
        mkdirSync(pkgDir, { recursive: true });
        writeFileSync(path.join(pkgDir, "package.json"), JSON.stringify({
          name: `@oxdeai/${name}`, version: "2.0.0", main: "index.cjs",
          ...(name === "guard" ? { dependencies: { "@oxdeai/core": "^2.0.0" } } : {}),
        }));
        writeFileSync(path.join(pkgDir, "index.cjs"), name === "core" ? 'module.exports = "H2-local-core-bytes";' : 'module.exports = require("@oxdeai/core");');
        const tarballPath = path.join(base, `${name}.tgz`);
        const tar = spawnSync("tar", ["-czf", tarballPath, "-C", dir, "package"], { encoding: "utf8" });
        assert.equal(tar.status, 0, tar.stderr);
        packed.push({ name: `@oxdeai/${name}`, tarballPath });
      }
      if (reverse) packed.reverse();
      const consumer = path.join(base, "consumer");
      installNpmConsumer(consumer, packed);
      const resolved = spawnSync(process.execPath, ["-e", 'if (require("@oxdeai/guard") !== "H2-local-core-bytes") process.exit(1)'], { cwd: consumer, encoding: "utf8" });
      assert.equal(resolved.status, 0, resolved.stderr);
      const lock = JSON.parse(readFileSync(path.join(consumer, "package-lock.json"), "utf8"));
      for (const name of ["core", "guard"]) {
        const entry = lock.packages[`node_modules/@oxdeai/${name}`];
        assert.equal(entry.version, "2.0.0");
        assert.match(entry.resolved, /^file:/);
      }
      assert.equal(lock.packages["node_modules/@oxdeai/guard"].dependencies["@oxdeai/core"], "^2.0.0");
      assert.equal(Object.keys(lock.packages).filter((key) => key.endsWith("node_modules/@oxdeai/core")).length, 1);
    } finally {
      process.env = saved;
      rmSync(base, { recursive: true, force: true });
    }
  });
}
