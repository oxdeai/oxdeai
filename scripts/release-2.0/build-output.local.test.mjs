// SPDX-License-Identifier: Apache-2.0
// #344: `pnpm pack` ships whatever `dist/` holds after `prepack`. dist/ is
// gitignored, so a leftover file is invisible to every clean-worktree check and
// still enters the tarball. Each publishable package's own build (which prepack
// runs) must therefore start from an empty dist/. Real subprocesses, real
// package builds; touches only gitignored build output.
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { discoverPublishablePackages } from "../verify-packed-artifacts.mjs";

const PROBE = ".oxdeai-stale-build-output-probe.js";

for (const pkg of discoverPublishablePackages()) {
  test(`${pkg.name}: prepack runs a build that discards stale dist/ output`, () => {
    assert.equal(pkg.manifest.scripts?.prepack, "pnpm build", "prepack must rebuild from source");
    const dist = path.join(pkg.dir, "dist");
    mkdirSync(dist, { recursive: true });
    const probe = path.join(dist, PROBE);
    writeFileSync(probe, "// left over from an earlier build; must never be packed\n");
    const build = spawnSync("pnpm", ["run", "build"], { cwd: pkg.dir, encoding: "utf8" });
    assert.ifError(build.error);
    assert.equal(build.status, 0, build.stdout + build.stderr);
    assert.equal(existsSync(probe), false, `stale ${path.relative(pkg.dir, probe)} survived the build and would be packed`);
    const entry = pkg.manifest.main ?? Object.values(pkg.manifest.bin ?? {})[0];
    assert.ok(entry, "package declares neither main nor bin");
    assert.equal(existsSync(path.join(pkg.dir, entry)), true, `build output ${entry} missing`);
  });
}
