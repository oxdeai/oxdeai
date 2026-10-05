// SPDX-License-Identifier: Apache-2.0
// #344: `pnpm pack` ships whatever `dist/` holds after `prepack`. dist/ is
// gitignored, so a leftover file is invisible to every clean-worktree check and
// still enters the tarball. Each publishable package's prepack (the lifecycle
// `pnpm pack` runs) must therefore rebuild from source into an empty dist/.
// Real subprocesses, real package builds; touches only gitignored build output.
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { discoverPublishablePackages } from "../verify-packed-artifacts.mjs";
import { ROOT } from "./orchestrator.mjs";

const PROBE = ".oxdeai-stale-build-output-probe.js";

function run(args, cwd) {
  const result = spawnSync("pnpm", args, { cwd, encoding: "utf8" });
  assert.ifError(result.error);
  assert.equal(result.status, 0, `pnpm ${args.join(" ")}\n${result.stdout}${result.stderr}`);
}

for (const pkg of discoverPublishablePackages()) {
  test(`${pkg.name}: prepack runs a build that discards stale dist/ output`, () => {
    assert.match(pkg.manifest.scripts?.prepack ?? "", /(^|&& )pnpm build$/, "prepack must rebuild from source");
    // The package compiles against its workspace dependencies' dist/; build
    // them first so the result does not depend on test order or earlier builds.
    run(["--filter", `${pkg.name}^...`, "build"], ROOT);
    const dist = path.join(pkg.dir, "dist");
    mkdirSync(dist, { recursive: true });
    const probe = path.join(dist, PROBE);
    writeFileSync(probe, "// left over from an earlier build; must never be packed\n");
    run(["run", "prepack"], pkg.dir);
    assert.equal(existsSync(probe), false, `stale ${path.relative(pkg.dir, probe)} survived prepack and would be packed`);
    const entry = pkg.manifest.main ?? Object.values(pkg.manifest.bin ?? {})[0];
    assert.ok(entry, "package declares neither main nor bin");
    assert.equal(existsSync(path.join(pkg.dir, entry)), true, `build output ${entry} missing`);
  });
}
