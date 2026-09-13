// SPDX-License-Identifier: Apache-2.0
// Real local consumer verification: builds, packs and installs only.
// No publishing/promotion transport or publication subprocess is used.
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { discoverPublishablePackages } from "../verify-packed-artifacts.mjs";
import { ROOT, STATE_FILENAME, pack, verifyLocal, loadState } from "./orchestrator.mjs";

test("verifyLocal persists VERIFIED_LOCAL after real artifact verification; failed artifact scan cannot persist it", () => {
  const base = mkdtempSync(path.join(tmpdir(), "oxdeai-local-persistence-"));
  try {
    const discovered = discoverPublishablePackages();
    const build = spawnSync("pnpm", [...discovered.flatMap(({ name }) => ["--filter", `${name}...`]), "build"], {
      cwd: ROOT, encoding: "utf8",
    });
    assert.ifError(build.error);
    assert.equal(build.status, 0, build.stdout + build.stderr);
    const releaseDir = path.join(base, "release");
    const { manifest, state } = pack({ discovered, releaseDir, sourceRevision: "a".repeat(40) });
    const result = verifyLocal({ discovered, manifest, state, releaseDir, baseDir: path.join(base, "consumer-checks") });
    assert.equal(result.phase, "VERIFIED_LOCAL");
    const saved = loadState(releaseDir);
    assert.equal(saved.phase, "VERIFIED_LOCAL");
    assert.deepEqual(saved, result);
    assert.equal(saved.history.at(-1).phase, "VERIFIED_LOCAL");

    // Matching SRI alone is insufficient: invalid archive bytes must fail the
    // real artifact verifier without recording a successful local verification.
    const badDir = path.join(base, "invalid-release");
    const bad = pack({
      discovered, releaseDir: badDir, sourceRevision: "b".repeat(40),
      packTransport: {
        packToDir(pkg, destDir) {
          // The fake archive is confined to this negative test; no subprocess.
          const file = path.join(destDir, `${pkg.name.replace("@oxdeai/", "")}.tgz`);
          writeFileSync(file, "invalid archive");
          return file;
        },
      },
    });
    const before = readFileSync(path.join(badDir, STATE_FILENAME));
    assert.throws(() => verifyLocal({ discovered, ...bad, releaseDir: badDir, baseDir: path.join(base, "bad-checks") }), /extract/);
    assert.deepEqual(readFileSync(path.join(badDir, STATE_FILENAME)), before);
    assert.equal(loadState(badDir).phase, "PACKED");
    assert.ok(!bad.state.history.some((entry) => entry.phase === "VERIFIED_LOCAL"));
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
