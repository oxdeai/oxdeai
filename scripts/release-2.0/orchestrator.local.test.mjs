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
import { RELEASE_REGISTRY_REQUIREMENTS } from "./auth-precheck.mjs";
import { ROOT, STATE_FILENAME, gitSourceTransport, precheck, pack, verifyLocal, loadState, loadAndValidateManifest, evaluateReleaseReadiness } from "./orchestrator.mjs";

test("real PRECHECK -> PACK -> VERIFY_LOCAL -> readiness; failed artifact scan cannot persist verification", (t) => {
  const base = mkdtempSync(path.join(tmpdir(), "oxdeai-local-persistence-"));
  try {
    const discovered = discoverPublishablePackages();
    // PACK observes this real checkout; it records an identity only for a clean
    // checkout at exactly the revision it is given (#344).
    const sourceTransport = gitSourceTransport(ROOT);
    const { revision, clean } = sourceTransport.snapshot();
    if (!clean) {
      assert.throws(
        () => pack({ discovered, releaseDir: path.join(base, "dirty"), sourceRevision: revision, sourceTransport }),
        /PACK source.*not clean/,
      );
      t.skip("checkout has uncommitted changes: verified that PACK refuses it; real artifact verification needs a clean checkout");
      return;
    }
    const build = spawnSync("pnpm", [...discovered.flatMap(({ name }) => ["--filter", `${name}...`]), "build"], {
      cwd: ROOT, encoding: "utf8",
    });
    assert.ifError(build.error);
    assert.equal(build.status, 0, build.stdout + build.stderr);
    const releaseDir = path.join(base, "release");
    precheck({ discovered, releaseDir, sourceRevision: revision, sourceTransport, gitTransport: { isClean: () => sourceTransport.snapshot().clean } });
    const { manifest, state } = pack({ discovered, releaseDir, sourceRevision: revision, sourceTransport });
    const result = verifyLocal({ discovered, manifest, state, releaseDir, baseDir: path.join(base, "consumer-checks") });
    assert.equal(result.phase, "VERIFIED_LOCAL");
    const saved = loadState(releaseDir);
    assert.equal(saved.phase, "VERIFIED_LOCAL");
    assert.deepEqual(saved, result);
    assert.equal(saved.history.at(-1).phase, "VERIFIED_LOCAL");
    const registry = RELEASE_REGISTRY_REQUIREMENTS.registry;
    const authPrecheck = { blockers: [], observations: {
      identity: { kind: "identity", registry, username: "maintainer" },
      access: { kind: "access", registry, subject: "maintainer", packages: Object.fromEntries(discovered.map(d => [d.name, "read-write"])) },
      packages: discovered.map(d => ({ kind: "existing", registry, packageName: d.name, visibility: "public" })),
    } };
    assert.equal(evaluateReleaseReadiness({ manifest: loadAndValidateManifest(releaseDir), state: saved, authPrecheck }).kind, "ready");

    // Matching SRI alone is insufficient: invalid archive bytes must fail the
    // real artifact verifier without recording a successful local verification.
    const badDir = path.join(base, "invalid-release");
    precheck({ discovered, releaseDir: badDir, sourceRevision: revision, sourceTransport, gitTransport: { isClean: () => sourceTransport.snapshot().clean } });
    const bad = pack({
      discovered, releaseDir: badDir, sourceRevision: revision, sourceTransport,
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
