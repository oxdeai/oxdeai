// SPDX-License-Identifier: Apache-2.0
// Real local consumer verification: builds, packs and installs only.
// No publishing/promotion transport or publication subprocess is used.
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, symlinkSync, unlinkSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { discoverPublishablePackages } from "../verify-packed-artifacts.mjs";
import { RELEASE_REGISTRY_REQUIREMENTS } from "./auth-precheck.mjs";
import { ROOT, STATE_FILENAME, gitSourceTransport, precheck, pack, verifyLocal, loadState, loadAndValidateManifest, evaluateReleaseReadiness, requireOriginalTarballs, defaultPackTransport } from "./orchestrator.mjs";

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
    const releaseDir = path.relative(ROOT, path.join(base, "release"));
    precheck({ discovered, releaseDir, sourceRevision: revision, sourceTransport, gitTransport: { isClean: () => sourceTransport.snapshot().clean } });
    const { manifest, state } = pack({ discovered, releaseDir, sourceRevision: revision, sourceTransport });
    const result = verifyLocal({ discovered, manifest, state, releaseDir, baseDir: path.relative(ROOT, path.join(base, "consumer-checks")) });
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

    // The real relative-path lifecycle must retain confined original bytes.
    for (const p of manifest.packages) {
      assert.ok(p.tarball.startsWith("tarballs/"));
      assert.ok(!path.isAbsolute(p.tarball) && !p.tarball.split("/").includes(".."));
    }
    const first = manifest.packages[0], archive = path.resolve(releaseDir, first.tarball);
    const original = readFileSync(archive), outside = path.join(base, "outside.tgz");
    const inode = statSync(archive).ino;
    const sourcePackage = discovered.find(d => d.name === first.package);
    assert.throws(() => defaultPackTransport().packToDir(sourcePackage, path.dirname(archive)),
      { code: "ARTIFACT_ALREADY_EXISTS" });
    assert.deepEqual(readFileSync(archive), original, "real packaging cannot overwrite a retained archive");
    assert.equal(statSync(archive).ino, inode);

    writeFileSync(outside, original);
    for (const tarball of ["../outside.tgz", outside]) {
      assert.throws(() => requireOriginalTarballs(releaseDir, { packages: [{ ...first, tarball }] }),
        { code: "UNSAFE_TARBALL_PATH" });
    }
    unlinkSync(archive); symlinkSync(outside, archive);
    assert.throws(() => requireOriginalTarballs(releaseDir, manifest), { code: "UNSAFE_TARBALL_PATH" });
    unlinkSync(archive); writeFileSync(archive, original);
    writeFileSync(archive, Buffer.concat([original, Buffer.from("tampered")]));
    assert.throws(() => verifyLocal({ discovered, manifest, state: { ...saved, phase: "PACKED" }, releaseDir }), /local tarball integrity/);
    writeFileSync(archive, original);
    requireOriginalTarballs(releaseDir, manifest);
    assert.deepEqual(loadState(releaseDir), saved, "negative paths and integrity checks cannot advance persisted state");


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
