// SPDX-License-Identifier: Apache-2.0
// Atomic JSON persistence of release evidence. Hermetic: temporary
// directories, injected or mocked node:fs failures, fake transports only.
// No npm, subprocess, network or registry effect.
import test, { mock } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { POLICY } from "../verify-packed-artifacts.mjs";
import { persistFixturePrecheck, fixturePackages } from "./precheck-fixture.mjs";
import {
  MANIFEST_FILENAME, MANIFEST_VERSION, STATE_FILENAME, STATE_VERSION, PersistenceError,
  loadAndValidateManifest, loadState, loadValidatedState, pack, saveState, validateState,
  verifyLocal, verifyRegistry, writeJsonAtomic,
} from "./orchestrator.mjs";

const SHA = "a".repeat(40);
const json = (v) => `${JSON.stringify(v, null, 2)}\n`;
const leftovers = (dir) => fs.readdirSync(dir).filter((name) => name.endsWith(".tmp"));

function dir(t) {
  const d = fs.mkdtempSync(path.join(tmpdir(), "oxdeai-atomic-"));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
}

// A real PRECHECK -> fixture PACK (no pnpm): writes manifest and state through
// the production persistence path.
function packed(t) {
  const releaseDir = dir(t);
  const discovered = Object.entries(POLICY).map(([name, p]) => ({ name, dir: `/fake/${name.slice(8)}`,
    manifest: { name, version: p.version, ...(name === "@oxdeai/core" ? {} : { dependencies: { "@oxdeai/core": "workspace:*" } }) } }));
  persistFixturePrecheck(discovered, releaseDir);
  const result = pack({
    discovered, releaseDir, sourceRevision: SHA, packageTransport: fixturePackages,
    sourceTransport: { snapshot: () => ({ root: "/fake", revision: SHA, clean: true }) },
    packTransport: { packToDir(d, out) { const f = path.join(out, `${d.name.slice(8)}.tgz`); fs.writeFileSync(f, d.name); return f; } },
    now: () => "2026-10-20T00:00:00.000Z",
  });
  return { releaseDir, discovered, ...result };
}

// node:fs wrapper that fails one named operation (optionally on its nth call).
function faultyIo({ op, nth = 1, error = Object.assign(new Error(`injected ${op} failure`), { code: "EIO" }), before } = {}) {
  let calls = 0;
  return new Proxy(fs, { get(target, key) {
    if (key !== op) return target[key];
    return (...args) => {
      if (++calls === nth) { before?.(...args); throw error; }
      return target[key](...args);
    };
  } });
}

test("normal write and reread of manifest and state through PACK", (t) => {
  const f = packed(t);
  const manifestBytes = fs.readFileSync(path.join(f.releaseDir, MANIFEST_FILENAME), "utf8");
  const stateBytes = fs.readFileSync(path.join(f.releaseDir, STATE_FILENAME), "utf8");
  assert.equal(manifestBytes, json(f.manifest), "JSON format unchanged");
  assert.equal(stateBytes, json(f.state));
  assert.deepEqual(loadAndValidateManifest(f.releaseDir), f.manifest);
  assert.equal(f.manifest.manifestVersion, MANIFEST_VERSION);
  assert.equal(loadValidatedState(f.releaseDir, f.manifest).stateVersion, STATE_VERSION);
  assert.deepEqual(leftovers(f.releaseDir), []);
});

test("existing state is replaced atomically by rename, never rewritten in place", (t) => {
  const f = packed(t), file = path.join(f.releaseDir, STATE_FILENAME);
  const before = fs.statSync(file).ino;
  const renames = [];
  const io = new Proxy(fs, { get: (target, key) => key === "renameSync"
    ? (from, to) => { renames.push([path.dirname(from), to]); return target.renameSync(from, to); } : target[key] });
  const next = { ...f.state, updatedAt: "2026-10-21T00:00:00.000Z" };
  writeJsonAtomic(file, next, io);
  assert.deepEqual(renames, [[f.releaseDir, file]], "temporary file lives in the destination directory");
  assert.notEqual(fs.statSync(file).ino, before, "a new inode was installed");
  assert.deepEqual(loadState(f.releaseDir), next);
  assert.deepEqual(leftovers(f.releaseDir), []);
});

for (const [label, fault] of [
  ["temporary open", { op: "openSync" }],
  ["first write", { op: "writeSync" }],
  ["write after a partial chunk", { op: "writeSync", nth: 2 }],
  ["temporary fsync", { op: "fsyncSync" }],
  ["temporary close", { op: "closeSync" }],
  ["rename", { op: "renameSync" }],
]) {
  test(`failure during ${label}: previous state intact and readable, no temporary file left`, (t) => {
    const f = packed(t), file = path.join(f.releaseDir, STATE_FILENAME);
    const original = fs.readFileSync(file);
    // Force several writeSync calls so the second one fails after partial output.
    let io = faultyIo(fault);
    if (fault.op === "writeSync") {
      const inner = io;
      io = new Proxy(fs, { get: (target, key) => key === "writeSync"
        ? (fd, buf, off, len) => inner.writeSync(fd, buf, off, Math.min(len, 64)) : target[key] });
    }
    const next = { ...f.state, phase: "VERIFIED_LOCAL", updatedAt: "changed" };
    assert.throws(() => writeJsonAtomic(file, next, io), (e) => e instanceof PersistenceError &&
      e.code === "PERSISTENCE_FAILED" && e.renamed === false && e.cause?.message?.startsWith("injected"));
    assert.deepEqual(fs.readFileSync(file), original);
    assert.equal(loadValidatedState(f.releaseDir, f.manifest).phase, "PACKED");
    assert.deepEqual(leftovers(f.releaseDir), []);
  });
}

test("a zero-byte write is treated as a failure, not an infinite loop or truncated file", (t) => {
  const f = packed(t), file = path.join(f.releaseDir, STATE_FILENAME), original = fs.readFileSync(file);
  const io = new Proxy(fs, { get: (target, key) => key === "writeSync" ? () => 0 : target[key] });
  assert.throws(() => writeJsonAtomic(file, { x: 1 }, io), { code: "PERSISTENCE_FAILED", stage: "write" });
  assert.deepEqual(fs.readFileSync(file), original);
  assert.deepEqual(leftovers(f.releaseDir), []);
});

test("cleanup failure is reported, not masked, and never touches the destination", (t) => {
  const f = packed(t), file = path.join(f.releaseDir, STATE_FILENAME), original = fs.readFileSync(file);
  const unlinked = [];
  const io = new Proxy(fs, { get: (target, key) => {
    if (key === "renameSync") return () => { throw Object.assign(new Error("injected rename failure"), { code: "EXDEV" }); };
    if (key === "unlinkSync") return (p) => { unlinked.push(p); throw Object.assign(new Error("injected unlink failure"), { code: "EACCES" }); };
    return target[key];
  } });
  assert.throws(() => writeJsonAtomic(file, { x: 1 }, io), (e) => e.stage === "rename" && e.cleanupError?.code === "EACCES");
  assert.equal(unlinked.length, 1);
  assert.notEqual(unlinked[0], file, "the destination is never a cleanup target");
  assert.deepEqual(fs.readFileSync(file), original);
  for (const name of leftovers(f.releaseDir)) fs.unlinkSync(path.join(f.releaseDir, name)); // test hygiene only
});

test("directory fsync failure after rename is surfaced; the new content may be installed", { skip: process.platform === "win32" }, (t) => {
  const f = packed(t), file = path.join(f.releaseDir, STATE_FILENAME);
  const next = { ...f.state, updatedAt: "after-rename" };
  assert.throws(() => writeJsonAtomic(file, next, faultyIo({ op: "fsyncSync", nth: 2 })),
    (e) => e.code === "PERSISTENCE_FAILED" && e.stage === "directory-fsync" && e.renamed === true);
  assert.equal(loadState(f.releaseDir).updatedAt, "after-rename", "reload reveals the installed state");
  assert.deepEqual(leftovers(f.releaseDir), []);
});

for (const code of ["EIO", "EINVAL", "ENOTSUP", "EOPNOTSUPP"]) {
  test(`directory close failure (${code}) after rename abandons memory and permits validated recovery`, { skip: process.platform === "win32" }, (t) => {
    const f = packed(t), file = path.join(f.releaseDir, STATE_FILENAME);
    const error = Object.assign(new Error("injected directory close failure"), { code });
    const close = fs.closeSync;
    let closes = 0;
    t.after(() => mock.restoreAll());
    mock.method(fs, "closeSync", (fd) => {
      close(fd); // Release the real descriptor even when simulating a close error.
      if (++closes === 2) throw error; // Temporary file closes first, directory second.
    });
    const updatedAt = "2026-10-21T00:00:00.000Z";
    assert.throws(() => saveState(f.releaseDir, f.state, { now: () => updatedAt }),
      (e) => e instanceof PersistenceError && e.code === "PERSISTENCE_FAILED" &&
        e.stage === "directory-close" && e.renamed === true && e.cause === error);
    mock.restoreAll();
    const installed = { ...f.state, updatedAt };
    assert.deepEqual(loadState(f.releaseDir), installed, "the renamed destination is neither removed nor restored");
    assert.deepEqual(leftovers(f.releaseDir), []);
    assert.throws(() => validateState(f.manifest, f.state), /abandoned after a persistence failure/);
    assert.throws(() => saveState(f.releaseDir, f.state), { code: "STATE_ABANDONED" });
    assert.deepEqual(loadState(f.releaseDir), installed, "abandoned memory cannot overwrite the destination");
    const reloaded = loadValidatedState(f.releaseDir, f.manifest);
    assert.notEqual(reloaded, f.state);
    assert.deepEqual(reloaded, installed);
    saveState(f.releaseDir, reloaded, { now: () => "2026-10-22T00:00:00.000Z" });
    assert.equal(loadValidatedState(f.releaseDir, f.manifest).updatedAt, "2026-10-22T00:00:00.000Z");
  });
}

for (const code of ["EINVAL", "ENOTSUP"]) {
  test(`directory fsync unsupported by the filesystem (${code}) is tolerated`, { skip: process.platform === "win32" }, (t) => {
    const f = packed(t), file = path.join(f.releaseDir, STATE_FILENAME);
    const error = Object.assign(new Error("unsupported"), { code });
    writeJsonAtomic(file, { ...f.state, updatedAt: "ok" }, faultyIo({ op: "fsyncSync", nth: 2, error }));
    assert.equal(loadState(f.releaseDir).updatedAt, "ok");
  });
}

test("persistence failure abandons the in-memory state until a validated reload", (t) => {
  const f = packed(t);
  const original = fs.readFileSync(path.join(f.releaseDir, STATE_FILENAME));
  t.after(() => mock.restoreAll());
  mock.method(fs, "renameSync", () => { throw Object.assign(new Error("injected rename failure"), { code: "EIO" }); });
  f.state.updatedAt = "in-memory only";
  assert.throws(() => saveState(f.releaseDir, f.state), { code: "PERSISTENCE_FAILED", stage: "rename" });
  mock.restoreAll();
  assert.deepEqual(fs.readFileSync(path.join(f.releaseDir, STATE_FILENAME)), original);
  assert.deepEqual(leftovers(f.releaseDir), []);
  // The in-memory object is unusable by every phase entry point and by saveState.
  assert.throws(() => validateState(f.manifest, f.state), /abandoned after a persistence failure/);
  const forbidden = new Proxy({}, { get() { assert.fail("transport consulted with abandoned state"); } });
  assert.throws(() => verifyRegistry({ ...f, registryTransport: forbidden }), /abandoned/);
  assert.throws(() => verifyLocal(f), /abandoned/);
  assert.throws(() => saveState(f.releaseDir, f.state), { code: "STATE_ABANDONED" }, "abandoned memory never reaches disk");
  assert.deepEqual(fs.readFileSync(path.join(f.releaseDir, STATE_FILENAME)), original);
  // Recovery: discard memory, reload and validate disk, then resume.
  const reloaded = loadValidatedState(f.releaseDir, f.manifest);
  assert.equal(reloaded.phase, "PACKED");
  assert.notEqual(reloaded.updatedAt, "in-memory only");
  saveState(f.releaseDir, reloaded, { now: () => "2026-10-21T00:00:00.000Z" });
  assert.equal(loadValidatedState(f.releaseDir, f.manifest).updatedAt, "2026-10-21T00:00:00.000Z");
});

test("PACK manifest persistence failure records no release identity and leaves no temporary file", (t) => {
  const releaseDir = dir(t);
  const discovered = Object.entries(POLICY).map(([name, p]) => ({ name, dir: `/fake/${name.slice(8)}`,
    manifest: { name, version: p.version, ...(name === "@oxdeai/core" ? {} : { dependencies: { "@oxdeai/core": "workspace:*" } }) } }));
  persistFixturePrecheck(discovered, releaseDir);
  mock.method(fs, "fsyncSync", () => { throw Object.assign(new Error("injected fsync failure"), { code: "EIO" }); });
  t.after(() => mock.restoreAll());
  assert.throws(() => pack({
    discovered, releaseDir, sourceRevision: SHA, packageTransport: fixturePackages,
    sourceTransport: { snapshot: () => ({ root: "/fake", revision: SHA, clean: true }) },
    packTransport: { packToDir(d, out) { const f = path.join(out, `${d.name.slice(8)}.tgz`); fs.writeFileSync(f, d.name); return f; } },
  }), { code: "PERSISTENCE_FAILED", stage: "fsync" });
  mock.restoreAll();
  assert.equal(fs.existsSync(path.join(releaseDir, MANIFEST_FILENAME)), false);
  assert.equal(fs.existsSync(path.join(releaseDir, STATE_FILENAME)), false);
  assert.deepEqual(leftovers(releaseDir), []);
});

test("persistence module adds no subprocess, registry or lock mechanism", () => {
  const source = fs.readFileSync(new URL("./orchestrator.mjs", import.meta.url), "utf8");
  const block = source.slice(source.indexOf("// ── Atomic JSON persistence"), source.indexOf("export function loadAndValidateManifest"));
  assert.doesNotMatch(block, /spawn|exec|npm|flock|lockfile|\.lock\b|fetch\(/);
});
