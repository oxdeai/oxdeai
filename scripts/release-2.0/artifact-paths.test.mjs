// SPDX-License-Identifier: Apache-2.0
// Hermetic paths/pack subprocess fixtures; never runs pnpm or touches release evidence.
import test, { mock } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { POLICY, packPublishablePackages, installNpmConsumer } from "../verify-packed-artifacts.mjs";
import { manifestTarball, packWithoutOverwrite } from "./artifact-paths.mjs";
import { persistFixturePrecheck, fixturePackages } from "./precheck-fixture.mjs";
import { pack, defaultPackTransport, requireOriginalTarballs, MANIFEST_FILENAME } from "./orchestrator.mjs";

function fixture(t) {
  const base = fs.mkdtempSync(path.join(tmpdir(), "oxdeai-paths-"));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const discovered = Object.entries(POLICY).map(([name, p]) => ({ name, dir: `/fake/${name.slice(8)}`,
    manifest: { name, version: p.version } }));
  const calls = [];
  const packTransport = { packToDir(d, dest) {
    calls.push(dest); assert.ok(path.isAbsolute(dest));
    const file = path.join(dest, `${d.name.slice(8)}.tgz`);
    fs.writeFileSync(file, d.name); return file;
  } };
  const releaseDir = path.join(base, "release");
  return { base, discovered, calls, releaseDir, packTransport };
}
function prepare(f, releaseDir = f.releaseDir) {
  persistFixturePrecheck(f.discovered, releaseDir);
  return { discovered: f.discovered, releaseDir, sourceRevision: "a".repeat(40),
    sourceTransport: { snapshot: () => ({ root: "/fake", revision: "a".repeat(40), clean: true }) },
    packageTransport: fixturePackages, packTransport: f.packTransport };
}
for (const relative of [false, true]) {
  test(`${relative ? "relative" : "absolute"} release directory produces absolute pack destinations and contained manifest paths`, t => {
    const f = fixture(t);
    const input = relative ? path.relative(process.cwd(), f.releaseDir) : f.releaseDir;
    const result = pack(prepare(f, input));
    assert.equal(result.manifest.precheck.releaseDir, f.releaseDir);
    assert.ok(f.calls.slice(2).every(dir => path.dirname(dir) === path.join(f.releaseDir, "tarballs")));
    assert.equal(result.manifest.packages.length, 10);
    for (const p of result.manifest.packages) {
      assert.ok(p.tarball.startsWith("tarballs/"));
      assert.ok(!path.isAbsolute(p.tarball) && !p.tarball.split("/").includes(".."));
      assert.equal(manifestTarball(input, p.tarball), path.join(f.releaseDir, p.tarball));
    }
    requireOriginalTarballs(input, result.manifest);
  });
}

for (const mode of ["absolute escape", "relative traversal", "archive symlink"]) {
  test(`PACK refuses ${mode} from injected output before freezing a manifest`, t => {
    const f = fixture(t), args = prepare(f);
    const outside = path.join(f.base, "outside.tgz"); fs.writeFileSync(outside, "unchanged");
    const original = args.packTransport.packToDir;
    let calls = 0;
    args.packTransport = { packToDir(d, dest) {
      if (++calls <= 2) return original(d, dest);
      if (mode === "absolute escape") return outside;
      if (mode === "relative traversal") return "../outside.tgz";
      const linked = path.join(dest, "linked.tgz"); fs.symlinkSync(outside, linked); return linked;
    } };
    assert.throws(() => pack(args), { code: "UNSAFE_TARBALL_PATH" });
    assert.equal(fs.existsSync(path.join(f.releaseDir, MANIFEST_FILENAME)), false);
    assert.equal(fs.readFileSync(outside, "utf8"), "unchanged");
  });
}

test("linked release directory and linked tarballs directory fail before any pack effect", t => {
  const f = fixture(t);
  fs.mkdirSync(path.join(f.base, "outside"));
  fs.symlinkSync(path.join(f.base, "outside"), f.releaseDir);
  assert.throws(() => prepare(f), { code: "UNSAFE_TARBALL_PATH" });
  fs.unlinkSync(f.releaseDir);
  const args = prepare(f);
  fs.symlinkSync(path.join(f.base, "missing-target"), path.join(f.releaseDir, "tarballs"));
  assert.throws(() => pack(args), { code: "UNSAFE_TARBALL_PATH" });
  assert.deepEqual(f.calls, []);
});

for (const output of ["../escape.tgz", "/tmp/escape.tgz", "tarballs/../escape.tgz", "tarballs/nested/../../escape.tgz"]) {
  test(`manifest path ${output} cannot be consumed`, t => {
    const f = fixture(t);
    assert.throws(() => manifestTarball(f.releaseDir, output), { code: "UNSAFE_TARBALL_PATH" });
  });
}

test("symlink archive and nested directory cannot bypass manifest containment", t => {
  const f = fixture(t), result = pack(prepare(f)), p = result.manifest.packages[0];
  const archive = path.join(f.releaseDir, p.tarball), outside = path.join(f.base, "outside.tgz");
  fs.renameSync(archive, outside); fs.symlinkSync(outside, archive);
  assert.throws(() => requireOriginalTarballs(f.releaseDir, result.manifest), { code: "UNSAFE_TARBALL_PATH" });
  fs.symlinkSync(f.base, path.join(f.releaseDir, "tarballs", "nested"));
  assert.throws(() => manifestTarball(f.releaseDir, "tarballs/nested/outside.tgz"), { code: "UNSAFE_TARBALL_PATH" });
});

function mockedPack(t, respond) {
  mock.method(childProcess, "spawnSync", respond); syncBuiltinESMExports();
  t.after(() => { mock.restoreAll(); syncBuiltinESMExports(); });
}
for (const standalone of [false, true]) {
  test(`${standalone ? "consumer gate" : "orchestrator"} pnpm pack receives an absolute destination despite package cwd`, t => {
    const f = fixture(t), dest = path.join(f.base, "tarballs"); fs.mkdirSync(dest);
    const pkg = { name: "@oxdeai/core", dir: path.join(f.base, "package") };
    mockedPack(t, (exe, args, opts) => {
      assert.equal(exe, "pnpm"); assert.equal(path.dirname(args[2]), dest); assert.equal(opts.cwd, pkg.dir);
      fs.writeFileSync(path.join(args[2], "core.tgz"), "bytes");
      return { status: 0, stdout: "core.tgz\n" };
    });
    const relative = path.relative(process.cwd(), dest);
    const actual = standalone ? packPublishablePackages([pkg], relative)[0].tarballPath : defaultPackTransport().packToDir(pkg, relative);
    assert.equal(actual, path.join(dest, "core.tgz"));
  });
}

test("pnpm output escape is rejected and preexisting linked output blocks spawning", t => {
  const f = fixture(t), dest = path.join(f.base,"tarballs"); fs.mkdirSync(dest);
  const outside = path.join(f.base,"outside.tgz"); fs.writeFileSync(outside,"unchanged");
  let calls = 0;
  mockedPack(t, () => { calls++; return {status:0,stdout:outside}; });
  assert.throws(() => defaultPackTransport().packToDir({name:"core",dir:f.base},dest), {code:"UNSAFE_TARBALL_PATH"});
  fs.symlinkSync(outside,path.join(dest,"core.tgz"));
  assert.throws(() => defaultPackTransport().packToDir({name:"core",dir:f.base},dest), {code:"UNSAFE_TARBALL_PATH"});
  assert.equal(calls,1); assert.equal(fs.readFileSync(outside,"utf8"),"unchanged");
});

test("npm consumer receives absolute archive paths and cwd from relative inputs", t => {
  const f = fixture(t), consumer = path.join(f.base,"consumer"), archive = path.join(f.base,"core.tgz");
  mockedPack(t, (exe,args,opts) => {
    assert.equal(exe,"npm"); assert.equal(opts.cwd,consumer); assert.equal(args.at(-1),archive);
    return {status:0,stdout:""};
  });
  installNpmConsumer(path.relative(process.cwd(),consumer),[{name:"core",tarballPath:path.relative(process.cwd(),archive)}]);
});

test("archive modification still fails integrity after normalization", t => {
  const f=fixture(t), result=pack(prepare(f));
  fs.appendFileSync(path.join(f.releaseDir,result.manifest.packages[0].tarball),"changed");
  assert.throws(()=>requireOriginalTarballs(path.relative(process.cwd(),f.releaseDir),result.manifest),/local tarball integrity/);
});


for (const tarball of ["../absent.tgz", "tarballs/../absent.tgz", "/absent-outside.tgz"]) {
  test(`requireOriginalTarballs validates ${tarball} before any existence query`, t => {
    const f = fixture(t);
    mock.method(fs, "existsSync", () => assert.fail("existence queried before validation"));
    mock.method(fs, "lstatSync", () => assert.fail("filesystem queried before lexical validation"));
    mock.method(fs, "readFileSync", () => assert.fail("archive read before validation"));
    t.after(() => mock.restoreAll());
    assert.throws(() => requireOriginalTarballs(f.releaseDir, { packages: [{package:"core",tarball}] }),
      {code:"UNSAFE_TARBALL_PATH"});
    mock.restoreAll();
  });
}

test("valid but missing archive retains an explicit no-regeneration diagnostic", t => {
  const f = fixture(t);
  assert.throws(() => requireOriginalTarballs(f.releaseDir, {packages:[{package:"core",tarball:"tarballs/missing.tgz"}]}),
    e => /original release tarball missing.*core/.test(e.message) && /Regeneration is forbidden/.test(e.message) && e.cause.code === "ENOENT");
});

for (const standalone of [false,true]) {
  test(`${standalone ? "consumer" : "orchestrator"} packaging preserves preexisting archive bytes and inode on collision`, t => {
    const f=fixture(t), dest=path.join(f.base,"retained"); fs.mkdirSync(dest);
    const existing=path.join(dest,"core.tgz"); fs.writeFileSync(existing,"original");
    const inode=fs.statSync(existing).ino;
    mockedPack(t, (_exe,args) => {
      assert.notEqual(args[2],dest); assert.equal(path.dirname(args[2]),dest);
      assert.deepEqual(fs.readdirSync(args[2]),[]);
      fs.writeFileSync(path.join(args[2],"core.tgz"),"replacement");
      return {status:0,stdout:"core.tgz"};
    });
    const pkg={name:"core",dir:f.base};
    assert.throws(()=> standalone ? packPublishablePackages([pkg],dest) : defaultPackTransport().packToDir(pkg,dest),
      {code:"ARTIFACT_ALREADY_EXISTS"});
    assert.equal(fs.readFileSync(existing,"utf8"),"original");
    assert.equal(fs.statSync(existing).ino,inode);
    assert.deepEqual(fs.readdirSync(dest),["core.tgz"]);
  });
}

test("duplicate output across packages fails without rewriting the first retained archive", t => {
  const f=fixture(t), args=prepare(f);
  let count=0;
  args.packTransport={packToDir(_pkg,dest){const file=path.join(dest,"same.tgz");fs.writeFileSync(file,String(++count));return file;}};
  assert.throws(()=>pack(args),{code:"ARTIFACT_ALREADY_EXISTS"});
  assert.equal(fs.readFileSync(path.join(f.releaseDir,"tarballs/same.tgz"),"utf8"),"3");
  assert.equal(fs.existsSync(path.join(f.releaseDir,MANIFEST_FILENAME)),false);
});

test("an archive created after staging begins is still never replaced", t => {
  const f=fixture(t), dest=path.join(f.base,"race");
  assert.throws(()=>packWithoutOverwrite(dest, staging=>{
    fs.writeFileSync(path.join(dest,"core.tgz"),"retained");
    const file=path.join(staging,"core.tgz");fs.writeFileSync(file,"new");return file;
  }),{code:"ARTIFACT_ALREADY_EXISTS"});
  assert.equal(fs.readFileSync(path.join(dest,"core.tgz"),"utf8"),"retained");
});
