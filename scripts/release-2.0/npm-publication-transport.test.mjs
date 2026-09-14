// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import * as live from "./npm-publication-transport.mjs";
import { fixture, consent, invoke, publications } from "./publication-authorization.fixture.mjs";
import { fixturePlan } from "./publication-fixture.mjs";
import { computeManifestIntegrity, computeSriIntegrity, loadState, RegistryIntegrityConflictError } from "./orchestrator.mjs";

const malformed = [
  ["other executable", c => { c.executable = "sh"; }],
  ["shell string", c => { c.args = c.args.join(" "); }],
  ["unpublish", c => { c.args[0] = "unpublish"; }],
  ["dist-tag", c => { c.args[0] = "dist-tag"; }],
  ["owner", c => { c.args[0] = "owner"; }],
  ["access mutation", c => { c.args[0] = "access"; }],
  ["extra flag", c => { c.args.push("--force"); }],
  ["duplicate flag", c => { c.args.push("--tag", "next"); }],
  ["latest", c => { c.args[3] = "latest"; }],
  ["private", c => { c.args[5] = "restricted"; }],
  ["other registry", c => { c.args[7] = "https://other.invalid/"; }],
  ["other tarball", c => { c.args[1] = "/tmp/other.tgz"; }],
  ["extra command field", c => { c.shell = true; }],
  ["package substitution", c => { c.package = "@oxdeai/cli"; }],
];
for (const [label, mutate] of malformed) {
  test(`closed command validator rejects ${label} independently`, t => {
    const f = fixture(t), op = f.plan.operations[0], command = structuredClone(op.command);
    mutate(command);
    assert.throws(() => live.validateNpmPublicationCommand({ command, operation: op, releaseDir: f.releaseDir }), { code: "LIVE_PUBLICATION_TRANSPORT_INVALID" });
    assert.equal(f.calls.length, 0);
  });
}
for (const registry of ["http://registry.npmjs.org/", "https://other.invalid/", "https://registry.npmjs.org", "https://registry.npmjs.org.evil.invalid/"]) {
  test(`coordinated plan and consent cannot redirect registry: ${registry}`, t => {
    const f = fixture(t);
    f.plan.registry = registry; f.plan.evidence.requirements.registry = registry;
    for (const p of f.plan.operations) { p.registry = registry; p.command.args[7] = registry; }
    f.authorization = consent(f);
    assert.throws(() => invoke(f), { code: "LIVE_PUBLICATION_TRANSPORT_INVALID" });
    assert.equal(f.calls.length, 0);
  });
}
for (const mode of ["zero exit", "nonzero", "throw", "signal", "spawn error"]) {
  for (const after of ["matching", "missing", "unknown", "conflicting"]) {
    test(`${mode} publication reconciles ${after} without a second publish process`, t => {
      const f = fixture(t); let attempted = false;
      const p = f.plan.operations[0];
      f.respond = (_exe, args) => {
        if (args[0] === "publish") {
          attempted = true;
          if (mode === "throw") throw new Error("fixture secret that must not persist");
          return { status: mode === "zero exit" ? 0 : mode === "nonzero" ? 1 : null, signal: mode === "signal" ? "SIGTERM" : null,
            error: mode === "spawn error" ? new Error("fixture secret") : undefined,
            stdout: "fixture secret", stderr: "fixture secret" };
        }
        if (attempted && after === "unknown") return { status: 1, stdout: '{"error":{"code":"E404"}}' };
        if (args[2] === "versions") return { status: 0, stdout: JSON.stringify(attempted && after !== "missing" ? [p.version] : ["1.0.0"]) };
        return { status: 0, stdout: JSON.stringify(after === "conflicting" ? computeSriIntegrity("other bytes") : p.integrity) };
      };
      if (after === "unknown") assert.throws(() => invoke(f), { code: "REGISTRY_STATE_UNDETERMINED" });
      else if (after === "conflicting") assert.throws(() => invoke(f), RegistryIntegrityConflictError);
      else invoke(f);
      assert.equal(publications(f).length, 1);
      const observations = f.calls.filter(([, args]) => args[0] === "view");
      assert.equal(observations.filter(([, args]) => args[2] === "versions").length, 2);
      assert.ok(observations.every(([, args]) => [p.package, `${p.package}@${p.version}`].includes(args[1])));
      assert.equal(f.state.packages[p.package].publishStatus, after === "matching" ? "published" : "pending");
      assert.equal(f.state.phase, "PARTIAL_NEXT");
      assert.equal(Object.hasOwn(loadState(f.releaseDir), "blocker"), after !== "matching");
      if (after === "matching" || after === "conflicting") {
        assert.deepEqual(observations.at(-1)[1].slice(0, 3), ["view", `${p.package}@${p.version}`, "dist.integrity"]);
      }
      assert.doesNotMatch(JSON.stringify(loadState(f.releaseDir)), /fixture secret/);
    });
  }
}
for (const conflicting of [false, true]) {
  test(`already present version (conflicting=${conflicting}) never publishes`, t => {
    const f = fixture(t), p = f.plan.operations[0];
    f.respond = (_exe, args) => ({ status: 0, stdout: JSON.stringify(args[2] === "versions" ? [p.version] : conflicting ? computeSriIntegrity("wrong") : p.integrity) });
    if (conflicting) assert.throws(() => invoke(f), RegistryIntegrityConflictError); else invoke(f);
    assert.equal(publications(f).length, 0);
  });
}
for (const output of ["not JSON", "null", "[]", '"1.0.0"', '["bad"]', '["1.0.0","1.0.0"]']) {
  test(`unsupported version observation ${output} never permits publication`, t => {
    const f = fixture(t); f.respond = () => ({ status: 0, stdout: output });
    assert.throws(() => invoke(f), { code: "REGISTRY_STATE_UNDETERMINED" });
    assert.equal(publications(f).length, 0);
  });
}
for (const code of ["E403", "E404", "ETIMEDOUT", "E401"]) {
  test(`initial ${code} is unknown, never inferred absence`, t => {
    const f = fixture(t); f.respond = () => ({ status: 1, stdout: JSON.stringify({ error: { code } }) });
    assert.throws(() => invoke(f), { code: "REGISTRY_STATE_UNDETERMINED" });
    assert.equal(publications(f).length, 0);
  });
}
for (const tarball of ["../outside.tgz", "/absolute.tgz", "C:\\outside.tgz", "tarballs/../../outside.tgz"]) {
  test(`unsafe authorized path rejected: ${tarball}`, t => {
    const f = fixture(t);
    f.manifest.packages[0].tarball = tarball;
    f.manifest.manifestIntegrity = computeManifestIntegrity(f.manifest);
    f.plan.evidence.manifestIntegrity = f.manifest.manifestIntegrity;
    f.plan.operations[0].tarball = tarball; f.authorization = consent(f);
    assert.throws(() => invoke(f), { code: "LIVE_PUBLICATION_TRANSPORT_INVALID" });
    assert.equal(f.calls.length, 0);
  });
}
test("shell metacharacters in the bound filename remain literal argument data", t => {
  const f = fixture(t), p = f.manifest.packages[0], old = p.tarball;
  p.tarball = "tarballs/literal $(echo nope);`echo nope`.tgz";
  fs.renameSync(path.join(f.releaseDir, old), path.join(f.releaseDir, p.tarball));
  f.manifest.manifestIntegrity = computeManifestIntegrity(f.manifest);
  f.plan = fixturePlan(f.manifest, f.releaseDir); f.authorization = consent(f);
  invoke(f);
  const [[exe, args, opts]] = publications(f);
  assert.equal(exe, "npm"); assert.equal(opts.shell, false);
  assert.equal(args[1], path.join(f.releaseDir, p.tarball));
  assert.equal(args.length, 8);
});
test("isolated npm execution suppresses scripts, retries and logs without persisting credentials", t => {
  const f = fixture(t); invoke(f);
  for (const [exe, args, opts] of f.calls) {
    assert.equal(exe, "npm"); assert.equal(opts.shell, false);
    assert.deepEqual(opts.stdio, ["ignore", "pipe", "pipe"]);
    assert.equal(opts.env["npm_config_ignore-scripts"], "true");
    assert.equal(opts.env["npm_config_fetch-retries"], "0");
    assert.equal(opts.env["npm_config_logs-max"], "0");
    assert.equal(opts.env["npm_config_@oxdeai:registry"], "https://registry.npmjs.org/");
    assert.equal(opts.env.npm_config_cache, opts.cwd);
    assert.equal(fs.existsSync(opts.cwd), false);
    assert.ok(!args.some(arg => /token|password|otp/i.test(arg)));
  }
});
test("another explicit call reconciles first and does not republish an accepted version", t => {
  const f = fixture(t), p = f.plan.operations[0]; invoke(f);
  f.respond = (_exe, args) => ({ status: 0, stdout: JSON.stringify(args[2] === "versions" ? [p.version] : p.integrity) });
  invoke(f);
  assert.equal(publications(f).length, 1);
});
test("only the authorized wrapper exposes effects; no public transport factory or batch API", t => {
  const f = fixture(t);
  assert.deepEqual(Object.keys(live).sort(), ["publishAuthorizedOperation", "validateNpmPublicationCommand"]);
  const source = fs.readFileSync(new URL("./npm-publication-transport.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /shell:\s*true|\bexec(?:Sync)?\s*\(|npm unpublish|npm dist-tag/);
  assert.equal((source.match(/publishPlannedOperation\(/g) ?? []).length, 1);
  assert.equal((source.match(/spawnSync\(/g) ?? []).length, 1);
  invoke(f); assert.equal(publications(f).length, 1);
});


test("ambient npm_config_dry_run=true and zero exit cannot record a missing version as published", t => {
  const previous = process.env.npm_config_dry_run;
  process.env.npm_config_dry_run = "true";
  t.after(() => {
    if (previous === undefined) delete process.env.npm_config_dry_run;
    else process.env.npm_config_dry_run = previous;
  });
  const f = fixture(t), p = f.plan.operations[0];
  f.respond = (_exe, args, options) => {
    assert.equal(options.env.npm_config_dry_run, "true");
    return { status: 0, stdout: JSON.stringify(args[0] === "view" ? ["1.0.0"] : {}) };
  };
  invoke(f);
  assert.equal(publications(f).length, 1);
  assert.deepEqual(f.calls.map(([, args]) => args.slice(0, 3)), [
    ["view", p.package, "versions"], p.command.args.slice(0, 3), ["view", p.package, "versions"],
  ]);
  const saved = loadState(f.releaseDir);
  assert.equal(saved.phase, "PARTIAL_NEXT");
  assert.equal(saved.packages[p.package].publishStatus, "pending");
  assert.equal(saved.packages[p.package].registryIntegrity, undefined);
  assert.equal(saved.blocker.package, p.package);
  assert.equal(saved.blocker.code, "PUBLICATION_FAILED");
});
