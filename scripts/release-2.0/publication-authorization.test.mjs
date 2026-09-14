// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { validatePublicationAuthorization } from "./publication-authorization.mjs";
import { fixture, consent, invoke, publications } from "./publication-authorization.fixture.mjs";
import { loadState, ReleaseOrchestratorError } from "./orchestrator.mjs";

for (const receipt of [undefined, null, false, [], "approve", {}]) {
  test(`authorization required and structurally valid: ${JSON.stringify(receipt)}`, t => {
    const f = fixture(t); f.authorization = receipt;
    const before = structuredClone(f.state);
    assert.throws(() => invoke(f), { code: receipt == null ? "PUBLICATION_AUTHORIZATION_REQUIRED" : "PUBLICATION_AUTHORIZATION_INVALID" });
    assert.equal(f.calls.length, 0); assert.deepEqual(f.state, before);
  });
}
for (const field of ["releaseId", "manifestIntegrity", "operationIndex", "package", "version", "tarball", "integrity", "registry", "tag", "access", "kind", "authorizationVersion"]) {
  for (const mode of ["changed", "missing"]) {
    test(`authorization ${field} ${mode} stops before process execution`, t => {
      const f = fixture(t);
      if (mode === "missing") delete f.authorization[field]; else f.authorization[field] = "wrong";
      assert.throws(() => invoke(f), ReleaseOrchestratorError);
      assert.equal(f.calls.length, 0);
    });
  }
}
test("valid explicitly supplied receipt binds one operation and publishes its exact argv", t => {
  const f = fixture(t), before = structuredClone(f.authorization);
  assert.deepEqual(validatePublicationAuthorization(f), f.plan.operations[0]);
  assert.equal(f.calls.length, 0);
  assert.equal(invoke(f).phase, "PARTIAL_NEXT");
  const [[exe, args, options]] = publications(f);
  assert.equal(exe, "npm"); assert.deepEqual(args, f.plan.operations[0].command.args);
  assert.equal(options.shell, false);
  assert.equal(publications(f).length, 1);
  assert.deepEqual(f.authorization, before);
  assert.equal(loadState(f.releaseDir).packages[f.authorization.package].publishStatus, "published");
  for (const p of f.plan.operations.slice(1)) assert.equal(f.state.packages[p.package].publishStatus, "pending");
});
test("authorization A cannot substitute for B in the same release", t => {
  const f = fixture(t); f.operationIndex = 1;
  assert.throws(() => invoke(f), { code: "PUBLICATION_AUTHORIZATION_MISMATCH" });
  assert.equal(f.calls.length, 0);
});
test("receipt from another release fails before execution", t => {
  const f = fixture(t); f.authorization.releaseId = "b".repeat(40);
  assert.throws(() => invoke(f), { code: "PUBLICATION_AUTHORIZATION_MISMATCH" });
  assert.equal(f.calls.length, 0);
});
test("extra wildcard authority is not accepted", t => {
  const f = fixture(t); f.authorization.allPackages = true;
  assert.throws(() => invoke(f), { code: "PUBLICATION_AUTHORIZATION_MISMATCH" });
  assert.equal(f.calls.length, 0);
});
test("exact authorization does not override predecessor order", t => {
  const f = fixture(t); f.operationIndex = 2; f.authorization = consent(f);
  const before = structuredClone(f.state);
  assert.throws(() => invoke(f), { code: "PUBLICATION_ORDER_NOT_SATISFIED" });
  assert.equal(f.calls.length, 0); assert.deepEqual(f.state, before);
});
test("correct predecessors permit a separately authorized explicit operation", t => {
  const f = fixture(t); f.operationIndex = 2; f.authorization = consent(f); f.state.phase = "PARTIAL_NEXT";
  for (const p of f.plan.operations.slice(0, 2)) f.state.packages[p.package] = { publishStatus: "published", registryIntegrity: p.integrity };
  invoke(f);
  assert.equal(publications(f).length, 1);
  assert.deepEqual(publications(f)[0][1], f.plan.operations[2].command.args);
  assert.equal(f.calls[0][1][1], f.authorization.package);
});
for (const mutation of [f => { f.state.phase = "PACKED"; }, f => { f.state.releaseId = "b".repeat(40); }, f => { f.plan.operations[0].command.args.push("--force"); }]) {
  test("authorization cannot override incompatible state or command", t => {
    const f = fixture(t); mutation(f);
    assert.throws(() => invoke(f), ReleaseOrchestratorError);
    assert.equal(f.calls.length, 0);
  });
}
test("each package requires its own consent and invocation; only the final one completes release", t => {
  const f = fixture(t);
  for (const op of f.plan.operations) {
    f.operationIndex = op.index; f.authorization = consent(f);
    invoke(f);
    assert.equal(publications(f).length, op.index + 1);
    assert.equal(f.state.phase, op.index === f.plan.operations.length - 1 ? "PUBLISHED_NEXT" : "PARTIAL_NEXT");
  }
});
