// SPDX-License-Identifier: Apache-2.0
// All process results are fixtures; no npm subprocess or registry is invoked.
import test from "node:test";
import assert from "node:assert/strict";
import { createNpmAuthTransport } from "./auth-transport.mjs";
import { RELEASE_REGISTRY_REQUIREMENTS, observeRegistryPrecheck } from "./auth-precheck.mjs";
import { precheck } from "./orchestrator.mjs";
import { POLICY } from "../verify-packed-artifacts.mjs";
const registry = RELEASE_REGISTRY_REQUIREMENTS.registry;
const pkg = "@oxdeai/core";
const ok = (body) => ({ status: 0, stdout: JSON.stringify(body), stderr: "" });
const failure = (code, summary = "fixture failure") => ({ status: 1, stdout: JSON.stringify({ error: { code, summary } }), stderr: "" });
function fixture(result) {
  const calls = [];
  const transport = createNpmAuthTransport({ registry, subprocess: (args) => { calls.push(args); return result; } });
  return { transport, calls };
}
const ds = [{ name: pkg, manifest: { name: pkg, version: POLICY[pkg].version } }];
const runPrecheck = (authTransport) => precheck({ discovered: ds, gitTransport: { isClean: () => true }, authTransport });
function reportedTransport({ status = { kind: "existing", visibility: "public" }, right = "read-write", target = registry } = {}) {
  return {
    whoami: () => ({ kind: "identity", registry: target, username: "maintainer" }),
    listPackageAccess: (subject) => ({ kind: "access", registry: target, subject, packages: { [pkg]: right } }),
    getPackageStatus: (packageName) => ({ ...status, registry: target, packageName }),
  };
}

test("closed frozen interface builds only fixed read commands, explicitly targets registry, returns observations only", () => {
  const replies = [ok("maintainer"), ok({ [pkg]: "read-write" }), ok({ [pkg]: "public" })];
  const calls = [];
  const auth = createNpmAuthTransport({ registry, subprocess: (args) => { calls.push(args); return replies.shift(); } });
  assert.deepEqual(Object.keys(auth).sort(), ["getPackageStatus", "listPackageAccess", "whoami"]);
  assert.ok(Object.isFrozen(auth));
  assert.equal(auth.execNpm, undefined);
  assert.equal(auth.runNpm, undefined);
  assert.equal(auth.exec, undefined);
  assert.throws(() => { auth.execNpm = () => {}; }, TypeError);
  const identity = auth.whoami(["arbitrary-command"]); // Extra argument cannot become a subcommand.
  assert.deepEqual(identity, { kind: "identity", registry, username: "maintainer" });
  const access = auth.listPackageAccess("maintainer");
  assert.deepEqual(access, { kind: "access", registry, subject: "maintainer", packages: { [pkg]: "read-write" } });
  const state = auth.getPackageStatus(pkg);
  assert.deepEqual(state, { kind: "existing", registry, packageName: pkg, visibility: "public" });
  const suffix = ["--json", `--registry=${registry}`, "--ignore-scripts", "--logs-max=0", "--update-notifier=false", "--color=false", "--fetch-retries=0", "--fetch-timeout=15000", "--offline=false", "--prefer-offline=false", "--prefer-online=true"];
  assert.deepEqual(calls, [["whoami", ...suffix], ["access", "list", "packages", "maintainer", ...suffix], ["access", "get", "status", pkg, ...suffix]]);
  for (const observation of [identity, access, state]) {
    for (const key of ["canPublish", "releaseAllowed", "authorized", "ok"]) assert.ok(!Object.hasOwn(observation, key));
  }
});

for (const input of ["--registry=https://evil.invalid/", "pkg --otp=123", "../package", "", ["access", "set"], null]) {
  test(`argument injection rejected before process call: ${JSON.stringify(input)}`, () => {
    const { transport, calls } = fixture(ok({}));
    assert.throws(() => transport.listPackageAccess(input), TypeError);
    assert.throws(() => transport.getPackageStatus(input), TypeError);
    assert.equal(calls.length, 0);
  });
}
for (const target of [undefined, "http://registry.npmjs.org/", "https://user:secret@example.test/", "https://example.test/?token=secret", "https://example.test/#fragment"]) {
  test(`unsafe/absent explicit registry refused: ${String(target)}`, () => {
    assert.throws(() => createNpmAuthTransport({ registry: target, subprocess: () => assert.fail("no process") }), TypeError);
  });
}

for (const [code, category] of [
  ["ENEEDAUTH", "AUTH_UNAUTHENTICATED"], ["E401", "AUTH_UNAUTHENTICATED"], ["EOTP", "AUTH_UNAUTHENTICATED"],
  ["ENOTFOUND", "REGISTRY_UNAVAILABLE"], ["ETIMEDOUT", "REGISTRY_UNAVAILABLE"], ["EAI_AGAIN", "REGISTRY_UNAVAILABLE"],
  ["ECONNREFUSED", "REGISTRY_UNAVAILABLE"], ["CERT_HAS_EXPIRED", "REGISTRY_UNAVAILABLE"], ["E503", "REGISTRY_UNAVAILABLE"],
  ["E403", "REGISTRY_STATE_UNDETERMINED"], ["EUNRECOGNIZED", "REGISTRY_STATE_UNDETERMINED"],
]) {
  test(`npm ${code} normalizes to ${category} for all capabilities`, () => {
    const { transport } = fixture(failure(code, "SECRET must not appear in observations"));
    for (const observed of [transport.whoami(), transport.listPackageAccess("maintainer"), transport.getPackageStatus(pkg)]) {
      assert.equal(observed.kind, "unknown");
      assert.equal(observed.reason.code, category);
      assert.ok(!JSON.stringify(observed).includes("SECRET"));
    }
  });
}
for (const result of [
  { status: null, error: { code: "ETIMEDOUT" } },
  { status: null, signal: "SIGTERM" },
  { status: 1, stdout: "", stderr: JSON.stringify({ error: { code: "ENOTFOUND" } }) },
]) {
  test(`process/network failure never becomes missing: ${JSON.stringify(result)}`, () => {
    assert.equal(fixture(result).transport.getPackageStatus(pkg).reason.code, "REGISTRY_UNAVAILABLE");
  });
}
for (const summary of ["Not found", "Package not found", `404 Not Found - GET ${registry}-/package/@oxdeai%2fcore/visibility - Not found`]) {
  test(`ambiguous E404 stays unknown, including absence-looking text: ${summary}`, () => {
    const status = fixture(failure("E404", summary)).transport.getPackageStatus(pkg);
    assert.equal(status.kind, "unknown");
    assert.equal(status.reason.code, "REGISTRY_STATE_UNDETERMINED");
    assert.match(status.reason.detail, /cannot distinguish absence/);
  });
}
for (const visibility of ["public", "private"]) {
  test(`existing ${visibility} remains an observation`, () => {
    assert.deepEqual(fixture(ok({ [pkg]: visibility })).transport.getPackageStatus(pkg), { kind: "existing", registry, packageName: pkg, visibility });
  });
}
for (const body of [null, [], true, {}, { username: "maintainer" }, "", "--registry=evil"]) {
  test(`unsupported identity JSON fails closed: ${JSON.stringify(body)}`, () => {
    assert.equal(fixture(ok(body)).transport.whoami().reason.code, "REGISTRY_STATE_UNDETERMINED");
  });
}
for (const body of [null, [], "public", {}, { [pkg]: "restricted" }, { [pkg]: "public", extra: "public" }]) {
  test(`unsupported visibility JSON fails closed: ${JSON.stringify(body)}`, () => {
    assert.equal(fixture(ok(body)).transport.getPackageStatus(pkg).reason.code, "REGISTRY_STATE_UNDETERMINED");
  });
}
for (const body of [null, [], { [pkg]: "write" }, { [pkg]: true }, { [pkg]: "owner" }]) {
  test(`unsupported access JSON fails closed: ${JSON.stringify(body)}`, () => {
    assert.equal(fixture(ok(body)).transport.listPackageAccess("maintainer").reason.code, "REGISTRY_STATE_UNDETERMINED");
  });
}

test("required write is explicit; transport reports read-only without making the decision", () => {
  assert.equal(RELEASE_REGISTRY_REQUIREMENTS.requiredRegistryAccess, "read-write");
  const observation = fixture(ok({ [pkg]: "read-only" })).transport.listPackageAccess("maintainer");
  assert.equal(observation.kind, "access");
  assert.equal(observation.packages[pkg], "read-only");
  assert.throws(() => runPrecheck(reportedTransport({ right: "read-only" })), /REGISTRY_ACCESS_INSUFFICIENT.*read-write/);
  assert.equal(runPrecheck(reportedTransport()).registryObservations.packages[0].visibility, "public");
});

for (const [index, capability] of ["whoami", "listPackageAccess", "getPackageStatus"].entries()) {
  test(`generic E403 in ${capability} blocks precheck without inferring insufficient package access`, () => {
    const replies = [ok("maintainer"), ok({ [pkg]: "read-write" }), ok({ [pkg]: "public" })];
    replies[index] = failure("E403", "Forbidden");
    let calls = 0;
    const authTransport = createNpmAuthTransport({ registry, subprocess: () => replies[calls++] });
    assert.throws(() => runPrecheck(authTransport), (error) => {
      assert.equal(error.blockers.length, 1);
      assert.match(error.blockers[0], /^REGISTRY_STATE_UNDETERMINED:/);
      assert.doesNotMatch(error.message, /REGISTRY_ACCESS_INSUFFICIENT/);
      return true;
    });
    assert.equal(calls, index + 1);
  });
}
test("private visibility cannot satisfy the public release requirement", () => {
  assert.throws(() => runPrecheck(reportedTransport({ status: { kind: "existing", visibility: "private" } })), /REGISTRY_ACCESS_INSUFFICIENT.*private/);
});
test("missing and unknown follow different policy branches; neither opens release precheck", () => {
  // A hypothetical observer with confirmed absence, NOT an invented npm E404 contract.
  const missing = { kind: "missing" };
  const unknown = { kind: "unknown", reason: { code: "REGISTRY_STATE_UNDETERMINED", detail: "ambiguous E404" } };
  const missingCheck = observeRegistryPrecheck({ discovered: ds, authTransport: reportedTransport({ status: missing }) });
  assert.match(missingCheck.blockers[0], /REGISTRY_ACCESS_INSUFFICIENT.*creation authority not established/);
  assert.ok(!Object.hasOwn(missingCheck.observations.packages[0], "visibility"));
  assert.throws(() => runPrecheck(reportedTransport({ status: unknown })), /REGISTRY_STATE_UNDETERMINED/);
  assert.throws(() => runPrecheck(reportedTransport({ status: missing })), /REGISTRY_ACCESS_INSUFFICIENT/);
});
for (const changes of [
  { status: { kind: "missing", visibility: "public" } },
  { status: { kind: "unknown" } },
  { status: { kind: "existing", visibility: "unknown" } },
  { status: { kind: "anything" } },
  { right: "write" }, { target: "https://other.invalid/" },
]) {
  test(`malformed/unattributed observations cannot pass precheck: ${JSON.stringify(changes)}`, () => {
    assert.throws(() => runPrecheck(reportedTransport(changes)), /REGISTRY_STATE_UNDETERMINED/);
  });
}
test("null/legacy/throwing auth transports fail closed; omitted auth remains local only", () => {
  for (const auth of [null, { whoami: () => true }, { whoami() { throw new Error("secret"); } }]) {
    assert.throws(() => runPrecheck(auth), /REGISTRY_STATE_UNDETERMINED|AUTH_UNAUTHENTICATED/);
  }
  assert.equal(runPrecheck(undefined).ok, true);
});
test("wrong subject, package identity, or missing write entry fails closed", () => {
  const auth = reportedTransport();
  auth.listPackageAccess = () => ({ kind: "access", registry, subject: "other-user", packages: { [pkg]: "read-write" } });
  assert.throws(() => runPrecheck(auth), /REGISTRY_STATE_UNDETERMINED/);
  const wrongPackage = reportedTransport();
  wrongPackage.getPackageStatus = () => ({ kind: "existing", registry, packageName: "@oxdeai/other", visibility: "public" });
  assert.throws(() => runPrecheck(wrongPackage), /REGISTRY_STATE_UNDETERMINED/);
  const noRight = reportedTransport();
  noRight.listPackageAccess = (subject) => ({ kind: "access", registry, subject, packages: {} });
  assert.throws(() => runPrecheck(noRight), /REGISTRY_ACCESS_INSUFFICIENT/);
});

test("precheck integrates normalized CLI fixtures without a release verdict in the transport", () => {
  const replies = [ok("maintainer"), ok({ [pkg]: "read-write" }), ok({ [pkg]: "public" })];
  let calls = 0;
  const authTransport = createNpmAuthTransport({ registry, subprocess: () => { calls++; return replies.shift(); } });
  const result = runPrecheck(authTransport);
  assert.equal(calls, 3);
  assert.equal(result.ok, true); // Decision belongs to orchestrator, not observations.
  assert.equal(result.registryObservations.identity.kind, "identity");
});
test("network/authentication failures propagate through precheck and stop later observations", () => {
  for (const [code, category] of [["ENEEDAUTH", "AUTH_UNAUTHENTICATED"], ["ENOTFOUND", "REGISTRY_UNAVAILABLE"]]) {
    const { transport, calls } = fixture(failure(code));
    assert.throws(() => runPrecheck(transport), new RegExp(category));
    assert.equal(calls.length, 1);
  }
});
test("invalid process/output results and thrown execution fail closed", () => {
  for (const result of [undefined, null, true, { status: 0, stdout: "not JSON" }, { status: 2, stdout: "not JSON" }]) {
    assert.equal(fixture(result).transport.whoami().reason.code, "REGISTRY_STATE_UNDETERMINED");
  }
  const auth = createNpmAuthTransport({ registry, subprocess() { throw new Error("sensitive message"); } });
  assert.equal(auth.whoami().reason.code, "REGISTRY_STATE_UNDETERMINED");
});
