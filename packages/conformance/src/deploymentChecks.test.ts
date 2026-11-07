// SPDX-License-Identifier: Apache-2.0
import { test } from "node:test";
import assert from "node:assert/strict";
import { DEPLOYMENT_CHECK_IDS, runDeploymentChecks } from "./deploymentChecks.js";
import type { DeploymentProbes, DeploymentRunContext, ProbeResponse, RefusalObservation, ReplayStoreHandle, ReplayTopology } from "./deploymentChecks.js";

// ── Fakes (no network, no real deployment) ───────────────────────────────────
/** Two handles over one atomic backend, each a distinct object (like two clients). */
function sharedBackend(): [ReplayStoreHandle, ReplayStoreHandle] {
  const seen = new Set<string>();
  const mk = (): ReplayStoreHandle => ({
    async consumeAuthId(id) {
      if (seen.has(id)) return false;
      seen.add(id);
      return true;
    },
  });
  return [mk(), mk()];
}
const tick = () => new Promise((r) => setImmediate(r));
function sharedNonAtomicBackend(): [ReplayStoreHandle, ReplayStoreHandle] {
  const seen = new Set<string>();
  const mk = (): ReplayStoreHandle => ({
    async consumeAuthId(id) {
      const had = seen.has(id);
      await tick();
      if (had) return false;
      seen.add(id);
      return true;
    },
  });
  return [mk(), mk()];
}
const TOPOLOGY: ReplayTopology = {
  kind: "independent-processes",
  instanceIds: ["pep-a", "pep-b"],
  connectionIds: ["redis-conn-1", "redis-conn-2"],
  evidenceRef: "run-2026-11-07/topology.json",
};
const refused = (status = 403, reason = "AUTH_ISSUER_POLICY_NOT_AUTHORIZED") =>
  async (): Promise<RefusalObservation> => ({ outcome: "refused", status, reason, sideEffects: 0 });
const healthyControl = async () => ({ executed: 1 });

function sizeProbe(limit: number, over: ProbeResponse, opts: { atLimit?: ProbeResponse; healthBefore?: boolean; healthAfter?: boolean } = {}) {
  let calls = 0;
  return {
    limitBytes: limit,
    send: async (n: number): Promise<ProbeResponse> => (n <= limit ? (opts.atLimit ?? { kind: "response", status: 403 }) : over),
    health: async () => (calls++ === 0 ? (opts.healthBefore ?? true) : (opts.healthAfter ?? true)),
  };
}
const CONTEXT: DeploymentRunContext = {
  deploymentId: "payments-pep/staging",
  probeSetId: "depcheck@1",
  now: () => new Date("2026-11-07T12:00:00.000Z"),
  probes: { "DEP-BYPASS": { probeId: "bypass-direct-upstream", evidenceRef: "log-4711" } },
};
function goodProbes(): DeploymentProbes {
  return {
    control: healthyControl,
    requestSize: sizeProbe(1024, { kind: "response", status: 413, attributedTo: "ingress:client_max_body_size" }),
    replay: { handles: sharedBackend(), idPrefix: "test-", topology: TOPOLOGY },
    replayError: refused(403, "REPLAY_STORE_UNAVAILABLE"),
    authority: refused(),
    delegationSigner: refused(403, "DELEGATION_SIGNER_NOT_AUTHORIZED"),
    delegationControl: healthyControl,
    revocation: refused(403, "DELEGATION_REVOKED"),
    configImmutability: refused(),
    bypass: refused(403, "missing_executor_token"),
  };
}
type Report = Awaited<ReturnType<typeof runDeploymentChecks>>;
const check = (r: Report, id: string) => r.checks.find((c) => c.id === id)!;
const outcome = (r: Report, id: string) => check(r, id).outcome;

// ── Baseline behavior ─────────────────────────────────────────────────────────
test("no probes -> every check NOT_TESTED, result INCOMPLETE", async () => {
  const r = await runDeploymentChecks({}, CONTEXT);
  assert.equal(r.kind, "deployment");
  assert.deepEqual(r.checks.map((c) => c.id), [...DEPLOYMENT_CHECK_IDS]);
  assert.ok(r.checks.every((c) => c.outcome === "NOT_TESTED"));
  assert.equal(r.result, "INCOMPLETE");
});

test("all probes with attributable evidence and complete provenance -> PASS", async () => {
  const r = await runDeploymentChecks(goodProbes(), CONTEXT);
  assert.ok(r.checks.every((c) => c.outcome === "PASS"), JSON.stringify(r.checks, null, 1));
  assert.equal(r.result, "PASS");
});

// ── 1. Request size: unexplained closure, timeouts, failures ─────────────────
test("request size: connection closed / reset is NOT_TESTED, not PASS (former false PASS)", async () => {
  const p = goodProbes();
  p.requestSize = sizeProbe(1024, { kind: "transport_error", code: "ECONNRESET" });
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-REQUEST-SIZE"), "NOT_TESTED");
});

test("request size: timeout is NOT_TESTED", async () => {
  const p = goodProbes();
  p.requestSize = sizeProbe(1024, { kind: "timeout" });
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-REQUEST-SIZE"), "NOT_TESTED");
});

test("request size: 5xx on the oversized request is NOT_TESTED", async () => {
  const p = goodProbes();
  p.requestSize = sizeProbe(1024, { kind: "response", status: 502 });
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-REQUEST-SIZE"), "NOT_TESTED");
});

test("request size: an unattributed 413 is NOT_TESTED", async () => {
  const p = goodProbes();
  p.requestSize = sizeProbe(1024, { kind: "response", status: 413 });
  const r = await runDeploymentChecks(p, CONTEXT);
  assert.equal(outcome(r, "DEP-REQUEST-SIZE"), "NOT_TESTED");
  assert.match(check(r, "DEP-REQUEST-SIZE").detail, /not attributed/);
});

test("request size: an attribution that is not an identifier is not accepted", async () => {
  const p = goodProbes();
  p.requestSize = sizeProbe(1024, { kind: "response", status: 413, attributedTo: "nginx says\nAuthorization: Bearer x" });
  const r = await runDeploymentChecks(p, CONTEXT);
  assert.equal(outcome(r, "DEP-REQUEST-SIZE"), "NOT_TESTED");
  assert.doesNotMatch(JSON.stringify(r), /Bearer/);
});

test("request size: service unhealthy after the oversized request -> FAIL, even with a 413", async () => {
  const p = goodProbes();
  p.requestSize = sizeProbe(1024, { kind: "response", status: 413, attributedTo: "ingress:limit" }, { healthAfter: false });
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-REQUEST-SIZE"), "FAIL");
});

test("request size: service unhealthy before the probe -> NOT_TESTED", async () => {
  const p = goodProbes();
  p.requestSize = sizeProbe(1024, { kind: "response", status: 413, attributedTo: "ingress:limit" }, { healthBefore: false });
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-REQUEST-SIZE"), "NOT_TESTED");
});

test("request size: a body processed past the limit -> FAIL; an at-limit 413 -> FAIL; at-limit transport error -> NOT_TESTED", async () => {
  const p = goodProbes();
  p.requestSize = sizeProbe(1024, { kind: "response", status: 403 });
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-REQUEST-SIZE"), "FAIL");
  p.requestSize = sizeProbe(1024, { kind: "response", status: 413, attributedTo: "ingress:limit" }, { atLimit: { kind: "response", status: 413 } });
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-REQUEST-SIZE"), "FAIL");
  p.requestSize = sizeProbe(1024, { kind: "response", status: 413, attributedTo: "ingress:limit" }, { atLimit: { kind: "transport_error" } });
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-REQUEST-SIZE"), "NOT_TESTED");
});

// ── 2. Shared replay: topology evidence ───────────────────────────────────────
test("shared replay: one in-process store referenced twice is NOT_TESTED, not PASS (former false PASS)", async () => {
  const p = goodProbes();
  const [one] = sharedBackend();
  p.replay = { handles: [one, one], idPrefix: "t-" };
  const r = await runDeploymentChecks(p, CONTEXT);
  assert.equal(outcome(r, "DEP-REPLAY-SHARED"), "NOT_TESTED");
  assert.match(check(r, "DEP-REPLAY-SHARED").detail, /same object/);
});

test("shared replay: two distinct handles without topology evidence are NOT_TESTED", async () => {
  const p = goodProbes();
  p.replay = { handles: sharedBackend(), idPrefix: "t-" };
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-REPLAY-SHARED"), "NOT_TESTED");
});

test("shared replay: topology declared in-process is NOT_TESTED", async () => {
  const p = goodProbes();
  p.replay = { handles: sharedBackend(), idPrefix: "t-", topology: { ...TOPOLOGY, kind: "in-process" } };
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-REPLAY-SHARED"), "NOT_TESTED");
});

test("shared replay: incomplete topology evidence is NOT_TESTED", async () => {
  const p = goodProbes();
  p.replay = { handles: sharedBackend(), idPrefix: "t-", topology: { ...TOPOLOGY, evidenceRef: "" } };
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-REPLAY-SHARED"), "NOT_TESTED");
});

test("shared replay: independence claimed for one object, or for one connection id, is FAIL", async () => {
  const p = goodProbes();
  const [one] = sharedBackend();
  p.replay = { handles: [one, one], idPrefix: "t-", topology: TOPOLOGY };
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-REPLAY-SHARED"), "FAIL");
  p.replay = { handles: sharedBackend(), idPrefix: "t-", topology: { ...TOPOLOGY, connectionIds: ["c1", "c1"] } };
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-REPLAY-SHARED"), "FAIL");
  p.replay = { handles: sharedBackend(), idPrefix: "t-", topology: { ...TOPOLOGY, instanceIds: ["pep-a", "pep-a"] } };
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-REPLAY-SHARED"), "FAIL");
});

test("shared replay: unshared or non-atomic state is FAIL whatever the topology says", async () => {
  const p = goodProbes();
  p.replay = { handles: [sharedBackend()[0], sharedBackend()[0]], idPrefix: "t-", topology: TOPOLOGY };
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-REPLAY-SHARED"), "FAIL");
  p.replay = { handles: sharedNonAtomicBackend(), idPrefix: "t-", topology: TOPOLOGY };
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-REPLAY-SHARED"), "FAIL");
  p.replay = { handles: [sharedBackend()[0], sharedBackend()[0]], idPrefix: "t-" };
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-REPLAY-SHARED"), "FAIL");
});

for (const bad of ["OK", 1, "true", {}, null, undefined]) {
  test(`replay result: store answering ${JSON.stringify(bad) ?? "undefined"} -> FAIL`, async () => {
    const p = goodProbes();
    p.replay = { handles: [{ consumeAuthId: async () => bad }], idPrefix: "t-" };
    assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-REPLAY-RESULT"), "FAIL");
  });
}

test("replay result: a store that throws is NOT_TESTED, and its error text is not echoed", async () => {
  const p = goodProbes();
  p.replay = { handles: [{ consumeAuthId: async () => { throw new Error("redis://user:secret@host"); } }], idPrefix: "t-" };
  const r = await runDeploymentChecks(p, CONTEXT);
  assert.equal(outcome(r, "DEP-REPLAY-RESULT"), "NOT_TESTED");
  assert.doesNotMatch(JSON.stringify(r), /secret/);
});

// ── 3. Availability: failures cannot satisfy refusal checks ──────────────────
test("refusal: a transport error from an unavailable service is NOT_TESTED, not PASS (former false PASS)", async () => {
  const p = goodProbes();
  p.bypass = async () => ({ outcome: "transport_error", sideEffects: 0 });
  p.authority = async () => ({ outcome: "timeout", sideEffects: 0 });
  const r = await runDeploymentChecks(p, CONTEXT);
  assert.equal(outcome(r, "DEP-BYPASS"), "NOT_TESTED");
  assert.equal(outcome(r, "DEP-AUTHORITY"), "NOT_TESTED");
  assert.equal(r.result, "INCOMPLETE");
});

test("refusal: a 5xx labelled as a refusal is a service failure, NOT_TESTED", async () => {
  const p = goodProbes();
  p.revocation = async () => ({ outcome: "refused", status: 503, sideEffects: 0 });
  p.replayError = async () => ({ outcome: "service_error", status: 500, sideEffects: 0 });
  const r = await runDeploymentChecks(p, CONTEXT);
  assert.equal(outcome(r, "DEP-REVOCATION"), "NOT_TESTED");
  assert.equal(outcome(r, "DEP-REPLAY-ERROR"), "NOT_TESTED");
});

test("refusal: a 403 while the protected upstream is down is NOT_TESTED (post-probe control fails)", async () => {
  const p = goodProbes();
  let upstreamUp = true;
  p.control = async () => ({ executed: upstreamUp ? 1 : 0 });
  p.bypass = async () => { upstreamUp = false; return { outcome: "refused", status: 403, sideEffects: 0 }; };
  const r = await runDeploymentChecks(p, CONTEXT);
  assert.equal(outcome(r, "DEP-CONTROL"), "PASS");
  assert.equal(outcome(r, "DEP-BYPASS"), "NOT_TESTED");
  assert.match(check(r, "DEP-BYPASS").detail, /after the probe/);
});

test("refusal: without a passing positive control, refusal probes are NOT_TESTED", async () => {
  const p = goodProbes();
  delete p.control;
  const r = await runDeploymentChecks(p, CONTEXT);
  for (const id of ["DEP-REPLAY-ERROR", "DEP-AUTHORITY", "DEP-REVOCATION", "DEP-CONFIG-IMMUTABLE", "DEP-BYPASS"]) assert.equal(outcome(r, id), "NOT_TESTED", id);
  p.control = async () => ({ executed: 0 });
  const r2 = await runDeploymentChecks(p, CONTEXT);
  assert.equal(outcome(r2, "DEP-CONTROL"), "FAIL");
  assert.equal(outcome(r2, "DEP-BYPASS"), "NOT_TESTED");
  assert.equal(r2.result, "FAIL");
});

test("refusal: observed side effects or a reported execution are FAIL", async () => {
  const p = goodProbes();
  p.bypass = async () => ({ outcome: "transport_error", sideEffects: 1 });
  p.authority = async () => ({ outcome: "executed", sideEffects: 0 });
  p.configImmutability = async () => ({ outcome: "refused", status: 403, sideEffects: 2 });
  const r = await runDeploymentChecks(p, CONTEXT);
  assert.equal(outcome(r, "DEP-BYPASS"), "FAIL");
  assert.equal(outcome(r, "DEP-AUTHORITY"), "FAIL");
  assert.equal(outcome(r, "DEP-CONFIG-IMMUTABLE"), "FAIL");
});

test("refusal: malformed observations and throwing probes are NOT_TESTED", async () => {
  const p = goodProbes();
  p.bypass = async () => ({ refused: true, sideEffects: 0 }) as unknown as RefusalObservation;
  p.authority = async () => { throw new Error("boom"); };
  const r = await runDeploymentChecks(p, CONTEXT);
  assert.equal(outcome(r, "DEP-BYPASS"), "NOT_TESTED");
  assert.equal(outcome(r, "DEP-AUTHORITY"), "NOT_TESTED");
});

// ── 4. Delegation signer authority (DIV-01) ───────────────────────────────────
test("delegation signer: without a delegation positive control the refusal is NOT_TESTED", async () => {
  const p = goodProbes();
  delete p.delegationControl;
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-DELEGATION-SIGNER"), "NOT_TESTED");
  p.delegationControl = async () => ({ executed: 0 });
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-DELEGATION-SIGNER"), "NOT_TESTED");
});

test("delegation signer: an unauthorized signer that executes is FAIL; a refused one is PASS", async () => {
  const p = goodProbes();
  p.delegationSigner = async () => ({ outcome: "executed", sideEffects: 1 });
  assert.equal(outcome(await runDeploymentChecks(p, CONTEXT), "DEP-DELEGATION-SIGNER"), "FAIL");
  p.delegationSigner = refused(403, "DELEGATION_SIGNER_NOT_AUTHORIZED");
  const r = await runDeploymentChecks(p, CONTEXT);
  assert.equal(outcome(r, "DEP-DELEGATION-SIGNER"), "PASS");
  assert.match(check(r, "DEP-DELEGATION-SIGNER").detail, /DELEGATION_SIGNER_NOT_AUTHORIZED/);
});

// ── 5. Provenance ─────────────────────────────────────────────────────────────
test("provenance: identity, timestamp, probe ids and evidence refs are reported", async () => {
  const r = await runDeploymentChecks(goodProbes(), CONTEXT);
  assert.equal(r.provenance.deploymentId, "payments-pep/staging");
  assert.equal(r.provenance.probeSetId, "depcheck@1");
  assert.equal(r.provenance.executedAt, "2026-11-07T12:00:00.000Z");
  assert.equal(r.provenance.complete, true);
  assert.deepEqual(r.provenance.replayTopology, { kind: "independent-processes", evidenceRef: "run-2026-11-07/topology.json" });
  assert.equal(check(r, "DEP-BYPASS").probeId, "bypass-direct-upstream");
  assert.equal(check(r, "DEP-BYPASS").evidenceRef, "log-4711");
});

test("provenance: missing or non-identifier deployment identity keeps the aggregate INCOMPLETE", async () => {
  const r = await runDeploymentChecks(goodProbes());
  assert.ok(r.checks.every((c) => c.outcome === "PASS"));
  assert.equal(r.provenance.deploymentId, "UNSPECIFIED");
  assert.equal(r.result, "INCOMPLETE");
  const r2 = await runDeploymentChecks(goodProbes(), { ...CONTEXT, deploymentId: "prod token=abc123" });
  assert.equal(r2.result, "INCOMPLETE");
  assert.doesNotMatch(JSON.stringify(r2), /abc123/);
});

test("provenance: free-text reasons and probe metadata are not echoed", async () => {
  const p = goodProbes();
  p.authority = async () => ({ outcome: "refused", status: 403, reason: "denied for user alice@example.com with key sk-live-xyz", sideEffects: 0 });
  const r = await runDeploymentChecks(p, { ...CONTEXT, probes: { "DEP-AUTHORITY": { probeId: "auth probe with spaces", evidenceRef: "Bearer abc" } } });
  const json = JSON.stringify(r);
  assert.doesNotMatch(json, /alice|sk-live|Bearer|with spaces/);
  assert.equal(check(r, "DEP-AUTHORITY").outcome, "PASS");
  assert.match(check(r, "DEP-AUTHORITY").detail, /\[unreported\]/);
});

// Regression: inconsistent refusal observations must never produce PASS.
test("refusal: HTTP 200 labelled refused is NOT_TESTED", async () => {
  const p = goodProbes();
  p.bypass = async () => ({
    outcome: "refused",
    status: 200,
    sideEffects: 0,
  });

  const r = await runDeploymentChecks(p, CONTEXT);
  assert.equal(outcome(r, "DEP-BYPASS"), "NOT_TESTED");
  assert.equal(r.result, "INCOMPLETE");
});

test("refusal: HTTP 302 labelled refused is NOT_TESTED", async () => {
  const p = goodProbes();
  p.bypass = async () => ({
    outcome: "refused",
    status: 302,
    sideEffects: 0,
  });

  const r = await runDeploymentChecks(p, CONTEXT);
  assert.equal(outcome(r, "DEP-BYPASS"), "NOT_TESTED");
});

test("refusal: HTTP 403 remains PASS", async () => {
  const r = await runDeploymentChecks(goodProbes(), CONTEXT);
  assert.equal(outcome(r, "DEP-BYPASS"), "PASS");
});

test("refusal: observed side effects remain FAIL despite HTTP 200", async () => {
  const p = goodProbes();
  p.bypass = async () => ({
    outcome: "refused",
    status: 200,
    sideEffects: 1,
  });

  const r = await runDeploymentChecks(p, CONTEXT);
  assert.equal(outcome(r, "DEP-BYPASS"), "FAIL");
});
