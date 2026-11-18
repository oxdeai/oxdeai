// SPDX-License-Identifier: Apache-2.0
/**
 * RR-01 (gateway consume site) and GW-COMP-01, backported to the 2.0.x line
 * from upstream `replay.strict-result.security.test.ts` (gateway section only).
 *
 * Contract (`replayStore.ts`, verification-v1 §4.3): `consumeAuthId` resolves
 * to a boolean. `true` means consumed now (first use); `false` means already
 * consumed. Before RR-01 the gateway tested truthiness (`if (!consumed)`), so a
 * store answering "false", "true", 1, {} or [] was treated as a successful
 * first consume and one authorization could execute any number of times.
 *
 * Scope note: the Guard direct and delegation consume sites are not changed on
 * the 2.0.x line; only the PEP gateway (in-process and HTTP) is pinned here.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { request } from "node:http";

import { signAuthorizationEd25519, sha256HexFromJson } from "@oxdeai/core";
import type { AuthorizationAuthority, AuthorizationV1, KeySet } from "@oxdeai/core";

import { createInMemoryReplayStore } from "../replayStore.js";
import { createPepGatewayExecutor, createPepGatewayHttpServer } from "../gateway.js";
import type { PepGatewayOptions } from "../gateway.js";
import type { ReplayStore } from "../replayStore.js";

const KP = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const ISSUER = "rr01-issuer";
const POLICY = "rr01-policy";
const T_NOW = Math.floor(Date.now() / 1000);
const KEYSET: KeySet = { issuer: ISSUER, version: "v1", keys: [{ kid: "k1", alg: "Ed25519", public_key: KP.publicKey.toString() }] };
const AUTHORITIES: readonly AuthorizationAuthority[] = [{ issuer: ISSUER, policyId: POLICY }];

/** Every value the brief requires, plus the store answers seen in the wild ("OK"). */
const ANSWERS: ReadonlyArray<[string, unknown]> = [
  ["true", true], ["false", false], ['"false"', "false"], ['"true"', "true"], ["0", 0], ["1", 1],
  ["null", null], ["undefined", undefined], ["{}", {}], ["[]", []], ['"OK"', "OK"],
];

function sign(o: Partial<AuthorizationV1> & { intent_hash: string; audience: string }): AuthorizationV1 {
  return signAuthorizationEd25519({
    auth_id: o.auth_id ?? `rr01-${randomUUID()}`, issuer: ISSUER, audience: o.audience, intent_hash: o.intent_hash,
    state_hash: o.state_hash ?? "b".repeat(64), policy_id: POLICY, decision: "ALLOW",
    issued_at: T_NOW - 5, expiry: T_NOW + 600, kid: "k1",
  } as never, KP.privateKey.toString());
}

// ── Replay stores ───────────────────────────────────────────────────────────

type Site = "auth" | "deleg";
type SpyStore = ReplayStore & { recorded: { auth: Set<string>; deleg: Set<string> }; calls: string[] };

/** Atomic in-memory store; `answers[site]`, when present, replaces the answer at that site (after recording the id). */
function spyStore(answers: Partial<Record<Site, unknown>> = {}): SpyStore {
  const recorded = { auth: new Set<string>(), deleg: new Set<string>() };
  const calls: string[] = [];
  const consume = (site: Site, id: string): unknown => {
    calls.push(`${site}:${id}`);
    const first = !recorded[site].has(id);
    recorded[site].add(id);
    return site in answers ? answers[site] : first;
  };
  return {
    recorded, calls,
    async consumeAuthId(id) { return consume("auth", id) as boolean; },
    async consumeDelegationId(id) { return consume("deleg", id) as boolean; },
  };
}

// Gateway: strict consume result
// ═══════════════════════════════════════════════════════════════════════════

const AUD = "rr01-gateway";
const TOKEN = "rr01-token";
const gwAction = () => ({ type: "PAYMENT", params: { to: "acct-1", amount: "10", tags: ["a"] } });
const gwAuth = (a: unknown) => sign({ audience: AUD, intent_hash: sha256HexFromJson(a) });

function gw(store: ReplayStore, extra: Partial<PepGatewayOptions> = {}) {
  const upstream: unknown[] = [];
  const options: PepGatewayOptions = {
    expectedAudience: AUD, trustedKeySets: [KEYSET], internalExecutorToken: TOKEN,
    trustedAuthorizationAuthorities: [{ issuer: ISSUER, policyId: POLICY }],
    replayStore: store,
    executeUpstream: async (a) => { upstream.push(a); return { status: 200, body: { ok: true } }; },
    ...extra,
  };
  return { exec: createPepGatewayExecutor(options), upstream, options };
}

test("RR-01 Gateway: only boolean true dispatches; false = AUTH_REPLAY; anything else = REPLAY_STORE_UNAVAILABLE:INVALID_RESULT", async (t) => {
  for (const [label, answer] of ANSWERS) {
    await t.test(`consumeAuthId -> ${label}`, async () => {
      const { exec, upstream } = gw(spyStore({ auth: answer }));
      const a = gwAction();
      const r = await exec({ action: a, authorization: gwAuth(a) });
      if (answer === true) {
        assert.equal(r.status, 200);
        assert.equal(upstream.length, 1);
        return;
      }
      assert.equal(upstream.length, 0, `answer ${label} must never reach the upstream`);
      assert.equal(r.status, 403);
      assert.equal(r.upstreamCalled, false);
      assert.equal(r.body.outcome, "NOT_DISPATCHED");
      assert.equal(r.body.reason, answer === false ? "AUTH_REPLAY" : "REPLAY_STORE_UNAVAILABLE:INVALID_RESULT");
    });
  }
});

test("RR-01 Gateway: provider throws / rejects -> 403, no dispatch; a pending consume never dispatches (no timeout)", async () => {
  for (const consumeAuthId of [async () => { throw new Error("down"); }, () => Promise.reject(new Error("rej"))]) {
    const { exec, upstream } = gw({ consumeAuthId } as ReplayStore);
    const a = gwAction();
    const r = await exec({ action: a, authorization: gwAuth(a) });
    assert.equal(r.status, 403);
    assert.match(String(r.body.reason), /^REPLAY_STORE_UNAVAILABLE:/);
    assert.equal(upstream.length, 0);
  }
  const { exec, upstream } = gw({ consumeAuthId: () => new Promise<boolean>(() => {}) });
  const a = gwAction();
  const state = await Promise.race([exec({ action: a, authorization: gwAuth(a) }).then(() => "settled"), new Promise((r) => setTimeout(() => r("pending"), 200))]);
  assert.equal(state, "pending");
  assert.equal(upstream.length, 0);
});

test("RR-01 Gateway: 16 concurrent presentations over two instances sharing a store dispatch exactly once", async () => {
  const store = spyStore();
  const g1 = gw(store), g2 = gw(store);
  const a = gwAction();
  const auth = gwAuth(a);
  const rs = await Promise.all([
    ...Array.from({ length: 8 }, () => g1.exec({ action: a, authorization: auth })),
    ...Array.from({ length: 8 }, () => g2.exec({ action: a, authorization: auth })),
  ]);
  assert.equal(g1.upstream.length + g2.upstream.length, 1);
  assert.equal(rs.filter((r) => r.status === 200).length, 1);
  assert.equal(rs.filter((r) => r.body.reason === "AUTH_REPLAY").length, 15);
});

test("RR-01 HTTP gateway: a malformed store answer is denied before dispatch", async () => {
  const upstream: unknown[] = [];
  const server = createPepGatewayHttpServer({
    expectedAudience: AUD, trustedKeySets: [KEYSET], internalExecutorToken: TOKEN,
    trustedAuthorizationAuthorities: [{ issuer: ISSUER, policyId: POLICY }],
    replayStore: spyStore({ auth: "false" }),
    executeUpstream: async (a) => { upstream.push(a); return { status: 200, body: {} }; },
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  try {
    const a = gwAction();
    const data = JSON.stringify({ action: a, authorization: gwAuth(a) });
    const port = (server.address() as { port: number }).port;
    const res = await new Promise<{ status: number; body: { reason?: string; outcome?: string } }>((resolve, rejectP) => {
      const q = request({ host: "127.0.0.1", port, path: "/execute", method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(data) } }, (s) => {
        let d = ""; s.on("data", (c) => (d += c)); s.on("end", () => resolve({ status: s.statusCode ?? 0, body: JSON.parse(d) }));
      });
      q.on("error", rejectP);
      q.end(data);
    });
    assert.equal(res.status, 403);
    assert.equal(res.body.reason, "REPLAY_STORE_UNAVAILABLE:INVALID_RESULT");
    assert.equal(res.body.outcome, "NOT_DISPATCHED");
    assert.equal(upstream.length, 0);
  } finally {
    server.close();
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// GW-COMP-01: executor receiver and upstream input
// ═══════════════════════════════════════════════════════════════════════════

test("GW-COMP-01 method-style executeUpstream using `this` works, with this === the options object", async () => {
  let receiver: unknown;
  const options = {
    expectedAudience: AUD, trustedKeySets: [KEYSET], internalExecutorToken: TOKEN,
    trustedAuthorizationAuthorities: [{ issuer: ISSUER, policyId: POLICY }],
    replayStore: spyStore(),
    client: { send: async (a: { params: { amount: string } }) => ({ status: 200, body: { amount: a.params.amount } }) },
    async executeUpstream(this: { client: { send: (a: never) => Promise<{ status: number; body: unknown }> } }, a: unknown) {
      receiver = this;
      return this.client.send(a as never);
    },
  };
  const exec = createPepGatewayExecutor(options);
  const a = gwAction();
  const r = await exec({ action: a, authorization: gwAuth(a) });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.outcome, "EXECUTED");
  assert.equal(receiver, options);
  assert.deepEqual(r.body.upstream_result, { amount: "10" });
});

test("GW-COMP-01 restoring the receiver does not reopen post-construction substitution", async () => {
  const calls: string[] = [];
  const headers: string[] = [];
  const { exec, options } = gw(spyStore(), {
    async executeUpstream(_a, h) { calls.push("original"); headers.push(h["x-internal-executor-token"]); return { status: 200, body: {} }; },
  });
  const mutable = options as { -readonly [K in keyof PepGatewayOptions]: PepGatewayOptions[K] };
  mutable.executeUpstream = async () => { calls.push("substituted"); return { status: 200, body: {} }; };
  mutable.internalExecutorToken = "leaked-token";
  mutable.expectedAudience = "attacker-audience";
  mutable.trustedAuthorizationAuthorities = [];

  const a = gwAction();
  const ok = await exec({ action: a, authorization: gwAuth(a) });
  assert.equal(ok.status, 200, "authorities were captured, so clearing the caller's list has no effect");
  assert.deepEqual(calls, ["original"], "the substituted executor is never called");
  assert.deepEqual(headers, [TOKEN], "the construction-time token is sent");

  const foreign = await exec({ action: a, authorization: sign({ audience: "attacker-audience", intent_hash: sha256HexFromJson(a) }) });
  assert.equal(foreign.status, 403, "the reassigned audience is not observed");
  assert.deepEqual(calls, ["original"]);
});

test("GW-COMP-01 an executor that mutates its input completes, and the mutation reaches nothing else", async () => {
  const { exec } = gw(spyStore(), {
    async executeUpstream(a) {
      const act = a as { params: { amount: string; normalized?: boolean; tags: string[] } };
      act.params.normalized = true;
      act.params.amount = "999999";
      act.params.tags.push("x");
      return { status: 200, body: {} };
    },
  });
  const a = gwAction();
  const before = JSON.stringify(a);
  const auth = gwAuth(a);
  const r = await exec({ action: a, authorization: auth });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.outcome, "EXECUTED");
  assert.equal(r.body.intent_hash, auth.intent_hash, "response binding is computed from the frozen snapshot");
  assert.equal(r.body.auth_id, auth.auth_id);
  assert.equal(JSON.stringify(a), before, "the caller's object is not reachable from the executor's copy");
});

test("GW-COMP-01 the executor's copy equals the authorized action at dispatch, even if the caller mutates during the await", async () => {
  let atDispatch = "";
  let received: unknown;
  const slowStore: ReplayStore = {
    async consumeAuthId() { await new Promise((r) => setImmediate(r)); return true; },
  };
  const { exec } = gw(slowStore, {
    async executeUpstream(x) { received = x; atDispatch = JSON.stringify(x); return { status: 200, body: {} }; },
  });
  const a = gwAction();
  const authorized = JSON.stringify(a);
  const auth = gwAuth(a);
  const pending = exec({ action: a, authorization: auth });
  a.params.to = "attacker";
  a.params.amount = "1000000";
  const r = await pending;
  assert.equal(r.status, 200);
  assert.equal(atDispatch, authorized);
  assert.equal(sha256HexFromJson(JSON.parse(atDispatch)), auth.intent_hash);
  assert.notEqual(received, a);
  assert.ok(!Object.isFrozen(received), "the executor's copy is mutable");
});

test("GW-COMP-01 the mutable copy keeps own __proto__ keys as data, null prototypes and bigint leaves", async () => {
  let received: Record<string, unknown> | undefined;
  const { exec } = gw(spyStore(), {
    async executeUpstream(x) { received = x as Record<string, unknown>; return { status: 200, body: {} }; },
  });
  const a = JSON.parse('{"type":"T","params":{"__proto__":{"polluted":1},"n":1}}') as Record<string, unknown>;
  a.np = Object.assign(Object.create(null), { q: 2 });
  a.big = 10n;
  const r = await exec({ action: a, authorization: gwAuth(a) });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const params = received!.params as Record<string, unknown>;
  assert.ok(Object.prototype.hasOwnProperty.call(params, "__proto__"));
  assert.equal(Object.getPrototypeOf(params), Object.prototype);
  assert.equal(Object.getPrototypeOf(received!.np), null);
  assert.equal(received!.big, 10n);
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
  assert.equal(sha256HexFromJson(received), sha256HexFromJson(a));
});
