// SPDX-License-Identifier: Apache-2.0
/**
 * RR-01: strict boolean replay consumption (Guard and Gateway), and
 * GW-COMP-01: Gateway upstream-executor compatibility.
 *
 * Contract (`replayStore.ts`, verification-v1 §4.3): `consumeAuthId` /
 * `consumeDelegationId` resolve to a boolean. `true` means consumed now (first
 * use); `false` means already consumed. "An indeterminate result MUST NOT be
 * reported as successful consumption."
 *
 * Before RR-01 every consume site tested truthiness (`if (!consumed)`), so a
 * store answering "false", "true", 1, {} or [] was treated as a successful
 * first consume. One authorization could then execute any number of times.
 *
 * These tests pin, for every consume site (Guard direct, Guard delegation
 * delegation_id + parent auth_id, on OxDeAIGuard and createSecureGuard, and
 * the PEP gateway in-process and over HTTP):
 *   - only the boolean `true` lets execution proceed;
 *   - `false` is a replay denial;
 *   - any other value is denied as REPLAY_STORE_UNAVAILABLE, with no new
 *     public failure code;
 *   - throw / rejection fail closed; a pending consume never executes. No
 *     timeout exists: the request stays pending, it is not bounded;
 *   - concurrency, shared stores and the replay modes keep working.
 *
 * Consumption state: a denial does NOT prove the id was left unconsumed. A
 * store that recorded the id and then answered malformed has spent it. The
 * guard cannot know this, so its lifecycle flag stays `false`
 * ("not confirmed").
 */
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { request } from "node:http";

import { signAuthorizationEd25519, createDelegation, stateSnapshotHash, intentHash, sha256HexFromJson } from "@oxdeai/core";
import type { Authorization, AuthorizationAuthority, AuthorizationV1, DelegationV1, Intent, KeySet, State } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

import { OxDeAIGuard } from "../guard.js";
import { createSecureGuard } from "../secureGuard.js";
import { createTrustedExecutionContext } from "../trustedContext.js";
import { createInMemoryReplayStore } from "../replayStore.js";
import { createRedisReplayStore } from "../replayStore.redis.js";
import { createPepGatewayExecutor, createPepGatewayHttpServer } from "../gateway.js";
import type { PepGatewayOptions } from "../gateway.js";
import type { GuardBoundaryAuditEvent } from "../boundaryEvent.js";
import type { OxDeAIGuardConfig, ProposedAction } from "../types.js";
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

// ── Guard fixtures ──────────────────────────────────────────────────────────

/** Engine that signs a FIXED auth_id bound to the evaluated intent and state, so the same id can be presented again. */
function fixedIdEngine(authId: string, audience: string) {
  return {
    evaluatePure(intent: Intent, state: State) {
      const authorization = sign({ auth_id: authId, audience, intent_hash: intentHash(intent), state_hash: stateSnapshotHash(state) });
      return { decision: "ALLOW" as const, reasons: [], authorization: authorization as unknown as Authorization, nextState: state };
    },
    computeStateHash(state: State) { return stateSnapshotHash(state); },
  };
}

function makeState(agent: string): State {
  return buildState({ agent_id: agent, allow_action_types: ["PROVISION"], budget_limit: 1_000_000_000n, max_amount_per_action: 1_000_000_000n, velocity_max_actions: 1000, max_concurrent: 16 });
}

type Entry = "OxDeAIGuard" | "createSecureGuard";
const ENTRIES: readonly Entry[] = ["OxDeAIGuard", "createSecureGuard"];

function directAction(): ProposedAction {
  return { name: "provision_gpu", args: { asset: "a100" }, estimatedCost: 0, context: { agent_id: "agent-1" }, timestampSeconds: T_NOW };
}

function directGuard(entry: Entry, over: Partial<OxDeAIGuardConfig> & { authId?: string } = {}) {
  const events: GuardBoundaryAuditEvent[] = [];
  const state = makeState("agent-1");
  const { authId, ...rest } = over;
  const cfg: OxDeAIGuardConfig = {
    engine: fixedIdEngine(authId ?? `rr01-${randomUUID()}`, "agent-1") as never,
    getState: () => ({ state, version: 0 }), setState: () => true,
    trustedKeySets: [KEYSET], expectedAudience: "agent-1", trustedDelegationAuthorities: AUTHORITIES,
    onBoundaryEvent: (e) => { events.push(e); },
    ...rest,
  };
  let call: (ex: () => Promise<unknown>) => Promise<unknown>;
  if (entry === "OxDeAIGuard") {
    const g = OxDeAIGuard(cfg);
    call = (ex) => g(directAction(), ex);
  } else {
    const g = createSecureGuard(cfg, { tenancy: "single-tenant" });
    const ctx = createTrustedExecutionContext({ principalId: "p-1", agentId: "agent-1", adapterId: "rr01", depth: 0 });
    call = (ex) => g(ctx, directAction(), ex);
  }
  return { call, events };
}

async function attempt(call: (ex: () => Promise<unknown>) => Promise<unknown>) {
  let executed = 0;
  let error: unknown;
  try { await call(async () => { executed++; }); } catch (e) { error = e; }
  return { executed, error };
}

const PARENT_SCOPE = { tools: ["provision_gpu"], max_amount: 1_000_000n };
function parentAuth(): AuthorizationV1 { return sign({ audience: "agent-A", intent_hash: "a".repeat(64) }); }
function childOf(p: AuthorizationV1): DelegationV1 {
  return createDelegation(p, { delegatee: "agent-B", issuer: ISSUER, scope: { tools: ["provision_gpu"], max_amount: 500_000n }, expiry: T_NOW + 300, kid: "k1" }, KP.privateKey.toString());
}
function delegationGuard(entry: Entry, store: ReplayStore) {
  const events: GuardBoundaryAuditEvent[] = [];
  const state = makeState("agent-B");
  const cfg: OxDeAIGuardConfig = {
    engine: fixedIdEngine("unused", "agent-A") as never,
    getState: () => ({ state, version: 0 }), setState: () => true,
    trustedKeySets: [KEYSET], expectedAudience: "agent-A", trustedDelegationAuthorities: AUTHORITIES,
    replayStore: store, onBoundaryEvent: (e) => { events.push(e); },
  };
  const action: ProposedAction = { name: "provision_gpu", args: {}, estimatedCost: 0, context: { agent_id: "agent-B" }, timestampSeconds: T_NOW };
  let call: (ex: () => Promise<unknown>, d: { delegation: DelegationV1; parentAuth: AuthorizationV1 }) => Promise<unknown>;
  if (entry === "OxDeAIGuard") {
    const g = OxDeAIGuard(cfg);
    call = (ex, d) => g(action, ex, { delegation: { ...d, parentScope: PARENT_SCOPE } });
  } else {
    const g = createSecureGuard(cfg, { tenancy: "single-tenant" });
    const ctx = createTrustedExecutionContext({ principalId: "p-B", agentId: "agent-B", adapterId: "rr01", depth: 0 });
    call = (ex, d) => g(ctx, action, ex, { delegation: { ...d, parentScope: PARENT_SCOPE } });
  }
  return { call, events };
}

// ═══════════════════════════════════════════════════════════════════════════
// Guard: every consume site, every answer
// ═══════════════════════════════════════════════════════════════════════════

test("RR-01 Guard direct path: only boolean true executes; false = replay; anything else = REPLAY_STORE_UNAVAILABLE", async (t) => {
  for (const entry of ENTRIES) {
    for (const [label, answer] of ANSWERS) {
      await t.test(`${entry} consumeAuthId -> ${label}`, async () => {
        const store = spyStore({ auth: answer });
        const { call, events } = directGuard(entry, { replayStore: store });
        const r = await attempt(call);
        if (answer === true) {
          assert.equal(r.executed, 1, String(r.error));
          return;
        }
        assert.equal(r.executed, 0, `answer ${label} must not execute`);
        assert.equal(store.calls.length, 1, "consume was reached exactly once");
        assert.equal(events.length, 1);
        assert.equal(events[0].stage, "REPLAY");
        assert.equal(events[0].authorizationConsumed, false);
        if (answer === false) {
          assert.equal(events[0].boundaryFailure, "AUTHORIZATION_REPLAY");
        } else {
          assert.equal(events[0].boundaryFailure, "REPLAY_STORE_UNAVAILABLE");
          assert.match(String((r.error as Error).message), /non-boolean result/);
        }
      });
    }
  }
});

test("RR-01 Guard delegation path: both consume sites (delegation_id and parent auth_id) require boolean true", async (t) => {
  for (const entry of ENTRIES) {
    for (const site of ["deleg", "auth"] as const) {
      for (const [label, answer] of ANSWERS) {
        await t.test(`${entry} ${site === "deleg" ? "consumeDelegationId" : "consumeAuthId(parent)"} -> ${label}`, async () => {
          const store = spyStore({ [site]: answer });
          const { call, events } = delegationGuard(entry, store);
          const p = parentAuth();
          let executed = 0;
          let error: unknown;
          try { await call(async () => { executed++; }, { delegation: childOf(p), parentAuth: p }); } catch (e) { error = e; }
          if (answer === true) {
            assert.equal(executed, 1, String(error));
            return;
          }
          assert.equal(executed, 0, `answer ${label} at ${site} must not execute`);
          assert.equal(events[0]?.stage, "REPLAY");
          const replayCode = site === "deleg" ? "DELEGATION_REPLAY" : "AUTHORIZATION_REPLAY";
          assert.equal(events[0]?.boundaryFailure, answer === false ? replayCode : "REPLAY_STORE_UNAVAILABLE");
          if (site === "deleg") assert.equal(store.calls.filter((c) => c.startsWith("auth:")).length, 0, "parent is not consumed after a delegation-site denial");
        });
      }
    }
  }
});

test("RR-01 Guard: a malformed answer may already have spent the id (denial is not proof of non-consumption)", async () => {
  for (const entry of ENTRIES) {
    // Store records the id, then answers "OK" (Redis-style). Denied, but the id is spent.
    const store = spyStore({ auth: "OK" });
    const authId = `rr01-${randomUUID()}`;
    const g = directGuard(entry, { replayStore: store, authId });
    assert.equal((await attempt(g.call)).executed, 0);
    assert.equal(g.events[0].authorizationConsumed, false, "flag means 'not confirmed consumed'");
    assert.ok(store.recorded.auth.has(authId), "the store did record the id");
    // The same store now answers correctly: the id is already spent, so a retry is a replay.
    delete (store as { consumeAuthId?: unknown }).consumeAuthId;
    (store as ReplayStore).consumeAuthId = async (id) => { const first = !store.recorded.auth.has(id); store.recorded.auth.add(id); return first; };
    const retry = directGuard(entry, { replayStore: store, authId });
    assert.equal((await attempt(retry.call)).executed, 0);
    assert.equal(retry.events[0].boundaryFailure, "AUTHORIZATION_REPLAY");
  }
});

test("RR-01 Guard: provider throws, throws synchronously or rejects -> fail closed, no execution", async () => {
  const impls: Array<[string, ReplayStore["consumeAuthId"]]> = [
    ["async throw", async () => { throw new Error("down"); }],
    ["sync throw", (() => { throw new Error("sync"); }) as never],
    ["rejects", () => Promise.reject(new Error("rejected"))],
  ];
  for (const entry of ENTRIES) {
    for (const [label, consumeAuthId] of impls) {
      const { call, events } = directGuard(entry, { replayStore: { consumeAuthId } });
      const r = await attempt(call);
      assert.equal(r.executed, 0, `${entry} ${label}`);
      assert.equal(events[0].boundaryFailure, "REPLAY_STORE_UNAVAILABLE", `${entry} ${label}`);
    }
  }
});

test("RR-01 Guard: a consume that never resolves never executes (no timeout exists: the call stays pending)", async () => {
  for (const entry of ENTRIES) {
    let executed = 0;
    const { call } = directGuard(entry, { replayStore: { consumeAuthId: () => new Promise<boolean>(() => {}) } });
    const outcome = call(async () => { executed++; }).then(() => "settled", () => "settled");
    const state = await Promise.race([outcome, new Promise((r) => setTimeout(() => r("pending"), 200))]);
    assert.equal(state, "pending", "the guard imposes no timeout on the replay store");
    assert.equal(executed, 0);
  }
});

test("RR-01 Guard: concurrent duplicates, and two instances sharing one store, execute exactly once", async () => {
  for (const entry of ENTRIES) {
    const store = createInMemoryReplayStore();
    const authId = `rr01-${randomUUID()}`;
    const a = directGuard(entry, { replayStore: store, authId });
    const b = directGuard(entry, { replayStore: store, authId });
    let executed = 0;
    await Promise.allSettled([
      ...Array.from({ length: 8 }, () => a.call(async () => { executed++; })),
      ...Array.from({ length: 8 }, () => b.call(async () => { executed++; })),
    ]);
    assert.equal(executed, 1, `${entry}: 16 concurrent presentations over two instances`);
    // Sequential duplicate on either instance is still denied.
    assert.equal((await attempt(a.call)).executed, 0);
    assert.equal((await attempt(b.call)).executed, 0);
  }
});

test("RR-01 Guard (OxDeAIGuard): process-local, shared, shared+strict and legacy replay modes: valid once, duplicate denied", async () => {
  const modes: Array<[string, () => Partial<OxDeAIGuardConfig>]> = [
    ["process-local", () => ({ replayProtection: { mode: "process-local" } })],
    ["shared", () => ({ replayProtection: { mode: "shared", store: spyStore() } })],
    ["shared + strict", () => ({ replayProtection: { mode: "shared", store: spyStore() }, requireExplicitReplayProtection: true })],
    ["legacy replayStore", () => ({ replayStore: createInMemoryReplayStore() })],
  ];
  for (const [label, mk] of modes) {
    const { call } = directGuard("OxDeAIGuard", { ...mk(), authId: `rr01-${randomUUID()}` });
    assert.equal((await attempt(call)).executed, 1, `${label}: valid executes`);
    assert.equal((await attempt(call)).executed, 0, `${label}: duplicate denied`);
  }
});

test("RR-01 Guard: shared + strict with a malformed store denies; no fallback to process-local protection", async () => {
  for (const answer of ["false", 1, {}, "OK"]) {
    const { call, events } = directGuard("OxDeAIGuard", {
      replayProtection: { mode: "shared", store: { consumeAuthId: async () => answer as never } },
      requireExplicitReplayProtection: true,
    });
    assert.equal((await attempt(call)).executed, 0, JSON.stringify(answer));
    assert.equal(events[0].boundaryFailure, "REPLAY_STORE_UNAVAILABLE");
  }
});

test("RR-01 built-in stores answer strict booleans and keep working (in-memory, Redis adapter)", async () => {
  const mem = createInMemoryReplayStore();
  assert.equal(await mem.consumeAuthId("x", { expiry: T_NOW + 60 }), true);
  assert.equal(await mem.consumeAuthId("x", { expiry: T_NOW + 60 }), false);
  const keys = new Set<string>();
  const redis = createRedisReplayStore({ client: { async set(k: string) { if (keys.has(k)) return null; keys.add(k); return "OK"; } } as never });
  assert.equal(await redis.consumeAuthId("y", { expiry: T_NOW + 60 }), true);
  assert.equal(await redis.consumeAuthId("y", { expiry: T_NOW + 60 }), false);
  const { call } = directGuard("OxDeAIGuard", { replayStore: redis, authId: `rr01-${randomUUID()}` });
  assert.equal((await attempt(call)).executed, 1);
  assert.equal((await attempt(call)).executed, 0);
});

// ═══════════════════════════════════════════════════════════════════════════
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
    replayProtection: { mode: "shared", store },
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
    replayProtection: { mode: "shared", store: spyStore({ auth: "false" }) },
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
    replayProtection: { mode: "shared" as const, store: spyStore() },
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
