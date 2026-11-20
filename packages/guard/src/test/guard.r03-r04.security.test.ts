// SPDX-License-Identifier: Apache-2.0
// R-03 / R-04 at the enforcement boundary.
//
// R-03: replay retention must follow the SIGNED effective expiry. Before the
// fix, a signed `expiry: null` artifact produced a 1-second Redis TTL (replay
// after expiry of the key) and a valid Encoding B artifact (no `expiry`)
// produced a NaN TTL (denied).
// R-04: hooks on the delegation path must not receive unsigned engine-HMAC
// legacy fields from an externally supplied parent; unknown fields are denied.
import test from "node:test";
import assert from "node:assert/strict";
import { sign } from "node:crypto";
import { canonicalJson, sha256HexFromJson, signAuthorizationEd25519, createDelegation, PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "@oxdeai/core";
import type { AuthorizationV1, Authorization } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";
import { createPepGatewayExecutor } from "../gateway.js";
import { createRedisReplayStore } from "../replayStore.redis.js";
import { OxDeAIGuard } from "../guard.js";
import { TEST_KEYSET, TEST_KEYPAIR, DELEGATION_AUTHORITIES } from "./helpers/fixtures.js";

const NOW = Math.floor(Date.now() / 1000);
const AUD = "gw-r03";
const POLICY = "p".repeat(64);
const ACTION = { type: "EXECUTE", tool: "payments.charge", params: { amount: "500", currency: "USD" } };

/** Redis mock honouring SET key val NX EX ttl, with a virtual clock. */
function mockRedis() {
  let clock = 0;
  const ttls: unknown[] = [];
  const kv = new Map<string, number>();
  return {
    ttls,
    advance(s: number) { clock += s; },
    client: {
      async set(k: string, _v: string, _nx: string, _ex: string, ttl: number) {
        ttls.push(ttl);
        if (!Number.isInteger(ttl) || ttl <= 0) throw new Error(`ERR invalid expire time (${ttl})`);
        const e = kv.get(k);
        if (e !== undefined && e > clock) return null;
        kv.set(k, clock + ttl);
        return "OK";
      },
    },
  };
}
function gateway(redis: ReturnType<typeof mockRedis>) {
  return createPepGatewayExecutor({
    expectedAudience: AUD,
    trustedKeySets: [TEST_KEYSET],
    internalExecutorToken: "t",
    trustedAuthorizationAuthorities: [{ issuer: TEST_KEYSET.issuer, policyId: POLICY }],
    replayStore: createRedisReplayStore({ client: redis.client as never }),
    executeUpstream: async () => ({ status: 200, body: { ok: true } }),
  });
}
const fields = (id: string) => ({
  auth_id: id, issuer: TEST_KEYSET.issuer, audience: AUD, intent_hash: sha256HexFromJson(ACTION),
  state_hash: "2".repeat(64), policy_id: POLICY, decision: "ALLOW", issued_at: NOW - 5,
});
const signPrefixed = (p: object) =>
  sign(null, Buffer.concat([Buffer.from("OXDEAI_AUTH_V1\n"), Buffer.from(canonicalJson(p))]), TEST_KEYPAIR.privateKey).toString("base64");

test("R-03 gateway: signed expiry:null + unsigned expires_at is denied and never reaches the replay store", async () => {
  const redis = mockRedis();
  const gw = gateway(redis);
  const f = { ...fields(`r03-${Math.random()}`), alg: "Ed25519", kid: "k1", expiry: null };
  const art = { ...f, signature: signPrefixed(f), expires_at: NOW + 10 * 365 * 86400 };
  for (let i = 0; i < 2; i++) {
    const r = await gw({ action: ACTION, authorization: structuredClone(art) });
    assert.equal(r.status, 403);
    assert.equal(r.upstreamCalled, false);
    redis.advance(5);
  }
  assert.equal(redis.ttls.length, 0, "no replay-store write for an unverified artifact");
});

test("R-03 gateway: valid Encoding B artifact uses its signed expires_at for Redis retention and replay is denied", async () => {
  const redis = mockRedis();
  const gw = gateway(redis);
  const meta = { alg: "ed25519", kid: "k1" };
  const f = { ...fields(`encb-${Math.random()}`), expires_at: NOW + 120 };
  const art = { ...f, signature: { ...meta, sig: sign(null, Buffer.from(canonicalJson({ ...f, signature: meta })), TEST_KEYPAIR.privateKey).toString("base64url") } };
  const r1 = await gw({ action: ACTION, authorization: structuredClone(art) });
  assert.equal(r1.status, 200, JSON.stringify(r1.body));
  const ttl = redis.ttls[0] as number;
  assert.ok(Number.isInteger(ttl) && ttl >= 100 && ttl <= 120, `ttl follows signed expires_at, got ${ttl}`);
  redis.advance(5);
  const r2 = await gw({ action: ACTION, authorization: structuredClone(art) });
  assert.equal(r2.status, 403);
  assert.match(String(r2.body.reason), /AUTH_REPLAY|REPLAY/);
});

test("R-03 gateway: Encoding A retention uses signed expiry", async () => {
  const redis = mockRedis();
  const gw = gateway(redis);
  const art = signAuthorizationEd25519({ ...fields(`a-${Math.random()}`), decision: "ALLOW", expiry: NOW + 300, kid: "k1" } as never, TEST_KEYPAIR.privateKey.toString());
  const r = await gw({ action: ACTION, authorization: art });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const ttl = redis.ttls[0] as number;
  assert.ok(ttl >= 280 && ttl <= 300, `ttl ${ttl}`);
});

test("R-03 redis store: non-integer expiry fails closed (throws) instead of a 1s/NaN TTL", async () => {
  const redis = mockRedis();
  const store = createRedisReplayStore({ client: redis.client as never });
  for (const bad of [null, undefined, Number.NaN, "123", 1.5]) {
    await assert.rejects(store.consumeAuthId("x", { expiry: bad as never }), /expiry must be integer/);
  }
  assert.equal(redis.ttls.length, 0);
});

test("R-04 gateway: unsigned scope / delegatee on a validly signed artifact is denied", async () => {
  for (const extra of [{ scope: { tools: ["*"] } }, { delegatee: "attacker" }]) {
    const redis = mockRedis();
    const art = { ...signAuthorizationEd25519({ ...fields(`u-${Math.random()}`), decision: "ALLOW", expiry: NOW + 300, kid: "k1" } as never, TEST_KEYPAIR.privateKey.toString()), ...extra };
    const r = await gateway(redis)({ action: ACTION, authorization: art });
    assert.equal(r.status, 403);
    assert.match(String(r.body.reason), /AUTH_SIGNATURE_INVALID/);
    assert.equal(redis.ttls.length, 0);
  }
});

// ── Delegation path: hooks get no unsigned legacy fields ────────────────────
const PARENT_SCOPE = { tools: ["provision_gpu"], max_amount: 1_000_000n };
function guardWith(hooks: { beforeExecute?: (a: unknown, auth: Authorization) => void; onDecision?: (r: { authorization?: AuthorizationV1 }) => void }) {
  const state = buildState({ agent_id: "agent-B", allow_action_types: ["PROVISION"], budget_limit: 1_000_000_000n,
    max_amount_per_action: 1_000_000_000n, velocity_max_actions: 1000, max_concurrent: 16 });
  return OxDeAIGuard({
    engine: new PolicyEngine({ policy_version: "v1", engine_secret: "test-secret-must-be-at-least-32-chars!!",
      authorization_signing_alg: "Ed25519", authorization_signing_kid: "k1", authorization_issuer: TEST_KEYSET.issuer,
      authorization_audience: "agent-A", authorization_ttl_seconds: 600, authorization_private_key_pem: TEST_KEYPAIR.privateKey.toString(),
      ...RECOMMENDED_TRUSTED_TIME_PROFILE }),
    getState: () => ({ state, version: 0 }), setState: () => true, trustedKeySets: [TEST_KEYSET], expectedAudience: "agent-A",
    trustedDelegationAuthorities: DELEGATION_AUTHORITIES, ...hooks,
  } as never);
}
function parentAndDelegation(unsigned: Record<string, unknown>) {
  const signed = signAuthorizationEd25519({ auth_id: `${Math.random()}`.slice(2).padEnd(64, "f"), issuer: TEST_KEYSET.issuer, audience: "agent-A",
    intent_hash: "a".repeat(64), state_hash: "b".repeat(64), policy_id: "policy-1", decision: "ALLOW", issued_at: NOW - 60, expiry: NOW + 900, kid: "k1" },
  TEST_KEYPAIR.privateKey.toString());
  const parentAuth = { ...signed, ...unsigned } as AuthorizationV1;
  const delegation = createDelegation(parentAuth, { delegatee: "agent-B", issuer: TEST_KEYSET.issuer, scope: {}, expiry: NOW + 300, kid: "k1" }, TEST_KEYPAIR.privateKey.toString());
  return { parentAuth, delegation };
}
const ACTION_D = { name: "provision_gpu", args: { asset: "a100" }, estimatedCost: 0, context: { agent_id: "agent-B", target: "gpu-pool" } };

test("R-04 guard delegation: hooks receive the parent WITHOUT unsigned engine-HMAC legacy fields", async () => {
  const seen: Record<string, unknown>[] = [];
  const guard = guardWith({
    beforeExecute: (_a, auth) => { seen.push(auth as unknown as Record<string, unknown>); },
    onDecision: (r) => { seen.push(r.authorization as unknown as Record<string, unknown>); },
  });
  const { parentAuth, delegation } = parentAndDelegation({ policy_version: "forged", state_snapshot_hash: "f".repeat(64), engine_signature: "0".repeat(64) });
  await guard(ACTION_D as never, async () => {}, { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } } as never);
  assert.equal(seen.length, 2);
  for (const auth of seen) {
    for (const k of ["policy_version", "state_snapshot_hash", "engine_signature"]) assert.equal(k in auth, false, k);
    assert.equal(auth.auth_id, parentAuth.auth_id);
    assert.ok(Object.isFrozen(auth));
  }
});

test("R-04 guard delegation: parent with an unsigned unknown field or conflicting expires_at is denied before hooks", async () => {
  for (const unsigned of [{ scope: { tools: ["*"] } }, { expires_at: NOW + 99999 }]) {
    let hookCalled = false;
    const guard = guardWith({ beforeExecute: () => { hookCalled = true; } });
    const { parentAuth, delegation } = parentAndDelegation(unsigned);
    await assert.rejects(guard(ACTION_D as never, async () => {}, { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } } as never), /AUTH_SIGNATURE_INVALID/);
    assert.equal(hookCalled, false);
  }
});
