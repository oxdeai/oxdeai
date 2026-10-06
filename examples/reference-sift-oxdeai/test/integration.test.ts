// SPDX-License-Identifier: Apache-2.0
// Sequential sandbox: the actual upstream counter is the effect oracle.
import { test } from "node:test";
import assert from "node:assert/strict";
import { startTestHarness, signAuthorization, type TestContext } from "./harness.js";
import { MemoryReplayStore } from "../packages/replay-store/index.js";
import { fetchSiftReceipt, callPepGateway } from "../apps/agent/client.js";
import { siftCanonicalJsonHash } from "../shared/canonical.js";

const PARAMS = { amount: 100, destination: "safe_account" };
class ObservedReplayStore extends MemoryReplayStore {
  attempts: string[] = [];
  override async consumeAuthId(id: string, expiry: number): Promise<boolean> {
    this.attempts.push(id);
    return super.consumeAuthId(id, expiry);
  }
}
async function authorize(ctx: TestContext, state = ctx.readCounter()) {
  const envelope = await fetchSiftReceipt(ctx.mockSiftUrl, "transfer");
  const result = await ctx.adapter.adapt({ kidAndReceipt: envelope, params: PARAMS, state });
  assert.ok(result.ok, !result.ok ? result.message : "");
  return result;
}
type Authorized = Awaited<ReturnType<typeof authorize>>;
function execute(ctx: TestContext, auth: Authorized, intent: unknown = auth.intent, state: unknown = auth.state) {
  return callPepGateway(ctx.pepUrl, intent, state, auth.authorization);
}
function rejected(response: { status: number; body: unknown }, code: string, status = 403) {
  assert.equal(response.status, status);
  assert.equal((response.body as { code: string }).code, code);
}

// Each test owns fresh servers, counter and replay store. No public reset route.
test("ALLOW: counter 0 -> 1; detached snapshots cannot mutate the store", async (t) => {
  const ctx = await startTestHarness(); t.after(() => ctx.close());
  const snapshot = ctx.readCounter(); snapshot.counter = 99;
  assert.deepEqual(ctx.readCounter(), { counter: 0 });
  const auth = await authorize(ctx);
  assert.equal(auth.authorization.state_hash, siftCanonicalJsonHash({ counter: 0 }));
  const response = await execute(ctx, auth);
  assert.equal(response.status, 200);
  assert.equal((response.body as { ok?: boolean }).ok, true);
  assert.equal((response.body as { counter: number }).counter, 1);
  assert.deepEqual(ctx.readCounter(), { counter: 1 });
});
test("DENY: DENY_DECISION and zero effect", async (t) => {
  const ctx = await startTestHarness(); t.after(() => ctx.close());
  const envelope = await fetchSiftReceipt(ctx.mockSiftUrl, "transfer", "DENY");
  const result = await ctx.adapter.adapt({ kidAndReceipt: envelope, params: PARAMS, state: ctx.readCounter() });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.code, "DENY_DECISION");
  assert.deepEqual(ctx.readCounter(), { counter: 0 });
});
test("POST-AUTHORIZATION MUTATION: INTENT_HASH_MISMATCH, no effect or replay consumption", async (t) => {
  const store = new ObservedReplayStore();
  const ctx = await startTestHarness({ replayStore: store }); t.after(() => ctx.close());
  const auth = await authorize(ctx);
  rejected(await execute(ctx, auth, { ...auth.intent, params: { amount: 999_999, destination: "attacker_account" } }), "INTENT_HASH_MISMATCH");
  assert.deepEqual(ctx.readCounter(), { counter: 0 });
  assert.equal(store.attempts.length, 0);
});
test("STALE LIVE STATE: authorization at 0, store at 1, STATE_HASH_MISMATCH", async (t) => {
  const ctx = await startTestHarness(); t.after(() => ctx.close());
  const auth = await authorize(ctx);
  ctx.setCounterForTest(1);
  rejected(await execute(ctx, auth, auth.intent, ctx.readCounter()), "STATE_HASH_MISMATCH");
  assert.deepEqual(ctx.readCounter(), { counter: 1 });
});
test("FAKE CALLER STATE: matching stale request state cannot override live state", async (t) => {
  const ctx = await startTestHarness(); t.after(() => ctx.close());
  const auth = await authorize(ctx);
  ctx.setCounterForTest(1);
  rejected(await execute(ctx, auth, auth.intent, { counter: 0 }), "STATE_HASH_MISMATCH");
  assert.deepEqual(ctx.readCounter(), { counter: 1 });
});
test("ORDINARY REPLAY: changed counter rejects before a second replay consume", async (t) => {
  const store = new ObservedReplayStore();
  const ctx = await startTestHarness({ replayStore: store }); t.after(() => ctx.close());
  const auth = await authorize(ctx);
  assert.equal((await execute(ctx, auth)).status, 200);
  assert.deepEqual(store.attempts, [auth.authorization.auth_id]);
  rejected(await execute(ctx, auth), "STATE_HASH_MISMATCH");
  assert.deepEqual(store.attempts, [auth.authorization.auth_id]);
  assert.deepEqual(ctx.readCounter(), { counter: 1 });
});
test("ISOLATED REPLAY: trusted reset preserves replay store; REPLAY_DETECTED, no second effect", async (t) => {
  const store = new ObservedReplayStore();
  const ctx = await startTestHarness({ replayStore: store }); t.after(() => ctx.close());
  const original = ctx.readCounter();
  const auth = await authorize(ctx, original);
  assert.equal((await execute(ctx, auth)).status, 200);
  assert.deepEqual(ctx.readCounter(), { counter: 1 });
  ctx.setCounterForTest(original.counter);
  rejected(await execute(ctx, auth), "REPLAY_DETECTED");
  assert.deepEqual(store.attempts, [auth.authorization.auth_id, auth.authorization.auth_id]);
  assert.deepEqual(ctx.readCounter(), original);
});
for (const failure of ["throw", "invalid state"] as const) {
  test(`TRUSTED ACCESSOR ${failure}: fail closed before replay or effect`, async (t) => {
    const store = new ObservedReplayStore();
    const ctx = await startTestHarness({ replayStore: store, getExecutionState: async () => {
      if (failure === "throw") throw new Error("store unavailable");
      return { counter: 0.5 };
    } }); t.after(() => ctx.close());
    const auth = await authorize(ctx);
    const response = await execute(ctx, auth);
    rejected(response, "STATE_HASH_MISMATCH");
    assert.equal((response.body as { message: string }).message,
      "Failed to obtain or normalize trusted execution state");
    assert.deepEqual(ctx.readCounter(), { counter: 0 });
    assert.equal(store.attempts.length, 0);
  });
}
test("BYPASS: FORBIDDEN and zero effect; reset is not an external capability", async (t) => {
  const ctx = await startTestHarness(); t.after(() => ctx.close());
  for (const route of ["execute", "reset"]) {
    const response = await fetch(`${ctx.upstreamUrl}/${route}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tool: "transfer",
        params: { amount: 999_999, destination: "attacker_account" },
      }),
    });
    rejected({ status: response.status, body: await response.json() }, "FORBIDDEN");
    assert.deepEqual(ctx.readCounter(), { counter: 0 });
  }
});
test("AUTHENTICATED RESET: valid internal token reaches routing; no reset route or effect", async (t) => {
  const ctx = await startTestHarness(); t.after(() => ctx.close());
  ctx.setCounterForTest(1);
  const before = ctx.readCounter();
  const response = await fetch(`${ctx.upstreamUrl}/reset`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-internal-executor-token": ctx.internalToken,
    },
    body: JSON.stringify({ counter: 0 }),
  });
  rejected({ status: response.status, body: await response.json() }, "NOT_FOUND", 404);
  assert.deepEqual(ctx.readCounter(), before);
});
test("PRE-ISSUANCE MUTATION: receipt accepts changed params; new auth binds changed intent", async (t) => {
  const ctx = await startTestHarness(); t.after(() => ctx.close());
  const envelope = await fetchSiftReceipt(ctx.mockSiftUrl, "transfer");
  const changed = { amount: 999_999, destination: "attacker_account" };
  const base = { kidAndReceipt: envelope, state: ctx.readCounter() };
  const original = await ctx.adapter.adapt({ ...base, params: PARAMS });
  const modified = await ctx.adapter.adapt({ ...base, params: changed });
  assert.ok(original.ok); assert.ok(modified.ok);
  assert.deepEqual(JSON.parse(JSON.stringify(modified.intent.params)), changed);
  assert.equal(modified.authorization.auth_id, original.authorization.auth_id);
  assert.notEqual(modified.authorization.intent_hash, original.authorization.intent_hash);
  assert.equal(modified.authorization.intent_hash, siftCanonicalJsonHash(modified.intent));
  // The receipt did not bind params. The adapter's newly signed intent does.
  assert.equal((await execute(ctx, modified)).status, 200);
  assert.deepEqual(ctx.readCounter(), { counter: 1 });
});
test("AUDIENCE_MISMATCH: correctly signed wrong audience has zero effect", async (t) => {
  const ctx = await startTestHarness(); t.after(() => ctx.close());
  const auth = await authorize(ctx);
  const changed = signAuthorization({ ...auth.authorization, audience: "wrong-pep" }, ctx.adapterPrivateKey);
  rejected(await callPepGateway(ctx.pepUrl, auth.intent, auth.state, changed), "AUDIENCE_MISMATCH");
  assert.deepEqual(ctx.readCounter(), { counter: 0 });
});
test("EXPIRED: expired authorization has zero effect", async (t) => {
  const ctx = await startTestHarness(); t.after(() => ctx.close());
  const envelope = await fetchSiftReceipt(ctx.mockSiftUrl, "transfer");
  const pastNow = new Date(Date.now() - 60_000);
  const auth = await ctx.adapter.adapt({
    kidAndReceipt: envelope,
    params: PARAMS,
    state: ctx.readCounter(),
    now: pastNow,
  });
  assert.ok(auth.ok, !auth.ok ? auth.message : "");
  assert.ok(auth.authorization.expires_at <= Math.floor(Date.now() / 1000));
  rejected(await callPepGateway(ctx.pepUrl, auth.intent, auth.state, auth.authorization), "EXPIRED");
  assert.deepEqual(ctx.readCounter(), { counter: 0 });
});
