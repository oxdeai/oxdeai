// SPDX-License-Identifier: Apache-2.0
/**
 * Legacy PEP gateway hardening:
 *
 *   - custom `hashAction` coverage guard: a request is accepted only if the
 *     custom hash equals the whole-action hash, so no forwarded field can be
 *     left outside `authorization.intent_hash` (`ACTION_HASH_UNCOVERED`);
 *   - bounded request bodies on the HTTP gateway and the protected upstream
 *     (`maxBodyBytes`), rejected in the parsing phase without truncation;
 *   - graceful early rejection: complete response, `Connection: close`,
 *     bounded drain of the remaining upload, then the socket is closed;
 *   - protected upstream authenticates the executor token before reading the
 *     body, with a constant-time comparison.
 *
 * Every test asserts the number of upstream invocations (side effects) and,
 * where relevant, replay-store consumption. Synthetic credentials only.
 */
import test from "node:test";
import type { TestContext } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { request, Agent } from "node:http";
import type { IncomingHttpHeaders, Server } from "node:http";
import type { Socket } from "node:net";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  PolicyEngine,
  RECOMMENDED_TRUSTED_TIME_PROFILE,
  intentHash,
  sha256HexFromJson,
  signAuthorizationEd25519,
} from "@oxdeai/core";
import type { AuthorizationV1, Intent, KeySet, State } from "@oxdeai/core";
import {
  __resetHashActionDeprecationWarningForTests,
  createHttpUpstreamExecutor,
  createPepGatewayExecutor,
  createPepGatewayHttpServer,
  createProtectedUpstreamHttpServer,
  hasValidInternalExecutorToken,
} from "../gateway.js";
import type { PepGatewayOptions, UpstreamExecutor } from "../gateway.js";
import { createInMemoryReplayStore } from "../replayStore.js";
import type { ReplayStore } from "../replayStore.js";

// ── Synthetic material ──────────────────────────────────────────────────────

const KP = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const OTHER_KP = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const ISSUER = "hardening-issuer";
const POLICY = "hardening-policy";
const AUDIENCE = "hardening-gateway";
const TOKEN = "hardening-internal-token-0123456789";
const KEYSET: KeySet = { issuer: ISSUER, version: "v1", keys: [{ kid: "k1", alg: "Ed25519", public_key: KP.publicKey.toString() }] };
const LIMIT = 1024;
const MIB = 1024 * 1024;
const DRAIN_READ_BOUND = 256 * 1024; // 64 KiB drain + kernel read-ahead, against a 10 MiB upload

function signFor(intent_hash: string, key: string = KP.privateKey.toString()): AuthorizationV1 {
  const issued_at = Math.floor(Date.now() / 1000);
  return signAuthorizationEd25519(
    {
      auth_id: `hardening-${randomUUID()}`, issuer: ISSUER, audience: AUDIENCE, intent_hash,
      state_hash: "s".repeat(64), policy_id: POLICY, decision: "ALLOW", issued_at, expiry: issued_at + 600, kid: "k1",
    },
    key
  );
}
const sign = (action: unknown): AuthorizationV1 => signFor(sha256HexFromJson(action));

function action(extra: Record<string, unknown> = {}) {
  return { type: "EXECUTE", tool: "payments.charge", params: { amount: "10", to: "merchant:acme" }, ...extra };
}

type Counters = { upstream: number; consumes: number; received: unknown[] };
function counters(): Counters {
  return { upstream: 0, consumes: 0, received: [] };
}
function recorder(c: Counters): UpstreamExecutor {
  return async (a) => {
    c.upstream++;
    c.received.push(a);
    return { status: 200, body: { ok: true } };
  };
}
function countingStore(c: Counters): ReplayStore {
  const inner = createInMemoryReplayStore();
  return {
    async consumeAuthId(id, opts) {
      c.consumes++;
      return inner.consumeAuthId(id, opts);
    },
  };
}
function gatewayOptions(c: Counters, extra: Partial<PepGatewayOptions> = {}): PepGatewayOptions {
  return {
    expectedAudience: AUDIENCE,
    trustedKeySets: [KEYSET],
    trustedAuthorizationAuthorities: [{ issuer: ISSUER, policyId: POLICY }],
    internalExecutorToken: TOKEN,
    executeUpstream: recorder(c),
    replayProtection: { mode: "shared", store: countingStore(c) },
    ...extra,
  };
}

function captureWarnings(): { codes: () => string[]; stop: () => void } {
  const seen: string[] = [];
  const onWarning = (w: Error & { code?: string }) => seen.push(String(w.code));
  process.on("warning", onWarning);
  return { codes: () => seen.slice(), stop: () => process.off("warning", onWarning) };
}
const tick = () => new Promise((r) => setImmediate(r));

// ── HTTP helpers ────────────────────────────────────────────────────────────

type Listening = { server: Server; port: number; sockets: Socket[]; close: () => Promise<void> };
async function listen(server: Server): Promise<Listening> {
  const sockets: Socket[] = [];
  server.on("connection", (s: Socket) => sockets.push(s));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  return {
    server, port, sockets,
    close: async () => {
      for (const s of sockets) s.destroy();
      await new Promise<void>((r) => server.close(() => r()));
    },
  };
}

type HttpResult = { status: number | null; headers: IncomingHttpHeaders; body: string | null; error?: string };
function post(port: number, path: string, payload: string | Buffer, opts: { headers?: Record<string, string | string[]>; chunked?: boolean; agent?: Agent } = {}): Promise<HttpResult & { reusedSocket?: boolean }> {
  return new Promise((resolve) => {
    const buf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
    const headers: Record<string, string | string[] | number> = { "content-type": "application/json", ...(opts.headers ?? {}) };
    if (!opts.chunked) headers["content-length"] = buf.length;
    const req = request({ host: "127.0.0.1", port, path, method: "POST", headers, agent: opts.agent }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (d) => (data += d));
      res.on("end", () => resolve({ status: res.statusCode ?? null, headers: res.headers, body: data, reusedSocket: req.reusedSocket }));
    });
    req.on("error", (e: NodeJS.ErrnoException) => resolve({ status: null, headers: {}, body: null, error: e.code ?? e.message }));
    if (opts.chunked) {
      // Write in pieces so the body is genuinely chunked on the wire.
      for (let i = 0; i < buf.length; i += 256) req.write(buf.subarray(i, i + 256));
    } else {
      req.write(buf);
    }
    req.end();
  });
}

function get(port: number, path: string, agent?: Agent): Promise<HttpResult & { reusedSocket?: boolean }> {
  return new Promise((resolve) => {
    const req = request({ host: "127.0.0.1", port, path, method: "GET", agent }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (d) => (data += d));
      res.on("end", () => resolve({ status: res.statusCode ?? null, headers: res.headers, body: data, reusedSocket: req.reusedSocket }));
    });
    req.on("error", (e: NodeJS.ErrnoException) => resolve({ status: null, headers: {}, body: null, error: e.code ?? e.message }));
    req.end();
  });
}

/**
 * Upload `size` bytes while the server rejects early. Resolves with the response
 * (if one was delivered), the bytes the server socket read and how long the
 * server took to close the socket after the response.
 */
async function activeUpload(l: Listening, path: string, size: number, opts: { headers?: Record<string, string>; chunked?: boolean } = {}) {
  const before = l.sockets.length;
  const t0 = Date.now();
  const result = await new Promise<HttpResult>((resolve) => {
    let settled = false;
    const done = (r: HttpResult) => {
      if (!settled) {
        settled = true;
        resolve(r);
      }
    };
    const headers: Record<string, string | number> = { "content-type": "application/json", ...(opts.headers ?? {}) };
    if (!opts.chunked) headers["content-length"] = size;
    const req = request({ host: "127.0.0.1", port: l.port, path, method: "POST", headers }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (d) => (data += d));
      res.on("end", () => done({ status: res.statusCode ?? null, headers: res.headers, body: data }));
      res.on("error", () => done({ status: res.statusCode ?? null, headers: res.headers, body: null }));
    });
    req.on("error", (e: NodeJS.ErrnoException) => setTimeout(() => done({ status: null, headers: {}, body: null, error: e.code ?? e.message }), 50));
    const chunk = Buffer.alloc(64 * 1024, 0x20);
    let sent = 0;
    const pump = () => {
      while (sent < size) {
        sent += chunk.length;
        if (!req.write(chunk)) {
          req.once("drain", pump);
          return;
        }
      }
      req.end();
    };
    pump();
    setTimeout(() => done({ status: null, headers: {}, body: null, error: "client-timeout" }), 10_000);
  });
  const socket = l.sockets[before];
  if (socket && !socket.destroyed) await new Promise<void>((r) => { socket.once("close", () => r()); setTimeout(r, 4_000); });
  return { ...result, bytesRead: socket?.bytesRead ?? -1, closed: socket?.destroyed ?? false, elapsedMs: Date.now() - t0 };
}

const parse = (body: string | null): Record<string, unknown> => (body ? (JSON.parse(body) as Record<string, unknown>) : {});

// ── Real PDP for end-to-end cases ───────────────────────────────────────────

const AGENT = "agent-hardening";
const BINDING_FIELDS = ["intent_id", "agent_id", "action_type", "depth", "amount", "asset", "target", "timestamp", "metadata_hash", "nonce", "type", "authorization_id", "tool", "tool_call"];
function freshState(): State {
  return {
    policy_version: "v1", period_id: "p1", kill_switch: { global: false, agents: {} },
    allowlists: { action_types: ["PAYMENT"], assets: [], targets: ["merchant:acme"] },
    budget: { budget_limit: { [AGENT]: 100_000_000n }, spent_in_period: { [AGENT]: 0n } },
    max_amount_per_action: { [AGENT]: 50_000_000n },
    velocity: { config: { window_seconds: 60, max_actions: 100 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { [AGENT]: 50 }, active: {}, active_auths: {} },
    recursion: { max_depth: { [AGENT]: 5 } },
    tool_limits: { window_seconds: 60, max_calls: { [AGENT]: 50 }, calls: {} },
  } as unknown as State;
}
let nonce = 1n;
function pdpIssue(): { projection: Record<string, unknown>; authorization: AuthorizationV1 } {
  const engine = new PolicyEngine({
    policy_version: "v1", engine_secret: "synthetic-engine-secret-at-least-32-chars!!", authorization_ttl_seconds: 120,
    authorization_issuer: ISSUER, authorization_audience: AUDIENCE, authorization_signing_alg: "Ed25519",
    authorization_signing_kid: "k1", authorization_private_key_pem: KP.privateKey.toString(), policyId: POLICY,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  } as unknown as ConstructorParameters<typeof PolicyEngine>[0]);
  const t = Math.floor(Date.now() / 1000);
  const intent = {
    type: "EXECUTE", intent_id: `intent-${nonce}`, agent_id: AGENT, action_type: "PAYMENT", amount: 5_000_000n, asset: "USD",
    target: "merchant:acme", timestamp: t, metadata_hash: "0".repeat(64), nonce: nonce++, signature: "placeholder",
    tool: "payments.charge", tool_call: true,
  } as unknown as Intent;
  const out = engine.evaluate(intent, freshState(), t);
  assert.equal(out.decision, "ALLOW", `PDP denied: ${JSON.stringify(out.reasons)}`);
  const src = intent as unknown as Record<string, unknown>;
  const projection: Record<string, unknown> = {};
  for (const k of BINDING_FIELDS) if (src[k] !== undefined) projection[k] = typeof src[k] === "bigint" ? String(src[k]) : src[k];
  const authorization = JSON.parse(JSON.stringify(out.authorization, (_k, v) => (typeof v === "bigint" ? v.toString() : v))) as AuthorizationV1;
  return { projection, authorization };
}
const projectionHash = (a: unknown) => intentHash(a as Intent);

async function e2e(extra: Partial<PepGatewayOptions>) {
  const ledger: unknown[] = [];
  const upstream = await listen(createProtectedUpstreamHttpServer({ path: "/charge", expectedToken: TOKEN, execute: async (b) => { ledger.push(b); return { ok: true }; } }));
  const c = counters();
  const gw = await listen(createPepGatewayHttpServer({ ...gatewayOptions(c), executeUpstream: createHttpUpstreamExecutor({ hostname: "127.0.0.1", port: upstream.port, path: "/charge" }), ...extra }));
  return { ledger, c, gw, close: async () => { await gw.close(); await upstream.close(); } };
}

// ─────────────────────────────────────────────────────────────────────────────
// Custom hashAction coverage guard
// ─────────────────────────────────────────────────────────────────────────────

test("P0-01 E2E real PDP: projection hashAction with an extra unbound field is denied ACTION_HASH_UNCOVERED; nothing forwarded or consumed", async (t) => {
  t.plan(5);
  const env = await e2e({ hashAction: projectionHash });
  try {
    const { projection, authorization } = pdpIssue();
    const r = await post(env.gw.port, "/execute", JSON.stringify({ action: { ...projection, params: { amount: "999999.00", to: "attacker" } }, authorization }));
    t.assert.equal(r.status, 403);
    t.assert.equal(parse(r.body).reason, "ACTION_HASH_UNCOVERED");
    t.assert.equal(parse(r.body).outcome, "NOT_DISPATCHED");
    t.assert.equal(env.ledger.length, 0);
    t.assert.equal(env.c.consumes, 0);
  } finally {
    await env.close();
  }
});

test("P0-02 E2E real PDP: projection hashAction with the pure binding projection executes once", async (t) => {
  t.plan(4);
  const env = await e2e({ hashAction: projectionHash });
  try {
    const { projection, authorization } = pdpIssue();
    const r = await post(env.gw.port, "/execute", JSON.stringify({ action: projection, authorization }));
    t.assert.equal(r.status, 200, r.body ?? "");
    t.assert.equal(parse(r.body).outcome, "EXECUTED");
    t.assert.equal(env.ledger.length, 1);
    t.assert.equal(env.c.consumes, 1);
  } finally {
    await env.close();
  }
});

test("P0-03 a full-coverage custom digest that differs from the whole-action hash is denied", async (t) => {
  t.plan(3);
  const c = counters();
  const prefixed = (a: unknown) => sha256HexFromJson({ domain: "custom", action: a });
  const exec = createPepGatewayExecutor(gatewayOptions(c, { hashAction: prefixed }));
  const a = action();
  const r = await exec({ action: a, authorization: signFor(prefixed(a)) });
  t.assert.equal(r.body.reason, "ACTION_HASH_UNCOVERED");
  t.assert.equal(c.upstream, 0);
  t.assert.equal(c.consumes, 0);
});

test("P0-04 a throwing hashAction is denied ACTION_CANONICALIZATION_FAILED", async (t) => {
  t.plan(3);
  const c = counters();
  const exec = createPepGatewayExecutor(gatewayOptions(c, { hashAction: () => { throw new Error("boom"); } }));
  const a = action();
  const r = await exec({ action: a, authorization: sign(a) });
  t.assert.equal(r.body.reason, "ACTION_CANONICALIZATION_FAILED:boom");
  t.assert.equal(c.upstream, 0);
  t.assert.equal(c.consumes, 0);
});

test("P0-05 non-string hashAction results (number, String object, Promise) are denied; a rejecting Promise cannot crash the process", async (t) => {
  t.plan(7);
  const unhandled: unknown[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(e);
  process.on("unhandledRejection", onUnhandled);
  try {
    const a = action();
    const results = [
      () => 42,
      () => new String(sha256HexFromJson(a)),
      () => Promise.resolve(sha256HexFromJson(a)),
      () => Promise.reject(new Error("async failure")),
    ];
    const c = counters();
    for (const fn of results) {
      const exec = createPepGatewayExecutor(gatewayOptions(c, { hashAction: fn as unknown as (x: unknown) => string }));
      const r = await exec({ action: a, authorization: sign(a) });
      t.assert.equal(r.body.reason, "ACTION_HASH_UNCOVERED");
    }
    await tick();
    await tick();
    t.assert.equal(c.upstream, 0);
    t.assert.equal(c.consumes, 0);
    t.assert.equal(unhandled.length, 0);
  } finally {
    process.off("unhandledRejection", onUnhandled);
  }
});

test("P0-06 a projection hashAction over an action with a float in a non-binding field is denied by the whole-action hash", async (t) => {
  t.plan(3);
  const c = counters();
  const exec = createPepGatewayExecutor(gatewayOptions(c, { hashAction: projectionHash }));
  const a = { type: "EXECUTE", tool: "payments.charge", params: { ratio: 1.5 } };
  const r = await exec({ action: a, authorization: signFor(projectionHash(a)) });
  t.assert.equal(r.body.reason, "ACTION_CANONICALIZATION_FAILED:FLOAT_NOT_ALLOWED");
  t.assert.equal(c.upstream, 0);
  t.assert.equal(c.consumes, 0);
});

test("P0-07 a non-function hashAction (other than null/undefined) is rejected at construction", (t) => {
  const bad: unknown[] = ["sha256", 1, true, {}, []];
  t.plan(bad.length);
  for (const value of bad) {
    t.assert.throws(() => createPepGatewayExecutor(gatewayOptions(counters(), { hashAction: value as (a: unknown) => string })), /hashAction must be a function/);
  }
});

test("P0-08 no option disables the coverage guard", async (t) => {
  t.plan(3);
  // Compile-time: the options type has no coverage switch (excess-property check).
  const typed: PepGatewayOptions = {
    ...gatewayOptions(counters()),
    // @ts-expect-error - there is no option to disable hashAction coverage
    allowUncoveredHashAction: true,
  };
  void typed;
  // Run-time: unknown keys are ignored; the guard stays active.
  const c = counters();
  const opts = { ...gatewayOptions(c, { hashAction: projectionHash }), allowUncoveredHashAction: true, hashActionCoverage: "off", unsafeHashAction: true } as PepGatewayOptions;
  const exec = createPepGatewayExecutor(opts);
  const a = { ...action(), params: { amount: "999" } };
  const r = await exec({ action: a, authorization: signFor(projectionHash(a)) });
  t.assert.equal(r.body.reason, "ACTION_HASH_UNCOVERED");
  t.assert.equal(c.upstream, 0);
  t.assert.equal(c.consumes, 0);
});

test("P0-09 the deprecation warning is emitted exactly once per process, only when hashAction is a function", async (t) => {
  t.plan(2);
  __resetHashActionDeprecationWarningForTests();
  const w = captureWarnings();
  try {
    createPepGatewayExecutor(gatewayOptions(counters(), { hashAction: null }));
    createPepGatewayExecutor(gatewayOptions(counters()));
    await tick();
    t.assert.deepEqual(w.codes().filter((c) => c === "OXDEAI_DEP_HASH_ACTION"), []);
    createPepGatewayExecutor(gatewayOptions(counters(), { hashAction: sha256HexFromJson }));
    createPepGatewayExecutor(gatewayOptions(counters(), { hashAction: sha256HexFromJson }));
    createPepGatewayExecutor(gatewayOptions(counters(), { hashAction: projectionHash }));
    await tick();
    t.assert.deepEqual(w.codes().filter((c) => c === "OXDEAI_DEP_HASH_ACTION"), ["OXDEAI_DEP_HASH_ACTION"]);
  } finally {
    w.stop();
  }
});

test("P0-10 the coverage guard runs before authorization verification and never touches replay state", async (t) => {
  t.plan(3);
  const c = counters();
  const exec = createPepGatewayExecutor(gatewayOptions(c, { hashAction: projectionHash }));
  const a = { ...action(), params: { amount: "999" } };
  const forged = signFor(projectionHash(a), OTHER_KP.privateKey.toString()); // untrusted key: would fail verification
  const r = await exec({ action: a, authorization: forged });
  t.assert.equal(r.body.reason, "ACTION_HASH_UNCOVERED");
  t.assert.equal(c.consumes, 0);
  t.assert.equal(c.upstream, 0);
});

// ─────────────────────────────────────────────────────────────────────────────
// Bounded bodies, parsing phase, graceful rejection (gateway)
// ─────────────────────────────────────────────────────────────────────────────

async function gatewayHttp(extra: Partial<PepGatewayOptions> = {}) {
  const c = counters();
  const l = await listen(createPepGatewayHttpServer(gatewayOptions(c, { maxBodyBytes: LIMIT, ...extra })));
  return { c, l };
}
function assertParsingPhaseDenial(t: TestContext, r: HttpResult, reason: string): void {
  const b = parse(r.body);
  t.assert.equal(r.status, 403);
  t.assert.equal(b.reason, reason);
  t.assert.equal(b.decision, "DENY");
  t.assert.equal(b.outcome, "NOT_DISPATCHED");
  t.assert.equal(b.executed, false);
}

test("P0-11 gateway: Content-Length above the limit is rejected BODY_TOO_LARGE with Connection: close; nothing dispatched or consumed", async (t) => {
  t.plan(8);
  const { c, l } = await gatewayHttp();
  try {
    const r = await post(l.port, "/execute", Buffer.alloc(LIMIT + 1, 0x20));
    assertParsingPhaseDenial(t, r, "BODY_TOO_LARGE");
    t.assert.equal(r.headers.connection, "close");
    t.assert.equal(c.upstream, 0);
    t.assert.equal(c.consumes, 0);
  } finally {
    await l.close();
  }
});

test("P0-12 gateway: a chunked body exceeding the limit is rejected BODY_TOO_LARGE; nothing dispatched or consumed", async (t) => {
  t.plan(7);
  const { c, l } = await gatewayHttp();
  try {
    const r = await post(l.port, "/execute", Buffer.alloc(LIMIT * 4, 0x20), { chunked: true });
    assertParsingPhaseDenial(t, r, "BODY_TOO_LARGE");
    t.assert.equal(c.upstream, 0);
    t.assert.equal(c.consumes, 0);
  } finally {
    await l.close();
  }
});

function paddedRequest(size: number): Buffer {
  const a = action();
  const json = JSON.stringify({ action: a, authorization: sign(a) });
  assert.ok(json.length <= size, `request ${json.length} exceeds ${size}`);
  return Buffer.concat([Buffer.from(json), Buffer.alloc(size - json.length, 0x20)]);
}

test("P0-13 gateway: a valid request of exactly maxBodyBytes is processed normally", async (t) => {
  t.plan(3);
  const { c, l } = await gatewayHttp({ maxBodyBytes: 4096 });
  try {
    const r = await post(l.port, "/execute", paddedRequest(4096));
    t.assert.equal(r.status, 200, r.body ?? "");
    t.assert.equal(parse(r.body).outcome, "EXECUTED");
    t.assert.equal(c.upstream, 1);
  } finally {
    await l.close();
  }
});

test("P0-14 maxBodyBytes outside 1024..67108864 or not a safe integer is rejected at construction (gateway and upstream)", (t) => {
  const bad: unknown[] = [0, 1023, 64 * MIB + 1, Infinity, 1.5, "1048576", -1, NaN];
  t.plan(bad.length * 2);
  for (const v of bad) {
    t.assert.throws(() => createPepGatewayHttpServer(gatewayOptions(counters(), { maxBodyBytes: v as number })), /maxBodyBytes/);
    t.assert.throws(() => createProtectedUpstreamHttpServer({ expectedToken: TOKEN, execute: () => null, maxBodyBytes: v as number }), /maxBodyBytes/);
  }
});

test("P0-15 maxBodyBytes boundary values 1024 and 67108864 are accepted", (t) => {
  t.plan(4);
  for (const v of [1024, 64 * MIB]) {
    t.assert.doesNotThrow(() => createPepGatewayHttpServer(gatewayOptions(counters(), { maxBodyBytes: v })).close());
    t.assert.doesNotThrow(() => createProtectedUpstreamHttpServer({ expectedToken: TOKEN, execute: () => null, maxBodyBytes: v }).close());
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Protected upstream: token before body, bounded body, constant-time token
// ─────────────────────────────────────────────────────────────────────────────

async function upstreamHttp(extra: { maxBodyBytes?: number } = {}) {
  const calls: unknown[] = [];
  const l = await listen(createProtectedUpstreamHttpServer({ path: "/execute", expectedToken: TOKEN, execute: async (b) => { calls.push(b); return { ok: true }; }, ...extra }));
  return { calls, l };
}

test("P0-16 upstream: a 10 MiB upload without a token gets a complete 403 before the body is read; execute not called", async (t) => {
  t.plan(5);
  const { calls, l } = await upstreamHttp();
  try {
    const r = await activeUpload(l, "/execute", 10 * MIB);
    t.assert.equal(r.status, 403, String(r.error));
    t.assert.equal(parse(r.body).error, "missing or invalid internal executor token");
    t.assert.equal(r.headers.connection, "close");
    t.assert.equal(r.bytesRead >= 0 && r.bytesRead <= DRAIN_READ_BOUND, true, `server read ${r.bytesRead} bytes`);
    t.assert.equal(calls.length, 0);
  } finally {
    await l.close();
  }
});

test("P0-17 upstream: a wrong token of the same length is rejected; execute not called", async (t) => {
  t.plan(2);
  const { calls, l } = await upstreamHttp();
  try {
    const wrong = "x".repeat(TOKEN.length);
    const r = await post(l.port, "/execute", "{}", { headers: { "x-internal-executor-token": wrong } });
    t.assert.equal(r.status, 403);
    t.assert.equal(calls.length, 0);
  } finally {
    await l.close();
  }
});

test("P0-18 upstream: a valid token with a body above the limit gets 413 BODY_TOO_LARGE; execute not called", async (t) => {
  t.plan(3);
  const { calls, l } = await upstreamHttp({ maxBodyBytes: LIMIT });
  try {
    const r = await post(l.port, "/execute", Buffer.alloc(LIMIT + 1, 0x20), { headers: { "x-internal-executor-token": TOKEN } });
    t.assert.equal(r.status, 413);
    t.assert.equal(parse(r.body).error, "BODY_TOO_LARGE");
    t.assert.equal(calls.length, 0);
  } finally {
    await l.close();
  }
});

test("P0-19 upstream: a valid token with a small body executes once with the parsed body", async (t) => {
  t.plan(3);
  const { calls, l } = await upstreamHttp();
  try {
    const r = await post(l.port, "/execute", JSON.stringify({ amount: "5" }), { headers: { "x-internal-executor-token": TOKEN } });
    t.assert.equal(r.status, 200);
    t.assert.equal(calls.length, 1);
    t.assert.deepEqual(calls[0], { amount: "5" });
  } finally {
    await l.close();
  }
});

test("P0-20 a non-matching path with a 10 MiB upload gets a complete 404 and a bounded drain (gateway and upstream)", async (t) => {
  t.plan(6);
  const gw = await gatewayHttp();
  const up = await upstreamHttp();
  try {
    for (const l of [gw.l, up.l]) {
      const r = await activeUpload(l, "/other", 10 * MIB);
      t.assert.equal(r.status, 404, String(r.error));
      t.assert.equal(parse(r.body).error, "not found");
      t.assert.equal(r.bytesRead >= 0 && r.bytesRead <= DRAIN_READ_BOUND, true, `server read ${r.bytesRead} bytes`);
    }
  } finally {
    await gw.l.close();
    await up.l.close();
  }
});

test("P0-21 bodiless requests keep keep-alive: no Connection: close and the socket is reused", async (t) => {
  t.plan(5);
  const { l } = await gatewayHttp();
  const agent = new Agent({ keepAlive: true, maxSockets: 1 });
  try {
    const first = await get(l.port, "/healthz", agent);
    const second = await get(l.port, "/healthz", agent);
    t.assert.equal(first.status, 200);
    t.assert.notEqual(first.headers.connection, "close");
    t.assert.equal(second.status, 200);
    t.assert.equal(second.reusedSocket, true);
    const notFound = await get(l.port, "/missing", agent);
    t.assert.notEqual(notFound.headers.connection, "close");
  } finally {
    agent.destroy();
    await l.close();
  }
});

test("P0-22 hasValidInternalExecutorToken: absent, duplicated, empty, wrong, prefix and correct values", (t) => {
  t.plan(7);
  t.assert.equal(hasValidInternalExecutorToken({}, TOKEN), false);
  t.assert.equal(hasValidInternalExecutorToken({ "x-internal-executor-token": [TOKEN, TOKEN] }, TOKEN), false);
  t.assert.equal(hasValidInternalExecutorToken({ "x-internal-executor-token": "" }, TOKEN), false);
  t.assert.equal(hasValidInternalExecutorToken({ "x-internal-executor-token": "wrong" }, TOKEN), false);
  t.assert.equal(hasValidInternalExecutorToken({ "x-internal-executor-token": TOKEN.slice(0, -1) }, TOKEN), false);
  t.assert.equal(hasValidInternalExecutorToken({ "x-internal-executor-token": TOKEN }, TOKEN), true);
  t.assert.equal(hasValidInternalExecutorToken({ "x-internal-executor-token": [TOKEN] }, TOKEN), true);
});

test("P0-22b the executor-token check uses a constant-time digest comparison", (t) => {
  t.plan(2);
  const source = readFileSync(fileURLToPath(new URL("../../src/gateway.ts", import.meta.url)), "utf8");
  const fn = source.slice(source.indexOf("export function hasValidInternalExecutorToken"), source.indexOf("export async function protectUpstreamExecution"));
  t.assert.match(fn, /timingSafeEqual\(/);
  t.assert.doesNotMatch(fn, /===\s*expectedToken/);
});

test("P0-23 hasValidInternalExecutorToken keeps its non-empty expectedToken precondition", (t) => {
  t.plan(1);
  t.assert.throws(() => hasValidInternalExecutorToken({ "x-internal-executor-token": "" }, ""), /expectedToken is required/);
});

test("P0-24 the protected upstream server rejects an empty expectedToken at construction", (t) => {
  t.plan(1);
  t.assert.throws(() => createProtectedUpstreamHttpServer({ expectedToken: "", execute: () => null }), /expectedToken is required/);
});

// ─────────────────────────────────────────────────────────────────────────────
// Additions from the final design review
// ─────────────────────────────────────────────────────────────────────────────

test("P0-27 gateway: an oversized chunked body whose first maxBodyBytes form a complete valid request is rejected, never truncated and parsed", async (t) => {
  t.plan(7);
  const { c, l } = await gatewayHttp({ maxBodyBytes: 4096 });
  try {
    // The first 4096 bytes are a valid, correctly signed request; the body continues past the limit.
    const body = Buffer.concat([paddedRequest(4096), Buffer.alloc(8192, 0x20)]);
    const r = await post(l.port, "/execute", body, { chunked: true });
    assertParsingPhaseDenial(t, r, "BODY_TOO_LARGE");
    t.assert.equal(c.upstream, 0);
    t.assert.equal(c.consumes, 0);
  } finally {
    await l.close();
  }
});

test("P0-28 gateway: BODY_TOO_LARGE is a parsing-phase denial for both Content-Length and chunked bodies, never UNKNOWN/INDETERMINATE", async (t) => {
  t.plan(7);
  const { c, l } = await gatewayHttp();
  try {
    for (const chunked of [false, true]) {
      // A complete, validly signed request of 2048 bytes against a 1024-byte limit.
      const r = await post(l.port, "/execute", paddedRequest(2048), { chunked });
      const b = parse(r.body);
      t.assert.equal(b.reason, "BODY_TOO_LARGE");
      t.assert.notEqual(b.decision, "UNKNOWN");
      t.assert.notEqual(b.outcome, "INDETERMINATE");
    }
    t.assert.equal(c.upstream + c.consumes, 0);
  } finally {
    await l.close();
  }
});

test("P0-29 hashAction null/undefined keep the default whole-action hash: no warning, no coverage denial", async (t) => {
  t.plan(5);
  __resetHashActionDeprecationWarningForTests();
  const w = captureWarnings();
  try {
    for (const hashAction of [null, undefined]) {
      const c = counters();
      const exec = createPepGatewayExecutor(gatewayOptions(c, { hashAction }));
      const a = action({ extra: { note: "signed over the whole action" } });
      const r = await exec({ action: a, authorization: sign(a) });
      t.assert.equal(r.body.outcome, "EXECUTED", String(r.body.reason));
      t.assert.equal(c.upstream, 1);
    }
    await tick();
    t.assert.deepEqual(w.codes().filter((c) => c === "OXDEAI_DEP_HASH_ACTION"), []);
  } finally {
    w.stop();
  }
});

test("P0-30 upstream: a duplicated executor-token header is rejected before the body is read; execute not called", async (t) => {
  t.plan(2);
  const { calls, l } = await upstreamHttp();
  try {
    const r = await post(l.port, "/execute", "{}", { headers: { "x-internal-executor-token": [TOKEN, TOKEN] } });
    t.assert.equal(r.status, 403);
    t.assert.equal(calls.length, 0);
  } finally {
    await l.close();
  }
});

test("P0-31 hashAction is captured at construction: reassigning options.hashAction later has no effect", async (t) => {
  t.plan(4);
  // Constructed without hashAction; installing a permissive one later must not change anything.
  const c1 = counters();
  const o1 = gatewayOptions(c1);
  const exec1 = createPepGatewayExecutor(o1);
  o1.hashAction = () => "0".repeat(64);
  const a = action();
  const r1 = await exec1({ action: a, authorization: sign(a) });
  t.assert.equal(r1.body.outcome, "EXECUTED");
  // Constructed with the guard; removing hashAction later must not disable it.
  const c2 = counters();
  const o2 = gatewayOptions(c2, { hashAction: projectionHash });
  const exec2 = createPepGatewayExecutor(o2);
  o2.hashAction = undefined;
  const b = { ...action(), params: { amount: "999" } };
  const r2 = await exec2({ action: b, authorization: sign(b) });
  t.assert.equal(r2.body.reason, "ACTION_HASH_UNCOVERED");
  t.assert.equal(c2.upstream, 0);
  t.assert.equal(c2.consumes, 0);
});

test("P0-32 graceful rejection under active upload: 20 x 10 MiB uploads each get the complete 403, a bounded read and a closed socket (gateway and upstream)", async (t) => {
  const RUNS = 20;
  t.plan(RUNS * 2 * 4);
  const gw = await gatewayHttp();
  const up = await upstreamHttp();
  try {
    for (let i = 0; i < RUNS; i++) {
      for (const [l, expectBody] of [[gw.l, "BODY_TOO_LARGE"], [up.l, "missing or invalid internal executor token"]] as const) {
        const r = await activeUpload(l, "/execute", 10 * MIB);
        const b = parse(r.body);
        t.assert.equal(r.status, 403, `run ${i}: ${String(r.error)}`);
        t.assert.equal(b.reason ?? b.error, expectBody);
        t.assert.equal(r.bytesRead >= 0 && r.bytesRead <= DRAIN_READ_BOUND, true, `run ${i}: server read ${r.bytesRead} bytes`);
        t.assert.equal(r.closed, true, `run ${i}: socket not closed`);
      }
    }
  } finally {
    await gw.l.close();
    await up.l.close();
  }
});

test("P0-33 gateway: invalid JSON within the limit is still INVALID_JSON (parsing phase)", async (t) => {
  t.plan(6);
  const { c, l } = await gatewayHttp();
  try {
    const r = await post(l.port, "/execute", "{not json");
    assertParsingPhaseDenial(t, r, "INVALID_JSON");
    t.assert.equal(c.upstream, 0);
  } finally {
    await l.close();
  }
});

test("P0-35 gateway: a declared Content-Length above the limit is rejected before the body is buffered (default 1 MiB limit, 10 MiB upload)", async (t) => {
  t.plan(4);
  const c = counters();
  const l = await listen(createPepGatewayHttpServer(gatewayOptions(c))); // default maxBodyBytes = 1 MiB
  try {
    const r = await activeUpload(l, "/execute", 10 * MIB);
    t.assert.equal(r.status, 403, String(r.error));
    t.assert.equal(parse(r.body).reason, "BODY_TOO_LARGE");
    // Without the Content-Length pre-check the server would buffer up to the 1 MiB limit first.
    t.assert.equal(r.bytesRead >= 0 && r.bytesRead <= DRAIN_READ_BOUND, true, `server read ${r.bytesRead} bytes`);
    t.assert.equal(c.upstream + c.consumes, 0);
  } finally {
    await l.close();
  }
});

test("P0-34 createPepGatewayExecutor ignores maxBodyBytes (only the HTTP server validates it)", async (t) => {
  t.plan(2);
  const c = counters();
  const exec = createPepGatewayExecutor(gatewayOptions(c, { maxBodyBytes: 0 }));
  const a = action();
  const r = await exec({ action: a, authorization: sign(a) });
  t.assert.equal(r.body.outcome, "EXECUTED");
  t.assert.equal(c.upstream, 1);
});
