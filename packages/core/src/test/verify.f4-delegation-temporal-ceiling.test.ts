// SPDX-License-Identifier: Apache-2.0
//
// Lot A regression tests (core delegation artifact and ceiling validation):
//   F4-R6-03 / F4-R8-02 - delegation temporal validity: `expiry` MUST be
//                         strictly greater than `issued_at` (delegation-v1
//                         §4.3), and `issued_at` MUST NOT be implausibly far in
//                         the future (same contract as AUTH_ISSUED_AT_IMPLAUSIBLE).
//   F4-R6-06 / C9       - a supplied parentScope ceiling is validated before
//                         narrowing; NaN / Infinity / fractional / negative /
//                         wrongly typed ceilings fail closed.
// All timestamps are fixed; synthetic keys only.

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { createDelegation } from "../delegation/createDelegation.js";
import { verifyDelegation, verifyDelegationChain } from "../verification/verifyDelegation.js";
import type { VerifyDelegationOptions } from "../verification/verifyDelegation.js";
import { signAuthorizationEd25519, verifyAuthorization, DEFAULT_MAX_FUTURE_ISSUED_AT_SKEW_SECONDS } from "../verification/verifyAuthorization.js";
import type { AuthorizationV1 } from "../types/authorization.js";
import type { DelegationScope, DelegationV1 } from "../types/delegation.js";
import type { KeySet } from "../types/keyset.js";

const NOW = 1_700_000_000;
const PARENT_EXP = NOW + 86_400;
const SKEW = DEFAULT_MAX_FUTURE_ISSUED_AT_SKEW_SECONDS;
const keys = generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
const KEYSETS: KeySet[] = [{ issuer: "agent-A", version: "1", keys: [{ kid: "k1", alg: "Ed25519", public_key: keys.publicKey, status: "active" }] }];

const parent: AuthorizationV1 = signAuthorizationEd25519({
  version: "AuthorizationV1", auth_id: "p".repeat(64), issuer: "central", audience: "agent-A",
  intent_hash: "a".repeat(64), state_hash: "b".repeat(64), policy_id: "P1",
  decision: "ALLOW", issued_at: NOW - 10, expiry: PARENT_EXP, kid: "central-k",
}, keys.privateKey) as AuthorizationV1;

function deleg(issuedAt: number, expiry: number, scope: DelegationScope = { tools: ["transfer"], max_amount: 100n }): DelegationV1 {
  return createDelegation(parent, { delegatee: "agent-B", scope, expiry, kid: "k1", issuedAt, delegationId: `d-${issuedAt}-${expiry}` }, keys.privateKey);
}
const base: VerifyDelegationOptions = { now: NOW, trustedKeySets: KEYSETS, requireSignatureVerification: true };
const codes = (r: { violations: { code: string }[] }) => r.violations.map((v) => v.code);

// ── Temporal validity ────────────────────────────────────────────────────────

test("A-T1 inverted interval (issued_at > expiry) is DELEGATION_TEMPORAL_INVALID, both entry points", () => {
  const d = deleg(NOW + 200, NOW + 100);
  for (const r of [verifyDelegation(d, base), verifyDelegationChain(d, parent, base)]) {
    assert.equal(r.ok, false);
    assert.deepEqual(codes(r), ["DELEGATION_TEMPORAL_INVALID"], JSON.stringify(r.violations));
  }
});

test("A-T2 empty interval (expiry == issued_at) is DELEGATION_TEMPORAL_INVALID", () => {
  const d = deleg(NOW - 5, NOW + 0 + 100);
  assert.equal(verifyDelegation(d, base).ok, true, "control: positive interval");
  const eq = deleg(NOW + 100, NOW + 100);
  assert.deepEqual(codes(verifyDelegationChain(eq, parent, base)), ["DELEGATION_TEMPORAL_INVALID"]);
});

test("A-T3 smallest valid interval (expiry == issued_at + 1) is accepted", () => {
  const d = deleg(NOW, NOW + 1);
  const r = verifyDelegationChain(d, parent, base);
  assert.equal(r.ok, true, JSON.stringify(r.violations));
});

test("A-T4 future issued_at beyond the default skew is DELEGATION_ISSUED_AT_IMPLAUSIBLE (10 years)", () => {
  const d = deleg(NOW + 10 * 365 * 86_400, PARENT_EXP);
  // expiry < issued_at here as well; both defects are reported, sorted.
  const r = verifyDelegationChain(d, parent, base);
  assert.deepEqual(codes(r), ["DELEGATION_ISSUED_AT_IMPLAUSIBLE", "DELEGATION_TEMPORAL_INVALID"]);
});

test("A-T5 exact skew boundaries: now+skew accepted, now+skew+1 rejected (default 300s)", () => {
  assert.equal(SKEW, 300);
  const atBoundary = deleg(NOW + SKEW, NOW + SKEW + 60);
  assert.equal(verifyDelegationChain(atBoundary, parent, base).ok, true);
  const beyond = deleg(NOW + SKEW + 1, NOW + SKEW + 60);
  assert.deepEqual(codes(verifyDelegationChain(beyond, parent, base)), ["DELEGATION_ISSUED_AT_IMPLAUSIBLE"]);
});

test("A-T6 configurable skew: 0 and 3600 boundaries; past issued_at is never implausible", () => {
  const zero = { ...base, maxFutureIssuedAtSkewSeconds: 0 };
  assert.equal(verifyDelegation(deleg(NOW, NOW + 60), zero).ok, true);
  assert.deepEqual(codes(verifyDelegation(deleg(NOW + 1, NOW + 60), zero)), ["DELEGATION_ISSUED_AT_IMPLAUSIBLE"]);
  const hour = { ...base, maxFutureIssuedAtSkewSeconds: 3600 };
  assert.equal(verifyDelegation(deleg(NOW + 3600, NOW + 3700), hour).ok, true);
  assert.deepEqual(codes(verifyDelegation(deleg(NOW + 3601, NOW + 3700), hour)), ["DELEGATION_ISSUED_AT_IMPLAUSIBLE"]);
  assert.equal(verifyDelegation(deleg(NOW - 86_000, NOW + 60), base).ok, true, "old issuance is fine");
});

test("A-T7 malformed maxFutureIssuedAtSkewSeconds throws (trusted configuration), never falls back", () => {
  for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "300", 2 ** 60]) {
    assert.throws(() => verifyDelegation(deleg(NOW, NOW + 60), { ...base, maxFutureIssuedAtSkewSeconds: bad as number }), /maxFutureIssuedAtSkewSeconds/);
  }
});

test("A-T8 unsafe-magnitude issued_at is implausible without overflow arithmetic", () => {
  const d = { ...deleg(NOW, NOW + 60), issued_at: 2 ** 60 };
  assert.ok(codes(verifyDelegation(d, { now: NOW })).includes("DELEGATION_ISSUED_AT_IMPLAUSIBLE"));
});

test("A-T9 authorization path is unchanged: future parent still AUTH_ISSUED_AT_IMPLAUSIBLE, no delegation codes", () => {
  const futureParent = signAuthorizationEd25519({
    version: "AuthorizationV1", auth_id: "q".repeat(64), issuer: "central", audience: "agent-A",
    intent_hash: "a".repeat(64), state_hash: "b".repeat(64), policy_id: "P1",
    decision: "ALLOW", issued_at: NOW + SKEW + 1, expiry: PARENT_EXP, kid: "central-k",
  }, keys.privateKey) as AuthorizationV1;
  const r = verifyAuthorization(futureParent, { now: NOW, mode: "strict", trustedKeySets: [{ issuer: "central", version: "1", keys: [{ kid: "central-k", alg: "Ed25519", public_key: keys.publicKey }] }] });
  assert.ok(codes(r).includes("AUTH_ISSUED_AT_IMPLAUSIBLE"));
  assert.ok(!codes(r).some((c) => c.startsWith("DELEGATION_")));
});

// ── Parent scope ceilings ────────────────────────────────────────────────────

const VALID_CHILD: DelegationScope = { tools: ["transfer"], max_amount: 100n, max_actions: 5, max_depth: 1 };
const VALID_PARENT: DelegationScope = { tools: ["transfer"], max_amount: 500n, max_actions: 10, max_depth: 3 };

test("A-C1 malformed parent ceilings fail closed as DELEGATION_SCOPE_VIOLATION (only that code), message names parentScope", () => {
  const bad: Record<string, unknown> = {
    "max_actions NaN": NaN, "max_actions Infinity": Infinity, "max_actions -Infinity": -Infinity,
    "max_actions 1.5": 1.5, "max_actions -1": -1, "max_actions '10'": "10", "max_actions 10n": 10n,
  };
  const d = deleg(NOW, NOW + 60, VALID_CHILD);
  for (const field of ["max_actions", "max_depth"] as const) {
    for (const [name, value] of Object.entries(bad)) {
      const parentScope = { ...VALID_PARENT, [field]: value } as DelegationScope;
      const r = verifyDelegationChain(d, parent, { ...base, parentScope });
      assert.deepEqual(codes(r), ["DELEGATION_SCOPE_VIOLATION"], `${field} ${name}: ${JSON.stringify(r.violations)}`);
      assert.match(r.violations[0].message ?? "", new RegExp(`^parentScope\\.${field} `));
    }
  }
  for (const [name, value] of Object.entries({ "-1n": -1n, "number 1000": 1000, "'1000'": "1000", "null": null, "{}": {} })) {
    const r = verifyDelegationChain(d, parent, { ...base, parentScope: { ...VALID_PARENT, max_amount: value } as DelegationScope });
    assert.deepEqual(codes(r), ["DELEGATION_SCOPE_VIOLATION"], `max_amount ${name}`);
  }
  for (const [name, value] of Object.entries({ string: "transfer", "[1]": [1], null: null })) {
    const r = verifyDelegationChain(d, parent, { ...base, parentScope: { ...VALID_PARENT, tools: value } as unknown as DelegationScope });
    assert.deepEqual(codes(r), ["DELEGATION_SCOPE_VIOLATION"], `tools ${name}`);
  }
  for (const value of [null, [], "scope"]) {
    const r = verifyDelegationChain(d, parent, { ...base, parentScope: value as unknown as DelegationScope });
    assert.deepEqual(codes(r), ["DELEGATION_SCOPE_VIOLATION"], `parentScope ${JSON.stringify(value)}`);
  }
});

test("A-C2 the reproduced bypass is closed: NaN/Infinity ceilings no longer accept a 1e6 / 99 child", () => {
  const d = deleg(NOW, NOW + 60, { tools: ["transfer"], max_actions: 1_000_000, max_depth: 99 });
  for (const ceil of [NaN, Infinity]) {
    const r = verifyDelegationChain(d, parent, { ...base, parentScope: { tools: ["transfer"], max_actions: ceil, max_depth: ceil } });
    assert.equal(r.ok, false);
    assert.ok(codes(r).every((c) => c === "DELEGATION_SCOPE_VIOLATION"));
  }
});

test("A-C3 inherited invalid ceiling: an omitted child field cannot inherit a malformed parent value", () => {
  const d = deleg(NOW, NOW + 60, { tools: ["transfer"] });
  for (const field of ["max_actions", "max_depth"] as const) {
    const r = verifyDelegationChain(d, parent, { ...base, parentScope: { tools: ["transfer"], [field]: NaN } });
    assert.deepEqual(codes(r), ["DELEGATION_SCOPE_VIOLATION"], field);
  }
});

test("A-C4 valid chains are unchanged: narrower, equal, zero ceilings, empty parent scope, no parent scope", () => {
  const cases: Array<[string, DelegationScope, DelegationScope | undefined]> = [
    ["narrower", VALID_CHILD, VALID_PARENT],
    ["equal", VALID_PARENT, VALID_PARENT],
    ["zero ceilings", { tools: [], max_amount: 0n, max_actions: 0, max_depth: 0 }, { tools: [], max_amount: 0n, max_actions: 0, max_depth: 0 }],
    ["omitted child inherits valid parent", { tools: ["transfer"] }, VALID_PARENT],
    ["empty parent scope", VALID_CHILD, {}],
    ["no parent scope", VALID_CHILD, undefined],
  ];
  for (const [name, child, ps] of cases) {
    const r = verifyDelegationChain(deleg(NOW, NOW + 60, child), parent, { ...base, ...(ps !== undefined ? { parentScope: ps } : {}) });
    assert.equal(r.ok, true, `${name}: ${JSON.stringify(r.violations)}`);
  }
  // Valid but wider child is still a narrowing violation (existing contract).
  const wider = verifyDelegationChain(deleg(NOW, NOW + 60, { ...VALID_CHILD, max_actions: 11 }), parent, { ...base, parentScope: VALID_PARENT });
  assert.deepEqual(codes(wider), ["DELEGATION_SCOPE_VIOLATION"]);
});

test("A-C5 malformed child AND malformed parent: both reported, no narrowing comparison runs (no throw)", () => {
  const d = { ...deleg(NOW, NOW + 60), scope: { max_amount: "unbounded" } } as unknown as DelegationV1;
  const r = verifyDelegation(d, { now: NOW, parentScope: { max_amount: -1n } });
  const msgs = r.violations.filter((v) => v.code === "DELEGATION_SCOPE_VIOLATION").map((v) => v.message);
  assert.ok(msgs.some((m) => m?.startsWith("scope.max_amount")) && msgs.some((m) => m?.startsWith("parentScope.max_amount")), JSON.stringify(msgs));
});

// ── Canonicalization / signature semantics unchanged ─────────────────────────

test("A-S1 signatures and canonical payload are unchanged: valid artifact verifies; any temporal tamper breaks the signature", () => {
  const d = deleg(NOW, NOW + 60);
  assert.equal(verifyDelegation(d, base).ok, true);
  const tampered = { ...d, issued_at: NOW - 1 };
  assert.deepEqual(codes(verifyDelegation(tampered, base)), ["DELEGATION_SIGNATURE_INVALID"]);
});
