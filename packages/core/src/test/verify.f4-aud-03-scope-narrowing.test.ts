// SPDX-License-Identifier: Apache-2.0
//
// F4-AUD-03 regression tests: delegation scope narrowing (`scope.tools` must be
// a subset of `parentScope.tools`) is no longer O(N × M).
//
// The check runs BEFORE the delegation signature is verified, and both lists
// are caller-supplied (`parentScope` is not a signed claim), so the former
// `parent.tools.includes(t)` per child tool let a large unsigned input block the
// event loop. These tests pin:
//   1. exact semantic equivalence with the former algorithm (same violations,
//      same order, same messages, duplicates included), over a fixed matrix and
//      a deterministic pseudo-random corpus;
//   2. that parent membership is no longer computed by a per-child linear scan
//      (structural, deterministic: no timing assertions);
//   3. large valid and invalid scopes.
// Timing is measured by bench/scope-narrowing.f4-aud-03.mjs, not asserted here.

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { createDelegation as createDelegationAtWallClock } from "../delegation/createDelegation.js";
import { verifyDelegationChain, resolveEffectiveChildScope } from "../verification/verifyDelegation.js";
import { signAuthorizationEd25519 } from "../verification/verifyAuthorization.js";
import type { AuthorizationV1 } from "../types/authorization.js";
import type { KeySet } from "../types/keyset.js";
import type { DelegationScope } from "../types/delegation.js";

const NOW = 1_700_000_000, EXP = NOW + 3600;
const createDelegation: typeof createDelegationAtWallClock = (parent, params, key) =>
  createDelegationAtWallClock(parent, { issuedAt: NOW - 10, ...params }, key);
const mkKey = () => generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
const central = mkKey(), svcA = mkKey();
const trusted: KeySet[] = [{ issuer: "svc-A", version: "1", keys: [{ kid: "svcA-k", alg: "Ed25519", public_key: svcA.publicKey, status: "active" }] }];
const parent: AuthorizationV1 = signAuthorizationEd25519({
  version: "AuthorizationV1", auth_id: "q".repeat(64), issuer: "central", audience: "svc-A",
  intent_hash: "a".repeat(64), state_hash: "b".repeat(64), policy_id: "P1",
  decision: "ALLOW", issued_at: NOW - 10, expiry: EXP, kid: "central-k",
}, central.privateKey) as AuthorizationV1;

let seq = 0;
function child(scope: DelegationScope) {
  return createDelegation(parent, { delegatee: "svc-B", issuer: "svc-A", kid: "svcA-k", scope, expiry: EXP - 60, delegationId: `aud03-${seq++}` }, svcA.privateKey);
}
function verify(childScope: DelegationScope, parentScope: DelegationScope) {
  return verifyDelegationChain(child(childScope), parent, { now: NOW, trustedKeySets: trusted, requireSignatureVerification: true, parentScope });
}
const scopeViolations = (r: ReturnType<typeof verify>) =>
  (r.violations ?? []).filter((v) => v.code === "DELEGATION_SCOPE_VIOLATION").map((v) => v.message ?? "");

/** The pre-F4-AUD-03 algorithm, verbatim, as the equivalence oracle (tools only). */
function formerToolsViolation(childScope: DelegationScope, parentScope: DelegationScope): string[] {
  const effective = resolveEffectiveChildScope(childScope, parentScope);
  if (effective.tools === undefined || parentScope.tools === undefined) return [];
  const notAllowed = effective.tools.filter((t) => !parentScope.tools!.includes(t));
  return notAllowed.length > 0 ? [`scope.tools contains tools not in parent: ${notAllowed.join(", ")}`] : [];
}
const toolsOnly = (msgs: string[]) => msgs.filter((m) => m.startsWith("scope.tools contains"));

test("F4-AUD-03 equivalence matrix: allowed, disallowed, empty, duplicates, inheritance, order", () => {
  const cases: Array<[string, DelegationScope, DelegationScope, boolean]> = [
    ["subset", { tools: ["a"] }, { tools: ["a", "b"] }, true],
    ["equal", { tools: ["a", "b"] }, { tools: ["b", "a"] }, true],
    ["one disallowed", { tools: ["a", "x"] }, { tools: ["a", "b"] }, false],
    ["all disallowed, order kept", { tools: ["z", "y", "x"] }, { tools: ["a"] }, false],
    ["empty child", { tools: [] }, { tools: ["a"] }, true],
    ["empty parent, empty child", { tools: [] }, { tools: [] }, true],
    ["empty parent, non-empty child", { tools: ["a"] }, { tools: [] }, false],
    ["duplicate allowed child", { tools: ["a", "a"] }, { tools: ["a"] }, true],
    ["duplicate disallowed child kept twice", { tools: ["x", "a", "x"] }, { tools: ["a"] }, false],
    ["duplicate parent", { tools: ["a"] }, { tools: ["a", "a", "b"] }, true],
    ["child omits tools: inherits parent", { max_amount: 1n }, { tools: ["a"] }, true],
    ["parent omits tools: unconstrained", { tools: ["anything"] }, { max_amount: 10n }, true],
    ["empty-string tool", { tools: [""] }, { tools: ["a"] }, false],
    ["empty-string tool allowed", { tools: [""] }, { tools: [""] }, true],
    ["case-sensitive", { tools: ["A"] }, { tools: ["a"] }, false],
    ["unicode / NFC vs NFD are distinct", { tools: ["é"] }, { tools: ["é"] }, false],
    ["prototype-like names", { tools: ["__proto__", "constructor"] }, { tools: ["constructor"] }, false],
  ];
  for (const [label, c, p, ok] of cases) {
    const got = toolsOnly(scopeViolations(verify(c, p)));
    assert.deepEqual(got, formerToolsViolation(c, p), `${label}: identical to former algorithm`);
    assert.equal(got.length === 0, ok, `${label}: expected ${ok ? "allowed" : "rejected"}`);
  }
});

test("F4-AUD-03 equivalence corpus: 400 deterministic pseudo-random scope pairs", () => {
  let s = 0x9e3779b9;
  const rnd = () => ((s = (Math.imul(s ^ (s >>> 15), 0x2c1b3c6d) + 0x6d2b79f5) >>> 0) / 2 ** 32);
  const alphabet = ["a", "b", "c", "d", "", "A", "tool.x", "é", "__proto__", "toString"];
  const pick = (n: number) => Array.from({ length: n }, () => alphabet[Math.floor(rnd() * alphabet.length)]);
  for (let i = 0; i < 400; i++) {
    const c: DelegationScope = rnd() < 0.1 ? {} : { tools: pick(Math.floor(rnd() * 8)) };
    const p: DelegationScope = rnd() < 0.1 ? { max_amount: 5n } : { tools: pick(Math.floor(rnd() * 8)) };
    assert.deepEqual(toolsOnly(scopeViolations(verify(c, p))), formerToolsViolation(c, p), `case ${i}: ${JSON.stringify([c, p], (_k, v) => (typeof v === "bigint" ? `${v}n` : v))}`);
  }
});

test("F4-AUD-03 other scope rules and malformed inputs unchanged (fail closed before narrowing)", () => {
  const amount = scopeViolations(verify({ tools: ["a"], max_amount: 11n }, { tools: ["a"], max_amount: 10n }));
  assert.deepEqual(amount, ["scope.max_amount 11 exceeds parent max_amount 10"]);
  const both = scopeViolations(verify({ tools: ["x"], max_amount: 11n }, { tools: ["a"], max_amount: 10n }));
  assert.deepEqual(both, ["scope.tools contains tools not in parent: x", "scope.max_amount 11 exceeds parent max_amount 10"], "violation order kept");
  for (const bad of [{ tools: "a" }, { tools: [1] }, { tools: [null] }] as unknown as DelegationScope[]) {
    const r = verifyDelegationChain({ ...child({ tools: ["a"] }), scope: bad }, parent, { now: NOW, parentScope: { tools: ["a"] } });
    assert.equal(r.ok, false);
    assert.ok(scopeViolations(r).some((m) => /scope\.tools must be an array of strings/.test(m)), JSON.stringify(r.violations));
  }
  const badParent = verifyDelegationChain(child({ tools: ["a"] }), parent, { now: NOW, parentScope: { tools: [1] } as unknown as DelegationScope });
  assert.ok(scopeViolations(badParent).some((m) => /parentScope\.tools must be an array of strings/.test(m)));
});

/**
 * A plain Array (behind a Proxy) whose membership scan is observable:
 * `includes` / `indexOf` throw, `Symbol.iterator` throws (IR-02: parent tools
 * are read by index only), and every index read is counted.
 */
function instrumented(values: string[]) {
  const stats = { indexReads: 0 };
  const arr = [...values];
  Object.defineProperty(arr, "includes", { value: () => { throw new Error("per-element linear membership scan"); } });
  Object.defineProperty(arr, "indexOf", { value: () => { throw new Error("per-element linear membership scan"); } });
  Object.defineProperty(arr, Symbol.iterator, { value: () => { throw new Error("parent tools traversed through Symbol.iterator"); } });
  const proxy = new Proxy(arr, {
    get(target, key, receiver) {
      if (typeof key === "string" && /^(0|[1-9][0-9]*)$/.test(key)) stats.indexReads++;
      return Reflect.get(target, key, receiver);
    },
  });
  return { arr: proxy, stats };
}

test("F4-AUD-03 / IR-02 structural: parent tools are read by index, O(M) per check, never scanned per child tool", () => {
  const m = 4_000;
  const parentValues = Array.from({ length: m }, (_, i) => `p${i}`);
  const measure = (childTools: string[], expectOk: boolean) => {
    const { arr, stats } = instrumented(parentValues);
    const r = verify({ tools: childTools }, { tools: arr });
    assert.equal(r.ok, expectOk, JSON.stringify(r.violations?.slice(0, 2)));
    return { r, reads: stats.indexReads };
  };
  // Rejected input (one unknown tool) and accepted input both exercise the check;
  // the child size varies by 20x while the parent stays fixed.
  const small = measure(parentValues.slice(0, 100), true);
  const large = measure(parentValues.slice(0, 2_000), true);
  const rejSmall = measure([...parentValues.slice(0, 100), "zz"], false);
  const rejLarge = measure([...parentValues.slice(0, 2_000), "zz"], false);
  assert.deepEqual(toolsOnly(scopeViolations(rejLarge.r)), ["scope.tools contains tools not in parent: zz"]);
  // Parent index reads do not depend on the child size (a per-child scan would
  // read up to N × M = 8 000 000 entries) ...
  assert.equal(large.reads, small.reads, "accepted: parent reads independent of child size");
  assert.equal(rejLarge.reads, rejSmall.reads, "rejected: parent reads independent of child size");
  assert.equal(rejLarge.reads, large.reads, "accepted and rejected read the parent identically");
  // ... and are a small constant multiple of M: one pass for scope type
  // validation (`every`) and one pass to fill the membership Set.
  assert.ok(large.reads >= m && large.reads <= 3 * m, `parent index reads ${large.reads} not O(M) for M=${m}`);
});

test("IR-02 a custom parent Symbol.iterator cannot add a tool to the authorized scope", () => {
  const lie = (held: string[], extra: string[]) => {
    const a = [...held];
    Object.defineProperty(a, Symbol.iterator, { value: function* () { yield* held; yield* extra; } });
    return a;
  };
  // Baseline (pre-F4-AUD-03) semantics, by index: "evil" is held at no index.
  const r = verify({ tools: ["evil"] }, { tools: lie(["a"], ["evil"]) });
  assert.equal(r.ok, false);
  assert.deepEqual(toolsOnly(scopeViolations(r)), ["scope.tools contains tools not in parent: evil"]);
  assert.deepEqual(toolsOnly(scopeViolations(r)), formerToolsViolation({ tools: ["evil"] }, { tools: ["a"] }));
  // Mixed: only the tool actually held by index is accepted.
  const mixed = verify({ tools: ["a", "evil", "b"] }, { tools: lie(["a", "b"], ["evil"]) });
  assert.deepEqual(toolsOnly(scopeViolations(mixed)), ["scope.tools contains tools not in parent: evil"]);
  // An iterator that yields FEWER tools does not narrow what is held by index either.
  const fewer = ["a", "b"];
  Object.defineProperty(fewer, Symbol.iterator, { value: function* () { yield "a"; } });
  assert.equal(verify({ tools: ["a", "b"] }, { tools: fewer }).ok, true);
  // Plain controls.
  assert.equal(verify({ tools: ["evil"] }, { tools: ["a", "evil"] }).ok, true);
  assert.equal(verify({ tools: ["evil"] }, { tools: ["a"] }).ok, false);
});

test("F4-AUD-03 large scopes: 20k valid subset accepted, 20k with one foreign tool rejected", () => {
  const n = 20_000;
  const tools = Array.from({ length: n }, (_, i) => `t${i}`);
  const parentTools = [...Array.from({ length: n }, (_, i) => `p${i}`), ...tools.slice().reverse()];
  assert.equal(verify({ tools }, { tools: parentTools }).ok, true, "large valid subset");
  const bad = verify({ tools: [...tools.slice(0, n - 1), "foreign"] }, { tools: parentTools });
  assert.equal(bad.ok, false);
  assert.deepEqual(toolsOnly(scopeViolations(bad)), ["scope.tools contains tools not in parent: foreign"]);
  // The audit's pathological shape: N disjoint from the first M/2 parent entries.
  const disjoint = Array.from({ length: n }, (_, i) => `x${i}`);
  const r = verify({ tools: disjoint }, { tools: parentTools });
  assert.equal(r.ok, false);
  assert.equal(toolsOnly(scopeViolations(r)).length, 1);
  assert.ok(toolsOnly(scopeViolations(r))[0].endsWith(`x${n - 1}`));
});
