// SPDX-License-Identifier: Apache-2.0
//
// F4 High remediation regression tests:
//   F4-1/F4-2 - delegation signer authority (a valid signature is not authority
//               to delegate; the signer must be the delegator, or an explicitly
//               authorized (delegator, issuer) pair).
//   F4-R6-01  - child-scope field type confusion (non-numeric max_amount etc.
//               must not bypass the ceiling via a fail-open `>` comparison).

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { createDelegation } from "../delegation/createDelegation.js";
import { verifyDelegationChain } from "../verification/verifyDelegation.js";
import { signAuthorizationEd25519 } from "../verification/verifyAuthorization.js";
import type { AuthorizationV1 } from "../types/authorization.js";
import type { KeySet } from "../types/keyset.js";

const NOW = 1_700_000_000, EXP = NOW + 3600;
function mkKey() { return generateKeyPairSync("ed25519", { publicKeyEncoding:{type:"spki",format:"pem"}, privateKeyEncoding:{type:"pkcs8",format:"pem"} }); }
const svcA = mkKey(), mallory = mkKey(), broker = mkKey(), central = mkKey();
const ks = (issuer: string, kid: string, pub: string): KeySet => ({ issuer, version:"1", keys:[{ kid, alg:"Ed25519", public_key: pub, status:"active" }] });
const trusted = [ ks("svc-A","svcA-k",svcA.publicKey), ks("mallory","mallory-k",mallory.publicKey), ks("broker","broker-k",broker.publicKey) ];

const parent: AuthorizationV1 = signAuthorizationEd25519({
  version:"AuthorizationV1", auth_id:"p".repeat(64), issuer:"central", audience:"svc-A",
  intent_hash:"a".repeat(64), state_hash:"b".repeat(64), policy_id:"P1",
  decision:"ALLOW", issued_at:NOW-10, expiry:EXP, kid:"central-k",
}, central.privateKey) as AuthorizationV1;
const parentScope = { tools:["transfer"], max_amount:500n, max_actions:10, max_depth:3 };
const baseOpts = { now:NOW, trustedKeySets:trusted, requireSignatureVerification:true, parentScope };

function deleg(issuer: string, kid: string, priv: string, scope: any = { tools:["transfer"], max_amount:100n }) {
  return createDelegation(parent, { issuer, kid, delegatee:"agent-1", scope, expiry:EXP }, priv);
}

// ── F4-1/F4-2 signer authority (opt-in via trustedDelegationAuthorities) ──────
// Default (no trustedDelegationAuthorities): signer authority is NOT enforced,
// preserving the central-issuer model (issuer may differ from delegator). This
// is the documented residual; flipping it to default-deny is a breaking change
// requiring maintainer approval (see report).
test("F4-1/F4-2: default (no authorities configured) preserves the central-issuer model", () => {
  // central issuer "central" signs a delegation whose delegator is svc-A; accepted by default.
  const d = createDelegation(parent, { issuer:"central", kid:"central-k", delegatee:"agent-1", scope:{ tools:["transfer"], max_amount:100n }, expiry:EXP }, central.privateKey);
  const ksCentral = [...trusted, ks("central","central-k",central.publicKey)];
  const r = verifyDelegationChain(d, parent, { ...baseOpts, trustedKeySets: ksCentral } as never);
  assert.equal(r.ok, true, JSON.stringify(r.violations));
  assert.ok(!r.violations.some(v => v.code === "DELEGATION_SIGNER_NOT_AUTHORIZED"));
});
test("F4-1/F4-2: with authorities configured, an unrelated trusted signer (mallory) is DENIED", () => {
  const auths = [{ delegator:"svc-A", issuer:"svc-A" }]; // only svc-A may delegate for svc-A
  const r = verifyDelegationChain(deleg("mallory","mallory-k",mallory.privateKey), parent, { ...baseOpts, trustedDelegationAuthorities: auths } as never);
  assert.equal(r.ok, false);
  assert.ok(r.violations.some(v => v.code === "DELEGATION_SIGNER_NOT_AUTHORIZED"), JSON.stringify(r.violations));
});
test("F4-1/F4-2: with authorities configured, legitimate authorized delegation still works", () => {
  const auths = [{ delegator:"svc-A", issuer:"svc-A" }, { delegator:"svc-A", issuer:"broker" }];
  // self-delegation svc-A: accepted
  assert.equal(verifyDelegationChain(deleg("svc-A","svcA-k",svcA.privateKey), parent, { ...baseOpts, trustedDelegationAuthorities: auths } as never).ok, true);
  // distinct authorized issuer broker: accepted
  assert.equal(verifyDelegationChain(deleg("broker","broker-k",broker.privateKey), parent, { ...baseOpts, trustedDelegationAuthorities: auths } as never).ok, true);
});
test("F4-1/F4-2: empty authorities list fails closed (authorizes no delegation)", () => {
  const r = verifyDelegationChain(deleg("svc-A","svcA-k",svcA.privateKey), parent, { ...baseOpts, trustedDelegationAuthorities: [] } as never);
  assert.equal(r.ok, false);
  assert.ok(r.violations.some(v => v.code === "DELEGATION_SIGNER_NOT_AUTHORIZED"));
});

// ── F4-R6-01 scope type confusion ────────────────────────────────────────────
test("F4-R6-01: valid child ceiling below parent is accepted", () => {
  const r = verifyDelegationChain(deleg("svc-A","svcA-k",svcA.privateKey,{ tools:["transfer"], max_amount:100n }), parent, baseOpts as never);
  assert.equal(r.ok, true, JSON.stringify(r.violations));
});
test("F4-R6-01: valid numeric child ceiling above parent is DENIED", () => {
  const r = verifyDelegationChain(deleg("svc-A","svcA-k",svcA.privateKey,{ tools:["transfer"], max_amount:999n }), parent, baseOpts as never);
  assert.equal(r.ok, false);
  assert.ok(r.violations.some(v => v.code === "DELEGATION_SCOPE_VIOLATION"));
});
test("F4-R6-01: non-numeric max_amount (string/object) is DENIED, never coerced", () => {
  for (const bad of ["unbounded","1e30","99999.5"] as const) {
    const r = verifyDelegationChain(deleg("svc-A","svcA-k",svcA.privateKey,{ tools:["transfer"], max_amount: bad }), parent, baseOpts as never);
    assert.equal(r.ok, false, `max_amount=${bad} must be denied`);
    assert.ok(r.violations.some(v => v.code === "DELEGATION_SCOPE_VIOLATION"), `max_amount=${bad}`);
  }
  const rObj = verifyDelegationChain(deleg("svc-A","svcA-k",svcA.privateKey,{ tools:["transfer"], max_amount: {} }), parent, baseOpts as never);
  assert.equal(rObj.ok, false);
  assert.ok(rObj.violations.some(v => v.code === "DELEGATION_SCOPE_VIOLATION"));
});
test("F4-R6-01: malformed scope values that CAN be signed are DENIED (via createDelegation)", () => {
  // These serialize fine (strings/objects/bigint/number), so a signer can mint them.
  const cases: any[] = [
    { tools:["transfer"], max_amount: -1n },   // negative bigint
    { tools:["transfer"], max_actions: -5 },   // negative integer
    { tools:["transfer"], max_amount: 100 },   // number where bigint required
    { tools:"transfer" },                       // tools must be string[]
    { tools:[1,2] },                            // tools elements must be strings
  ];
  for (const scope of cases) {
    const r = verifyDelegationChain(deleg("svc-A","svcA-k",svcA.privateKey,scope), parent, baseOpts as never);
    assert.equal(r.ok, false, `scope ${JSON.stringify(scope, (_,x)=>typeof x==="bigint"?String(x):x)} must be denied`);
    assert.ok(r.violations.some(v => v.code === "DELEGATION_SCOPE_VIOLATION"));
  }
});
test("F4-R6-01: hand-crafted non-integer / non-finite numerics are DENIED by verify, not thrown", () => {
  // canonicalJson rejects floats/NaN/Infinity at SIGNING (FLOAT_NOT_ALLOWED), so a
  // conformant signer cannot mint these; a hand-crafted artifact still must be
  // DENIED (and must not throw) at verification. Signature check off to isolate scope.
  const legit = deleg("svc-A","svcA-k",svcA.privateKey,{ tools:["transfer"], max_amount:100n });
  for (const bad of [1.5, Number.POSITIVE_INFINITY, Number.NaN] as const) {
    const crafted = { ...legit, scope: { tools:["transfer"], max_actions: bad } } as any;
    let r: ReturnType<typeof verifyDelegationChain> | undefined;
    assert.doesNotThrow(() => { r = verifyDelegationChain(crafted, parent, { now:NOW, parentScope } as never); });
    assert.equal(r!.ok, false, `max_actions=${String(bad)} must be denied`);
    assert.ok(r!.violations.some(v => v.code === "DELEGATION_SCOPE_VIOLATION"));
  }
});
test("F4-R6-01: well-typed delegation with no scope fields still verifies (no false positive)", () => {
  const r = verifyDelegationChain(deleg("svc-A","svcA-k",svcA.privateKey,{}), parent, baseOpts as never);
  assert.equal(r.ok, true, JSON.stringify(r.violations));
});
