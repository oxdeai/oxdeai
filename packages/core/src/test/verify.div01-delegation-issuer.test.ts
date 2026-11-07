// SPDX-License-Identifier: Apache-2.0
//
// DIV-01: semantics of DelegationV1 `issuer`, `delegator` and `parent.audience`.
//
// SPEC.md §5.3 stated "`issuer` ... MUST equal `parent.audience`". The normative
// artifact spec (docs/spec/artifacts/delegation-v1.md), the verification spec
// (docs/spec/verification/verification-v1.md §delegation step 6), SPEC.md §5.8
// itself and the Stable delegation corpus (`delegation-valid`, issuer
// "issuer-1" != parent audience "pep-gateway.local", expected ALLOW) instead
// define:
//   - `delegator` MUST equal `parent.audience`   (authority binding to the parent)
//   - `issuer` selects the KeySet that verifies the signature   (signer identity)
//   - which issuer may sign for which delegator is opt-in relying-party
//     configuration (`trustedDelegationAuthorities`).
// These tests pin that behavior, positive and negative, so that any change to
// the normative interpretation is a visible, deliberate test change.

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { createDelegation as createDelegationAtWallClock } from "../delegation/createDelegation.js";
import { delegationSigningPayload, verifyDelegationChain } from "../verification/verifyDelegation.js";
import { signAuthorizationEd25519 } from "../verification/verifyAuthorization.js";
import { SIGNING_DOMAINS, signEd25519 } from "../crypto/signatures.js";
import type { AuthorizationV1 } from "../types/authorization.js";
import type { DelegationV1 } from "../types/delegation.js";
import type { KeySet } from "../types/keyset.js";

const NOW = 1_700_000_000, EXP = NOW + 3600;
const mkKey = () => generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
const central = mkKey(), svcA = mkKey(), mallory = mkKey();
const keySet = (issuer: string, kid: string, k: ReturnType<typeof mkKey>): KeySet =>
  ({ issuer, version: "1", keys: [{ kid, alg: "Ed25519", public_key: k.publicKey, status: "active" }] });
const TRUSTED: KeySet[] = [keySet("central", "central-k", central), keySet("svc-A", "svcA-k", svcA), keySet("mallory", "mallory-k", mallory)];

// Parent issued by the central PDP issuer to audience "svc-A".
const parent: AuthorizationV1 = signAuthorizationEd25519({
  version: "AuthorizationV1", auth_id: "d".repeat(64), issuer: "central", audience: "svc-A",
  intent_hash: "a".repeat(64), state_hash: "b".repeat(64), policy_id: "P1",
  decision: "ALLOW", issued_at: NOW - 10, expiry: EXP, kid: "central-k",
}, central.privateKey) as AuthorizationV1;

let seq = 0;
function delegate(issuer: string, kid: string, key: ReturnType<typeof mkKey>): DelegationV1 {
  return createDelegationAtWallClock(parent, {
    delegatee: "svc-B", issuer, kid, scope: { tools: ["t"] }, expiry: EXP - 60,
    delegationId: `div01-${seq++}`, issuedAt: NOW - 5,
  }, key.privateKey);
}
const codes = (r: ReturnType<typeof verifyDelegationChain>) => (r.violations ?? []).map((v) => v.code);
const verify = (d: DelegationV1, extra: Parameters<typeof verifyDelegationChain>[2] = {}) =>
  verifyDelegationChain(d, parent, { now: NOW, trustedKeySets: TRUSTED, requireSignatureVerification: true, parentScope: { tools: ["t"] }, ...extra });

test("DIV-01 positive: central issuer signs (issuer != parent.audience); delegator == parent.audience; accepted by default", () => {
  const d = delegate("central", "central-k", central);
  assert.equal(d.delegator, parent.audience);
  assert.notEqual(d.issuer, parent.audience);
  const r = verify(d);
  assert.equal(r.ok, true, JSON.stringify(r.violations));
});

test("DIV-01 positive: self-issued delegation (issuer == parent.audience == delegator) accepted", () => {
  const d = delegate("svc-A", "svcA-k", svcA);
  assert.equal(d.issuer, parent.audience);
  const r = verify(d);
  assert.equal(r.ok, true, JSON.stringify(r.violations));
});

test("DIV-01 negative: delegator != parent.audience is rejected even with a valid signature", () => {
  const base = delegate("central", "central-k", central);
  const unsigned: DelegationV1 = { ...base, delegator: "svc-Z", signature: "" };
  const d: DelegationV1 = { ...unsigned, signature: signEd25519(SIGNING_DOMAINS.DELEGATION_V1, delegationSigningPayload(unsigned), central.privateKey) };
  const r = verify(d);
  assert.equal(r.ok, false);
  assert.ok(codes(r).includes("DELEGATION_DELEGATOR_MISMATCH"), JSON.stringify(r.violations));
});

test("DIV-01 negative: issuer without a trusted KeySet is rejected", () => {
  const stranger = mkKey();
  const d = delegate("stranger", "stranger-k", stranger);
  const r = verify(d);
  assert.equal(r.ok, false, JSON.stringify(r.violations));
});

test("DIV-01 negative: claimed issuer signed with another issuer's key is rejected", () => {
  const d = delegate("svc-A", "svcA-k", mallory);
  const r = verify(d);
  assert.equal(r.ok, false);
  assert.ok(codes(r).includes("DELEGATION_SIGNATURE_INVALID"), JSON.stringify(r.violations));
});

test("DIV-01 default: an unrelated trusted issuer can sign for any delegator unless signer authority is configured", () => {
  // This is the documented opt-in trust model (verifyDelegation.ts JSDoc), pinned here
  // because it is what the former SPEC.md §5.3 sentence appeared to forbid.
  const d = delegate("mallory", "mallory-k", mallory);
  assert.equal(verify(d).ok, true);
  const restricted = verify(d, { trustedDelegationAuthorities: [{ delegator: "svc-A", issuer: "central" }] });
  assert.equal(restricted.ok, false);
  assert.ok(codes(restricted).includes("DELEGATION_SIGNER_NOT_AUTHORIZED"));
});

test("DIV-01 profile: self-issued-only is expressible with existing signer authority (no new option)", () => {
  // `issuer == parent.audience` as a relying-party requirement: list (X, X) pairs only.
  const selfOnly = { trustedDelegationAuthorities: [{ delegator: "svc-A", issuer: "svc-A" }] };
  assert.equal(verify(delegate("svc-A", "svcA-k", svcA), selfOnly).ok, true);
  const centralSigned = verify(delegate("central", "central-k", central), selfOnly);
  assert.equal(centralSigned.ok, false);
  assert.ok(codes(centralSigned).includes("DELEGATION_SIGNER_NOT_AUTHORIZED"));
});
