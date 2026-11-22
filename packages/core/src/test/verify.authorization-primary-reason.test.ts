// SPDX-License-Identifier: Apache-2.0
// AuthorizationV1 determining code (verification-v1.md §5, §9.1):
// opt-in `primaryReasonCode`, and compatibility of the default result.
//
//  - pairwise: every combination of two independent defects reports, as
//    primaryReasonCode, the defect of the earlier §5 step;
//  - compatibility: without the option the result carries no new key and
//    `violations` (content AND order, so `violations[0]` too) is unchanged by
//    the option;
//  - no determining code for a valid result or for verifier-configuration-only
//    failures;
//  - determinism across repeated calls.
//
// No-consume-on-failure at the boundary is covered by the guard test
// "INVREG-F02 (8)" (gateway.input-integrity.security.test.ts).
import assert from "node:assert/strict";
import test from "node:test";
import { createHash, generateKeyPairSync } from "node:crypto";
import { signAuthorizationEd25519, verifyAuthorization } from "../verification/verifyAuthorization.js";
import type { VerifyAuthorizationOptions } from "../verification/verifyAuthorization.js";
import type { AuthorizationV1 } from "../types/authorization.js";

const K = generateKeyPairSync("ed25519", { privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
const NOW = 1_800_000_000;
const ISS = "issuer.example";
const AUD = "aud.example";
const POL = "a".repeat(64);
const KID = "k1";
const h = (s: string) => createHash("sha256").update(s).digest("hex");

// §5 step of each defect's code.
const STEP: Record<string, number> = {
  AUTH_DECISION_INVALID: 4, AUTH_ISSUER_MISMATCH: 6, AUTH_ISSUER_POLICY_NOT_AUTHORIZED: 7,
  AUTH_KID_UNKNOWN: 8, AUTH_KEY_INACTIVE: 9, AUTH_SIGNATURE_INVALID: 10, AUTH_EXPIRED: 11,
  AUTH_ISSUED_AT_IMPLAUSIBLE: 12, AUTH_AUDIENCE_MISMATCH: 13, AUTH_POLICY_ID_MISMATCH: 14, AUTH_REPLAY: 16,
};

type Defect = {
  code: string;
  fields?: Partial<AuthorizationV1>;
  opts?: Partial<VerifyAuthorizationOptions>;
  key?: Record<string, unknown>;
  tamper?: boolean;
  replay?: boolean;
};
const D: Record<string, Defect> = {
  decision: { code: "AUTH_DECISION_INVALID", fields: { decision: "DENY" as never } },
  issuer: { code: "AUTH_ISSUER_MISMATCH", opts: { expectedIssuer: "other.issuer" } },
  authority: { code: "AUTH_ISSUER_POLICY_NOT_AUTHORIZED", opts: { trustedAuthorizationAuthorities: [{ issuer: ISS, policyId: "b".repeat(64) }] } },
  kid: { code: "AUTH_KID_UNKNOWN", fields: { kid: "k-unknown" } },
  inactive: { code: "AUTH_KEY_INACTIVE", key: { not_after: NOW - 10 } },
  sig: { code: "AUTH_SIGNATURE_INVALID", tamper: true },
  expired: { code: "AUTH_EXPIRED", fields: { issued_at: NOW - 100, expiry: NOW - 50 } },
  future: { code: "AUTH_ISSUED_AT_IMPLAUSIBLE", fields: { issued_at: NOW + 100_000, expiry: NOW + 200_000 } },
  audience: { code: "AUTH_AUDIENCE_MISMATCH", opts: { expectedAudience: "other.aud" } },
  policy: { code: "AUTH_POLICY_ID_MISMATCH", opts: { expectedPolicyId: "c".repeat(64) } },
  replay: { code: "AUTH_REPLAY", replay: true },
};
// expired and future both rewrite issued_at/expiry: not independent.
const EXCLUDED = new Set(["expired+future"]);

let n = 0;
function build(names: string[]) {
  let fields: Record<string, unknown> = {
    auth_id: h(`a${++n}`), issuer: ISS, audience: AUD, decision: "ALLOW", intent_hash: h("i"), state_hash: h("s"),
    policy_id: POL, issued_at: NOW - 10, expiry: NOW + 60, kid: KID,
  };
  let opts: VerifyAuthorizationOptions = { now: NOW, mode: "strict", expectedIssuer: ISS, expectedAudience: AUD, expectedPolicyId: POL };
  let key: Record<string, unknown> = { kid: KID, alg: "Ed25519", public_key: K.publicKey };
  let tamper = false;
  let replay = false;
  for (const x of names) {
    const d = D[x];
    if (d.fields) fields = { ...fields, ...d.fields };
    if (d.opts) opts = { ...opts, ...d.opts };
    if (d.key) key = { ...key, ...d.key };
    if (d.tamper) tamper = true;
    if (d.replay) replay = true;
  }
  let auth = signAuthorizationEd25519(fields as never, K.privateKey);
  if (tamper) auth = { ...auth, signature: ((auth.signature as string)[0] === "A" ? "B" : "A") + (auth.signature as string).slice(1) };
  opts = { ...opts, trustedKeySets: [{ issuer: ISS, version: "v1", keys: [key as never] }] };
  if (replay) opts = { ...opts, consumedAuthIds: [auth.auth_id] };
  return { auth, opts };
}

const names = Object.keys(D);
const pairs: string[][] = [];
for (let i = 0; i < names.length; i++) for (let j = i + 1; j < names.length; j++) {
  if (!EXCLUDED.has(`${names[i]}+${names[j]}`)) pairs.push([names[i], names[j]]);
}

test("single defects: primaryReasonCode is the defect's code", () => {
  for (const x of names) {
    const { auth, opts } = build([x]);
    const r = verifyAuthorization(auth, { ...opts, reportPrimaryReasonCode: true });
    assert.equal(r.status, "invalid", x);
    assert.equal(r.primaryReasonCode, D[x].code, x);
  }
});

test("pairwise defects (54 independent pairs): primaryReasonCode is the earlier §5 step", () => {
  assert.equal(pairs.length, 54);
  for (const p of pairs) {
    const { auth, opts } = build(p);
    const r = verifyAuthorization(auth, { ...opts, reportPrimaryReasonCode: true });
    const expected = p.map((x) => D[x].code).sort((a, b) => STEP[a] - STEP[b])[0];
    assert.equal(r.primaryReasonCode, expected, p.join("+"));
  }
});

test("mandated pairs: signature over replay, expiry over audience, policy over replay", () => {
  const cases: Array<[string[], string]> = [
    [["sig", "replay"], "AUTH_SIGNATURE_INVALID"],
    [["expired", "audience"], "AUTH_EXPIRED"],
    [["policy", "replay"], "AUTH_POLICY_ID_MISMATCH"],
  ];
  for (const [p, code] of cases) {
    const { auth, opts } = build(p);
    assert.equal(verifyAuthorization(auth, { ...opts, reportPrimaryReasonCode: true }).primaryReasonCode, code, p.join("+"));
  }
});

test("compatibility: the option changes nothing but the added field; default results carry no new key", () => {
  for (const p of [...names.map((x) => [x]), ...pairs]) {
    const { auth, opts } = build(p);
    const plain = verifyAuthorization(structuredClone(auth), opts);
    const withPrimary = verifyAuthorization(structuredClone(auth), { ...opts, reportPrimaryReasonCode: true });
    assert.equal("primaryReasonCode" in plain, false, `${p.join("+")}: default result gained a key`);
    const { primaryReasonCode: _omit, ...rest } = withPrimary;
    assert.deepEqual(rest, plain, `${p.join("+")}: option altered the result beyond primaryReasonCode`);
    // violations[0] consumers: first entry is identical with and without the option.
    assert.deepEqual(withPrimary.violations[0], plain.violations[0], `${p.join("+")}: violations[0]`);
  }
});

test("valid authorization: no violations and no primaryReasonCode", () => {
  const { auth, opts } = build([]);
  const r = verifyAuthorization(auth, { ...opts, reportPrimaryReasonCode: true });
  assert.equal(r.status, "ok");
  assert.deepEqual(r.violations, []);
  assert.equal("primaryReasonCode" in r, false);
});

test("verifier-configuration-only failures have no determining code", () => {
  const { auth } = build([]);
  const strictNoKeys = verifyAuthorization(auth, { now: NOW, mode: "strict", reportPrimaryReasonCode: true });
  assert.equal(strictNoKeys.status, "invalid");
  assert.equal(strictNoKeys.violations[0].code, "TRUSTED_KEYSETS_REQUIRED");
  assert.equal("primaryReasonCode" in strictNoKeys, false);
  const sigRequiredNoKeys = verifyAuthorization(auth, { now: NOW, requireSignatureVerification: true, reportPrimaryReasonCode: true });
  assert.deepEqual(sigRequiredNoKeys.violations.map((v) => v.code), ["AUTH_TRUST_MISSING"]);
  assert.equal("primaryReasonCode" in sigRequiredNoKeys, false);
});

test("determinism: identical inputs give identical results, field included", () => {
  for (const p of pairs.slice(0, 20)) {
    const { auth, opts } = build(p);
    const o = { ...opts, reportPrimaryReasonCode: true };
    assert.deepEqual(verifyAuthorization(structuredClone(auth), o), verifyAuthorization(structuredClone(auth), o), p.join("+"));
  }
});
