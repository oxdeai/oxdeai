// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  DEFAULT_MAX_FUTURE_ISSUED_AT_SKEW_SECONDS,
  signAuthorizationEd25519,
  verifyAuthorization
} from "../verification/index.js";
import type { KeySet } from "../types/keyset.js";

const TEST_RUNTIME_ED25519_KEYPAIR_DO_NOT_USE_IN_PRODUCTION = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

const TEST_KEYSET: KeySet = {
  issuer: "issuer-A",
  version: "1",
  keys: [{ kid: "2026-01", alg: "Ed25519", public_key: TEST_RUNTIME_ED25519_KEYPAIR_DO_NOT_USE_IN_PRODUCTION.publicKey }]
};

function makeAuth(overrides?: { issued_at?: number; expiry?: number }) {
  return signAuthorizationEd25519(
    {
      auth_id: "f".repeat(64),
      issuer: "issuer-A",
      audience: "rp-A",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: "c".repeat(64),
      decision: "ALLOW",
      issued_at: overrides?.issued_at ?? 1000,
      expiry: overrides?.expiry ?? 1060,
      kid: "2026-01"
    },
    TEST_RUNTIME_ED25519_KEYPAIR_DO_NOT_USE_IN_PRODUCTION.privateKey
  );
}

test("ok: valid signed authorization", () => {
  const out = verifyAuthorization(makeAuth(), {
    now: 1010,
    trustedKeySets: TEST_KEYSET,
    expectedIssuer: "issuer-A",
    expectedAudience: "rp-A",
    expectedPolicyId: "c".repeat(64),
    requireSignatureVerification: true
  });
  assert.equal(out.status, "ok");
});

test("invalid: tampered authorization field", () => {
  const auth = makeAuth();
  const out = verifyAuthorization({ ...auth, state_hash: "d".repeat(64) }, {
    now: 1010,
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true
  });
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "AUTH_SIGNATURE_INVALID"));
});

test("invalid: unknown kid", () => {
  const auth = makeAuth();
  const out = verifyAuthorization({ ...auth, kid: "missing" }, {
    now: 1010,
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true
  });
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "AUTH_KID_UNKNOWN"));
});

test("invalid: strict mode without trustedKeySets fails closed with TRUSTED_KEYSETS_REQUIRED", () => {
  const out = verifyAuthorization(makeAuth(), { now: 1010, mode: "strict" });
  assert.equal(out.ok, false);
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "TRUSTED_KEYSETS_REQUIRED"));
});

test("invalid: strict mode with empty trustedKeySets array fails closed with TRUSTED_KEYSETS_REQUIRED", () => {
  const out = verifyAuthorization(makeAuth(), { now: 1010, mode: "strict", trustedKeySets: [] });
  assert.equal(out.ok, false);
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "TRUSTED_KEYSETS_REQUIRED"));
});

test("ok: strict mode with trustedKeySets passes the guard", () => {
  const out = verifyAuthorization(makeAuth(), {
    now: 1010,
    mode: "strict",
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true
  });
  assert.equal(out.status, "ok");
  assert.equal(out.violations.filter((v) => v.code === "TRUSTED_KEYSETS_REQUIRED").length, 0);
});

test("invalid: unsupported alg", () => {
  const auth = makeAuth();
  const out = verifyAuthorization({ ...auth, alg: "Unknown" as any }, {
    now: 1010,
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true
  });
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "AUTH_ALG_UNSUPPORTED"));
});

// ── issued_at future-plausibility (#190) ────────────────────────────────────

const NOW = 1_000_000;

test("ok: issued_at exactly at the future-skew boundary is allowed", () => {
  const issued_at = NOW + DEFAULT_MAX_FUTURE_ISSUED_AT_SKEW_SECONDS;
  const auth = makeAuth({ issued_at, expiry: issued_at + 60 });
  const out = verifyAuthorization(auth, {
    now: NOW,
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true
  });
  assert.equal(out.status, "ok");
  assert.deepEqual(out.violations, []);
});

test("invalid: issued_at one second beyond the boundary is rejected", () => {
  const issued_at = NOW + DEFAULT_MAX_FUTURE_ISSUED_AT_SKEW_SECONDS + 1;
  const auth = makeAuth({ issued_at, expiry: issued_at + 60 });
  const out = verifyAuthorization(auth, {
    now: NOW,
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true
  });
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "AUTH_ISSUED_AT_IMPLAUSIBLE"));
});

test("invalid: issued_at 100 years in the future is rejected even though not expired", () => {
  const ONE_HUNDRED_YEARS_SECONDS = 100 * 365 * 24 * 60 * 60;
  const issued_at = NOW + ONE_HUNDRED_YEARS_SECONDS;
  const auth = makeAuth({ issued_at, expiry: issued_at + 60 });
  const out = verifyAuthorization(auth, {
    now: NOW,
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true
  });
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "AUTH_ISSUED_AT_IMPLAUSIBLE"));
  // Would otherwise still be within its validity window - proves the old
  // "expiry hasn't passed" check alone cannot catch this.
  assert.ok(!out.violations.some((v) => v.code === "AUTH_EXPIRED"));
});

test("ok: normal authorization (issued_at in the recent past) is unaffected", () => {
  const auth = makeAuth({ issued_at: NOW - 5, expiry: NOW + 60 });
  const out = verifyAuthorization(auth, {
    now: NOW,
    trustedKeySets: TEST_KEYSET,
    expectedIssuer: "issuer-A",
    expectedAudience: "rp-A",
    requireSignatureVerification: true
  });
  assert.equal(out.status, "ok");
  assert.deepEqual(out.violations, []);
});

test("expiry behavior unchanged: expired authorization with a plausible issued_at still rejects with AUTH_EXPIRED only", () => {
  const auth = makeAuth({ issued_at: NOW - 120, expiry: NOW });
  const out = verifyAuthorization(auth, {
    now: NOW,
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true
  });
  assert.equal(out.status, "invalid");
  assert.deepEqual(out.violations.map((v) => v.code), ["AUTH_EXPIRED"]);
});

test("determinism: identical inputs produce identical results", () => {
  const issued_at = NOW + DEFAULT_MAX_FUTURE_ISSUED_AT_SKEW_SECONDS + 1;
  const auth = makeAuth({ issued_at, expiry: issued_at + 60 });
  const opts = { now: NOW, trustedKeySets: TEST_KEYSET, requireSignatureVerification: true };
  const first = verifyAuthorization(auth, opts);
  const second = verifyAuthorization(auth, opts);
  assert.deepEqual(first, second);
});

test("invalid: changing only an unrelated intent-shaped field cannot affect the issued_at check", () => {
  // verifyAuthorization has no `intent` parameter; the comparison MUST use
  // only opts.now (the trusted verificationTime) and auth.issued_at. Smuggle
  // an extraneous 'timestamp' field onto the artifact (as if an agent tried
  // to influence the check by supplying an Intent-shaped payload) and confirm
  // it has zero effect on the outcome.
  const issued_at = NOW + DEFAULT_MAX_FUTURE_ISSUED_AT_SKEW_SECONDS + 1;
  const auth = makeAuth({ issued_at, expiry: issued_at + 60 });
  const opts = { now: NOW, trustedKeySets: TEST_KEYSET, requireSignatureVerification: true };

  const baseline = verifyAuthorization(auth, opts);
  const withFakeIntentTimestamp = verifyAuthorization(
    { ...auth, timestamp: NOW } as any,
    opts
  );

  // The smuggled field has zero effect on the issued_at outcome ...
  const isR04 = (v: { code: string; message?: string }) =>
    v.code === "AUTH_SIGNATURE_INVALID" && String(v.message).startsWith("field(s) not covered by the signature");
  assert.deepEqual(withFakeIntentTimestamp.violations.filter((v) => !isR04(v)), baseline.violations);
  assert.ok(baseline.violations.some((v) => v.code === "AUTH_ISSUED_AT_IMPLAUSIBLE"));
  // ... and, under R-04 (authorization-v1.md §5 "Signed field set"), the
  // unsigned field is itself rejected rather than silently tolerated.
  assert.ok(withFakeIntentTimestamp.violations.some(isR04));
  assert.equal(baseline.violations.some(isR04), false);
});

test("ok: explicit maxFutureIssuedAtSkewSeconds overrides the default", () => {
  const issued_at = NOW + 10_000;
  const auth = makeAuth({ issued_at, expiry: issued_at + 60 });
  const out = verifyAuthorization(auth, {
    now: NOW,
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true,
    maxFutureIssuedAtSkewSeconds: 10_000
  });
  assert.equal(out.status, "ok");
});

test("invalid: explicit maxFutureIssuedAtSkewSeconds tightens the default and still rejects", () => {
  const issued_at = NOW + 100;
  const auth = makeAuth({ issued_at, expiry: issued_at + 60 });
  const out = verifyAuthorization(auth, {
    now: NOW,
    trustedKeySets: TEST_KEYSET,
    requireSignatureVerification: true,
    maxFutureIssuedAtSkewSeconds: 10
  });
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "AUTH_ISSUED_AT_IMPLAUSIBLE"));
});

for (const malformed of [-1, NaN, Infinity, -Infinity, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
  test(`throws: malformed maxFutureIssuedAtSkewSeconds (${String(malformed)}) fails closed instead of silently accepting/defaulting`, () => {
    const auth = makeAuth();
    assert.throws(() =>
      verifyAuthorization(auth, {
        now: 1010,
        trustedKeySets: TEST_KEYSET,
        maxFutureIssuedAtSkewSeconds: malformed
      })
    );
  });
}

test("invalid: unsafe-magnitude issued_at is rejected as implausible without overflowing", () => {
  // canonicalJson itself refuses to sign an unsafe-magnitude number, so a real
  // artifact can never carry one - construct the malformed field directly on
  // an otherwise-valid artifact (as a tampered/non-conformant wire payload
  // would) to exercise the overflow-safe guard in isolation from signing.
  const auth = { ...makeAuth(), issued_at: Number.MAX_SAFE_INTEGER + 2, expiry: NOW + 60 };
  const out = verifyAuthorization(auth, { now: NOW });
  assert.equal(out.status, "invalid");
  assert.ok(out.violations.some((v) => v.code === "AUTH_ISSUED_AT_IMPLAUSIBLE"));
});
