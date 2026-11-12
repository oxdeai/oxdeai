// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { createHash, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { authorizationSigningPayload, canonicalJson, verifyAuthorization } from "@oxdeai/core";
import type { AuthorizationV1, KeySet } from "@oxdeai/core";
import { createPepGatewayExecutor } from "../gateway.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "../../../..");
const fixedNow = 1712448050;

function loadJson(path: string): any {
  return JSON.parse(readFileSync(resolve(repoRoot, path), "utf8"));
}

function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

function vectorKeySet(authVectors: any): KeySet {
  return {
    issuer: "issuer-1",
    version: "vectors",
    keys: authVectors.keys.map((key: any) => ({
      kid: key.kid,
      alg: key.alg,
      public_key: key.public_key_pem,
    })),
  };
}

function authByRef(authVectors: any, id: string): AuthorizationV1 {
  const vector = authVectors.vectors.find((entry: any) => entry.id === id);
  assert.ok(vector, `missing authorization vector ${id}`);
  return structuredClone(vector.artifact) as AuthorizationV1;
}

/**
 * Issuer-policy authority for the locked vector corpus.
 *
 * Fixed corpus constants, NOT read off the artifact under test. The previous
 * helper passed `expectedPolicyId: auth.policy_id`, which compared each vector
 * against itself and could never fail (#301).
 */
const VECTOR_AUTHORITIES = [{ issuer: "issuer-1", policyId: "policy-1" }] as const;

// Consumer scope, not amendments to the authoritative vector expectations.
// external-provider-profile.md §§2.1.3/2.2.4: A/B sign state_hash, no live read.
// §2.3: Profile C requires OxDeAIGuard, not createPepGatewayExecutor.
// The corpus has no profile tags; the two snapshot-dependent expectations need
// a maintainer-approved state-binding surface. They are not gateway conformance
// passes. Full classification: docs/conformance/gateway-vector-parity-validation.md.
const PEP_GATEWAY_SCOPE = {
  "pep-allow-upstream-success": "gateway",
  "pep-auth-invalid-signature": "gateway",
  "pep-auth-intent-mismatch": "gateway",
  "pep-upstream-error": "gateway",
  "pep-upstream-timeout": "gateway",
  "pep-sb-state-mismatch": "deferred-state-binding-surface",
  "pep-sb-missing-state-snapshot": "deferred-state-binding-surface",
  "pep-auth-forged-valid-hashes": "gateway",
  "pep-sb-missing-auth-state-hash": "gateway",
} as const;

function expectedAuthorizationDecision(vector: any, authVectors: any): { decision: "ALLOW" | "DENY"; error: string | null } {
  const auth = structuredClone(vector.artifact) as AuthorizationV1;
  const keySet = vectorKeySet(authVectors);
  const verification = verifyAuthorization(auth, {
    now: fixedNow,
    mode: "strict",
    trustedKeySets: [keySet],
    requireSignatureVerification: true,
    expectedAudience: "pep-gateway.local",
    trustedAuthorizationAuthorities: VECTOR_AUTHORITIES,
  });

  if (verification.status !== "ok") {
    if (verification.violations.some((v) => v.code === "AUTH_EXPIRED")) {
      return { decision: "DENY", error: "EXPIRED" };
    }
    if (vector.state_snapshot !== undefined && !auth.state_hash) {
      return { decision: "DENY", error: "STATE_HASH_MISSING" };
    }
    if (verification.violations.some((v) => v.code === "AUTH_KID_UNKNOWN")) {
      return { decision: "DENY", error: "UNKNOWN_KID" };
    }
    if (verification.violations.some((v) => v.code === "AUTH_SIGNATURE_INVALID")) {
      return { decision: "DENY", error: "INVALID_SIGNATURE" };
    }
    return { decision: "DENY", error: verification.violations[0]?.code ?? "AUTHORIZATION_INVALID" };
  }

  const expectedIntentHash = vector.proposed_action !== undefined
    ? sha256Hex(canonicalJson(vector.proposed_action))
    : authVectors.vectors.find((entry: any) => entry.id === "auth-allow-valid")?.artifact.intent_hash;
  if (expectedIntentHash && auth.intent_hash !== expectedIntentHash) {
    return { decision: "DENY", error: "INTENT_HASH_MISMATCH" };
  }
  if (vector.state_snapshot !== undefined && sha256Hex(canonicalJson(vector.state_snapshot)) !== auth.state_hash) {
    return { decision: "DENY", error: "STATE_HASH_MISMATCH" };
  }
  return { decision: "ALLOW", error: null };
}

test("canonicalization-v1 locked vectors match core canonicalJson", () => {
  const vectors = loadJson("docs/spec/test-vectors/canonicalization-v1.json");
  for (const vector of vectors) {
    if (vector.status === "ok") {
      const actual = canonicalJson(vector.input);
      assert.equal(actual, vector.expected_canonical_json, vector.id);
      assert.equal(sha256Hex(actual), vector.expected_sha256, vector.id);
    } else {
      assert.throws(
        () => canonicalJson(vector.input),
        (err: unknown) => err instanceof Error && err.message === vector.expected_error,
        vector.id
      );
    }
  }
});

test("authorization-v1 corpus checks combine Core verification with fixture action/state context", () => {
  const authVectors = loadJson("docs/spec/test-vectors/authorization-v1.json");
  for (const vector of authVectors.vectors) {
    const actual = expectedAuthorizationDecision(vector, authVectors);
    assert.deepEqual(actual, vector.expected, vector.id);
  }
});

test("nested corpus signatures bind top-level alg/kid and public fields", () => {
  const corpus = loadJson("docs/spec/test-vectors/authorization-v1.json");
  for (const id of ["auth-allow-valid", "sb-auth-allow-valid"]) {
    const auth = authByRef(corpus, id);
    const { signature, ...signed } = auth;
    assert.ok(typeof signature === "object");
    const key = corpus.keys.find((entry: any) => entry.kid === signature.kid);
    // Independent crypto over the committed corpus construction, not a
    // signature generated with the same payload helper that we are testing.
    const bytes = canonicalJson(signed);
    assert.equal(verify(null, Buffer.from(bytes), key.public_key_pem, Buffer.from(signature.sig, "base64")), true, id);
    assert.equal(canonicalJson(authorizationSigningPayload(auth)), bytes, id);
    const { alg: _alg, kid: _kid, ...oldPayload } = signed;
    assert.equal(verify(null, Buffer.from(canonicalJson(oldPayload)), key.public_key_pem, Buffer.from(signature.sig, "base64")), false, id);
    for (const field of ["alg", "kid", "audience", "policy_id", "state_hash"] as const) {
      const mutated = { ...auth, [field]: `${auth[field]}-tampered` } as AuthorizationV1;
      const result = verifyAuthorization(mutated, {
        now: fixedNow,
        mode: "strict",
        trustedKeySets: vectorKeySet(corpus),
        trustedAuthorizationAuthorities: VECTOR_AUTHORITIES,
        expectedAudience: "pep-gateway.local",
      });
      assert.equal(result.signatureVerified, false, `${id}: ${field}`);
      assert.equal(result.status, "invalid", `${id}: ${field}`);
      assert.ok(result.violations.some(v => v.code === "AUTH_SIGNATURE_INVALID"), `${id}: ${field}`);
    }
  }
});

test("valid nested corpus signature cannot authorize a cross-pair gateway request", async () => {
  const corpus = loadJson("docs/spec/test-vectors/authorization-v1.json");
  const pep = loadJson("docs/spec/test-vectors/pep-vectors-v1.json");
  let calls = 0;
  const gateway = createPepGatewayExecutor({
    expectedAudience: "pep-gateway.local",
    trustedKeySets: vectorKeySet(corpus),
    trustedAuthorizationAuthorities: [
      { issuer: "issuer-1", policyId: "policy-2" },
      { issuer: "issuer-2", policyId: "policy-1" },
    ],
    internalExecutorToken: pep.gateway_secret,
    now: () => fixedNow,
    executeUpstream: async () => { calls++; return { status: 200 }; },
  });
  const result = await gateway({ action: pep.vectors[0].request.action, authorization: authByRef(corpus, "sb-auth-allow-valid") });
  assert.equal(result.status, 403);
  assert.equal(result.body.reason, "AUTH_ISSUER_POLICY_NOT_AUTHORIZED");
  assert.equal(result.upstreamCalled, false);
  assert.equal(calls, 0);
});

test("A/B gateway protects signed state_hash without requiring live snapshot comparison", async () => {
  const corpus = loadJson("docs/spec/test-vectors/authorization-v1.json");
  const pep = loadJson("docs/spec/test-vectors/pep-vectors-v1.json");
  // Use these artifacts as signed inputs only. This is an A/B surface test,
  // NOT a passing execution of the two conditional-state PEP vectors.
  for (const id of ["sb-auth-state-mismatch", "sb-auth-allow-valid"]) {
    let calls = 0;
    const gateway = createPepGatewayExecutor({
      expectedAudience: "pep-gateway.local",
      trustedAuthorizationAuthorities: VECTOR_AUTHORITIES,
      trustedKeySets: vectorKeySet(corpus),
      internalExecutorToken: pep.gateway_secret,
      now: () => fixedNow,
      executeUpstream: async () => { calls++; return { status: 200 }; },
    });
    const auth = authByRef(corpus, id);
    const action = pep.vectors[0].request.action;
    const tampered = await gateway({ action, authorization: { ...auth, state_hash: "tampered" } });
    assert.equal(tampered.status, 403);
    assert.equal(tampered.body.reason, "AUTH_SIGNATURE_INVALID");
    assert.equal(tampered.body.executed, false);
    assert.equal(tampered.upstreamCalled, false);
    assert.equal(calls, 0);
    const intact = await gateway({ action, authorization: auth });
    assert.equal(intact.status, 200, id);
    assert.equal(intact.body.executed, true, id);
    assert.equal(calls, 1, id);
  }
});

test("pep-gateway-v1 gateway subset (7 cases; 2 state-binding dispositions deferred)", async (t) => {
  const authVectors = loadJson("docs/spec/test-vectors/authorization-v1.json");
  const pepVectors = loadJson("docs/spec/test-vectors/pep-vectors-v1.json");
  const keySet = vectorKeySet(authVectors);
  assert.deepEqual(Object.keys(PEP_GATEWAY_SCOPE).sort(), pepVectors.vectors.map((v: any) => v.id).sort(),
    "Every corpus ID must have an explicit reviewed surface disposition");

  for (const vector of pepVectors.vectors) {
    if (PEP_GATEWAY_SCOPE[vector.id as keyof typeof PEP_GATEWAY_SCOPE] !== "gateway") {
      t.diagnostic(`DEFERRED ${vector.id}: conditional state-binding surface, not an A/B gateway conformance pass`);
      continue;
    }
    let upstreamCalls = 0;
    const gateway = createPepGatewayExecutor({
      expectedAudience: "pep-gateway.local",
      trustedAuthorizationAuthorities: VECTOR_AUTHORITIES,
      trustedKeySets: [keySet],
      internalExecutorToken: pepVectors.gateway_secret,
      now: () => fixedNow,
      timeoutMs: 10,
      executeUpstream: async (_action, headers) => {
        upstreamCalls++;
        assert.equal(headers[pepVectors.upstream_header], pepVectors.gateway_secret, vector.id);
        switch (vector.request.upstream_behavior) {
          case "success":
            return { status: 200, body: { ok: true, executed: true } };
          case "error":
            return { status: 500, body: { ok: false, executed: false } };
          case "timeout":
            return new Promise((resolve) => setTimeout(() => resolve({ status: 200, body: {} }), 100));
          case "not_called":
          default:
            throw new Error("UPSTREAM_MUST_NOT_BE_CALLED");
        }
      },
    });

    const result = await gateway({
      action: vector.request.action,
      authorization: authByRef(authVectors, vector.request.authorization_ref),
    });

    assert.equal(result.status, vector.expected.status, vector.id);
    assert.equal(result.body.decision, vector.expected.decision, vector.id);
    assert.equal(result.body.executed, vector.expected.executed, vector.id);
    // H-1: the three-state outcome is now the authoritative field.
    if (vector.expected.outcome !== undefined) {
      assert.equal(result.body.outcome, vector.expected.outcome, vector.id);
    }
    const expectedCalls = vector.request.upstream_behavior === "not_called" ? 0 : 1;
    assert.equal(upstreamCalls, expectedCalls, vector.id);
    assert.equal(result.upstreamCalled, expectedCalls === 1, vector.id);
  }
});
