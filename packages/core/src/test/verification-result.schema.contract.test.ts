// SPDX-License-Identifier: Apache-2.0
//
// SCHEMA-PARITY-01: contract parity between the public VerificationResult
// TypeScript contract (packages/core/src/verification/types.ts) and the
// published JSON Schema (packages/core/schemas/verification-result.schema.json).
//
// These tests exercise ACTUAL JSON Schema validation semantics via a small,
// self-contained validator for the exact draft-2020-12 keyword subset this
// schema uses (type, enum, required, additionalProperties:false, properties,
// items, pattern, minimum). ajv is not a dependency of @oxdeai/core and the
// mandate forbids adding one; the subset validator is the minimal, necessary
// infrastructure. The validator itself is covered by positive AND negative
// controls below, so a trivially-accepting validator would fail the suite.
//
// Parity source of truth is the public union text in types.ts, parsed at test
// time. There is NO second hand-maintained code list: adding a code to the
// public union (or removing one) changes the parsed set and fails the parity
// test until the schema is updated to match.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { generateKeyPairSync } from "node:crypto";
import { signAuthorizationEd25519, verifyAuthorization } from "../verification/verifyAuthorization.js";
import type { AuthorizationV1 } from "../types/authorization.js";
import type { KeySet } from "../types/keyset.js";

// ── Load the two contracts from disk (core package root) ──────────────────────
const here = path.dirname(fileURLToPath(import.meta.url)); // dist/test
const coreRoot = path.resolve(here, "../.."); // packages/core
const typesSrcPath = path.join(coreRoot, "src/verification/types.ts");
const schemaPath = path.join(coreRoot, "schemas/verification-result.schema.json");

const typesSrc = readFileSync(typesSrcPath, "utf8");
const schema = JSON.parse(readFileSync(schemaPath, "utf8"));

// Extract the string-literal members of a public union type. Members are
// SCREAMING_SNAKE / kebab string literals; the regex is scoped to the single
// `export type <Name> = ... ;` declaration so it cannot pick up another union.
function extractUnion(name: string): string[] {
  const m = typesSrc.match(new RegExp(`export type ${name}\\s*=([\\s\\S]*?);`));
  assert.ok(m, `public union ${name} not found in types.ts`);
  const members = [...m![1].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
  assert.ok(members.length > 0, `public union ${name} parsed empty`);
  return members;
}

// ── Supported keyword set (single source for the validator AND the guard) ─────
// The subset validator below implements exactly these validation keywords.
// Annotation/identifier keywords carry no validation semantics and are ignored.
// The coverage guard test asserts the schema uses ONLY these; if the schema
// later introduces any other keyword (allOf, anyOf, oneOf, $ref, format,
// minLength, patternProperties, const, ...), the guard FAILS so the validator
// must be extended (or a full JSON Schema engine vendored) before the schema
// can drift past what these tests actually enforce.
const SUPPORTED_VALIDATION_KEYWORDS = new Set<string>([
  "type", "enum", "required", "properties", "items", "additionalProperties", "pattern", "minimum",
]);
const IGNORED_ANNOTATION_KEYWORDS = new Set<string>([
  "$schema", "$id", "title", "description", "$comment",
]);

// Collect every keyword that appears in a keyword position of the schema,
// recursing into `properties` values, `items`, and a schema-valued
// `additionalProperties`. Property NAMES under `properties` are data, not
// keywords, and are deliberately not collected.
function collectSchemaKeywords(node: unknown, acc: Set<string> = new Set()): Set<string> {
  if (node === null || typeof node !== "object" || Array.isArray(node)) return acc;
  const obj = node as Record<string, unknown>;
  for (const k of Object.keys(obj)) {
    acc.add(k);
    if (k === "properties" && obj[k] && typeof obj[k] === "object") {
      for (const v of Object.values(obj[k] as Record<string, unknown>)) collectSchemaKeywords(v, acc);
    } else if (k === "items") {
      collectSchemaKeywords(obj[k], acc);
    } else if (k === "additionalProperties" && obj[k] && typeof obj[k] === "object") {
      collectSchemaKeywords(obj[k], acc);
    }
  }
  return acc;
}

// ── Minimal JSON Schema validator (exact subset this schema uses) ─────────────
type SchemaNode = Record<string, any>;
function validate(node: SchemaNode, data: unknown, p = "$"): string[] {
  const errors: string[] = [];
  const walk = (s: SchemaNode, d: unknown, at: string): void => {
    if (typeof s.type === "string") {
      const t = s.type;
      const ok =
        t === "object" ? d !== null && typeof d === "object" && !Array.isArray(d) :
        t === "array" ? Array.isArray(d) :
        t === "string" ? typeof d === "string" :
        t === "boolean" ? typeof d === "boolean" :
        t === "integer" ? typeof d === "number" && Number.isInteger(d) :
        t === "number" ? typeof d === "number" : true;
      if (!ok) { errors.push(`${at}: expected type ${t}`); return; }
    }
    if (Array.isArray(s.enum) && !s.enum.includes(d as never)) errors.push(`${at}: value not in enum`);
    if (typeof s.pattern === "string" && typeof d === "string" && !new RegExp(s.pattern).test(d)) errors.push(`${at}: pattern mismatch`);
    if (typeof s.minimum === "number" && typeof d === "number" && d < s.minimum) errors.push(`${at}: below minimum`);
    if (s.type === "object" && d !== null && typeof d === "object" && !Array.isArray(d)) {
      const obj = d as Record<string, unknown>;
      for (const r of (s.required ?? []) as string[]) if (!(r in obj)) errors.push(`${at}: missing required '${r}'`);
      const props = (s.properties ?? {}) as Record<string, SchemaNode>;
      for (const k of Object.keys(obj)) {
        if (k in props) walk(props[k], obj[k], `${at}.${k}`);
        else if (s.additionalProperties === false) errors.push(`${at}: unexpected property '${k}'`);
      }
    }
    if (s.type === "array" && Array.isArray(d) && s.items) {
      (d as unknown[]).forEach((it, i) => walk(s.items as SchemaNode, it, `${at}[${i}]`));
    }
  };
  walk(node, data, p);
  return errors;
}
const isValid = (data: unknown) => validate(schema, data).length === 0;

const codeEnum: string[] = schema.properties.violations.items.properties.code.enum;
const ok = (status: string, violations: unknown[] = [], extra: Record<string, unknown> = {}) =>
  ({ ok: status === "ok", status, violations, ...extra });

// ── 0. Validator self-check (positive + negative controls) ────────────────────
test("validator accepts a known-good minimal result and rejects a known-bad one", () => {
  assert.ok(isValid(ok("ok")), "minimal valid result must validate");
  assert.ok(!isValid({ ok: true }), "missing required fields must fail (validator is not trivially accepting)");
  assert.ok(!isValid(ok("ok", [], { bogusUnknown: 1 })), "unknown property must fail");
});

// ── 0b. Keyword-coverage guard: schema must use ONLY validator-supported keywords
// Enforces the documented limitation: the subset validator silently ignores
// unknown keywords, so this guard fails if the schema introduces any keyword the
// validator does not actually enforce. This is the condition on accepting a
// subset validator rather than a full Draft 2020-12 engine.
test("schema uses only keywords the subset validator actually enforces", () => {
  const used = collectSchemaKeywords(schema);
  const unsupported = [...used].filter(
    (k) => !SUPPORTED_VALIDATION_KEYWORDS.has(k) && !IGNORED_ANNOTATION_KEYWORDS.has(k),
  );
  assert.deepEqual(
    unsupported,
    [],
    `schema uses keyword(s) not enforced by the subset validator: ${unsupported.join(", ")}. ` +
      `Extend the validator (and SUPPORTED_VALIDATION_KEYWORDS) or vendor a full JSON Schema engine before relying on these tests.`,
  );
  // Sanity: the validator's supported set is actually exercised by this schema
  // (so the guard cannot pass vacuously by the schema being near-empty).
  for (const kw of ["type", "enum", "required", "properties", "additionalProperties"]) {
    assert.ok(used.has(kw), `expected schema to exercise '${kw}'`);
  }
});

// ── 1. Every applicable public violation code is accepted ─────────────────────
test("every public violation code is accepted by the schema", () => {
  for (const code of extractUnion("VerificationViolationCode")) {
    const errs = validate(schema, ok("invalid", [{ code }]));
    assert.deepEqual(errs, [], `code ${code} should be accepted; errors: ${errs.join("; ")}`);
  }
});

// ── 2. Code enum matches the public TypeScript contract (drift guard) ─────────
test("schema code enum is in exact parity with the public VerificationViolationCode union", () => {
  const publicCodes = extractUnion("VerificationViolationCode");
  const missingFromSchema = publicCodes.filter((c) => !codeEnum.includes(c));
  const extraInSchema = codeEnum.filter((c) => !publicCodes.includes(c));
  assert.deepEqual(missingFromSchema, [], `codes in TS contract but absent from schema: ${missingFromSchema.join(", ")}`);
  assert.deepEqual(extraInSchema, [], `codes in schema but absent from TS contract: ${extraInSchema.join(", ")}`);
  // set equality, order-independent
  assert.equal(new Set(codeEnum).size, new Set(publicCodes).size);
});

// ── 2b. Metadata enums (mode/coverage/status) are in parity with the contract ──
test("schema verificationMode / verificationCoverage / status enums match the public unions", () => {
  assert.deepEqual(new Set(schema.properties.verificationMode.enum), new Set(extractUnion("VerificationMode")));
  assert.deepEqual(new Set(schema.properties.verificationCoverage.enum), new Set(extractUnion("VerificationCoverage")));
  assert.deepEqual(new Set(schema.properties.status.enum), new Set(extractUnion("VerificationStatus")));
});

// ── 3. All three optional verification fields accepted with valid values ──────
test("optional verification-metadata fields are accepted with valid values", () => {
  for (const mode of extractUnion("VerificationMode")) {
    for (const coverage of extractUnion("VerificationCoverage")) {
      for (const sig of [true, false]) {
        const errs = validate(schema, ok("ok", [], { signatureVerified: sig, verificationMode: mode, verificationCoverage: coverage }));
        assert.deepEqual(errs, [], `metadata {${sig},${mode},${coverage}} should validate; errors: ${errs.join("; ")}`);
      }
    }
  }
});

// ── 4. Invalid enum values and incorrect field types are rejected ─────────────
test("invalid enum values are rejected", () => {
  assert.ok(!isValid(ok("invalid", [{ code: "NOT_A_REAL_CODE" }])), "unknown violation code must be rejected");
  assert.ok(!isValid(ok("bogus-status")), "unknown status must be rejected");
  assert.ok(!isValid(ok("ok", [], { verificationMode: "lenient" })), "unknown verificationMode must be rejected");
  assert.ok(!isValid(ok("ok", [], { verificationCoverage: "partial" })), "unknown verificationCoverage must be rejected");
});
test("incorrect field types are rejected", () => {
  assert.ok(!isValid({ ok: "yes", status: "ok", violations: [] }), "ok must be boolean");
  assert.ok(!isValid(ok("ok", [], { signatureVerified: "true" })), "signatureVerified must be boolean");
  assert.ok(!isValid(ok("invalid", [{ code: "AUTH_EXPIRED", index: -1 }])), "index below minimum must be rejected");
  assert.ok(!isValid(ok("invalid", [{ code: "AUTH_EXPIRED", index: 1.5 }])), "non-integer index must be rejected");
  assert.ok(!isValid(ok("ok", "not-an-array" as unknown as unknown[])), "violations must be an array");
});

// ── 5. Unknown properties remain rejected (root and violation item) ───────────
test("unknown properties are rejected at root and in violation items", () => {
  assert.ok(!isValid(ok("ok", [], { somethingNew: 1 })), "unknown root property must be rejected");
  assert.ok(!isValid(ok("invalid", [{ code: "AUTH_EXPIRED", unexpected: true }])), "unknown violation-item property must be rejected");
});

// ── 6. Required fields remain mandatory ───────────────────────────────────────
test("required fields remain mandatory", () => {
  assert.ok(!isValid({ status: "ok", violations: [] }), "missing ok must fail");
  assert.ok(!isValid({ ok: true, violations: [] }), "missing status must fail");
  assert.ok(!isValid({ ok: true, status: "ok" }), "missing violations must fail");
  assert.ok(!isValid(ok("invalid", [{ message: "no code" }])), "violation missing code must fail");
});

// ── 7. Representative real authorization-verification results validate ────────
const KEYS = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
const KEYSET: KeySet = { issuer: "issuer-schema", version: "1", keys: [{ kid: "kid-schema-1", alg: "Ed25519", public_key: KEYS.publicKey }] };
const T_ISSUED = 1_000_000, T_NOW = 1_001_000, T_EXPIRY = 1_003_600;
function signed(decision: "ALLOW" | "DENY" = "ALLOW"): AuthorizationV1 {
  return signAuthorizationEd25519(
    {
      version: "AuthorizationV1",
      auth_id: "f".repeat(64), issuer: "issuer-schema", audience: "rp-schema",
      intent_hash: "a".repeat(64), state_hash: "b".repeat(64), policy_id: "c".repeat(64),
      decision, issued_at: T_ISSUED, expiry: T_EXPIRY, kid: "kid-schema-1",
    },
    KEYS.privateKey,
  );
}
const vopts = { now: T_NOW, mode: "strict" as const, trustedKeySets: [KEYSET], requireSignatureVerification: true, expectedAudience: "rp-schema" };

test("a passing real AuthorizationVerificationResult validates against the schema", () => {
  const result = verifyAuthorization(signed("ALLOW"), vopts as never);
  assert.equal(result.ok, true, "fixture precondition: must verify ok");
  const errs = validate(schema, result);
  assert.deepEqual(errs, [], `real ALLOW result should conform; errors: ${errs.join("; ")}`);
});
test("a rejected real AuthorizationVerificationResult (tampered) validates against the schema", () => {
  const bad = signed("ALLOW");
  (bad as { intent_hash: string }).intent_hash = "e".repeat(64); // break the signature binding
  const result = verifyAuthorization(bad, vopts as never);
  assert.equal(result.ok, false, "fixture precondition: tampered must fail verification");
  const errs = validate(schema, result);
  assert.deepEqual(errs, [], `real rejected result should still conform to the schema; errors: ${errs.join("; ")}`);
  assert.ok(result.violations.every((v) => codeEnum.includes(v.code)), "every emitted violation code must be in the schema enum");
});
