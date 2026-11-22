// SPDX-License-Identifier: Apache-2.0
//
// Reproducible AuthorizationV1 verification-precedence fixtures
// (verification-v1.md §5 reference sequence, §9.1 determining code).
// Each case combines defects whose determining code is fixed by step order,
// plus the single-defect issuer/kid cases that pin step 6 vs step 8.
// Self-contained: node:crypto only.
//
// TEST KEY ONLY - the repository's public conformance fixture key. Never fund.
//
// The committed corpus is docs/spec/test-vectors/authorization-precedence-v1.json.
// Ed25519 signatures are deterministic, so regeneration is byte-identical.
//
// Usage:
//   node scripts/repro/authorization-precedence-fixtures.mjs           # print to stdout
//   node scripts/repro/authorization-precedence-fixtures.mjs --check   # exit 1 if the committed corpus drifts
//   node scripts/repro/authorization-precedence-fixtures.mjs --write   # rewrite the committed corpus

import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const CORPUS = resolve(dirname(fileURLToPath(import.meta.url)), "../../docs/spec/test-vectors/authorization-precedence-v1.json");

const PRIVATE_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBx0hBPi6cIYPo/JZbavNXDDLlfV1vj+IyS+R4oq2Zvx
-----END PRIVATE KEY-----`;
const priv = createPrivateKey(PRIVATE_PEM);
const PUBLIC_PEM = createPublicKey(priv).export({ format: "pem", type: "spki" }).toString();
const DOMAIN = "OXDEAI_AUTH_V1\n";
const NOW = 1730000010;
const ISSUER = "oxdeai.policy-engine";
const KID = "2026-01";

function canon(v) {
  if (v === null) return "null";
  if (typeof v === "string") return JSON.stringify(v.normalize("NFC"));
  if (typeof v === "number") { if (!Number.isSafeInteger(v)) throw new Error("UNSUPPORTED_NUMBER"); return String(v); }
  if (typeof v === "boolean") return String(v);
  if (Array.isArray(v)) return `[${v.map(canon).join(",")}]`;
  const keys = Object.keys(v).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(",")}}`;
}

// Core-native (Encoding A) nested signature: the preimage is the top-level
// fields (including top-level alg/kid); the nested object is excluded.
function nested(fields, { tamper = false } = {}) {
  let s = sign(null, Buffer.concat([Buffer.from(DOMAIN), Buffer.from(canon(fields), "utf8")]), priv).toString("base64");
  if (tamper) s = (s[0] === "A" ? "B" : "A") + s.slice(1);
  return { ...fields, signature: { alg: "Ed25519", kid: fields.kid, sig: s } };
}

const base = {
  auth_id: "f".repeat(64), issuer: ISSUER, audience: "merchant-gateway",
  decision: "ALLOW", intent_hash: "a".repeat(64), state_hash: "b".repeat(64),
  policy_id: "c".repeat(64), issued_at: 1730000000, expiry: 1730000060,
  alg: "Ed25519", kid: KID,
};
const expired = { issued_at: NOW - 100, expiry: NOW - 50 };
const futureIssued = { issued_at: NOW + 100000, expiry: NOW + 200000 };
const keyset = (extra = {}) => [{ issuer: ISSUER, version: "1", keys: [{ kid: KID, alg: "Ed25519", public_key: PUBLIC_PEM, ...extra }] }];

const vectors = [];
let n = 0;
const add = (id, description, defects, artifact, options, step, code) => {
  n++;
  vectors.push({ id, description, defects, artifact, options, expected: { status: "invalid", step, determining_code: code } });
};
const id = (k) => ({ ...base, auth_id: k.repeat(64) });

// Issuer recognition vs key resolution (steps 6 and 8).
add("p-001", "Issuer recognized, kid unknown", ["kid-unknown"],
  nested({ ...id("1"), kid: "k-unknown" }), {}, 8, "AUTH_KID_UNKNOWN");
add("p-002", "Issuer differs from expectedIssuer and has no trusted key set: expectedIssuer decides before any kid lookup", ["issuer-mismatch", "kid-unknown"],
  nested({ ...id("2"), issuer: "other.issuer" }), {}, 6, "AUTH_ISSUER_MISMATCH");
add("p-003", "Issuer absent from trust configuration, no expectedIssuer configured", ["issuer-unrecognized"],
  nested({ ...id("3"), issuer: "other.issuer" }), { expectedIssuer: null }, 8, "AUTH_KID_UNKNOWN");
add("p-004", "kid unknown and signature cannot verify: step 8 decides, not step 10", ["kid-unknown", "signature-invalid"],
  nested({ ...id("4"), kid: "k-unknown" }, { tamper: true }), {}, 8, "AUTH_KID_UNKNOWN");

// Structural defects decide before cryptographic and temporal ones.
add("p-005", "decision DENY and audience mismatch", ["decision-invalid", "audience-mismatch"],
  nested({ ...id("5"), decision: "DENY" }), { expectedAudience: "other-gateway" }, 4, "AUTH_DECISION_INVALID");
add("p-006", "Unknown top-level field and expired: the step-2 AUTH_SIGNATURE_INVALID decides", ["unknown-field", "expired"],
  nested({ ...id("6"), ...expired, memo: "x" }), {}, 2, "AUTH_SIGNATURE_INVALID");
add("p-007", "Issuer/policy pair not authorized and expired", ["authority-not-authorized", "expired"],
  nested({ ...id("7"), ...expired }), { trustedAuthorizationAuthorities: [{ issuer: ISSUER, policyId: "e".repeat(64) }] }, 7, "AUTH_ISSUER_POLICY_NOT_AUTHORIZED");

// Key and signature decide before temporal, audience, policy and replay.
add("p-008", "Key inactive and audience mismatch", ["key-inactive", "audience-mismatch"],
  nested(id("8")), { trustedKeySets: keyset({ not_after: NOW - 5 }), expectedAudience: "other-gateway" }, 9, "AUTH_KEY_INACTIVE");
add("p-009", "Tampered signature and expired", ["signature-invalid", "expired"],
  nested({ ...id("9"), ...expired }, { tamper: true }), {}, 10, "AUTH_SIGNATURE_INVALID");
add("p-010", "Tampered signature and already consumed", ["signature-invalid", "replayed"],
  nested(id("a"), { tamper: true }), { consumedAuthIds: ["a".repeat(64)] }, 10, "AUTH_SIGNATURE_INVALID");
add("p-011", "Tampered signature and audience mismatch", ["signature-invalid", "audience-mismatch"],
  nested(id("b"), { tamper: true }), { expectedAudience: "other-gateway" }, 10, "AUTH_SIGNATURE_INVALID");

// Temporal before audience, audience before policy, policy before replay.
add("p-012", "Expired and audience mismatch", ["expired", "audience-mismatch"],
  nested({ ...id("c"), ...expired }), { expectedAudience: "other-gateway" }, 11, "AUTH_EXPIRED");
add("p-013", "issued_at implausible and audience mismatch", ["issued-at-implausible", "audience-mismatch"],
  nested({ ...id("d"), ...futureIssued }), { expectedAudience: "other-gateway" }, 12, "AUTH_ISSUED_AT_IMPLAUSIBLE");
add("p-014", "Audience mismatch and policy mismatch", ["audience-mismatch", "policy-mismatch"],
  nested(id("e")), { expectedAudience: "other-gateway", expectedPolicyId: "d".repeat(64) }, 13, "AUTH_AUDIENCE_MISMATCH");
add("p-015", "Policy mismatch and already consumed: replay is the last step", ["policy-mismatch", "replayed"],
  nested(id("0")), { expectedPolicyId: "d".repeat(64), consumedAuthIds: ["0".repeat(64)] }, 14, "AUTH_POLICY_ID_MISMATCH");

const out = JSON.stringify({
  version: 1,
  note: "TEST KEY ONLY - never funded. expected.determining_code is the code of the first failing step of verification-v1.md §5 (expected.step). Conformance compares the verdict and the determining code only (verification-v1.md §9.1); additional diagnostic codes are not compared. options are merged over verifier_options; a null value removes the option.",
  verifier_options: {
    now: NOW, mode: "strict", requireSignatureVerification: true,
    expectedIssuer: ISSUER, expectedAudience: "merchant-gateway",
    trustedKeySets: keyset(),
  },
  vectors,
}, null, 2) + "\n";

if (process.argv.includes("--write")) {
  writeFileSync(CORPUS, out);
  console.error(`wrote ${CORPUS}`);
} else if (process.argv.includes("--check")) {
  let committed = null;
  try { committed = readFileSync(CORPUS, "utf8"); } catch { /* missing corpus is drift */ }
  if (committed !== out) {
    console.error("authorization-precedence-v1.json drifts from the generator; run with --write");
    process.exit(1);
  }
  console.error("authorization-precedence-v1.json matches the generator");
} else {
  process.stdout.write(out);
}
