// SPDX-License-Identifier: Apache-2.0
//
// Reproducible AuthorizationV1 wire-encoding fixtures (authorization-v1.md §5):
// encoding separation (Core-native vs Sift-compatible), nested-signature
// preimage, and alg/kid ambiguity. Self-contained: node:crypto only.
//
// TEST KEY ONLY — the repository's public conformance fixture key. Never fund.
//
// Usage: node scripts/repro/authorization-wire-encoding-fixtures.mjs > fixtures.json

import { createPrivateKey, createPublicKey, sign } from "node:crypto";

const PRIVATE_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBx0hBPi6cIYPo/JZbavNXDDLlfV1vj+IyS+R4oq2Zvx
-----END PRIVATE KEY-----`;
const priv = createPrivateKey(PRIVATE_PEM);
const PUBLIC_PEM = createPublicKey(priv).export({ format: "pem", type: "spki" }).toString();
const DOMAIN = "OXDEAI_AUTH_V1\n";
const NOW = 1730000010;

function canon(v) {
  if (v === null) return "null";
  if (typeof v === "string") return JSON.stringify(v.normalize("NFC"));
  if (typeof v === "number") { if (!Number.isSafeInteger(v)) throw new Error("UNSUPPORTED_NUMBER"); return String(v); }
  if (typeof v === "boolean") return String(v);
  if (Array.isArray(v)) return `[${v.map(canon).join(",")}]`;
  const keys = Object.keys(v).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(",")}}`;
}
const sig = (payload, { prefixed, alphabet }) => {
  const body = Buffer.from(canon(payload), "utf8");
  const msg = prefixed ? Buffer.concat([Buffer.from(DOMAIN), body]) : body;
  return sign(null, msg, priv).toString(alphabet);
};

const base = {
  auth_id: "f".repeat(64), issuer: "oxdeai.policy-engine", audience: "merchant-gateway",
  decision: "ALLOW", intent_hash: "a".repeat(64), state_hash: "b".repeat(64),
  policy_id: "c".repeat(64), issued_at: 1730000000,
};
const coreFields = { ...base, expiry: 1730000060, alg: "Ed25519", kid: "2026-01" };
const siftFields = { ...base, expires_at: 1730000060 };

const vectors = [];
const add = (id, description, artifact, expected) => vectors.push({ id, description, artifact, expected });
const OK = { status: "ok", violations: [] };
const bad = (code) => ({ status: "invalid", codes: [code] });

// Baselines
add("w-001", "Core-native flat: Ed25519, expiry, prefixed preimage, standard base64",
  { ...coreFields, signature: sig(coreFields, { prefixed: true, alphabet: "base64" }) }, OK);
add("w-003", "Sift-compatible: ed25519, nested, expires_at, non-prefixed, base64url",
  { ...siftFields, signature: { alg: "ed25519", kid: "2026-01",
    sig: sig({ ...siftFields, signature: { alg: "ed25519", kid: "2026-01" } }, { prefixed: false, alphabet: "base64url" }) } }, OK);

// w-002: nested signature with top-level alg/kid
add("w-002a", "Core-native nested {alg,kid,sig} + equal top-level alg/kid: preimage = top-level fields, nested object excluded",
  { ...coreFields, signature: { alg: "Ed25519", kid: "2026-01", sig: sig(coreFields, { prefixed: true, alphabet: "base64" }) } }, OK);
add("w-002b", "Same shape, signed with signature:{alg,kid} ALSO in the preimage (previous §5 step-2 reading) -> rejected",
  { ...coreFields, signature: { alg: "Ed25519", kid: "2026-01",
    sig: sig({ ...coreFields, signature: { alg: "Ed25519", kid: "2026-01" } }, { prefixed: true, alphabet: "base64" }) } },
  bad("AUTH_SIGNATURE_INVALID"));
add("w-002c", "Nested kid differs from top-level kid (ambiguous encoding) -> rejected",
  { ...coreFields, kid: "k-decoy", signature: { alg: "Ed25519", kid: "2026-01",
    sig: sig({ ...coreFields, kid: "k-decoy" }, { prefixed: true, alphabet: "base64" }) } },
  bad("AUTH_ALG_UNSUPPORTED"));

// w-006..w-008: cross-encoding / cross-alphabet
add("w-006", "Declared Ed25519 (Core-native), standard base64, but NON-prefixed preimage -> rejected",
  { ...coreFields, signature: sig(coreFields, { prefixed: false, alphabet: "base64" }) }, bad("AUTH_SIGNATURE_INVALID"));
add("w-007", "Declared ed25519 (Sift), base64url, but PREFIXED preimage -> rejected",
  { ...siftFields, signature: { alg: "ed25519", kid: "2026-01",
    sig: sig({ ...siftFields, signature: { alg: "ed25519", kid: "2026-01" } }, { prefixed: true, alphabet: "base64url" }) } },
  bad("AUTH_SIGNATURE_INVALID"));
add("w-008a", "Declared Ed25519 with base64url signature over non-prefixed preimage (cross-alphabet) -> rejected",
  { ...coreFields, signature: sig(coreFields, { prefixed: false, alphabet: "base64url" }) }, bad("AUTH_SIGNATURE_INVALID"));
add("w-008b", "Declared ed25519 with STANDARD base64 signature, non-prefixed preimage (cross-alphabet) -> rejected",
  { ...siftFields, signature: { alg: "ed25519", kid: "2026-01",
    sig: sig({ ...siftFields, signature: { alg: "ed25519", kid: "2026-01" } }, { prefixed: false, alphabet: "base64" }) } },
  bad("AUTH_SIGNATURE_INVALID"));
add("w-009", "Flat signature declared ed25519 (Encoding B requires the nested object) -> rejected",
  (() => { const f = { ...siftFields, alg: "ed25519", kid: "2026-01" };
    return { ...f, signature: sig(f, { prefixed: false, alphabet: "base64url" }) }; })(),
  bad("AUTH_ALG_UNSUPPORTED"));

// Guard: base64url and standard base64 strings must be distinguishable for the
// cross-alphabet vectors to mean anything.
for (const id of ["w-008a", "w-008b"]) {
  const v = vectors.find((x) => x.id === id);
  const s = typeof v.artifact.signature === "string" ? v.artifact.signature : v.artifact.signature.sig;
  if (id === "w-008a" && s.endsWith("=")) throw new Error("w-008a must be unpadded base64url");
  if (id === "w-008b" && !s.endsWith("=")) throw new Error("w-008b must be padded standard base64");
}

process.stdout.write(JSON.stringify({
  version: 1,
  note: "TEST KEY ONLY - never funded. Expected codes are normative AUTH_* codes (authorization-v1.md).",
  verifier_options: {
    now: NOW, mode: "strict", requireSignatureVerification: true,
    expectedIssuer: "oxdeai.policy-engine", expectedAudience: "merchant-gateway",
    trustedKeySets: [{ issuer: "oxdeai.policy-engine", version: "1", keys: [{ kid: "2026-01", alg: "Ed25519", public_key: PUBLIC_PEM }] }],
  },
  vectors,
}, null, 2) + "\n");
