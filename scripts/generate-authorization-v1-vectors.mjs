// SPDX-License-Identifier: Apache-2.0
//
// Regenerates the signatures of docs/spec/test-vectors/authorization-v1.json
// so the locked corpus matches authorization-v1.md §5 (Encoding A, Core-native):
//
//   preimage  = UTF8("OXDEAI_AUTH_V1\n") || UTF8(canonicalJson(artifact \ signature))
//   signature = standard base64 (RFC 4648 §4), 64 bytes
//
// Self-contained on purpose (node:crypto only, no @oxdeai/* import) so the
// corpus is independently reproducible.
//
// TEST KEYS ONLY — NEVER FUND, NEVER DEPLOY. Private keys are either the
// repository's public test fixture (portable-key-1) or derived from a public
// seed string, so anyone can regenerate byte-identical vectors.
//
// Usage:
//   node scripts/generate-authorization-v1-vectors.mjs          # check only (exit 1 on drift)
//   node scripts/generate-authorization-v1-vectors.mjs --write  # rewrite the corpus

import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const CORPUS = resolve("docs/spec/test-vectors/authorization-v1.json");
const DOMAIN = "OXDEAI_AUTH_V1\n";
const SEED_PREFIX = "OXDEAI-AUTHORIZATION-V1-TEST-VECTOR-KEY-DO-NOT-USE:";

// Same bytes as packages/conformance/src/fixtures/ed25519.test-only.fixture.ts
const PORTABLE_KEY_1_PRIVATE_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBx0hBPi6cIYPo/JZbavNXDDLlfV1vj+IyS+R4oq2Zvx
-----END PRIVATE KEY-----`;

function privateKeyFromSeed(seed32) {
  // PKCS#8 wrapper for a raw 32-byte Ed25519 seed (RFC 8410).
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed32]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function testKey(kid) {
  if (kid === "portable-key-1") return createPrivateKey(PORTABLE_KEY_1_PRIVATE_PEM);
  const seed = createHash("sha256").update(SEED_PREFIX + kid, "utf8").digest();
  return privateKeyFromSeed(seed);
}

// canonicalization-v1 subset sufficient for this corpus (ASCII strings, safe
// integers, objects). Rejects anything else rather than guessing.
function canon(v) {
  if (v === null) return "null";
  if (typeof v === "string") return JSON.stringify(v.normalize("NFC"));
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Error("UNSUPPORTED_NUMBER");
    return String(v);
  }
  if (Array.isArray(v)) return `[${v.map(canon).join(",")}]`;
  if (typeof v === "object") {
    const keys = Object.keys(v).sort((a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")));
    return `{${keys.map((k) => `${JSON.stringify(k.normalize("NFC"))}:${canon(v[k])}`).join(",")}}`;
  }
  throw new Error("UNSUPPORTED_TYPE");
}

// Preimage rule for the corpus shape (nested signature + top-level alg/kid):
// top-level alg/kid are signed; the nested signature object is excluded.
export function corePreimage(artifact) {
  const { signature: _sig, ...signed } = artifact;
  return Buffer.concat([Buffer.from(DOMAIN, "utf8"), Buffer.from(canon(signed), "utf8")]);
}

// Vectors whose signature is deliberately not a valid signature.
const FORGED = new Set(["auth-invalid-signature", "pep-auth-forged"]);
// Vector that reuses another vector's signature under an untrusted kid.
const COPY_SIG_FROM = { "pb-trust-provider-key-rejected": "pb-trust-oxdeai-key-allow" };

function main() {
  const write = process.argv.includes("--write");
  const original = readFileSync(CORPUS, "utf8");
  const corpus = JSON.parse(original);

  // Public keys follow the private keys.
  for (const k of corpus.keys) {
    k.public_key_pem = createPublicKey(testKey(k.kid)).export({ format: "pem", type: "spki" }).toString();
  }

  const byId = new Map(corpus.vectors.map((v) => [v.id, v]));
  for (const v of corpus.vectors) {
    if (FORGED.has(v.id) || COPY_SIG_FROM[v.id]) continue;
    const a = v.artifact;
    if (a.alg !== "Ed25519" || a.signature?.alg !== "Ed25519" || a.kid !== a.signature?.kid) {
      throw new Error(`${v.id}: corpus vectors must be Core-native with consistent alg/kid`);
    }
    a.signature.sig = sign(null, corePreimage(a), testKey(a.signature.kid)).toString("base64");
  }
  for (const [id, from] of Object.entries(COPY_SIG_FROM)) {
    byId.get(id).artifact.signature.sig = byId.get(from).artifact.signature.sig;
  }

  // Self-check: every non-forged vector verifies ONLY with the prefixed preimage.
  for (const v of corpus.vectors) {
    if (FORGED.has(v.id) || COPY_SIG_FROM[v.id]) continue;
    const a = v.artifact;
    const pub = createPublicKey(testKey(a.signature.kid));
    const sig = Buffer.from(a.signature.sig, "base64");
    const { signature: _s, ...signed } = a;
    const raw = Buffer.from(canon(signed), "utf8");
    if (!verify(null, corePreimage(a), pub, sig)) throw new Error(`${v.id}: prefixed verify failed`);
    if (verify(null, raw, pub, sig)) throw new Error(`${v.id}: raw preimage must NOT verify`);
  }

  // Rewrite only the changed string values so the committed layout is kept.
  const before = JSON.parse(original);
  let next = original;
  const swap = (from, to) => {
    if (from === to) return;
    const needle = JSON.stringify(from);
    if (!next.includes(needle)) throw new Error(`cannot locate value to replace: ${needle.slice(0, 40)}`);
    next = next.split(needle).join(JSON.stringify(to));
  };
  before.keys.forEach((k, i) => swap(k.public_key_pem, corpus.keys[i].public_key_pem));
  const seen = new Set();
  before.vectors.forEach((v, i) => {
    const from = v.artifact.signature.sig;
    const to = corpus.vectors[i].artifact.signature.sig;
    if (seen.has(from)) return; // shared signature (COPY_SIG_FROM) replaced once
    seen.add(from);
    swap(from, to);
  });
  if (JSON.stringify(JSON.parse(next)) !== JSON.stringify(corpus)) {
    throw new Error("in-place rewrite diverged from the regenerated corpus");
  }
  if (write) {
    writeFileSync(CORPUS, next);
    console.log(`wrote ${CORPUS}`);
    return;
  }
  if (next !== original) {
    console.error("authorization-v1.json drifts from the generator; run with --write");
    process.exit(1);
  }
  console.log("authorization-v1.json matches the generator");
}

main();
