// SPDX-License-Identifier: Apache-2.0
import { createHash, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

function sha256Hex(data) {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

function jsonValue(v) {
  if (v === null) return "null";
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("UNSUPPORTED_NUMBER");
    return String(v);
  }
  if (typeof v === "boolean") return v ? "true" : "false";
  if (Array.isArray(v)) return `[${v.map(jsonValue).join(",")}]`;
  if (typeof v === "object") return canonicalize(v);
  throw new Error("UNSUPPORTED_TYPE");
}

function canonicalize(obj) {
  const keys = Object.keys(obj).sort((a, b) =>
    Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"))
  );
  const parts = keys.map((k) => `${JSON.stringify(k)}:${jsonValue(obj[k])}`);
  return `{${parts.join(",")}}`;
}

function load() {
  const file = resolve("docs/spec/test-vectors/authorization-v1.json");
  return JSON.parse(readFileSync(file, "utf8"));
}

function verifyAuth(auth, keys, expectedIntentHash, stateSnapshot) {
  if (auth.version !== "AuthorizationV1") return { decision: "DENY", error: "VERSION_MISMATCH" };
  if (auth.decision !== "ALLOW") return { decision: "DENY", error: "DECISION_DENY" };
  const now = 1712448050; // fixed for determinism
  if (auth.expiry <= now) return { decision: "DENY", error: "EXPIRED" };
  if (expectedIntentHash && auth.intent_hash !== expectedIntentHash) {
    return { decision: "DENY", error: "INTENT_HASH_MISMATCH" };
  }

  if (stateSnapshot !== undefined) {
    if (!auth.state_hash) return { decision: "DENY", error: "STATE_HASH_MISSING" };
    const computedStateHash = sha256Hex(canonicalize(stateSnapshot));
    if (auth.state_hash !== computedStateHash) return { decision: "DENY", error: "STATE_HASH_MISMATCH" };
  }

  const { signature, ...rest } = auth;
  // Preimage excludes signature entirely to match the provided test vectors
  const preimage = canonicalize(rest);

  const key = keys.find((k) => k.kid === signature.kid && k.alg === signature.alg);
  if (!key) return { decision: "DENY", error: "UNKNOWN_KID" };

  const ok = verify(null, Buffer.from(preimage, "utf8"), key.public_key_pem, Buffer.from(signature.sig, "base64"));
  if (!ok) return { decision: "DENY", error: "INVALID_SIGNATURE" };

  return { decision: "ALLOW", error: null };
}

function main() {
  const { keys, vectors } = load();
  const baseIntentHash = vectors.find((v) => v.id === "auth-allow-valid")?.artifact.intent_hash;
  let failed = 0;

  for (const v of vectors) {
    const expectedIntentHash = v.proposed_action
      ? sha256Hex(canonicalize(v.proposed_action))
      : baseIntentHash;
    const result = verifyAuth(v.artifact, keys, expectedIntentHash, v.state_snapshot);
    const pass =
      result.decision === v.expected.decision &&
      ((result.error === null && v.expected.error === null) || result.error === v.expected.error);

    if (!pass) {
      failed++;
      console.error(`FAIL ${v.id}: expected ${JSON.stringify(v.expected)}, got ${JSON.stringify(result)}`);
    } else {
      console.log(`PASS ${v.id}`);
    }
  }

  if (failed > 0) {
    console.error(`\n${failed} authorization vector(s) failed`);
    process.exit(1);
  }
  console.log(`\nAll ${vectors.length} authorization vector(s) passed (diagnostic only; scoped report: pnpm test:vectors:auth)`);
}

main();
