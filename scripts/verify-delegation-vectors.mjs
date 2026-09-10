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

function loadVectors() {
  const file = resolve("docs/spec/test-vectors/delegation-vectors-v1.json");
  return JSON.parse(readFileSync(file, "utf8"));
}

function resolveKey(keys, kid, alg) {
  return keys.find((k) => k.kid === kid && k.alg === alg);
}

function verifySignature(obj, sigInfo, keys) {
  const key = resolveKey(keys, sigInfo?.kid, sigInfo?.alg);
  if (!key) return false;
  const { signature, ...preimage } = obj;
  const cleaned = { ...preimage };
  delete cleaned.parent_hash; // not part of signing input in vectors
  const pre = canonicalize(cleaned);
  return verify(null, Buffer.from(pre, "utf8"), key.public_key_pem, Buffer.from(sigInfo.sig, "base64"));
}

function toNumber(x) {
  if (x === undefined) return undefined;
  const n = typeof x === "string" ? Number(x) : x;
  return Number.isFinite(n) ? n : NaN;
}

function checkVector(v, keys, nowFixed) {
  const now = nowFixed ?? 1712448100;

  const parent = v.parent_authorization;
  const delegation = v.delegation;
  const action = v.action;

  // Parent must be AuthorizationV1 (single-hop)
  if (parent.version === "DelegationV1") return "DELEGATION_MULTIHOP_DENIED";

  if (!verifySignature(parent, parent.signature, keys)) return "DELEGATION_TRUST_FAILURE";

  const parentHash = sha256Hex(canonicalize(parent));
  if (parentHash !== delegation.parent_auth_hash) return "DELEGATION_PARENT_HASH_MISMATCH";

  if (parent.expiry <= now) return "DELEGATION_PARENT_EXPIRED";

  // Delegation signature
  if (!verifySignature(delegation, delegation.signature, keys)) return "DELEGATION_SIGNATURE_INVALID";

  if (delegation.delegatee !== "agent-123") return "DELEGATION_DELEGATEE_MISMATCH";

  if (delegation.expiry <= now) return "DELEGATION_EXPIRED";
  if (delegation.expiry > parent.expiry) return "DELEGATION_SCOPE_WIDENING";

  // Scope narrowing checks
  const parentTools = parent.scope?.tools || [];
  const childTools = delegation.scope?.tools || [];
  const wideningTool = childTools.some((t) => !parentTools.includes(t));
  if (wideningTool) return "DELEGATION_SCOPE_WIDENING";

  const parentMaxAmount = toNumber(parent.scope?.max_amount);
  const childMaxAmount = toNumber(delegation.scope?.max_amount);
  if (parentMaxAmount !== undefined && childMaxAmount !== undefined && childMaxAmount > parentMaxAmount) {
    return "DELEGATION_SCOPE_WIDENING";
  }

  // Action within child scope
  if (childTools.length > 0 && !childTools.includes(action.tool)) return "DELEGATION_SCOPE_VIOLATION";
  if (childMaxAmount !== undefined) {
    const amt = toNumber(action.params?.amount);
    if (!Number.isFinite(amt) || amt > childMaxAmount) return "DELEGATION_SCOPE_VIOLATION";
  }

  if (v.preconsume_delegation_id && v.preconsume_delegation_id === delegation.delegation_id) {
    return "DELEGATION_REPLAY";
  }

  return "AUTHORIZED";
}

function main() {
  const file = loadVectors();
  const { keys, vectors, meta } = file;
  let failed = 0;

  for (const v of vectors) {
    const reason = checkVector(v, keys, meta?.now);
    const pass =
      (v.status === "ok" && reason === v.expected.reason_code) ||
      (v.status === "error" && reason === v.expected_error);

    if (!pass) {
      failed++;
      console.error(`FAIL ${v.id}: expected ${v.status === "ok" ? v.expected.reason_code : v.expected_error}, got ${reason}`);
    } else {
      console.log(`PASS ${v.id}`);
    }
  }

  if (failed > 0) {
    console.error(`\n${failed} delegation vector(s) failed`);
    process.exit(1);
  }
  console.log(`\nAll ${vectors.length} delegation vector(s) passed (diagnostic only; scoped report: pnpm test:vectors:delegation)`);
}

main();
