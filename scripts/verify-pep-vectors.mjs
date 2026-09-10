// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createHash, verify } from "node:crypto";

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

function sha256Hex(data) {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

function loadAuth() {
  const file = resolve("docs/spec/test-vectors/authorization-v1.json");
  return JSON.parse(readFileSync(file, "utf8"));
}

function loadPep() {
  const file = resolve("docs/spec/test-vectors/pep-vectors-v1.json");
  return JSON.parse(readFileSync(file, "utf8"));
}

function verifyAuthByRef(ref, authFile) {
  const v = authFile.vectors.find((x) => x.id === ref);
  if (!v) throw new Error(`authorization_ref not found: ${ref}`);
  const auth = v.artifact;
  const { signature, ...rest } = auth;
  const preimage = canonicalize(rest);
  const key = authFile.keys.find((k) => k.kid === signature.kid && k.alg === signature.alg);
  if (!key) return { ok: false, error: "UNKNOWN_KID" };
  const ok = verify(null, Buffer.from(preimage, "utf8"), key.public_key_pem, Buffer.from(signature.sig, "base64"));
  if (!ok) return { ok: false, error: "INVALID_SIGNATURE" };
  const now = 1712448050;
  if (auth.expiry <= now) return { ok: false, error: "EXPIRED" };
  return { ok: true, auth };
}

function expectedIntentHash(action) {
  return sha256Hex(jsonValue(action));
}

function verifyPepVector(v, authFile) {
  const authResult = verifyAuthByRef(v.request.authorization_ref, authFile);
  if (!authResult.ok) {
    return { status: 403, decision: "DENY", executed: false };
  }
  const auth = authResult.auth;
  const hash = expectedIntentHash(v.request.action);
  if (hash !== auth.intent_hash) {
    return { status: 403, decision: "DENY", executed: false };
  }

  // State binding check
  if (!auth.state_hash) {
    return { status: 403, decision: "DENY", executed: false };
  }
  const stateSnapshotRef = v.request.state_snapshot_ref;
  if (!stateSnapshotRef) {
    return { status: 403, decision: "DENY", executed: false };
  }
  const snapshotVector = authFile.vectors.find((x) => x.id === stateSnapshotRef);
  if (!snapshotVector?.state_snapshot) {
    return { status: 403, decision: "DENY", executed: false };
  }
  const computedStateHash = sha256Hex(canonicalize(snapshotVector.state_snapshot));
  if (computedStateHash !== auth.state_hash) {
    return { status: 403, decision: "DENY", executed: false };
  }

  switch (v.request.upstream_behavior) {
    case "success":
      return { status: 200, decision: "ALLOW", executed: true };
    case "error":
      return { status: 502, decision: "DENY", executed: false };
    case "timeout":
      return { status: 504, decision: "DENY", executed: false };
    case "not_called":
    default:
      return { status: 403, decision: "DENY", executed: false };
  }
}

function main() {
  const pepFile = loadPep();
  const authFile = loadAuth();
  let failed = 0;
  for (const v of pepFile.vectors) {
    const res = verifyPepVector(v, authFile);
    const exp = v.expected;
    const pass = res.status === exp.status && res.decision === exp.decision && res.executed === exp.executed;
    if (!pass) {
      failed++;
      console.error(`FAIL ${v.id}: expected ${JSON.stringify(exp)}, got ${JSON.stringify(res)}`);
    } else {
      console.log(`PASS ${v.id}`);
    }
  }
  if (failed > 0) {
    console.error(`\n${failed} PEP vector(s) failed`);
    process.exit(1);
  }
  console.log(`\nAll ${pepFile.vectors.length} PEP vector(s) passed (diagnostic only; scoped report: pnpm test:vectors:pep)`);
}

main();
