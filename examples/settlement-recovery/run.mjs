// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256HexFromJson, verifyAuthorization } from "../../packages/core/dist/index.js";

const fixturePath = join(dirname(fileURLToPath(import.meta.url)), "settlement-recovery-v1.json");
const raw = readFileSync(fixturePath, "utf8");
if (raw.includes("\r")) throw new Error("fixture must be LF");
if (/seed_hex|BEGIN PRIVATE KEY/i.test(raw)) throw new Error("fixture contains key material");

const fixture = JSON.parse(raw);
if (fixture.vectors.length !== 12) {
  throw new Error(`expected 12 vectors, got ${fixture.vectors.length}`);
}
if (fixture.alg !== "Ed25519") throw new Error("fixture alg must be Ed25519");
if (typeof fixture.public_key !== "string" || !fixture.public_key.includes("BEGIN PUBLIC KEY")) {
  throw new Error("fixture public_key missing");
}

const verifyOptions = {
  now: fixture.now,
  mode: "strict",
  requireSignatureVerification: true,
  expectedIssuer: fixture.issuer,
  expectedAudience: fixture.audience,
  trustedKeySets: [
    {
      issuer: fixture.issuer,
      version: "1",
      keys: [{ kid: fixture.kid, alg: "Ed25519", public_key: fixture.public_key }],
    },
  ],
};

function acquire(store, authId, intentHash, signedHash) {
  const existing = store.get(authId);
  if (!existing) {
    if (intentHash !== signedHash) return { status: "REPLAY_REJECTED", errorCode: "AUTH_REPLAYED" };
    const record = {
      intent_hash: intentHash,
      state: "LEASED",
      epoch: 1,
      tx_hash: null,
      transitions: ["UNSEEN", "LEASED"],
    };
    store.set(authId, record);
    return { status: "ACQUIRED", record };
  }
  if (existing.intent_hash !== intentHash) {
    return { status: "REPLAY_REJECTED", errorCode: "AUTH_REPLAYED", record: existing };
  }
  if (existing.state === "SETTLED") return { status: "COALESCED_SETTLED", record: existing };
  if (existing.state === "LEASED") return { status: "IN_FLIGHT", record: existing };
  return { status: "REPLAY_REJECTED", errorCode: "AUTH_REPLAYED", record: existing };
}

function recover(record) {
  record.epoch += 1;
  record.state = "RECOVERY_PENDING";
  record.transitions.push("RECOVERY_PENDING");
  return record;
}

function commit(record, epoch, next, tx) {
  if (record.epoch !== epoch) return { ok: false, errorCode: "STALE_LEASE_EPOCH" };
  record.state = next;
  record.tx_hash = tx;
  record.transitions.push(next);
  return { ok: true };
}

function runVector(vec) {
  const auth = vec.authorization;
  const presented = sha256HexFromJson(vec.intent);
  const binding = presented === auth.intent_hash ? null : "AUTH_INTENT_MISMATCH";
  const secondary = vec.secondary_intent
    ? sha256HexFromJson(vec.secondary_intent) === auth.intent_hash
      ? null
      : "AUTH_INTENT_MISMATCH"
    : null;
  const store = new Map();
  if (vec.initial === "SETTLED") {
    store.set(auth.auth_id, {
      intent_hash: auth.intent_hash,
      state: "SETTLED",
      epoch: 1,
      tx_hash: vec.tx_hash,
      transitions: ["SETTLED"],
    });
  }

  const verified = verifyAuthorization(structuredClone(auth), verifyOptions);
  const codes = [...new Set(verified.violations.map((v) => v.code))].sort();
  assert.equal(verified.signatureVerified, true, vec.id);
  assert.equal(verified.ok, vec.expect.verifier_ok, `${vec.id} verifier`);
  assert.deepEqual(codes, [...vec.expect.verifier_codes].sort(), vec.id);
  assert.equal(binding, vec.expect.binding_code, `${vec.id} binding`);
  if (vec.expect.secondary_binding_code !== undefined) {
    assert.equal(secondary, vec.expect.secondary_binding_code, `${vec.id} secondary`);
  }

  let extension = null;
  let http = 200;
  let recovered = null;

  if (!verified.ok) {
    http = 422;
  } else if (vec.case === "replay-settled") {
    const existing = store.get(auth.auth_id);
    assert.ok(existing);
    assert.equal(existing.state, "SETTLED");
    extension = "AUTH_REPLAYED";
    recovered = existing.tx_hash;
    http = 422;
  } else {
    const first = acquire(store, auth.auth_id, presented, auth.intent_hash);
    assert.equal(first.status, "ACQUIRED", vec.id);
    if (vec.case === "settle") {
      assert.equal(commit(first.record, 1, "SETTLED", vec.tx_hash).ok, true);
      recovered = vec.tx_hash;
    } else if (vec.case === "abort-before-send") {
      const record = recover(first.record);
      assert.equal(commit(record, record.epoch, "FAILED_FINAL", null).ok, true);
      extension = "LEASE_ABORTED_NO_SETTLEMENT";
      http = 422;
    } else if (vec.case === "recover-confirmed" || vec.case === "settle-after-short-expiry") {
      const record = recover(first.record);
      assert.equal(commit(record, record.epoch, "SETTLED", vec.tx_hash).ok, true);
      recovered = vec.tx_hash;
    } else if (vec.case === "hold-pending") {
      recover(first.record);
      extension = "SETTLEMENT_UNCERTAIN";
      http = 504;
    } else if (vec.case === "coalesce") {
      assert.equal(acquire(store, auth.auth_id, presented, auth.intent_hash).status, "IN_FLIGHT");
      assert.equal(commit(first.record, 1, "SETTLED", vec.tx_hash).ok, true);
      const again = acquire(store, auth.auth_id, presented, auth.intent_hash);
      assert.equal(again.status, "COALESCED_SETTLED");
      recovered = again.record.tx_hash;
    } else if (vec.case === "reject-mutated") {
      const replay = acquire(
        store,
        auth.auth_id,
        sha256HexFromJson(vec.secondary_intent),
        auth.intent_hash
      );
      assert.equal(replay.status, "REPLAY_REJECTED");
      assert.equal(replay.errorCode, "AUTH_REPLAYED");
      extension = "AUTH_REPLAYED";
      http = 409;
      assert.equal(commit(first.record, 1, "SETTLED", vec.tx_hash).ok, true);
      recovered = vec.tx_hash;
    } else if (vec.case === "fence-epoch") {
      const record = recover(first.record);
      const stale = commit(record, 1, "FAILED_FINAL", null);
      assert.equal(stale.ok, false);
      assert.equal(stale.errorCode, "STALE_LEASE_EPOCH");
      extension = "STALE_LEASE_EPOCH";
      assert.equal(commit(record, record.epoch, "SETTLED", vec.tx_hash).ok, true);
      recovered = vec.tx_hash;
    } else if (vec.case === "block-after-verify") {
      assert.equal(commit(first.record, 1, "FAILED_FINAL", null).ok, true);
      extension = "COMPLIANCE_BLOCKED";
      http = 403;
    } else if (vec.case === "hold-partial") {
      recover(first.record);
      recovered = vec.tx_hash;
      extension = "PARTIAL_SETTLEMENT_DRIFT";
      http = 502;
    } else {
      throw new Error(`unknown case ${vec.case}`);
    }
  }

  const record = store.get(auth.auth_id);
  assert.deepEqual(record ? record.transitions : ["UNSEEN"], vec.expect.transitions, vec.id);
  assert.equal(record ? record.state : "UNSEEN", vec.expect.final_state, vec.id);
  assert.equal(record ? record.epoch : 0, vec.expect.epoch, vec.id);
  assert.equal(recovered, vec.expect.recovered_tx_hash, vec.id);
  assert.equal(extension, vec.expect.extension_code, vec.id);
  assert.equal(http, vec.expect.http_status, vec.id);

  if (vec.id === "sr-001") {
    const flipped = structuredClone(auth);
    const chars = flipped.signature.split("");
    chars[0] = chars[0] === "A" ? "B" : "A";
    flipped.signature = chars.join("");
    const bad = verifyAuthorization(flipped, verifyOptions);
    assert.equal(bad.ok, false);
    assert.ok(bad.violations.some((v) => v.code === "AUTH_SIGNATURE_INVALID"));
  }
}

for (const vec of fixture.vectors) {
  test(vec.id, () => {
    runVector(vec);
  });
}
