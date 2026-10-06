// SPDX-License-Identifier: Apache-2.0
/**
 * Test harness.
 *
 * Generates key pairs, starts servers, wires them together, and exposes
 * helper functions used by integration tests.
 */

import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { SiftAdapter } from "../packages/adapter/index.js";
import { MemoryReplayStore, type ReplayStore } from "../packages/replay-store/index.js";
import { KNOWN_POLICIES, KNOWN_ISSUERS } from "../packages/policy/index.js";
import { startMockSift } from "../mock-sift/server.js";
import { startPepGateway } from "../apps/pep-gateway/server.js";
import { startUpstream, type CounterSnapshot } from "../apps/upstream/server.js";
import { siftCanonicalJsonBytes, b64uEncode } from "../shared/canonical.js";
import type { AuthorizationV1Payload } from "../shared/types.js";

// ─── TestContext ──────────────────────────────────────────────────────────────

export interface TestContext {
  /** Base URL of the mock-sift server (e.g. http://127.0.0.1:{port}). */
  mockSiftUrl: string;
  /** kid used by mock-sift to sign receipts. */
  mockSiftKid: string;
  /** Base URL of the PEP Gateway (e.g. http://127.0.0.1:{port}). */
  pepUrl: string;
  /** Base URL of the upstream (e.g. http://127.0.0.1:{port}). */
  upstreamUrl: string;
  /** Existing upstream token, exposed only to in-process adversarial tests. */
  internalToken: string;
  /** Configured adapter instance. */
  adapter: SiftAdapter;
  /**
   * Private key used by the adapter to sign AuthorizationV1.
   * Exposed here so tests can re-sign tampered payloads.
   */
  adapterPrivateKey: KeyObject;
  readCounter(): CounterSnapshot;
  setCounterForTest(value: number): void;
  /** Tears down all servers. */
  close(): Promise<void>;
}

// ─── Startup ──────────────────────────────────────────────────────────────────

export async function startTestHarness(options?: { replayStore?: ReplayStore; getExecutionState?: () => unknown | Promise<unknown> }): Promise<TestContext> {
  // ── Key generation ──────────────────────────────────────────────────────────
  const siftKeyPair = generateKeyPairSync("ed25519");
  const adapterKeyPair = generateKeyPairSync("ed25519");
  const siftKid = "sift-key-1";
  const adapterKid = "adapter-key-1";
  const internalToken = randomBytes(32).toString("hex");

  // ── Servers ─────────────────────────────────────────────────────────────────
  // Port 0 → OS assigns an available port.
  const upstream = await startUpstream({ port: 0, internalToken });
  const mockSift = await startMockSift({
    port: 0,
    privateKey: siftKeyPair.privateKey,
    kid: siftKid,
  });
  const replayStore = options?.replayStore ?? new MemoryReplayStore();
  const pep = await startPepGateway({
    port: 0,
    adapterPublicKey: adapterKeyPair.publicKey,
    knownIssuers: new Set(KNOWN_ISSUERS),
    audience: "pep-payments",
    upstreamUrl: `${upstream.url}/execute`,
    internalToken,
    replayStore,
    getExecutionState: options?.getExecutionState ?? (() => upstream.readCounter()),
    knownPolicies: new Set(KNOWN_POLICIES),
  });

  // ── Adapter ─────────────────────────────────────────────────────────────────
  const adapter = new SiftAdapter({
    siftJwksUrl: `${mockSift.url}/sift-jwks.json`,
    siftKrlUrl: `${mockSift.url}/sift-krl.json`,
    privateKey: adapterKeyPair.privateKey,
    keyId: adapterKid,
    issuer: "adapter-issuer",
    audience: "pep-payments",
    ttlSeconds: 30,
  });

  return {
    mockSiftUrl: mockSift.url,
    mockSiftKid: siftKid,
    pepUrl: pep.url,
    upstreamUrl: upstream.url,
    internalToken,
    adapter,
    adapterPrivateKey: adapterKeyPair.privateKey,
    readCounter: () => upstream.readCounter(),
    setCounterForTest: (value) => upstream.setCounterForTest(value),
    async close() {
      await Promise.all([mockSift.close(), pep.close(), upstream.close()]);
    },
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Re-signs an AuthorizationV1 payload after field modification.
 * Used in adversarial tests (AUDIENCE_MISMATCH, EXPIRED, etc.) to produce
 * validly-signed payloads with tampered semantics.
 */
export function signAuthorization(
  auth: AuthorizationV1Payload,
  privateKey: KeyObject
): AuthorizationV1Payload {
  const signingPayload = {
    version: auth.version,
    auth_id: auth.auth_id,
    issuer: auth.issuer,
    audience: auth.audience,
    decision: auth.decision,
    intent_hash: auth.intent_hash,
    state_hash: auth.state_hash,
    policy_id: auth.policy_id,
    issued_at: auth.issued_at,
    expires_at: auth.expires_at,
    signature: {
      alg: auth.signature.alg,
      kid: auth.signature.kid,
      // sig intentionally absent
    },
  };
  const preimage = siftCanonicalJsonBytes(signingPayload);
  const sigBuf = sign(null, preimage, privateKey);
  return {
    ...auth,
    signature: { ...auth.signature, sig: b64uEncode(sigBuf) },
  };
}
