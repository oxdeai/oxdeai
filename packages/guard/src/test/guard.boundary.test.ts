// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { OxDeAIGuard } from "../index.js";
import type { ProposedAction, StateVersion } from "../types.js";
import type { State, Intent, Authorization, AuthorizationV1, KeySet } from "@oxdeai/core";
import {
  PolicyEngine,
  RECOMMENDED_TRUSTED_TIME_PROFILE,
  signAuthorizationEd25519,
  stateSnapshotHash,
  intentHash,
  createDelegation,
} from "@oxdeai/core";
import { defaultNormalizeAction } from "../normalizeAction.js";

// ---------------------------------------------------------------------------
// Fixtures

const { privateKey, publicKey } = generateKeyPairSync("ed25519");

const TRUSTED_KEYSET: KeySet = {
  issuer: "issuer-test",
  version: "v1",
  keys: [
    {
      kid: "k1",
      alg: "Ed25519",
      public_key: publicKey.export({ type: "spki", format: "pem" }).toString(),
    },
  ],
};

/** #301 delegation-root authority: one explicit pair, never issuers x policies. */
const BOUNDARY_AUTHORITIES = [{ issuer: TRUSTED_KEYSET.issuer, policyId: "p".repeat(64) }] as const;

function makeState(policyVersion = "policy-test"): State {
  return {
    policy_version: policyVersion,
    period_id: "p1",
    kill_switch: { global: false, agents: {} },
    allowlists: {},
    budget: { budget_limit: { "agent-1": 1_000_000n }, spent_in_period: { "agent-1": 0n } },
    max_amount_per_action: { "agent-1": 1_000_000n },
    velocity: { config: { window_seconds: 3600, max_actions: 100 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { "agent-1": 3 }, active: {}, active_auths: {} },
    recursion: { max_depth: { "agent-1": 5 } },
    tool_limits: { window_seconds: 3600, max_calls: { "agent-1": 100 }, calls: {} },
  };
}

function makeAction(overrides: Partial<ProposedAction["context"]> = {}, extra?: Partial<ProposedAction>): ProposedAction {
  return {
    name: "pay",
    args: { amount: 1 },
    estimatedCost: 0,
    ...extra,
    context: {
      agent_id: "agent-1",
      target: "vendor",
      ...overrides,
    },
  } satisfies ProposedAction;
}

function makeEngine(policyVersion = "policy-test") {
  return new PolicyEngine({
    policy_version: policyVersion,
    engine_secret: "a".repeat(32),
    authorization_ttl_seconds: 60,
    authorization_signing_alg: "Ed25519",
    authorization_signing_kid: "k1",
    authorization_issuer: TRUSTED_KEYSET.issuer,
    authorization_audience: "aud-test",
    authorization_private_key_pem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });
}

// ---------------------------------------------------------------------------
// Helpers

function makeVersionedStore(initial: State): {
  getState: () => { state: State; version: StateVersion };
  setState: (s: State, v: StateVersion) => boolean;
} {
  let stored = initial;
  let version: StateVersion = 0;
  return {
    getState: () => ({ state: stored, version }),
    setState: (s, v) => { if (v !== version) return false; stored = s; version = (version as number) + 1; return true; },
  };
}

// ---------------------------------------------------------------------------
// Tests

test("expired authorization is denied (execute not called)", async () => {
  // The intent itself must be fresh to clear the trusted-time freshness gate
  // (see #184) — an already-old intent.timestamp is now rejected earlier,
  // with INTENT_STALE, before any authorization is even minted. To exercise
  // the *post-issuance* expiry check this test targets, tamper the minted
  // authorization's expiry directly instead of backdating the intent,
  // mirroring the tampering pattern used by the audience test below.
  const engine = makeEngine();
  const state = makeState();
  const store = makeVersionedStore(state);

  const originalEval = engine.evaluatePure.bind(engine);
  engine.evaluatePure = ((intent: Intent, st: State, evaluationTime: number) => {
    const out = originalEval(intent, st, evaluationTime);
    if (out.decision === "ALLOW") {
      // Cast as Authorization: spread of AuthorizationV1 + tampered field; internal
      // engine fields are present at runtime even though TypeScript type was narrowed.
      const tampered = { ...out.authorization, expiry: 1, expires_at: 1 } as Authorization;
      return { ...out, authorization: tampered };
    }
    return out;
  }) as any;

  const guard = OxDeAIGuard({
    engine,
    ...store,
    trustedKeySets: [TRUSTED_KEYSET],
    expectedAudience: "aud-test",
    trustedDelegationAuthorities: BOUNDARY_AUTHORITIES,
  });

  const action = makeAction();

  let executed = false;
  await assert.rejects(
    guard(action, async () => {
      executed = true;
    }),
    /AUTH_EXPIRED|Authorization verification failed/i
  );
  assert.equal(executed, false);
});

test("audience tampering is denied by strict verifier", async () => {
  const engine = makeEngine();
  const state = makeState();
  const store = makeVersionedStore(state);

  const originalEval = engine.evaluatePure.bind(engine);
  engine.evaluatePure = ((intent: Intent, st: State, evaluationTime: number) => {
    const out = originalEval(intent, st, evaluationTime);
    if (out.decision === "ALLOW") {
      // Cast as Authorization: spread of AuthorizationV1 + tampered field; internal
      // engine fields are present at runtime even though TypeScript type was narrowed.
      const tampered = { ...out.authorization, audience: "attacker" } as Authorization;
      return { ...out, authorization: tampered };
    }
    return out;
  }) as any;

  const guard = OxDeAIGuard({
    engine,
    ...store,
    trustedKeySets: [TRUSTED_KEYSET],
    expectedAudience: "aud-test",
    trustedDelegationAuthorities: BOUNDARY_AUTHORITIES,
  });

  const action = makeAction();
  let executed = false;
  await assert.rejects(
    guard(action, async () => {
      executed = true;
    }),
    /AUTH_AUDIENCE_MISMATCH|Authorization verification failed/i
  );
  assert.equal(executed, false);
});

test("auth_id replay is denied on second use", async () => {
  // Fixed fields make defaultNormalizeAction deterministic so intent_hash can be
  // pre-computed and placed in the manually-crafted auth for step 6d.
  const replayAction: ProposedAction = {
    name: "pay",
    args: { amount: 1 },
    estimatedCost: 0,
    timestampSeconds: 1_700_000_000,
    context: { agent_id: "agent-1", target: "vendor", intent_id: "boundary-replay-intent", nonce: 1n },
  };
  const replayIntentHash = intentHash(defaultNormalizeAction(replayAction));

  const issued_at = Math.floor(Date.now() / 1000);
  const replayState = makeState();
  const auth: AuthorizationV1 = signAuthorizationEd25519(
    {
      auth_id: "auth-replay-test",
      issuer: TRUSTED_KEYSET.issuer,
      audience: "aud-test",
      intent_hash: replayIntentHash,
      state_hash: stateSnapshotHash(replayState),
      policy_id: "p".repeat(64),
      decision: "ALLOW",
      issued_at,
      expiry: issued_at + 300,
      kid: "k1",
      nonce: "1",
      capability: "exec",
    },
    privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  );

  class FakeEngine {
    evaluatePure(_intent: Intent, state: State) {
      return { decision: "ALLOW" as const, reasons: [], authorization: auth as Authorization, nextState: state };
    }
    computeStateHash(state: State) {
      return stateSnapshotHash(state);
    }
    verifyAuthorization() {
      return { valid: true };
    }
  }

  const store = makeVersionedStore(replayState);
  const guard = OxDeAIGuard({
    engine: new FakeEngine() as any,
    ...store,
    trustedKeySets: [TRUSTED_KEYSET],
    expectedAudience: "aud-test",
    trustedDelegationAuthorities: BOUNDARY_AUTHORITIES,
  });

  let executions = 0;
  await guard(replayAction, async () => {
    executions += 1;
  });
  await assert.rejects(
    guard(replayAction, async () => {
      executions += 1;
    }),
    /Authorization replay detected|AUTH_REPLAY/i
  );
  assert.equal(executions, 1);
});

test("delegation tool widening is denied", async () => {
  const parentAuth = signAuthorizationEd25519(
    {
      auth_id: "auth-parent-tool",
      issuer: TRUSTED_KEYSET.issuer,
      audience: "child",
      intent_hash: "i".repeat(64),
      state_hash: "s".repeat(64),
      policy_id: "p".repeat(64),
      decision: "ALLOW",
      issued_at: Math.floor(Date.now() / 1000),
      expiry: Math.floor(Date.now() / 1000) + 300,
      kid: "k1",
      capability: "exec",
      nonce: "1",
    },
    privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  ) as Authorization;
  const delegation = createDelegation(
    parentAuth as AuthorizationV1,
    {
      delegatee: "agent-1", // the acting agent (makeAction); #350 binds delegatee to intent.agent_id
      scope: { tools: ["read", "write"], max_amount: 100n },
      expiry: parentAuth.expiry,
      kid: "k1",
      audience: "child",
      issuer: TRUSTED_KEYSET.issuer,
    },
    privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  );

  const state = makeState();
  const store = makeVersionedStore(state);
  const guard = OxDeAIGuard({
    engine: makeEngine(),
    ...store,
    trustedKeySets: [TRUSTED_KEYSET],
    expectedAudience: "child",
    trustedDelegationAuthorities: BOUNDARY_AUTHORITIES,
  });

  const action = makeAction();
  let executed = false;
  await assert.rejects(
    guard(action, async () => {
      executed = true;
    }, { delegation: { delegation, parentAuth: parentAuth as AuthorizationV1, parentScope: { tools: ["read"], max_amount: 100n } } }),
    /DELEGATION_SCOPE_VIOLATION|execution blocked/i
  );
  assert.equal(executed, false);
});

test("delegation amount widening is denied", async () => {
  const parentAuth = signAuthorizationEd25519(
    {
      auth_id: "auth-parent-amount",
      issuer: TRUSTED_KEYSET.issuer,
      audience: "child",
      intent_hash: "i".repeat(64),
      state_hash: "s".repeat(64),
      policy_id: "p".repeat(64),
      decision: "ALLOW",
      issued_at: Math.floor(Date.now() / 1000),
      expiry: Math.floor(Date.now() / 1000) + 300,
      kid: "k1",
      capability: "exec",
      nonce: "2",
    },
    privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  ) as Authorization;
  const delegation = createDelegation(
    parentAuth as AuthorizationV1,
    {
      delegatee: "agent-1",
      scope: { tools: ["read"], max_amount: 1000n },
      expiry: parentAuth.expiry,
      kid: "k1",
      audience: "child",
      issuer: TRUSTED_KEYSET.issuer,
    },
    privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  );

  const state = makeState();
  const store = makeVersionedStore(state);
  const guard = OxDeAIGuard({
    engine: makeEngine(),
    ...store,
    trustedKeySets: [TRUSTED_KEYSET],
    expectedAudience: "child",
    trustedDelegationAuthorities: BOUNDARY_AUTHORITIES,
  });

  const action = makeAction();
  let executed = false;
  await assert.rejects(
    guard(action, async () => {
      executed = true;
    }, { delegation: { delegation, parentAuth: parentAuth as AuthorizationV1, parentScope: { tools: ["read"], max_amount: 100n } } }),
    /DELEGATION_SCOPE_VIOLATION|execution blocked/i
  );
  assert.equal(executed, false);
});

test("delegation narrowing is allowed", async () => {
  const parentAuth = signAuthorizationEd25519(
    {
      auth_id: "auth-parent-narrow",
      issuer: TRUSTED_KEYSET.issuer,
      audience: "child",
      intent_hash: "i".repeat(64),
      state_hash: "s".repeat(64),
      policy_id: "p".repeat(64),
      decision: "ALLOW",
      issued_at: Math.floor(Date.now() / 1000),
      expiry: Math.floor(Date.now() / 1000) + 300,
      kid: "k1",
      capability: "exec",
      nonce: "3",
    },
    privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  ) as Authorization;
  const delegation = createDelegation(
    parentAuth as AuthorizationV1,
    {
      delegatee: "agent-1",
      scope: { tools: ["pay", "read"], max_amount: 100n },
      expiry: parentAuth.expiry,
      kid: "k1",
      audience: "child",
      issuer: TRUSTED_KEYSET.issuer,
    },
    privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  );

  const state = makeState();
  const store = makeVersionedStore(state);
  const guard = OxDeAIGuard({
    engine: makeEngine(),
    ...store,
    trustedKeySets: [TRUSTED_KEYSET],
    expectedAudience: "child",
    trustedDelegationAuthorities: BOUNDARY_AUTHORITIES,
  });

  const action = makeAction();
  let executed = false;
  await guard(action, async () => {
    executed = true;
  }, { delegation: { delegation, parentAuth: parentAuth as AuthorizationV1, parentScope: { tools: ["pay", "read", "write"], max_amount: 1000n } } });

  assert.equal(executed, true);
});

test("delegation replay is denied", async () => {
  const issued_at = Math.floor(Date.now() / 1000);
  const parentAuth = signAuthorizationEd25519(
    {
      auth_id: "auth-parent-replay",
      issuer: TRUSTED_KEYSET.issuer,
      audience: "child",
      intent_hash: "i".repeat(64),
      state_hash: "s".repeat(64),
      policy_id: "p".repeat(64),
      decision: "ALLOW",
      issued_at,
      expiry: issued_at + 300,
      kid: "k1",
      capability: "exec",
      nonce: "4",
    },
    privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  ) as Authorization;
  const delegation = createDelegation(
    parentAuth as AuthorizationV1,
    {
      delegatee: "agent-1",
      scope: { tools: ["pay", "read"], max_amount: 100n },
      expiry: parentAuth.expiry,
      kid: "k1",
      audience: "child",
      issuer: TRUSTED_KEYSET.issuer,
    },
    privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  );

  const state = makeState();
  const store = makeVersionedStore(state);
  const guard = OxDeAIGuard({
    engine: makeEngine(),
    ...store,
    trustedKeySets: [TRUSTED_KEYSET],
    expectedAudience: "child",
    trustedDelegationAuthorities: BOUNDARY_AUTHORITIES,
  });

  const action = makeAction();
  let executions = 0;

  await guard(action, async () => {
    executions += 1;
  }, { delegation: { delegation, parentAuth: parentAuth as AuthorizationV1, parentScope: { tools: ["pay", "read"], max_amount: 100n } } });

  await assert.rejects(
    guard(action, async () => {
      executions += 1;
    }, { delegation: { delegation, parentAuth: parentAuth as AuthorizationV1, parentScope: { tools: ["pay", "read"], max_amount: 100n } } }),
    /Delegation replay detected|DELEGATION_REPLAY/i
  );

  assert.equal(executions, 1);
});

test("unsigned delegation is denied", async () => {
  const issued_at = Math.floor(Date.now() / 1000);
  const parentAuth = signAuthorizationEd25519(
    {
      auth_id: "auth-parent-unsigned",
      issuer: TRUSTED_KEYSET.issuer,
      audience: "child",
      intent_hash: "i".repeat(64),
      state_hash: "s".repeat(64),
      policy_id: "p".repeat(64),
      decision: "ALLOW",
      issued_at,
      expiry: issued_at + 300,
      kid: "k1",
      capability: "exec",
      nonce: "5",
    },
    privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  ) as Authorization;
  const unsignedDelegation = createDelegation(
    parentAuth as AuthorizationV1,
    {
      delegatee: "agent-1",
      scope: { tools: ["read"], max_amount: 100n },
      expiry: parentAuth.expiry,
      kid: "k1",
      audience: "child",
      issuer: TRUSTED_KEYSET.issuer,
    },
    privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  );
  (unsignedDelegation as any).signature = "";

  const state = makeState();
  const store = makeVersionedStore(state);
  const guard = OxDeAIGuard({
    engine: makeEngine(),
    ...store,
    trustedKeySets: [TRUSTED_KEYSET],
    expectedAudience: "child",
    trustedDelegationAuthorities: BOUNDARY_AUTHORITIES,
  });

  const action = makeAction();
  await assert.rejects(
    guard(action, async () => {
      /* no-op */
    }, { delegation: { delegation: unsignedDelegation, parentAuth: parentAuth as AuthorizationV1, parentScope: { tools: ["read"], max_amount: 100n } } }),
    /DELEGATION_SIGNATURE_INVALID|signature verification failed|execution blocked/i
  );
});

test("tampered delegation signature is denied", async () => {
  const issued_at = Math.floor(Date.now() / 1000);
  const parentAuth = signAuthorizationEd25519(
    {
      auth_id: "auth-parent-tamper",
      issuer: TRUSTED_KEYSET.issuer,
      audience: "child",
      intent_hash: "i".repeat(64),
      state_hash: "s".repeat(64),
      policy_id: "p".repeat(64),
      decision: "ALLOW",
      issued_at,
      expiry: issued_at + 300,
      kid: "k1",
      capability: "exec",
      nonce: "6",
    },
    privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  ) as Authorization;
  const delegation = createDelegation(
    parentAuth as AuthorizationV1,
    {
      delegatee: "agent-1",
      scope: { tools: ["read"], max_amount: 100n },
      expiry: parentAuth.expiry,
      kid: "k1",
      audience: "child",
      issuer: TRUSTED_KEYSET.issuer,
    },
    privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  );
  (delegation as any).signature = "invalid-signature";

  const state = makeState();
  const store = makeVersionedStore(state);
  const guard = OxDeAIGuard({
    engine: makeEngine(),
    ...store,
    trustedKeySets: [TRUSTED_KEYSET],
    expectedAudience: "child",
    trustedDelegationAuthorities: BOUNDARY_AUTHORITIES,
  });

  const action = makeAction();
  await assert.rejects(
    guard(action, async () => {
      /* no-op */
    }, { delegation: { delegation, parentAuth: parentAuth as AuthorizationV1, parentScope: { tools: ["read"], max_amount: 100n } } }),
    /DELEGATION_SIGNATURE_INVALID|signature verification failed|execution blocked/i
  );
});

test("verifier failure (throws) blocks execution", async () => {
  // Create an evil keyset that throws when accessed to simulate verifier throw.
  const evilKeyset = new Proxy(
    {
      issuer: "issuer-evil",
      version: "v1",
      keys: [],
    },
    {
      get() {
        throw new Error("boom");
      },
    }
  ) as unknown as KeySet;

  const engine = makeEngine();
  const state = makeState();
  const store = makeVersionedStore(state);
  const guard = OxDeAIGuard({
    engine,
    ...store,
    trustedKeySets: [evilKeyset],
    expectedAudience: "aud-test",
    trustedDelegationAuthorities: BOUNDARY_AUTHORITIES,
  });

  const action = makeAction();
  let executed = false;
  await assert.rejects(
    guard(action, async () => {
      executed = true;
    }),
    /boom|Authorization verification failed/i
  );
  assert.equal(executed, false);
});

test("missing required auth fields is denied before execution", async () => {
  const badAuth: AuthorizationV1 = {
    auth_id: "",
    issuer: "",
    audience: "",
    intent_hash: "",
    state_hash: "",
    policy_id: "",
    decision: "ALLOW",
    issued_at: 0,
    expiry: 0,
    alg: "Ed25519",
    kid: "k1",
    signature: "",
  };

  class FakeEngineBadAuth {
    evaluatePure(_intent: Intent, state: State) {
      return { decision: "ALLOW" as const, reasons: [], authorization: badAuth as Authorization, nextState: state };
    }
    verifyAuthorization() {
      return { valid: true };
    }
  }

  const state = makeState();
  const store = makeVersionedStore(state);
  const guard = OxDeAIGuard({
    engine: new FakeEngineBadAuth() as any,
    ...store,
    trustedKeySets: [TRUSTED_KEYSET],
    expectedAudience: "aud-test",
    trustedDelegationAuthorities: BOUNDARY_AUTHORITIES,
  });

  const action = makeAction();
  let executed = false;
  await assert.rejects(
    guard(action, async () => {
      executed = true;
    }),
    /AUTH_MISSING_FIELD|Authorization verification failed/i
  );
  assert.equal(executed, false);
});
