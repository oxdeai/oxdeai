// SPDX-License-Identifier: Apache-2.0
/**
 * Delegation path tests for @oxdeai/guard.
 *
 * Covers the guard(action, execute, { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } })
 * execution path introduced in v2.x.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  PolicyEngine,
  RECOMMENDED_TRUSTED_TIME_PROFILE,
  signAuthorizationEd25519,
  createDelegation,
} from "@oxdeai/core";
import type { AuthorizationV1, DelegationScope, DelegationV1 } from "@oxdeai/core";
import { buildState } from "@oxdeai/sdk";

import { OxDeAIGuard } from "../guard.js";
import {
  OxDeAIAuthorizationError,
  OxDeAIDelegationError,
} from "../errors.js";
import { OxDeAIGuardConfigurationError } from "../errors.js";
import type { ProposedAction, OxDeAIGuardConfig } from "../types.js";
import { TEST_KEYSET, TEST_KEYPAIR, DELEGATION_AUTHORITIES } from "./helpers/fixtures.js";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const T_NOW = Math.floor(Date.now() / 1000);

const PARENT_SCOPE = { tools: ["provision_gpu"], max_amount: 1_000_000n };

function makeParentAuth(overrides?: { expiry?: number; audience?: string }): AuthorizationV1 {
  return signAuthorizationEd25519(
    {
      auth_id: "f".repeat(64),
      issuer: TEST_KEYSET.issuer,
      audience: overrides?.audience ?? "agent-A",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: "policy-1",
      decision: "ALLOW",
      issued_at: T_NOW - 60,
      expiry: overrides?.expiry ?? T_NOW + 900,
      kid: "k1",
    },
    TEST_KEYPAIR.privateKey.toString()
  );
}

function makeDelegation(
  parentAuth: AuthorizationV1,
  overrides?: Partial<{ delegatee: string; expiry: number; tools: string[]; max_amount: bigint }>
): DelegationV1 {
  return createDelegation(
    parentAuth,
    {
      delegatee: overrides?.delegatee ?? "agent-B",
      issuer: TEST_KEYSET.issuer,
      scope: {
        tools: overrides?.tools,
        max_amount: overrides?.max_amount,
      },
      expiry: overrides?.expiry ?? T_NOW + 300,
      kid: "k1",
    },
    TEST_KEYPAIR.privateKey.toString()
  );
}

function makeGuardConfig(overrides?: Partial<OxDeAIGuardConfig>): OxDeAIGuardConfig {
  const state = buildState({
    agent_id: "agent-B",
    allow_action_types: ["PROVISION"],
    budget_limit: 1_000_000_000n,
    max_amount_per_action: 1_000_000_000n,
    velocity_max_actions: 1000,
    max_concurrent: 16,
  });
  return {
    engine: new PolicyEngine({
      policy_version: "v1",
      engine_secret: "test-secret-must-be-at-least-32-chars!!",
      authorization_signing_alg: "Ed25519",
      authorization_signing_kid: "k1",
      authorization_issuer: TEST_KEYSET.issuer,
      authorization_audience: "agent-A",
      authorization_ttl_seconds: 600,
      authorization_private_key_pem: TEST_KEYPAIR.privateKey.toString(),
      ...RECOMMENDED_TRUSTED_TIME_PROFILE,
    }),
    getState: () => ({ state, version: 0 }),
    setState: () => true,
    trustedKeySets: [TEST_KEYSET],
    expectedAudience: "agent-A",
    trustedDelegationAuthorities: DELEGATION_AUTHORITIES,
    ...overrides,
  };
}

const baseAction: ProposedAction = {
  name: "provision_gpu",
  args: { asset: "a100" },
  estimatedCost: 0,
  context: {
    agent_id: "agent-B",
    target: "gpu-pool",
  },
  timestampSeconds: T_NOW,
};

// ── Happy path ────────────────────────────────────────────────────────────────

test("delegation: valid delegation allows execution", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);
  const config = makeGuardConfig({ trustedKeySets: TEST_KEYSET });
  const guard = OxDeAIGuard(config);

  let executed = false;
  const result = await guard(
    baseAction,
    async () => { executed = true; return "ok"; },
    { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } }
  );

  assert.ok(executed, "execute should be called on valid delegation");
  assert.equal(result, "ok");
});

test("delegation: does not call setState", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);
  let setStateCalled = false;

  const config = makeGuardConfig({ setState: () => { setStateCalled = true; return true; } });
  const guard = OxDeAIGuard(config);

  await guard(baseAction, async () => {}, { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } });

  assert.ok(!setStateCalled, "setState must not be called on delegation path");
});

test("delegation: fires onDecision ALLOW hook with delegation field", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);

  let capturedDecision: string | undefined;
  let capturedDelegation: DelegationV1 | undefined;

  const config = makeGuardConfig({
    onDecision({ decision, delegation: d }) {
      capturedDecision = decision;
      capturedDelegation = d;
    },
  });
  const guard = OxDeAIGuard(config);

  await guard(baseAction, async () => {}, { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } });

  assert.equal(capturedDecision, "ALLOW");
  assert.ok(capturedDelegation !== undefined, "delegation should be in onDecision record");
  assert.equal(capturedDelegation!.delegation_id, delegation.delegation_id);
});

test("delegation: calls beforeExecute hook", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);

  const callOrder: string[] = [];
  const config = makeGuardConfig({
    beforeExecute: () => { callOrder.push("beforeExecute"); },
  });
  const guard = OxDeAIGuard(config);

  await guard(
    baseAction,
    async () => { callOrder.push("execute"); },
    { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } }
  );

  assert.deepEqual(callOrder, ["beforeExecute", "execute"]);
});

// ── Scope enforcement ─────────────────────────────────────────────────────────

test("delegation: blocks action not in scope.tools", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth, { tools: ["query_db"] }); // not provision_gpu

  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(baseAction, async () => { executed = true; }, { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDelegationError, `expected OxDeAIDelegationError, got ${err}`);
      assert.ok(err.violations.some((v) => v.includes("provision_gpu")));
      return true;
    }
  );
  assert.ok(!executed);
});

test("delegation: allows action in scope.tools", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth, { tools: ["provision_gpu"] });

  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);

  let executed = false;
  await guard(baseAction, async () => { executed = true; }, { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } });
  assert.ok(executed);
});

test("delegation: blocks intent amount exceeding scope.max_amount", async () => {
  const parentAuth = makeParentAuth();
  // max_amount = 0n, action estimatedCost = 1.0 → amount = 1_000_000n
  const delegation = makeDelegation(parentAuth, { max_amount: 0n });

  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  const expensiveAction: ProposedAction = { ...baseAction, estimatedCost: 1.0 };

  await assert.rejects(
    () => guard(expensiveAction, async () => { executed = true; }, { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDelegationError);
      assert.ok(err.violations.some((v) => v.includes("max_amount")));
      return true;
    }
  );
  assert.ok(!executed);
});

// ── Chain verification failures ───────────────────────────────────────────────

test("delegation: blocks expired delegation", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth, { expiry: T_NOW - 1 }); // already expired

  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(baseAction, async () => { executed = true; }, { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDelegationError);
      assert.ok(err.violations.some((v) => v.toLowerCase().includes("expir")));
      return true;
    }
  );
  assert.ok(!executed);
});

test("delegation: blocks when parent hash mismatches", async () => {
  const parentAuth = makeParentAuth();
  // #301: differ by expiry, not audience. Under the corrected ordering an
  // audience mismatch fails parent authentication before verifyDelegationChain
  // runs, so it would no longer isolate the parent-hash binding this test covers.
  const otherAuth = makeParentAuth({ expiry: T_NOW + 800 });
  const delegation = makeDelegation(parentAuth); // bound to parentAuth

  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  // Present with the wrong parent
  await assert.rejects(
    () => guard(baseAction, async () => { executed = true; }, { delegation: { delegation, parentAuth: otherAuth, parentScope: PARENT_SCOPE } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDelegationError);
      return true;
    }
  );
  assert.ok(!executed);
});

test("delegation: blocks invalid signature when requireDelegationSignatureVerification", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);
  const tampered = { ...delegation, delegatee: "agent-EVIL" }; // breaks signature

  const config = makeGuardConfig({ trustedKeySets: TEST_KEYSET });
  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(baseAction, async () => { executed = true; }, { delegation: { delegation: tampered, parentAuth, parentScope: PARENT_SCOPE } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIDelegationError);
      return true;
    }
  );
  assert.ok(!executed);
});

test("delegation: blocks when delegation and parentAuth are missing from input", async () => {
  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);

  await assert.rejects(
    () => guard(baseAction, async () => {}, {
      delegation: { delegation: null as unknown as DelegationV1, parentAuth: null as unknown as AuthorizationV1, parentScope: {} }
    }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      return true;
    }
  );
});

// ── OxDeAIDelegationError is-a OxDeAIAuthorizationError ───────────────────────

test("OxDeAIDelegationError is instanceof OxDeAIAuthorizationError", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth, { expiry: T_NOW - 1 });

  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);

  await assert.rejects(
    () => guard(baseAction, async () => {}, { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } }),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError, "OxDeAIDelegationError must be catchable as OxDeAIAuthorizationError");
      assert.ok(err instanceof OxDeAIDelegationError, "and also as OxDeAIDelegationError");
      assert.ok(Array.isArray((err as OxDeAIDelegationError).violations));
      return true;
    }
  );
});

// ── parentScope validation ────────────────────────────────────────────────────

test("delegation: missing parentScope blocks before chain verification", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);
  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(
      baseAction,
      async () => { executed = true; },
      { delegation: { delegation, parentAuth, parentScope: undefined as unknown as DelegationScope } }
    ),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      assert.ok(!(err instanceof OxDeAIDelegationError), "missing parentScope must be OxDeAIAuthorizationError, not delegation error");
      assert.match((err as Error).message, /parent authorization scope/i);
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when parentScope is missing");
});

test("delegation: malformed parentScope (non-object) blocks before chain verification", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);
  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(
      baseAction,
      async () => { executed = true; },
      { delegation: { delegation, parentAuth, parentScope: "not-an-object" as unknown as DelegationScope } }
    ),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      assert.ok(!(err instanceof OxDeAIDelegationError));
      assert.match((err as Error).message, /parent authorization scope/i);
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when parentScope is malformed");
});

test("delegation: malformed parentScope (tools not array) blocks before chain verification", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);
  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  await assert.rejects(
    () => guard(
      baseAction,
      async () => { executed = true; },
      { delegation: { delegation, parentAuth, parentScope: { tools: "not-an-array" } as unknown as DelegationScope } }
    ),
    (err: unknown) => {
      assert.ok(err instanceof OxDeAIAuthorizationError);
      assert.ok(!(err instanceof OxDeAIDelegationError));
      assert.match((err as Error).message, /parent authorization scope/i);
      return true;
    }
  );
  assert.ok(!executed, "execute must not be called when parentScope.tools is not an array");
});

test("delegation: valid empty parentScope ({}) is accepted", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);
  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);
  let executed = false;

  // An empty scope ({}) places no restrictions — all tools and amounts allowed.
  await guard(
    baseAction,
    async () => { executed = true; },
    { delegation: { delegation, parentAuth, parentScope: {} } }
  );
  assert.ok(executed, "execute must be called when parentScope is a valid empty object");
});

// ── Standard path unaffected ──────────────────────────────────────────────────

test("standard path: unaffected when no opts.delegation provided", async () => {
  const config = makeGuardConfig();
  const guard = OxDeAIGuard(config);

  const result = await guard(baseAction, async () => "standard-ok");
  assert.equal(result, "standard-ok");
});

// F4-C: A verified delegation may execute only after the revocation
// provider explicitly returns ACTIVE. Assert that the lookup key
// matches the signed delegation and is frozen before execution.
test("F4-C: ACTIVE delegation revocation status permits execution", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);

  let checked = false;
  let executed = false;

  const guard = OxDeAIGuard(
    makeGuardConfig({
      delegationRevocationProvider: {
        async check(key) {
          checked = true;

          assert.equal(key.delegationId, delegation.delegation_id);
          assert.equal(key.issuer, delegation.issuer);
          assert.equal(key.delegator, delegation.delegator);
          assert.equal(key.parentAuthHash, delegation.parent_auth_hash);
          assert.ok(Object.isFrozen(key));

          return { status: "ACTIVE" };
        },
      },
      requireDelegationRevocation: true,
    })
  );

  const result = await guard(
    baseAction,
    async () => {
      executed = true;
      return "ok";
    },
    {
      delegation: {
        delegation,
        parentAuth,
        parentScope: PARENT_SCOPE,
      },
    }
  );

  assert.equal(checked, true);
  assert.equal(executed, true);
  assert.equal(result, "ok");
});

// F4-C: A revoked delegation must be denied at the execution boundary,
// even when its signature and authorization chain remain valid.
test("F4-C: REVOKED delegation blocks execution", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);

  let checks = 0;
  let executed = false;
  let beforeExecuteCalled = false;

  const events: Array<{
    stage: string;
    boundaryFailure: string;
    authorizationConsumed: boolean;
    delegationConsumed: boolean;
    executionStarted: boolean;
  }> = [];

  const guard = OxDeAIGuard(
    makeGuardConfig({
      delegationRevocationProvider: {
        async check() {
          checks++;
          return { status: "REVOKED" };
        },
      },
      requireDelegationRevocation: true,
      beforeExecute: () => {
        beforeExecuteCalled = true;
      },
      onBoundaryEvent: (event) => {
        events.push(event);
      },
    })
  );

  await assert.rejects(
    guard(
      baseAction,
      async () => {
        executed = true;
        return "SHOULD_NOT_EXECUTE";
      },
      {
        delegation: {
          delegation,
          parentAuth,
          parentScope: PARENT_SCOPE,
        },
      }
    ),
    OxDeAIDelegationError
  );

  assert.equal(checks, 1);
  assert.equal(executed, false);
  assert.equal(beforeExecuteCalled, false);

  assert.equal(events.length, 1);
  assert.equal(events[0]!.stage, "DELEGATION");
  assert.equal(events[0]!.boundaryFailure, "DELEGATION_REVOKED");
  assert.equal(events[0]!.authorizationConsumed, false);
  assert.equal(events[0]!.delegationConsumed, false);
  assert.equal(events[0]!.executionStarted, false);
});

// F4-C: A required revocation check must not silently fall back
// to legacy behavior when no provider is configured.
test("F4-C: required revocation without provider fails closed", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);

  let executed = false;
  let beforeExecuteCalled = false;
  const events: Array<{
    stage: string;
    boundaryFailure: string;
    authorizationConsumed: boolean;
    delegationConsumed: boolean;
    executionStarted: boolean;
  }> = [];

  const guard = OxDeAIGuard(
    makeGuardConfig({
      requireDelegationRevocation: true,
      beforeExecute: () => {
        beforeExecuteCalled = true;
      },
      onBoundaryEvent: (event) => {
        events.push(event);
      },
    })
  );

  await assert.rejects(
    guard(
      baseAction,
      async () => {
        executed = true;
        return "SHOULD_NOT_EXECUTE";
      },
      {
        delegation: {
          delegation,
          parentAuth,
          parentScope: PARENT_SCOPE,
        },
      }
    ),
    OxDeAIDelegationError
  );

  assert.equal(executed, false);
  assert.equal(beforeExecuteCalled, false);
  assert.equal(events.length, 1);
  assert.equal(events[0]!.stage, "DELEGATION");
  assert.equal(
    events[0]!.boundaryFailure,
    "DELEGATION_REVOCATION_UNAVAILABLE"
  );
  assert.equal(events[0]!.authorizationConsumed, false);
  assert.equal(events[0]!.delegationConsumed, false);
  assert.equal(events[0]!.executionStarted, false);
});

// F4-C: A provider failure must never be interpreted as ACTIVE.
test("F4-C: provider failure blocks execution", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);

  let checks = 0;
  let executed = false;
  let beforeExecuteCalled = false;
  const events: Array<{
    stage: string;
    boundaryFailure: string;
    authorizationConsumed: boolean;
    delegationConsumed: boolean;
    executionStarted: boolean;
  }> = [];

  const guard = OxDeAIGuard(
    makeGuardConfig({
      requireDelegationRevocation: true,
      delegationRevocationProvider: {
        async check() {
          checks++;
          throw new Error("Synthetic revocation provider outage");
        },
      },
      beforeExecute: () => {
        beforeExecuteCalled = true;
      },
      onBoundaryEvent: (event) => {
        events.push(event);
      },
    })
  );

  await assert.rejects(
    guard(
      baseAction,
      async () => {
        executed = true;
        return "SHOULD_NOT_EXECUTE";
      },
      {
        delegation: {
          delegation,
          parentAuth,
          parentScope: PARENT_SCOPE,
        },
      }
    ),
    OxDeAIDelegationError
  );

  assert.equal(checks, 1);
  assert.equal(executed, false);
  assert.equal(beforeExecuteCalled, false);

  assert.equal(events.length, 1);
  assert.equal(events[0]!.stage, "DELEGATION");
  assert.equal(
    events[0]!.boundaryFailure,
    "DELEGATION_REVOCATION_UNAVAILABLE"
  );
  assert.equal(events[0]!.authorizationConsumed, false);
  assert.equal(events[0]!.delegationConsumed, false);
  assert.equal(events[0]!.executionStarted, false);
});

// F4-C: Malformed or hostile provider responses must never authorize execution.
test("F4-C: invalid revocation responses fail closed", async (t) => {
  const cases: Array<{ name: string; result: unknown }> = [
    { name: "unknown status", result: { status: "UNKNOWN" } },
    { name: "missing status", result: {} },
    {
      name: "throwing getter",
      result: Object.defineProperty({}, "status", {
        get() {
          throw new Error("Synthetic getter failure");
        },
      }),
    },
    {
      name: "hostile Proxy",
      result: new Proxy({}, {
        getOwnPropertyDescriptor() {
          throw new Error("Synthetic Proxy failure");
        },
      }),
    },
  ];

  for (const scenario of cases) {
    await t.test(scenario.name, async () => {
      const parentAuth = makeParentAuth();
      const delegation = makeDelegation(parentAuth);

      let executed = false;
      let beforeExecuteCalled = false;
      let checks = 0;

      const events: Array<{
        stage: string;
        boundaryFailure: string;
        authorizationConsumed: boolean;
        delegationConsumed: boolean;
        executionStarted: boolean;
      }> = [];

      const guard = OxDeAIGuard(
        makeGuardConfig({
          requireDelegationRevocation: true,
          delegationRevocationProvider: {
            async check() {
              checks++;
              return scenario.result as { status: "ACTIVE" | "REVOKED" };
            },
          },
          beforeExecute: () => {
            beforeExecuteCalled = true;
          },
          onBoundaryEvent: (event) => {
            events.push(event);
          },
        })
      );

      await assert.rejects(
        guard(
          baseAction,
          async () => {
            executed = true;
            return "SHOULD_NOT_EXECUTE";
          },
          {
            delegation: {
              delegation,
              parentAuth,
              parentScope: PARENT_SCOPE,
            },
          }
        ),
        OxDeAIDelegationError
      );

      assert.equal(checks, 1);
      assert.equal(executed, false);
      assert.equal(beforeExecuteCalled, false);
      assert.equal(events.length, 1);
      assert.equal(events[0]!.stage, "DELEGATION");
      assert.equal(
        events[0]!.boundaryFailure,
        "DELEGATION_REVOCATION_UNAVAILABLE"
      );
      assert.equal(events[0]!.authorizationConsumed, false);
      assert.equal(events[0]!.delegationConsumed, false);
      assert.equal(events[0]!.executionStarted, false);
    });
  }
});

// F4-C: The revocation extension is opt-in. Without a provider and
// without the required flag, valid legacy delegations still execute.
test("F4-C: optional revocation without provider preserves legacy execution", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);

  let executed = false;
  let beforeExecuteCalled = false;
  let boundaryEvents = 0;

  const guard = OxDeAIGuard(
    makeGuardConfig({
      requireDelegationRevocation: false,
      beforeExecute: () => {
        beforeExecuteCalled = true;
      },
      onBoundaryEvent: () => {
        boundaryEvents++;
      },
    })
  );

  const result = await guard(
    baseAction,
    async () => {
      executed = true;
      return "ok";
    },
    {
      delegation: {
        delegation,
        parentAuth,
        parentScope: PARENT_SCOPE,
      },
    }
  );

  assert.equal(result, "ok");
  assert.equal(executed, true);
  assert.equal(beforeExecuteCalled, true);
  assert.equal(boundaryEvents, 0);
});

// F4-C: The Guard must retain the provider check function captured
// at construction, rather than resolving a mutable method at execution.
test("F4-C: provider method mutation cannot bypass revocation", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);

  let originalChecks = 0;
  let replacementChecks = 0;
  let executed = false;
  const events: string[] = [];

  const provider: {
    check(): Promise<{ status: "ACTIVE" | "REVOKED" }>;
  } = {
    async check() {
      originalChecks++;
      return { status: "REVOKED" };
    },
  };

  const guard = OxDeAIGuard(
    makeGuardConfig({
      requireDelegationRevocation: true,
      delegationRevocationProvider: provider,
      onBoundaryEvent: (event) => {
        events.push(event.boundaryFailure);
      },
    })
  );

  // Attempt to replace the authorization-relevant provider method.
  provider.check = async () => {
    replacementChecks++;
    return { status: "ACTIVE" as const };
  };

  await assert.rejects(
    guard(
      baseAction,
      async () => {
        executed = true;
        return "SHOULD_NOT_EXECUTE";
      },
      {
        delegation: {
          delegation,
          parentAuth,
          parentScope: PARENT_SCOPE,
        },
      }
    ),
    OxDeAIDelegationError
  );

  assert.equal(originalChecks, 1);
  assert.equal(replacementChecks, 0);
  assert.equal(executed, false);
  assert.deepEqual(events, ["DELEGATION_REVOKED"]);
});

// F4-C: Revocation rejection must happen before either replay ID
// is consumed. Verify actual store calls, not just audit flags.
test("F4-C: revocation rejection does not consume replay IDs", async (t) => {
  for (const status of ["REVOKED", "UNAVAILABLE"] as const) {
    await t.test(status, async () => {
      const parentAuth = makeParentAuth();
      const delegation = makeDelegation(parentAuth);
      const calls: string[] = [];
      let executed = false;

      const guard = OxDeAIGuard(
        makeGuardConfig({
          replayProtection: {
            mode: "shared",
            store: {
              async consumeAuthId() {
                calls.push("consumeAuthId");
                return true;
              },
              async consumeDelegationId() {
                calls.push("consumeDelegationId");
                return true;
              },
            },
          },
          requireDelegationRevocation: true,
          delegationRevocationProvider: {
            async check() {
              calls.push("revocationCheck");
              if (status === "UNAVAILABLE") {
                throw new Error("Synthetic provider outage");
              }
              return { status: "REVOKED" };
            },
          },
        })
      );

      await assert.rejects(
        guard(
          baseAction,
          async () => {
            executed = true;
            return "SHOULD_NOT_EXECUTE";
          },
          {
            delegation: {
              delegation,
              parentAuth,
              parentScope: PARENT_SCOPE,
            },
          }
        ),
        OxDeAIDelegationError
      );

      assert.deepEqual(calls, ["revocationCheck"]);
      assert.equal(executed, false);
    });
  }
});

// F4-C: A fresh authorization check must observe a changed revocation
// status. Independent replay stores isolate revocation from replay denial.
test("F4-C: revocation state change blocks a subsequent execution", async () => {
  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);

  let status: "ACTIVE" | "REVOKED" = "ACTIVE";
  let checks = 0;
  let executions = 0;
  const events: string[] = [];

  const provider = {
    async check() {
      checks++;
      return { status };
    },
  };

  const config = () =>
    makeGuardConfig({
      replayProtection: { mode: "process-local" },
      requireDelegationRevocation: true,
      delegationRevocationProvider: provider,
      onBoundaryEvent: (event) => {
        events.push(event.boundaryFailure);
      },
    });

  const context = {
    delegation: {
      delegation,
      parentAuth,
      parentScope: PARENT_SCOPE,
    },
  };

  const execute = async () => {
    executions++;
    return "ok";
  };

  const firstGuard = OxDeAIGuard(config());

  assert.equal(await firstGuard(baseAction, execute, context), "ok");
  assert.equal(executions, 1);
  assert.equal(checks, 1);

  status = "REVOKED";

  const secondGuard = OxDeAIGuard(config());

  await assert.rejects(
    secondGuard(baseAction, execute, context),
    OxDeAIDelegationError
  );

  assert.equal(checks, 2);
  assert.equal(executions, 1);
  assert.deepEqual(events, ["DELEGATION_REVOKED"]);
});


// F4-C-CONFIG-REGRESSION-TESTS
// Configuration errors must not silently disable revocation enforcement.

test("F4-C: invalid revocation configuration fails at construction", () => {
  const invalidCases: Array<{
    name: string;
    overrides: Record<string, unknown>;
  }> = [
    {
      name: "non-boolean required flag",
      overrides: { requireDelegationRevocation: "true" },
    },
    {
      name: "null provider",
      overrides: { delegationRevocationProvider: null },
    },
    {
      name: "provider without check",
      overrides: { delegationRevocationProvider: {} },
    },
    {
      name: "provider with non-function check",
      overrides: { delegationRevocationProvider: { check: "ACTIVE" } },
    },
    {
      name: "array provider",
      overrides: { delegationRevocationProvider: [] },
    },
  ];

  for (const { name, overrides } of invalidCases) {
    assert.throws(
      () => OxDeAIGuard(makeGuardConfig(
        overrides as Partial<OxDeAIGuardConfig>
      )),
      {
        name: "OxDeAIGuardConfigurationError",
      },
      name
    );
  }
});

test("F4-C: provider check getter is read once at construction", async () => {
  let reads = 0;
  let calls = 0;

  const provider = {
    get check() {
      reads++;

      if (reads !== 1) {
        throw new Error("check getter read more than once");
      }

      return async function () {
        calls++;
        return { status: "ACTIVE" as const };
      };
    },
  };

  const guard = OxDeAIGuard(
    makeGuardConfig({
      delegationRevocationProvider: provider,
      requireDelegationRevocation: true,
    })
  );

  assert.equal(reads, 1);

  const parentAuth = makeParentAuth();
  const delegation = makeDelegation(parentAuth);

  const result = await guard(
    baseAction,
    async () => "ok",
    { delegation: { delegation, parentAuth, parentScope: PARENT_SCOPE } }
  );

  assert.equal(result, "ok");
  assert.equal(reads, 1);
  assert.equal(calls, 1);
});

test("F4-C: throwing provider check getter fails at construction", () => {
  const provider = {
    get check(): never {
      throw new Error("synthetic getter failure");
    },
  };

  assert.throws(
    () => OxDeAIGuard(
      makeGuardConfig({
        delegationRevocationProvider: provider,
        requireDelegationRevocation: true,
      })
    ),
    {
      name: "OxDeAIGuardConfigurationError",
    }
  );
});

test("F4-C: required revocation does not affect direct authorization", async () => {
  let providerCalls = 0;
  let executions = 0;

  const guard = OxDeAIGuard(
    makeGuardConfig({
      requireDelegationRevocation: true,
      delegationRevocationProvider: {
        async check() {
          providerCalls++;
          return { status: "REVOKED" };
        },
      },
    })
  );

  const result = await guard(
    baseAction,
    async () => {
      executions++;
      return "direct-ok";
    }
  );

  assert.equal(result, "direct-ok");
  assert.equal(executions, 1);
  assert.equal(providerCalls, 0);
});

test("F4-C: provider bind failure is a configuration error", () => {
  const hostileCheck = new Proxy(
    async (_key: unknown) => ({ status: "ACTIVE" as const }),
    {
      get(target, property, receiver) {
        if (property === "bind") {
          throw new Error("synthetic bind failure");
        }
        return Reflect.get(target, property, receiver);
      },
    }
  );

  assert.throws(
    () =>
      OxDeAIGuard(
        makeGuardConfig({
          delegationRevocationProvider: {
            check: hostileCheck,
          },
          requireDelegationRevocation: true,
        })
      ),
    (error: unknown) =>
      error instanceof OxDeAIGuardConfigurationError &&
      error.message.includes("could not be bound")
  );
});
