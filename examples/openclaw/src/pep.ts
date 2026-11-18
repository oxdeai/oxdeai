// SPDX-License-Identifier: Apache-2.0
/**
 * pep.ts - Policy Enforcement Point (PEP)
 *
 * Uses @oxdeai/openclaw to delegate all authorization logic to the
 * universal guard. No evaluatePure / verifyAuthorization calls here.
 */

import type { AuthorizationV1, State } from "@oxdeai/core";
import { createOpenClawGuard, OxDeAIDenyError } from "@oxdeai/openclaw";
import type { OpenClawAction } from "@oxdeai/openclaw";
import { buildProvisionIntent, engine, gpuCost, AGENT_ID } from "./policy.js";
import { DEMO_KEYSET } from "./crypto.js";

// ── ANSI color helpers ────────────────────────────────────────────────────────
const C = {
  reset:   "\x1b[0m",
  dim:     "\x1b[2m",
  cyan:    "\x1b[36m",
  green:   "\x1b[32m",
  red:     "\x1b[31m",
  yellow:  "\x1b[33m",
  blue:    "\x1b[34m",
  bGreen:  "\x1b[1;32m",
  bRed:    "\x1b[1;31m",
  bYellow: "\x1b[1;33m",
  bCyan:   "\x1b[1;36m",
  bWhite:  "\x1b[1;97m",
};
const c = (color: string, text: string) => `${color}${text}${C.reset}`;

let provisionCounter = 0;

function provision_gpu(asset: string, region: string): string {
  provisionCounter += 1;
  return `${asset}-${region}-${provisionCounter.toString(36)}`;
}

export type GuardedResult =
  | { allowed: true; instanceId: string; authorization: AuthorizationV1; nextState: State }
  | { allowed: false; reasons: string[] };

export async function guardedProvision(
  asset: string,
  region: string,
  state: State,
  timestampSeconds: number,
  log: (msg: string) => void
): Promise<GuardedResult> {
  const cost   = gpuCost(asset, region);

  // Build the intent once - used for logging and passed directly via mapActionToIntent.
  // This avoids double-incrementing the nonce counter.
  const intent = buildProvisionIntent(asset, region, timestampSeconds);

  // ── Proposal box header ──────────────────────────────────────────────────
  log(`\n${c(C.dim, "┌─ Proposed tool call")}`);
  log(`${c(C.dim, "│")}  ${c(C.bWhite, `provision_gpu`)}${c(C.dim, `(asset=${asset}, region=${region})`)}`);
  log(`${c(C.dim, "│")}  ${c(C.dim, `cost=${c(C.yellow, String(cost))} minor units  nonce=${intent.nonce}  intent_id=${intent.intent_id}`)}`);

  let nextState = state;
  let capturedAuth: AuthorizationV1 | undefined;

  const action: OpenClawAction = {
    name: "provision_gpu",
    args: { asset, region },
    step_id: intent.intent_id,
    workflow_id: "openclaw-gpu-demo",
  };

  const guard = createOpenClawGuard({
    engine,
    agentId: AGENT_ID,
    getState: () => ({ state, version: 0 }),
    setState: (s) => { nextState = s; return true; },
    trustedKeySets: [DEMO_KEYSET],
    // Return the pre-built intent so nonce/intent_id are stable.
    mapActionToIntent: () => intent,
    beforeExecute(_action: unknown, authorization: AuthorizationV1) {
      capturedAuth = authorization;
      log(`${c(C.dim, "│")}  ${c(C.bGreen, "ALLOW")}  ${c(C.dim, "auth_id=")}${c(C.blue, authorization.auth_id.slice(0, 16) + "...")}`);
      log(`${c(C.dim, "│")}         ${c(C.dim, "expires=")}${authorization.expiry}  ${c(C.dim, "state_hash=")}${c(C.blue, authorization.state_hash.slice(0, 16) + "...")}`);
    },
  });

  try {
    const instanceId = await guard(action, async (verified) => {
      // Read the tool arguments from the verified action the guard authorized,
      // not from `action`, which is caller-owned (ACT-1).
      const id = provision_gpu(String(verified.args.asset), String(verified.args.region));
      log(`${c(C.bGreen, "└─ EXECUTED")}  ${c(C.dim, "instance_id=")}${c(C.cyan, id)}`);
      return id;
    });

    return { allowed: true, instanceId: instanceId as string, authorization: capturedAuth!, nextState };
  } catch (err) {
    if (err instanceof OxDeAIDenyError) {
      const reasons = [...(err as OxDeAIDenyError).reasons];
      log(`${c(C.bRed, "└─ DENY")}  ${c(C.dim, "reasons:")} ${c(C.bYellow, reasons.join(", "))}`);
      return { allowed: false, reasons };
    }
    // OxDeAIAuthorizationError and others: re-throw (fail closed).
    throw err;
  }
}
