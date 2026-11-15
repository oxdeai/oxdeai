// SPDX-License-Identifier: Apache-2.0
/**
 * pep.ts — Policy Enforcement Point (PEP)
 *
 * Uses @oxdeai/langgraph to delegate all authorization logic to the
 * universal guard. No evaluatePure / verifyAuthorization calls here.
 */

import type { AuthorizationV1, State } from "@oxdeai/core";
import { createLangGraphGuard, OxDeAIDenyError } from "@oxdeai/langgraph";
import type { LangGraphToolCall } from "@oxdeai/langgraph";
import { buildProvisionIntent, engine, gpuCost, AGENT_ID } from "./policy.js";
import { DEMO_KEYSET } from "./crypto.js";

const C = {
  reset:      "\x1b[0m",
  bold:       "\x1b[1m",
  dim:        "\x1b[2m",
  cyan:       "\x1b[36m",
  green:      "\x1b[32m",
  red:        "\x1b[31m",
  yellow:     "\x1b[33m",
  blue:       "\x1b[34m",
  magenta:    "\x1b[35m",
  white:      "\x1b[97m",
  bCyan:      "\x1b[1;36m",
  bGreen:     "\x1b[1;32m",
  bRed:       "\x1b[1;31m",
  bYellow:    "\x1b[1;33m",
  bWhite:     "\x1b[1;97m",
  bMagenta:   "\x1b[1;35m",
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
  const cost = gpuCost(asset, region);

  // Build the intent once — used for logging and passed directly via mapActionToIntent.
  // This avoids double-incrementing the nonce counter.
  const intent = buildProvisionIntent(asset, region, timestampSeconds);

  log(`\n${c(C.dim, "┌─ Proposed tool call")}`);
  log(`${c(C.dim, "│")}  ${c(C.bWhite, "provision_gpu")}(asset=${asset}, region=${region})`);
  log(`${c(C.dim, "│")}  cost=${c(C.yellow, String(cost))} minor units  nonce=${intent.nonce}  intent_id=${intent.intent_id}`);

  let nextState = state;
  let capturedAuth: AuthorizationV1 | undefined;

  const toolCall: LangGraphToolCall = {
    name: "provision_gpu",
    args: { asset, region },
    id: intent.intent_id,
  };

  const guard = createLangGraphGuard({
    engine,
    agentId: AGENT_ID,
    getState: () => ({ state, version: 0 }),
    setState: (s) => { nextState = s; return true; },
    trustedKeySets: [DEMO_KEYSET],
    // Return the pre-built intent so nonce/intent_id are stable.
    mapActionToIntent: () => intent,
    beforeExecute(_action: unknown, authorization: AuthorizationV1) {
      capturedAuth = authorization;
      log(`${c(C.dim, "│")}  ${c(C.bGreen, "ALLOW")}  auth_id=${c(C.blue, authorization.auth_id.slice(0, 16) + "...")}`);
      log(`${c(C.dim, "│")}         expires=${authorization.expiry}  state_hash=${c(C.cyan, authorization.state_hash.slice(0, 16) + "...")}`);
    },
  });

  try {
    const instanceId = await guard(toolCall, async (verified) => {
      // Read the tool arguments from the verified action the guard authorized,
      // not from `toolCall`, which is caller-owned (ACT-1).
      const id = provision_gpu(String(verified.args.asset), String(verified.args.region));
      log(`${c(C.bGreen, "└─ EXECUTED")}  instance_id=${c(C.cyan, id)}`);
      return id;
    });

    return { allowed: true, instanceId: instanceId as string, authorization: capturedAuth!, nextState };
  } catch (err) {
    if (err instanceof OxDeAIDenyError) {
      const reasons = [...(err as OxDeAIDenyError).reasons];
      log(`${c(C.bRed, "└─ DENY")}  reasons: ${c(C.bYellow, reasons.join(", "))}`);
      return { allowed: false, reasons };
    }
    // OxDeAIAuthorizationError and others: re-throw (fail closed).
    throw err;
  }
}
