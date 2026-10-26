#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  PolicyEngine,
  RECOMMENDED_TRUSTED_TIME_PROFILE,
  decodeCanonicalState,
  decodeEnvelope,
  encodeCanonicalState,
  encodeEnvelope,
  verifyAuditEvents,
  verifyAuthorization,
  verifyEnvelope,
  verifySnapshot
} from "@oxdeai/core";
import type { ActionType, AuthorizationV1, Intent, KeySet, State, VerificationResult } from "@oxdeai/core";

import { appendAuditEvents, normalizeStateBigInts, readAuditEvents, readStateFile, resetAuditFile, writeStateFile } from "./store.js";

type Flags = {
  help?: boolean;
  version?: boolean;
  json?: boolean;
  state?: string;
  audit?: string;
  file?: string;
  out?: string;
  agent?: string;
  nonce?: string;
  asset?: string;
  kind?: "snapshot" | "audit" | "envelope" | "authorization";
  mode?: "strict" | "best-effort";
  expectedPolicyId?: string;
  expectedIssuer?: string;
  expectedAudience?: string;
  consumedAuthId?: string;
  trustedKeyset?: string;
  requireSignatureVerification?: boolean;
  legacyHmacSecret?: string;
};

type Io = {
  out: (line: string) => void;
  err: (line: string) => void;
  now: () => number;
};

const DEFAULT_STATE_PATH = ".oxdeai/state.json";
const DEFAULT_AUDIT_PATH = ".oxdeai/audit.ndjson";
const DEFAULT_SNAPSHOT_PATH = ".oxdeai/snapshot.bin";
const DEFAULT_ENVELOPE_PATH = ".oxdeai/envelope.bin";
const ACTION_TYPES = new Set<ActionType>(["PAYMENT", "PURCHASE", "PROVISION", "ONCHAIN_TX"]);
const EXIT_CODE_OK = 0;
const EXIT_CODE_INVALID = 1;
const EXIT_CODE_USAGE = 2;
const EXIT_CODE_INCONCLUSIVE = 3;
const require = createRequire(import.meta.url);
const CLI_VERSION = (require("../package.json") as { version: string }).version;
const VERIFY_KIND_ALIAS = {
  snap: "snapshot",
  snapshot: "snapshot",
  audit: "audit",
  envelope: "envelope",
  auth: "authorization",
  authorization: "authorization"
} as const;

function usage(): string {
  return `oxdeai CLI

Usage:
  oxdeai --help
  oxdeai --version
  oxdeai build [--state <state.json>] [--out <snapshot.bin>] [--json]
  oxdeai verify --kind <snapshot|audit|envelope|authorization> [--file <path>|-] [--mode <strict|best-effort>] [--expected-policy-id <hex>] [--expected-issuer <id>] [--expected-audience <id>] [--consumed-auth-id <id>] [--trusted-keyset <keyset.json>] [--require-signature] [--legacy-hmac-secret <secret>] [--json]
  oxdeai inspect <snapshot|audit|envelope|auth|authorization> [--file <path>] [--json]
  oxdeai verify all [--state <state.json>] [--audit <audit.ndjson>] [--json]
  oxdeai doctor [--json]
  oxdeai paths [--json]
  oxdeai auth create <actionType> <amount> <target> --agent <id> --nonce <n> --out <authorization.json> [--asset <asset>] [--state <state.json>] [--json]
  oxdeai auth inspect [--file <authorization.json>] [--json]
  oxdeai examples init [--state <state.json>] [--audit <audit.ndjson>] [--json]
  oxdeai replay [--json]
  oxdeai init --file <policy.json> [--state <state.json>] [--audit <audit.ndjson>] [--json]
  oxdeai launch <actionType> <amount> <target> --agent <id> --nonce <n> [--asset <asset>] [--state <state.json>] [--audit <audit.ndjson>] [--json]
  oxdeai launch dry-run <actionType> <amount> <target> --agent <id> --nonce <n> [--asset <asset>] [--state <state.json>] [--json]
  oxdeai make-envelope --out <file> [--state <state.json>] [--audit <audit.ndjson>] [--json]
  oxdeai verify-envelope <file> [--json]
  oxdeai verify-audit [--audit <audit.ndjson>] [--json]
  oxdeai snapshot-hash [--state <state.json>] [--json]
  oxdeai audit [--audit <audit.ndjson>] [--json]
  oxdeai state [--state <state.json>] [--json]

Defaults:
  --state .oxdeai/state.json
  --audit .oxdeai/audit.ndjson

Use "oxdeai help <command>" for command-specific help.`;
}

function commandUsage(cmd: string): string {
  switch (cmd) {
    case "build":
      return `Usage:
  oxdeai build [--state <state.json>] [--out <snapshot.bin>] [--expected-policy-id <hex>] [--json]
  oxdeai build snapshot [--state <state.json>] [--out <snapshot.bin>] [--expected-policy-id <hex>] [--json]

Builds a canonical snapshot payload from state.
Default state path: .oxdeai/state.json`;
    case "verify":
      return `Usage:
  oxdeai verify --kind <snapshot|audit|envelope|authorization> [--file <path>|-] [options]
  oxdeai verify <snapshot|snap|audit|envelope|auth|authorization> [--file <path>] [options]
  oxdeai verify all [--state <state.json>] [--audit <audit.ndjson>] [--json]

Examples:
  oxdeai verify snap
  oxdeai verify audit
  oxdeai verify envelope
  oxdeai verify --kind snapshot --file .oxdeai/snapshot.bin --json
  oxdeai verify --kind audit --file .oxdeai/audit.ndjson --mode strict --json
  oxdeai verify --kind envelope --file .oxdeai/envelope.bin --trusted-keyset keyset.json --require-signature --json
  oxdeai verify --kind authorization --file authorization.json --expected-issuer oxdeai://issuer --expected-audience rp://tool-gateway --json`;
    case "replay":
      return "Usage: oxdeai replay [--json]\n\nReplay is a protocol-aware stub in @oxdeai/cli v0.2.x. Use verify --kind audit for deterministic offline chain checks.";
    case "inspect":
      return `Usage: oxdeai inspect <snapshot|audit|envelope|auth|authorization> [--file <path>] [--json]

Examples:
  oxdeai inspect snapshot --file .oxdeai/snapshot.bin
  oxdeai inspect audit --file .oxdeai/audit.ndjson
  oxdeai inspect envelope --file .oxdeai/envelope.bin
  oxdeai inspect auth --file authorization.json`;
    case "doctor":
      return "Usage: oxdeai doctor [--json]";
    case "paths":
      return "Usage: oxdeai paths [--json]";
    case "auth":
      return `Usage:
  oxdeai auth create <actionType> <amount> <target> --agent <id> --nonce <n> --out <authorization.json> [--asset <asset>] [--state <state.json>] [--json]
  oxdeai auth inspect [--file <authorization.json>] [--json]`;
    case "examples":
      return "Usage: oxdeai examples init [--state <state.json>] [--audit <audit.ndjson>] [--json]";
    case "init":
      return `Usage: oxdeai init --file <policy.json> [--state <state.json>] [--audit <audit.ndjson>] [--json]

Initializes local state and clears the audit log.`;
    case "launch":
      return `Usage:
  oxdeai launch <actionType> <amount> <target> --agent <id> --nonce <n> [--asset <asset>] [--state <state.json>] [--audit <audit.ndjson>] [--json]
  oxdeai launch dry-run <actionType> <amount> <target> --agent <id> --nonce <n> [--asset <asset>] [--state <state.json>] [--json]`;
    case "make-envelope":
      return "Usage: oxdeai make-envelope --out <file> [--state <state.json>] [--audit <audit.ndjson>] [--json]";
    case "verify-envelope":
      return "Usage: oxdeai verify-envelope <file> [--json]";
    case "verify-audit":
      return "Usage: oxdeai verify-audit [--audit <audit.ndjson>] [--json]";
    case "snapshot-hash":
      return "Usage: oxdeai snapshot-hash [--state <state.json>] [--json]";
    case "audit":
      return "Usage: oxdeai audit [--audit <audit.ndjson>] [--json]";
    case "state":
      return "Usage: oxdeai state [--state <state.json>] [--json]";
    default:
      return usage();
  }
}

function parseFlags(argv: string[]): { args: string[]; flags: Flags } {
  const args: string[] = [];
  const flags: Flags = {};

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") continue;
    if (!a.startsWith("--")) {
      args.push(a);
      continue;
    }

    if (a === "--json") {
      flags.json = true;
      continue;
    }
    if (a === "--help" || a === "-h") {
      flags.help = true;
      continue;
    }
    if (a === "--version" || a === "-v") {
      flags.version = true;
      continue;
    }

    const next = () => {
      const v = argv[++i];
      if (!v) throw new Error(`Missing value for ${a}`);
      return v;
    };

    if (a === "--state") {
      flags.state = next();
      continue;
    }
    if (a === "--audit") {
      flags.audit = next();
      continue;
    }
    if (a === "--file") {
      flags.file = next();
      continue;
    }
    if (a === "--out") {
      flags.out = next();
      continue;
    }
    if (a === "--agent") {
      flags.agent = next();
      continue;
    }
    if (a === "--nonce") {
      flags.nonce = next();
      continue;
    }
    if (a === "--asset") {
      flags.asset = next();
      continue;
    }
    if (a === "--kind") {
      const v = next();
      if (v !== "snapshot" && v !== "audit" && v !== "envelope" && v !== "authorization") {
        throw new Error("Invalid --kind value (must be snapshot|audit|envelope|authorization)");
      }
      flags.kind = v;
      continue;
    }
    if (a === "--mode") {
      const v = next();
      if (v !== "strict" && v !== "best-effort") {
        throw new Error("Invalid --mode value (must be strict|best-effort)");
      }
      flags.mode = v;
      continue;
    }
    if (a === "--expected-policy-id") {
      flags.expectedPolicyId = next();
      continue;
    }
    if (a === "--expected-issuer") {
      flags.expectedIssuer = next();
      continue;
    }
    if (a === "--expected-audience") {
      flags.expectedAudience = next();
      continue;
    }
    if (a === "--consumed-auth-id") {
      flags.consumedAuthId = next();
      continue;
    }
    if (a === "--trusted-keyset") {
      flags.trustedKeyset = next();
      continue;
    }
    if (a === "--require-signature") {
      flags.requireSignatureVerification = true;
      continue;
    }
    if (a === "--legacy-hmac-secret") {
      flags.legacyHmacSecret = next();
      continue;
    }

    if (a.startsWith("--state=")) {
      flags.state = a.slice(8);
      continue;
    }
    if (a.startsWith("--audit=")) {
      flags.audit = a.slice(8);
      continue;
    }
    if (a.startsWith("--file=")) {
      flags.file = a.slice(7);
      continue;
    }
    if (a.startsWith("--out=")) {
      flags.out = a.slice(6);
      continue;
    }
    if (a.startsWith("--agent=")) {
      flags.agent = a.slice(8);
      continue;
    }
    if (a.startsWith("--nonce=")) {
      flags.nonce = a.slice(8);
      continue;
    }
    if (a.startsWith("--asset=")) {
      flags.asset = a.slice(8);
      continue;
    }
    if (a.startsWith("--kind=")) {
      const v = a.slice(7);
      if (v !== "snapshot" && v !== "audit" && v !== "envelope" && v !== "authorization") {
        throw new Error("Invalid --kind value (must be snapshot|audit|envelope|authorization)");
      }
      flags.kind = v;
      continue;
    }
    if (a.startsWith("--mode=")) {
      const v = a.slice(7);
      if (v !== "strict" && v !== "best-effort") {
        throw new Error("Invalid --mode value (must be strict|best-effort)");
      }
      flags.mode = v;
      continue;
    }
    if (a.startsWith("--expected-policy-id=")) {
      flags.expectedPolicyId = a.slice("--expected-policy-id=".length);
      continue;
    }
    if (a.startsWith("--expected-issuer=")) {
      flags.expectedIssuer = a.slice("--expected-issuer=".length);
      continue;
    }
    if (a.startsWith("--expected-audience=")) {
      flags.expectedAudience = a.slice("--expected-audience=".length);
      continue;
    }
    if (a.startsWith("--consumed-auth-id=")) {
      flags.consumedAuthId = a.slice("--consumed-auth-id=".length);
      continue;
    }
    if (a.startsWith("--trusted-keyset=")) {
      flags.trustedKeyset = a.slice("--trusted-keyset=".length);
      continue;
    }
    if (a.startsWith("--legacy-hmac-secret=")) {
      flags.legacyHmacSecret = a.slice("--legacy-hmac-secret=".length);
      continue;
    }

    throw new Error(`Unknown flag: ${a}`);
  }

  return { args, flags };
}

function toJson(value: unknown): string {
  return JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? `${v.toString()}n` : v), 2);
}

function parseBigIntArg(input: string): bigint {
  const s = input.endsWith("n") ? input.slice(0, -1) : input;
  return BigInt(s);
}

async function readStdinBytes(): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Uint8Array.from(Buffer.concat(chunks));
}

function parseAuditInputBytes(bytes: Uint8Array): unknown[] {
  const text = new TextDecoder().decode(bytes).trim();
  if (text.length === 0) return [];
  if (text.startsWith("[")) {
    const parsed = JSON.parse(text);
    if (!Array.isArray(parsed)) throw new Error("audit payload must be a JSON array or NDJSON");
    return parsed;
  }
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function parseJsonObjectBytes<T>(bytes: Uint8Array, label: string): T {
  const text = new TextDecoder().decode(bytes).trim();
  if (text.length === 0) throw new Error(`${label} payload is empty`);
  const parsed = JSON.parse(text) as unknown;
  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error(`${label} payload must be a JSON object`);
  }
  return parsed as T;
}

function resolveVerifyKind(input: string | undefined): Flags["kind"] | undefined {
  if (!input) return undefined;
  return VERIFY_KIND_ALIAS[input as keyof typeof VERIFY_KIND_ALIAS];
}

function defaultVerifyFile(kind: Flags["kind"]): string | undefined {
  switch (kind) {
    case "snapshot":
      return DEFAULT_SNAPSHOT_PATH;
    case "audit":
      return DEFAULT_AUDIT_PATH;
    case "envelope":
      return DEFAULT_ENVELOPE_PATH;
    default:
      return undefined;
  }
}

function isBuildTarget(input: string | undefined): boolean {
  return input === undefined || input === "snapshot" || input === "snap";
}

function sampleState(): State {
  return {
    policy_version: "v1",
    period_id: "2026-03",
    kill_switch: { global: false, agents: {} },
    allowlists: {
      action_types: ["PROVISION"],
      assets: ["a100"],
      targets: ["us-east-1"]
    },
    budget: {
      budget_limit: { "agent-1": 1_000_000n },
      spent_in_period: { "agent-1": 0n }
    },
    max_amount_per_action: { "agent-1": 1_000_000n },
    velocity: { config: { window_seconds: 60, max_actions: 10 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    concurrency: { max_concurrent: { "agent-1": 4 }, active: {}, active_auths: {} },
    recursion: { max_depth: { "agent-1": 5 } },
    tool_limits: { window_seconds: 60, max_calls: { "agent-1": 100 }, max_calls_by_tool: {}, calls: {} }
  };
}

function basePaths(flags: Flags) {
  const state = flags.state ?? DEFAULT_STATE_PATH;
  const audit = flags.audit ?? DEFAULT_AUDIT_PATH;
  const baseDir = dirname(state);
  return {
    state,
    audit,
    snapshot: flags.state ? join(baseDir, "snapshot.bin") : DEFAULT_SNAPSHOT_PATH,
    envelope: flags.state ? join(baseDir, "envelope.bin") : DEFAULT_ENVELOPE_PATH
  };
}

type VerificationMap = Record<"snapshot" | "audit" | "envelope", VerificationResult>;

function aggregateVerificationExit(results: VerificationMap): number {
  const ordered = [results.snapshot, results.audit, results.envelope];
  if (ordered.some((r) => r.status === "invalid")) return EXIT_CODE_INVALID;
  if (ordered.some((r) => r.status === "inconclusive")) return EXIT_CODE_INCONCLUSIVE;
  return EXIT_CODE_OK;
}

function inspectSummary(kind: string, payload: Record<string, unknown>): string {
  const lines = [`${kind}:`];
  for (const [k, v] of Object.entries(payload)) {
    lines.push(`${k}: ${typeof v === "object" ? toJson(v) : String(v)}`);
  }
  return lines.join("\n");
}

function verificationExitCode(result: VerificationResult): number {
  if (result.status === "ok") return EXIT_CODE_OK;
  if (result.status === "inconclusive") return EXIT_CODE_INCONCLUSIVE;
  return EXIT_CODE_INVALID;
}

function writePayload(out: (line: string) => void, flags: Flags, payload: unknown, humanSummary?: string): void {
  if (flags.json) {
    out(toJson(payload));
    return;
  }
  if (humanSummary) {
    out(humanSummary);
    return;
  }
  out(toJson(payload));
}

function verificationSummary(kind: Flags["kind"], result: VerificationResult): string {
  const label = kind ?? "artifact";
  const lines = [`${label}: ${result.status.toUpperCase()}`];
  if (result.policyId) lines.push(`policyId: ${result.policyId}`);
  if (result.stateHash) lines.push(`stateHash: ${result.stateHash}`);
  if (result.auditHeadHash) lines.push(`auditHeadHash: ${result.auditHeadHash}`);
  if (result.violations.length === 0) {
    lines.push("violations: none");
  } else {
    lines.push(`violations: ${result.violations.map((v) => v.code).join(", ")}`);
  }
  return lines.join("\n");
}

async function readTrustedKeySet(path: string | undefined): Promise<KeySet[] | undefined> {
  if (!path) return undefined;
  const text = await readFile(path, "utf8");
  const parsed = JSON.parse(text) as unknown;
  if (Array.isArray(parsed)) return parsed as KeySet[];
  if (parsed && typeof parsed === "object") return [parsed as KeySet];
  throw new Error("trusted keyset payload must be a JSON object or array");
}

function buildValidationIntent(state: State): Intent {
  const agent = Object.keys(state.budget.budget_limit)[0] ?? "agent";
  const action_type = state.allowlists.action_types?.[0] ?? "PAYMENT";
  const target = state.allowlists.targets?.[0] ?? "target:probe";
  return {
    intent_id: "validate-intent",
    type: "EXECUTE",
    agent_id: agent,
    action_type,
    amount: 0n,
    asset: state.allowlists.assets?.[0],
    target,
    timestamp: 0,
    metadata_hash: "0x" + "0".repeat(64),
    nonce: 0n,
    signature: "validate-signature"
  };
}

function validateStateStructure(state: State): void {
  const engine = new PolicyEngine({
    policy_version: state.policy_version,
    engine_secret: "validate-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 1,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });
  const probe = buildValidationIntent(state);
  const out = engine.evaluatePure(probe, structuredClone(state), probe.timestamp, { mode: "fail-fast" });
  if (out.decision === "DENY" && out.reasons.includes("STATE_INVALID")) {
    throw new Error("STATE_INVALID");
  }
}

function buildEngine(state: State): PolicyEngine {
  const secret = process.env["OXDEAI_ENGINE_SECRET"] ?? "";
  if (!secret) throw new Error("Missing required env var: OXDEAI_ENGINE_SECRET");
  const ttl = Number(process.env["OXDEAI_AUTH_TTL_SECONDS"] ?? "120");
  return new PolicyEngine({
    policy_version: state.policy_version,
    engine_secret: secret,
    authorization_ttl_seconds: Number.isFinite(ttl) ? ttl : 120,
    // #184: no CLI flags for trusted-time tolerances yet (deferred); the CLI
    // explicitly uses the recommended profile rather than any implicit default.
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });
}

export async function runCli(argv: string[], io?: Partial<Io>): Promise<number> {
  const out = io?.out ?? ((line: string) => console.log(line));
  const err = io?.err ?? ((line: string) => console.error(line));
  const now = io?.now ?? (() => Math.floor(Date.now() / 1000));

  let parsed: { args: string[]; flags: Flags };
  try {
    parsed = parseFlags(argv);
  } catch (e) {
    err((e as Error).message);
    err(usage());
    return EXIT_CODE_USAGE;
  }

  const { args, flags } = parsed;
  const cmd = args[0];
  const requestedHelp = flags.help || cmd === "help";

  if (flags.version && !cmd) {
    out(CLI_VERSION);
    return EXIT_CODE_OK;
  }

  if (!cmd) {
    if (requestedHelp) {
      out(usage());
      return EXIT_CODE_OK;
    }
    out(usage());
    return EXIT_CODE_OK;
  }

  if (cmd === "help") {
    out(commandUsage(args[1] ?? ""));
    return EXIT_CODE_OK;
  }

  if (flags.version) {
    out(CLI_VERSION);
    return EXIT_CODE_OK;
  }

  if (requestedHelp) {
    out(commandUsage(cmd));
    return EXIT_CODE_OK;
  }

  const statePath = flags.state ?? DEFAULT_STATE_PATH;
  const auditPath = flags.audit ?? DEFAULT_AUDIT_PATH;

  try {
    if (cmd === "paths") {
      writePayload(out, flags, basePaths(flags));
      return EXIT_CODE_OK;
    }

    if (cmd === "doctor") {
      const paths = basePaths(flags);
      const checks = await Promise.all(
        Object.entries(paths).map(async ([label, file]) => {
          try {
            await readFile(file);
            return { kind: label, path: file, exists: true };
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code === "ENOENT") {
              return { kind: label, path: file, exists: false };
            }
            throw error;
          }
        })
      );
      const payload = {
        ok: true,
        node: process.version,
        cwd: process.cwd(),
        linkedBin: process.argv[1] ?? null,
        defaults: paths,
        checks
      };
      writePayload(out, flags, payload);
      return EXIT_CODE_OK;
    }

    if (cmd === "examples") {
      if (args[1] !== "init") throw new Error(`Unknown examples command: ${args[1] ?? ""}`);
      const state = sampleState();
      await writeStateFile(statePath, state);
      await resetAuditFile(auditPath);
      writePayload(out, flags, { ok: true, state: statePath, audit: auditPath }, `OK\nstate: ${statePath}\naudit: ${auditPath}`);
      return EXIT_CODE_OK;
    }

    if (cmd === "inspect") {
      const rawKind = resolveVerifyKind(args[1]) ?? (args[1] === "envelope" || args[1] === "audit" ? (args[1] as Flags["kind"]) : undefined);
      const kind = rawKind;
      if (!kind) throw new Error("Usage: inspect <snapshot|audit|envelope|auth|authorization> [--file <path>]");
      const file = flags.file ?? defaultVerifyFile(kind);
      if (!file) throw new Error(`${kind} inspection requires --file <path>`);
      const bytes = Uint8Array.from(await readFile(file));

      if (kind === "snapshot") {
        const snapshot = decodeCanonicalState(bytes);
        const payload = {
          formatVersion: snapshot.formatVersion,
          engineVersion: snapshot.engineVersion,
          policyId: snapshot.policyId,
          moduleKeys: Object.keys(snapshot.modules).sort(),
          moduleCount: Object.keys(snapshot.modules).length
        };
        writePayload(out, flags, payload, inspectSummary("snapshot", payload));
        return EXIT_CODE_OK;
      }

      if (kind === "envelope") {
        const envelope = decodeEnvelope(bytes);
        const snapshot = decodeCanonicalState(envelope.snapshot);
        const payload = {
          formatVersion: envelope.formatVersion,
          eventCount: envelope.events.length,
          eventTypes: Array.from(new Set(envelope.events.map((e) => (e as any).type ?? "unknown"))).sort(),
          policyId: snapshot.policyId,
          issuer: envelope.issuer ?? null,
          alg: envelope.alg ?? null,
          kid: envelope.kid ?? null,
          signed: Boolean(envelope.signature)
        };
        writePayload(out, flags, payload, inspectSummary("envelope", payload));
        return EXIT_CODE_OK;
      }

      if (kind === "authorization") {
        const auth = parseJsonObjectBytes<AuthorizationV1>(bytes, "authorization");
        const payload = {
          authorizationId: (auth as any).authorization_id ?? auth.auth_id,
          issuer: auth.issuer,
          audience: auth.audience,
          policyId: auth.policy_id,
          stateHash: auth.state_hash,
          decision: auth.decision,
          alg: auth.alg,
          kid: auth.kid,
          expiresAt: (auth as any).expires_at ?? auth.expiry
        };
        writePayload(out, flags, payload, inspectSummary("authorization", payload));
        return EXIT_CODE_OK;
      }

      const events = parseAuditInputBytes(bytes);
      const payload = {
        eventCount: events.length,
        eventTypes: Array.from(new Set(events.map((e: any) => e?.type ?? "unknown"))).sort(),
        firstTimestamp: (events[0] as any)?.timestamp ?? null,
        lastTimestamp: (events[events.length - 1] as any)?.timestamp ?? null
      };
      writePayload(out, flags, payload, inspectSummary("audit", payload));
      return EXIT_CODE_OK;
    }

    if (cmd === "build") {
      const target = args[1];
      if (!isBuildTarget(target)) {
        throw new Error(`Unknown build target: ${target}`);
      }
      const state = await readStateFile(statePath);
      const engine = buildEngine(state);
      const snapshot = engine.exportState(state);
      const snapshotBytes = encodeCanonicalState(snapshot);
      const verified = verifySnapshot(snapshotBytes, flags.expectedPolicyId ? { expectedPolicyId: flags.expectedPolicyId } : undefined);

      if (flags.out) {
        await mkdir(dirname(flags.out), { recursive: true });
        await writeFile(flags.out, Buffer.from(snapshotBytes));
      }

      const payload = {
        ok: verified.ok,
        status: verified.status,
        policyId: snapshot.policyId,
        stateHash: verified.stateHash,
        violations: verified.violations,
        snapshotBytes: snapshotBytes.length,
        out: flags.out
      };
      writePayload(out, flags, payload, `build: ${verified.status.toUpperCase()}\npolicyId: ${snapshot.policyId}\nstateHash: ${verified.stateHash ?? "unknown"}${flags.out ? `\nout: ${flags.out}` : ""}`);
      return verificationExitCode(verified);
    }

    if (cmd === "verify") {
      if (args[1] === "all") {
        const mode = flags.mode ?? "strict";
        if (mode === "strict" && !flags.trustedKeyset) {
          err("Strict verification requires --trusted-keyset. Pass one or more trusted keysets, or explicitly use --mode best-effort.");
          return EXIT_CODE_INVALID;
        }
        const paths = basePaths(flags);
        const trustedKeySets = await readTrustedKeySet(flags.trustedKeyset);
        const snapshotBytes = Uint8Array.from(await readFile(paths.snapshot));
        const auditBytes = Uint8Array.from(await readFile(paths.audit));
        const envelopeBytes = Uint8Array.from(await readFile(paths.envelope));
        const snapshot = verifySnapshot(snapshotBytes, flags.expectedPolicyId ? { expectedPolicyId: flags.expectedPolicyId } : undefined);
        const audit = verifyAuditEvents(parseAuditInputBytes(auditBytes) as Parameters<typeof verifyAuditEvents>[0], {
          mode,
          expectedPolicyId: flags.expectedPolicyId
        });
        const envelope = verifyEnvelope(envelopeBytes, {
          mode,
          expectedPolicyId: flags.expectedPolicyId,
          expectedIssuer: flags.expectedIssuer,
          trustedKeySets,
          requireSignatureVerification: flags.requireSignatureVerification
        });
        const payload = { snapshot, audit, envelope, paths };
        writePayload(out, flags, payload);
        return aggregateVerificationExit({ snapshot, audit, envelope });
      }
      const positionalKind = resolveVerifyKind(args[1]);
      const kind = flags.kind ?? positionalKind;
      if (!kind) throw new Error("Usage: verify --kind <snapshot|audit|envelope|authorization> [--file <path>|-]");

      const file = flags.file ?? defaultVerifyFile(kind);
      if (kind === "authorization" && !file) {
        throw new Error("authorization verification requires --file <authorization.json>");
      }
      const mode = flags.mode ?? "strict";
      if (mode === "strict" && !flags.trustedKeyset && (kind === "envelope" || kind === "authorization")) {
        err("Strict verification requires --trusted-keyset. Pass one or more trusted keysets, or explicitly use --mode best-effort.");
        return EXIT_CODE_INVALID;
      }
      const fromFile = file && file !== "-";
      const bytes = fromFile
        ? Uint8Array.from(await readFile(file))
        : await readStdinBytes();

      if (kind === "snapshot") {
        const res = verifySnapshot(bytes, flags.expectedPolicyId ? { expectedPolicyId: flags.expectedPolicyId } : undefined);
        writePayload(out, flags, res, verificationSummary(kind, res));
        return verificationExitCode(res);
      }

      if (kind === "envelope") {
        const trustedKeySets = await readTrustedKeySet(flags.trustedKeyset);
        const res = verifyEnvelope(bytes, {
          mode,
          expectedPolicyId: flags.expectedPolicyId,
          expectedIssuer: flags.expectedIssuer,
          trustedKeySets,
          requireSignatureVerification: flags.requireSignatureVerification
        });
        writePayload(out, flags, res, verificationSummary(kind, res));
        return verificationExitCode(res);
      }

      if (kind === "authorization") {
        const trustedKeySets = await readTrustedKeySet(flags.trustedKeyset);
        const auth = parseJsonObjectBytes<AuthorizationV1>(bytes, "authorization");
        const res = verifyAuthorization(auth, {
          now: now(),
          expectedIssuer: flags.expectedIssuer,
          expectedAudience: flags.expectedAudience,
          expectedPolicyId: flags.expectedPolicyId,
          consumedAuthIds: flags.consumedAuthId ? [flags.consumedAuthId] : [],
          trustedKeySets,
          // SECURITY (CLI-1): forward the posture. Strict must also make a
          // successful cryptographic check mandatory; without this an
          // HMAC-SHA256 artifact with no legacy secret verified as `ok` with
          // `signatureVerified: false`, so forged authorizations passed.
          mode,
          requireSignatureVerification: mode === "strict" || flags.requireSignatureVerification,
          legacyHmacSecret: flags.legacyHmacSecret
        });
        writePayload(out, flags, res, verificationSummary(kind, res));
        return verificationExitCode(res);
      }

      const events = parseAuditInputBytes(bytes);
      const res = verifyAuditEvents(events as Parameters<typeof verifyAuditEvents>[0], {
        mode,
        expectedPolicyId: flags.expectedPolicyId
      });
      writePayload(out, flags, res, verificationSummary(kind, res));
      return verificationExitCode(res);
    }

    if (cmd === "replay") {
      const payload = {
        ok: false,
        status: "unsupported",
        message: "Replay verifier is a protocol-aware stub in @oxdeai/cli v0.2.x. Use verify --kind audit for deterministic offline chain checks."
      };
      writePayload(out, flags, payload, `${payload.status.toUpperCase()}: ${payload.message}`);
      return EXIT_CODE_OK;
    }

    if (cmd === "auth") {
      const sub = args[1];
      if (sub === "inspect") {
        const file = flags.file;
        if (!file) throw new Error("auth inspect requires --file <authorization.json>");
        const bytes = Uint8Array.from(await readFile(file));
        const auth = parseJsonObjectBytes<AuthorizationV1>(bytes, "authorization");
        const payload = {
          authorizationId: (auth as any).authorization_id ?? auth.auth_id,
          issuer: auth.issuer,
          audience: auth.audience,
          policyId: auth.policy_id,
          stateHash: auth.state_hash,
          decision: auth.decision,
          alg: auth.alg,
          kid: auth.kid,
          expiresAt: (auth as any).expires_at ?? auth.expiry
        };
        writePayload(out, flags, payload, inspectSummary("authorization", payload));
        return EXIT_CODE_OK;
      }
      if (sub !== "create") throw new Error(`Unknown auth command: ${sub ?? ""}`);
      const action = args[2] as ActionType | undefined;
      const amountRaw = args[3];
      const target = args[4];
      if (!action || !amountRaw || !target) throw new Error("Usage: auth create <actionType> <amount> <target> --agent <id> --nonce <n> --out <authorization.json>");
      if (!ACTION_TYPES.has(action)) throw new Error(`Invalid actionType: ${action}`);
      if (!flags.agent) throw new Error("Missing --agent <id>");
      if (!flags.nonce) throw new Error("Missing --nonce <n>");
      if (!flags.out) throw new Error("Missing --out <authorization.json>");
      const state = await readStateFile(statePath);
      const engine = buildEngine(state);
      const evaluationTime = now();
      const intent: Intent = {
        intent_id: `intent:${flags.agent}:${flags.nonce}`,
        type: "EXECUTE",
        agent_id: flags.agent,
        action_type: action,
        amount: parseBigIntArg(amountRaw),
        asset: flags.asset,
        target,
        timestamp: evaluationTime,
        metadata_hash: "0x" + "0".repeat(64),
        nonce: parseBigIntArg(flags.nonce),
        signature: "cli-signature-placeholder"
      };
      const outEval = engine.evaluatePure(intent, state, evaluationTime, { mode: "fail-fast" });
      if (outEval.decision !== "ALLOW") {
        const payload = { decision: "DENY" as const, reasons: outEval.reasons };
        writePayload(out, flags, payload, `DENY: ${toJson(payload.reasons)}`);
        return EXIT_CODE_OK;
      }
      await mkdir(dirname(flags.out), { recursive: true });
      await writeFile(flags.out, `${toJson(outEval.authorization)}\n`, "utf8");
      const payload = { ok: true, out: flags.out, authorization_id: outEval.authorization.auth_id };
      writePayload(out, flags, payload, `ALLOW: ${outEval.authorization.auth_id}\nout: ${flags.out}`);
      return EXIT_CODE_OK;
    }

    if (cmd === "init") {
      if (!flags.file) throw new Error("Missing --file <policy.json>");
      const text = await readFile(flags.file, "utf8");
      const state = normalizeStateBigInts(JSON.parse(text));
      validateStateStructure(state);
      await writeStateFile(statePath, state);
      await resetAuditFile(auditPath);
      writePayload(out, flags, { ok: true }, "OK");
      return EXIT_CODE_OK;
    }

    if (cmd === "state") {
      const state = await readStateFile(statePath);
      writePayload(out, flags, state);
      return EXIT_CODE_OK;
    }

    if (cmd === "audit") {
      const events = await readAuditEvents(auditPath);
      const verified = verifyAuditEvents(events as Parameters<typeof verifyAuditEvents>[0], { mode: "best-effort" });
      const payload = {
        headHash: verified.auditHeadHash && verified.auditHeadHash.length > 0 ? verified.auditHeadHash : "GENESIS",
        verify: verified.ok,
        events
      };
      writePayload(out, flags, payload);
      return EXIT_CODE_OK;
    }

    if (cmd === "verify-audit") {
      const events = await readAuditEvents(auditPath);
      const verified = verifyAuditEvents(events as Parameters<typeof verifyAuditEvents>[0], { mode: "strict" });
      writePayload(out, flags, verified, verificationSummary("audit", verified));
      return verificationExitCode(verified);
    }

    if (cmd === "verify-envelope") {
      const file = args[1] ?? flags.file;
      if (!file) throw new Error("Usage: verify-envelope <file>");
      const mode = flags.mode ?? "strict";
      if (mode === "strict" && !flags.trustedKeyset) {
        err("Strict verification requires --trusted-keyset. Pass one or more trusted keysets, or explicitly use --mode best-effort.");
        return EXIT_CODE_INVALID;
      }
      const trustedKeySets = await readTrustedKeySet(flags.trustedKeyset);
      const bytes = Uint8Array.from(await readFile(file));
      const verified = verifyEnvelope(bytes, { mode, trustedKeySets });
      writePayload(out, flags, verified, verificationSummary("envelope", verified));
      return verificationExitCode(verified);
    }

    if (cmd === "make-envelope") {
      if (!flags.out) throw new Error("Usage: make-envelope --out <file>");
      const state = await readStateFile(statePath);
      const events = await readAuditEvents(auditPath);
      const engine = buildEngine(state);
      const snapshotBytes = encodeCanonicalState(engine.exportState(state));
      const envelope = encodeEnvelope({
        formatVersion: 1,
        snapshot: snapshotBytes,
        events: events as Parameters<typeof encodeEnvelope>[0]["events"]
      });

      await mkdir(dirname(flags.out), { recursive: true });
      await writeFile(flags.out, Buffer.from(envelope));
      const payload = { ok: true, file: flags.out };
      writePayload(out, flags, payload, `OK: ${flags.out}`);
      return EXIT_CODE_OK;
    }

    if (cmd === "snapshot-hash") {
      const state = await readStateFile(statePath);
      const engine = buildEngine(state);
      const snapshot = engine.exportState(state);
      const bytes = encodeCanonicalState(snapshot);
      const verified = verifySnapshot(bytes);
      const payload = {
        policyId: snapshot.policyId,
        stateHash: verified.stateHash,
        status: verified.status,
        violations: verified.violations
      };
      writePayload(out, flags, payload, `snapshot: ${verified.status.toUpperCase()}\npolicyId: ${snapshot.policyId}\nstateHash: ${verified.stateHash ?? "unknown"}`);
      return verificationExitCode(verified);
    }

    if (cmd === "launch") {
      const dryRun = args[1] === "dry-run";
      const offset = dryRun ? 2 : 1;
      const action = args[offset] as ActionType | undefined;
      const amountRaw = args[offset + 1];
      const target = args[offset + 2];
      if (!action || !amountRaw || !target) throw new Error("Usage: launch <actionType> <amount> <target> --agent <id> --nonce <n>");
      if (!ACTION_TYPES.has(action)) throw new Error(`Invalid actionType: ${action}`);
      if (!flags.agent) throw new Error("Missing --agent <id>");
      if (!flags.nonce) throw new Error("Missing --nonce <n>");

      const state = await readStateFile(statePath);
      const engine = buildEngine(state);
      const ts = now();

      const intent: Intent = {
        intent_id: `intent:${flags.agent}:${flags.nonce}`,
        type: "EXECUTE",
        agent_id: flags.agent,
        action_type: action,
        amount: parseBigIntArg(amountRaw),
        asset: flags.asset,
        target,
        timestamp: ts,
        metadata_hash: "0x" + "0".repeat(64),
        nonce: parseBigIntArg(flags.nonce),
        signature: "cli-signature-placeholder"
      };

      const outEval = engine.evaluatePure(intent, state, ts, { mode: "fail-fast" });
      const emitted = engine.audit.snapshot();

      if (outEval.decision === "ALLOW") {
        if (!dryRun) {
          await appendAuditEvents(auditPath, emitted);
          await writeStateFile(statePath, outEval.nextState);
        }
        const payload = { decision: "ALLOW" as const, authorization_id: outEval.authorization.auth_id, reasons: [] as string[], dryRun };
        writePayload(out, flags, payload, `ALLOW: ${payload.authorization_id}`);
        return EXIT_CODE_OK;
      }

      if (!dryRun) {
        await appendAuditEvents(auditPath, emitted);
      }
      const payload = { decision: "DENY" as const, reasons: outEval.reasons, dryRun };
      writePayload(out, flags, payload, `DENY: ${toJson(payload.reasons)}`);
      return EXIT_CODE_OK;
    }

    err(`Unknown command: ${cmd}`);
    err(usage());
    return EXIT_CODE_USAGE;
  } catch (e) {
    err((e as Error).message);
    if (cmd) err(commandUsage(cmd));
    return EXIT_CODE_INVALID;
  }
}

async function main(): Promise<void> {
  const code = await runCli(process.argv.slice(2));
  process.exit(code);
}

function isDirectExecution(): boolean {
  const argv1 = process.argv[1];
  if (!argv1) return false;

  try {
    return realpathSync(argv1) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return import.meta.url === pathToFileURL(argv1).href;
  }
}

if (isDirectExecution()) {
  void main();
}
