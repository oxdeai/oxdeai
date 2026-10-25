// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { generateKeyPairSync } from "node:crypto";

import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE, encodeCanonicalState, encodeEnvelope, signAuthorizationEd25519 } from "@oxdeai/core";
import type { State } from "@oxdeai/core";



// (Dynamic import instead) CLI tests invoke buildEngine() in-process; satisfy the mandatory secret requirement.
process.env["OXDEAI_ENGINE_SECRET"] = "test-secret-must-be-at-least-32-chars!!";

const { runCli } = await import("./main.js");

function baseState(): State {
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

function jsonWithBigInt(v: unknown): string {
  return JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? `${x.toString()}n` : x), 2);
}

async function setup() {
  const dir = await mkdtemp(join(tmpdir(), "oxdeai-cli-test-"));
  const policyFile = join(dir, "policy.json");
  const stateFile = join(dir, "state.json");
  const auditFile = join(dir, "audit.ndjson");
  await writeFile(policyFile, jsonWithBigInt(baseState()), "utf8");
  return { dir, policyFile, stateFile, auditFile };
}

function ioCapture(now = 1_770_000_000) {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    io: {
      out: (line: string) => out.push(line),
      err: (line: string) => err.push(line),
      now: () => now
    }
  };
}

test("init writes state and clears audit", async () => {
  const { policyFile, stateFile, auditFile } = await setup();
  await writeFile(auditFile, "{\"junk\":1}\n", "utf8");

  const cap = ioCapture();
  const code = await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile, "--json"], cap.io);
  assert.equal(code, 0);

  const stateText = await readFile(stateFile, "utf8");
  assert.ok(stateText.length > 0);
  const auditText = await readFile(auditFile, "utf8");
  assert.equal(auditText, "");
  assert.equal(cap.err.length, 0);
});

test("help and version behave like a normal CLI", async () => {
  const cap = ioCapture();

  assert.equal(await runCli(["--help"], cap.io), 0);
  assert.match(cap.out[0] ?? "", /oxdeai CLI/);

  cap.out.length = 0;
  assert.equal(await runCli(["help", "verify"], cap.io), 0);
  assert.match(cap.out[0] ?? "", /oxdeai verify --kind/);

  cap.out.length = 0;
  assert.equal(await runCli(["verify", "--help"], cap.io), 0);
  assert.match(cap.out[0] ?? "", /oxdeai verify --kind/);

  cap.out.length = 0;
  assert.equal(await runCli(["--version"], cap.io), 0);
  assert.match(cap.out[0] ?? "", /^\d+\.\d+\.\d+$/);
});

test("unknown top-level flag returns usage error", async () => {
  const cap = ioCapture();
  const code = await runCli(["--wat"], cap.io);
  assert.equal(code, 2);
  assert.match(cap.err[0] ?? "", /Unknown flag/);
  assert.match(cap.err[1] ?? "", /oxdeai CLI/);
});

test("launch allow path mutates state and appends audit", async () => {
  const { policyFile, stateFile, auditFile } = await setup();
  const cap = ioCapture();
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);

  const code = await runCli(
    ["launch", "PROVISION", "320", "us-east-1", "--agent", "agent-1", "--nonce", "42", "--state", stateFile, "--audit", auditFile, "--json"],
    cap.io
  );
  assert.equal(code, 0);

  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(latest.decision, "ALLOW");
  assert.equal(typeof latest.authorization_id, "string");

  const stateText = await readFile(stateFile, "utf8");
  assert.ok(stateText.includes("\"spent_in_period\":{\"agent-1\":\"320n\"}"));
  const auditText = await readFile(auditFile, "utf8");
  assert.ok(auditText.trim().split("\n").length >= 3);
});

test("launch deny path keeps state unchanged", async () => {
  const { policyFile, stateFile, auditFile } = await setup();
  const denyState = baseState();
  denyState.kill_switch.global = true;
  await writeFile(policyFile, jsonWithBigInt(denyState), "utf8");

  const cap = ioCapture();
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  const before = await readFile(stateFile, "utf8");

  const code = await runCli(
    ["launch", "PROVISION", "320", "us-east-1", "--agent", "agent-1", "--nonce", "77", "--state", stateFile, "--audit", auditFile, "--json"],
    cap.io
  );
  assert.equal(code, 0);

  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(latest.decision, "DENY");
  const after = await readFile(stateFile, "utf8");
  assert.equal(after, before);
});

test("audit command reports verify=true on valid chain", async () => {
  const { policyFile, stateFile, auditFile } = await setup();
  const cap = ioCapture();
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  await runCli(["launch", "PROVISION", "100", "us-east-1", "--agent", "agent-1", "--nonce", "9", "--state", stateFile, "--audit", auditFile], cap.io);

  const code = await runCli(["audit", "--audit", auditFile, "--json"], cap.io);
  assert.equal(code, 0);
  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(latest.verify, true);
  assert.equal(Array.isArray(latest.events), true);
});

test("state command prints valid json state", async () => {
  const { policyFile, stateFile, auditFile } = await setup();
  const cap = ioCapture();
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);

  const code = await runCli(["state", "--state", stateFile, "--json"], cap.io);
  assert.equal(code, 0);
  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(latest.policy_version, "v1");
  assert.ok(latest.velocity?.config);
});

test("verify-audit returns strict result for current audit file", async () => {
  const { policyFile, stateFile, auditFile } = await setup();
  const cap = ioCapture();
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  await runCli(["launch", "PROVISION", "100", "us-east-1", "--agent", "agent-1", "--nonce", "11", "--state", stateFile, "--audit", auditFile], cap.io);

  const code = await runCli(["verify-audit", "--audit", auditFile, "--json"], cap.io);
  assert.equal(code, 3);
  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(typeof latest.status, "string");
  assert.equal(latest.status, "inconclusive");
  assert.equal(Array.isArray(latest.violations), true);
});

test("snapshot-hash returns policyId and stateHash", async () => {
  const { policyFile, stateFile, auditFile } = await setup();
  const cap = ioCapture();
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);

  const code = await runCli(["snapshot-hash", "--state", stateFile, "--json"], cap.io);
  assert.equal(code, 0);
  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(typeof latest.policyId, "string");
  assert.equal(typeof latest.stateHash, "string");
  assert.equal(latest.status, "ok");
});

test("verify-envelope reads file and verifies", async () => {
  const { policyFile, stateFile, auditFile, dir } = await setup();
  const cap = ioCapture(1_770_000_123);
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  await runCli(["launch", "PROVISION", "100", "us-east-1", "--agent", "agent-1", "--nonce", "12", "--state", stateFile, "--audit", auditFile], cap.io);

  const state = JSON.parse(await readFile(stateFile, "utf8"), (_k, v) => {
    if (typeof v === "string" && /^-?\d+n$/.test(v)) return BigInt(v.slice(0, -1));
    return v;
  }) as State;
  const events = (await readFile(auditFile, "utf8"))
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line));

  const engine = new PolicyEngine({
    policy_version: state.policy_version,
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 120,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });
  const snapshotBytes = encodeCanonicalState(engine.exportState(state));
  const envelope = encodeEnvelope({ formatVersion: 1, snapshot: snapshotBytes, events });
  const envelopePath = join(dir, "envelope.bin");
  await writeFile(envelopePath, Buffer.from(envelope));

  const code = await runCli(["verify-envelope", envelopePath, "--mode", "best-effort", "--json"], cap.io);
  assert.equal(code, 0);
  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(typeof latest.status, "string");
  assert.equal(latest.status, "ok");
  assert.equal(Array.isArray(latest.violations), true);
});

test("make-envelope writes envelope file that verify-envelope accepts", async () => {
  const { policyFile, stateFile, auditFile, dir } = await setup();
  const cap = ioCapture(1_770_000_222);
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  await runCli(["launch", "PROVISION", "100", "us-east-1", "--agent", "agent-1", "--nonce", "13", "--state", stateFile, "--audit", auditFile], cap.io);

  const envelopePath = join(dir, "made-envelope.bin");
  const makeCode = await runCli(
    ["make-envelope", "--out", envelopePath, "--state", stateFile, "--audit", auditFile, "--json"],
    cap.io
  );
  assert.equal(makeCode, 0);

  const verifyCode = await runCli(["verify-envelope", envelopePath, "--mode", "best-effort", "--json"], cap.io);
  assert.equal(verifyCode, 0);
  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(typeof latest.status, "string");
  assert.equal(latest.status, "ok");
  assert.equal(Array.isArray(latest.violations), true);
});

test("build emits snapshot verification payload and optional file", async () => {
  const { policyFile, stateFile, auditFile, dir } = await setup();
  const cap = ioCapture();
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);

  const snapshotOut = join(dir, "snapshot.bin");
  const code = await runCli(["build", "--state", stateFile, "--out", snapshotOut, "--json"], cap.io);
  assert.equal(code, 0);
  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(latest.status, "ok");
  assert.equal(typeof latest.policyId, "string");
  assert.equal(typeof latest.stateHash, "string");
  const bytes = await readFile(snapshotOut);
  assert.ok(bytes.length > 0);
});

test("build supports positional snapshot target", async () => {
  const { policyFile, stateFile, auditFile, dir } = await setup();
  const cap = ioCapture();
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);

  const snapshotOut = join(dir, "snapshot-positional.bin");
  const code = await runCli(["build", "snapshot", "--state", stateFile, "--out", snapshotOut, "--json"], cap.io);
  assert.equal(code, 0);
  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(latest.status, "ok");
  const bytes = await readFile(snapshotOut);
  assert.ok(bytes.length > 0);
});

test("verify supports --kind audit from file and replay command is clear stub", async () => {
  const { policyFile, stateFile, auditFile } = await setup();
  const cap = ioCapture();
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  await runCli(["launch", "PROVISION", "100", "us-east-1", "--agent", "agent-1", "--nonce", "20", "--state", stateFile, "--audit", auditFile], cap.io);

  const verifyCode = await runCli(["verify", "--kind", "audit", "--file", auditFile, "--mode", "strict", "--json"], cap.io);
  assert.equal(verifyCode, 3); // strict mode without checkpoint => inconclusive
  const verifyLatest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(verifyLatest.status, "inconclusive");

  const replayCode = await runCli(["replay", "--json"], cap.io);
  assert.equal(replayCode, 0);
  const replayLatest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(replayLatest.status, "unsupported");
});

test("verify supports positional aliases and default files", async () => {
  const { policyFile, stateFile, auditFile, dir } = await setup();
  const cap = ioCapture(1_770_000_333);
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  await runCli(["launch", "PROVISION", "100", "us-east-1", "--agent", "agent-1", "--nonce", "21", "--state", stateFile, "--audit", auditFile], cap.io);

  const snapshotPath = join(dir, "snapshot.bin");
  await runCli(["build", "--state", stateFile, "--out", snapshotPath, "--json"], cap.io);
  const envelopePath = join(dir, "envelope.bin");
  await runCli(["make-envelope", "--out", envelopePath, "--state", stateFile, "--audit", auditFile, "--json"], cap.io);

  const snapshotCode = await runCli(["verify", "snap", "--file", snapshotPath, "--json"], cap.io);
  assert.equal(snapshotCode, 0);
  const snapshotLatest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(snapshotLatest.status, "ok");

  const auditCode = await runCli(["verify", "audit", "--file", auditFile, "--mode", "strict", "--json"], cap.io);
  assert.equal(auditCode, 3);
  const auditLatest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(auditLatest.status, "inconclusive");

  const envCode = await runCli(["verify", "envelope", "--file", envelopePath, "--mode", "best-effort", "--json"], cap.io);
  assert.equal(envCode, 0);
  const envLatest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(envLatest.status, "ok");
});

test("verify supports --kind authorization from file", async () => {
  const { policyFile, stateFile, auditFile, dir } = await setup();
  const cap = ioCapture(1_770_000_500);
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  await runCli(["launch", "PROVISION", "100", "us-east-1", "--agent", "agent-1", "--nonce", "21", "--state", stateFile, "--audit", auditFile], cap.io);

  const state = JSON.parse(await readFile(stateFile, "utf8"), (_k, v) => {
    if (typeof v === "string" && /^-?\d+n$/.test(v)) return BigInt(v.slice(0, -1));
    return v;
  }) as State;

  const engine = new PolicyEngine({
    policy_version: state.policy_version,
    engine_secret: "test-secret-must-be-at-least-32-chars!!",
    authorization_ttl_seconds: 120,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE
  });
  const intent = {
    intent_id: "intent:agent-1:22",
    type: "EXECUTE" as const,
    agent_id: "agent-1",
    action_type: "PROVISION" as const,
    amount: 100n,
    asset: "a100",
    target: "us-east-1",
    timestamp: cap.io.now(),
    metadata_hash: "0x" + "0".repeat(64),
    nonce: 22n,
    signature: "cli-signature-placeholder"
  };
  const evaluated = engine.evaluatePure(intent, state, intent.timestamp, { mode: "fail-fast" });
  assert.equal(evaluated.decision, "ALLOW");

  const authPath = join(dir, "authorization.json");
  await writeFile(authPath, jsonWithBigInt(evaluated.authorization), "utf8");

  const code = await runCli(
    [
      "verify",
      "--kind",
      "authorization",
      "--file",
      authPath,
      "--expected-issuer",
      evaluated.authorization.issuer,
      "--expected-audience",
      evaluated.authorization.audience,
      "--mode",
      "best-effort",
      "--json"
    ],
    cap.io
  );
  assert.equal(code, 0);
  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(latest.status, "ok");
  assert.equal(Array.isArray(latest.violations), true);
  assert.equal(latest.violations.length, 0);
});

test("verify fails closed on malformed authorization payload", async () => {
  const { dir } = await setup();
  const cap = ioCapture();
  const malformedPath = join(dir, "bad-auth.json");
  await writeFile(malformedPath, "{\"not\":\"authorization\"}", "utf8");

  const code = await runCli(["verify", "--kind", "authorization", "--file", malformedPath, "--mode", "best-effort", "--json"], cap.io);
  assert.equal(code, 1);
  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(latest.status, "invalid");
  assert.ok((latest.violations ?? []).length > 0);
});

test("verify auth without file returns actionable guidance", async () => {
  const cap = ioCapture();
  const code = await runCli(["verify", "auth"], cap.io);
  assert.equal(code, 1);
  assert.match(cap.err[0] ?? "", /authorization verification requires --file/);
});

test("paths, doctor, and examples init support local setup flows", async () => {
  const { dir } = await setup();
  const cap = ioCapture();
  const stateFile = join(dir, "example-state.json");
  const auditFile = join(dir, "example-audit.ndjson");

  assert.equal(await runCli(["paths", "--json"], cap.io), 0);
  const paths = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(typeof paths.state, "string");

  assert.equal(await runCli(["examples", "init", "--state", stateFile, "--audit", auditFile, "--json"], cap.io), 0);
  const doctorCode = await runCli(["doctor", "--state", stateFile, "--audit", auditFile, "--json"], cap.io);
  assert.equal(doctorCode, 0);
  const doctor = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(Array.isArray(doctor.checks), true);
  assert.equal(doctor.checks.every((c: any) => typeof c.exists === "boolean"), true);
});

test("inspect, verify all, auth create, and launch dry-run work together", async () => {
  const { policyFile, stateFile, auditFile, dir } = await setup();
  const cap = ioCapture(1_770_000_700);
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);

  const launchCode = await runCli(
    ["launch", "dry-run", "PROVISION", "100", "us-east-1", "--agent", "agent-1", "--nonce", "31", "--state", stateFile, "--json"],
    cap.io
  );
  assert.equal(launchCode, 0);
  const launchLatest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(launchLatest.dryRun, true);

  const authPath = join(dir, "authorization.json");
  const createCode = await runCli(
    ["auth", "create", "PROVISION", "100", "us-east-1", "--agent", "agent-1", "--nonce", "32", "--state", stateFile, "--out", authPath, "--json"],
    cap.io
  );
  assert.equal(createCode, 0);

  const snapshotPath = join(dir, "snapshot.bin");
  await runCli(["build", "snapshot", "--state", stateFile, "--out", snapshotPath, "--json"], cap.io);
  const envelopePath = join(dir, "envelope.bin");
  await runCli(["make-envelope", "--out", envelopePath, "--state", stateFile, "--audit", auditFile, "--json"], cap.io);

  assert.equal(await runCli(["inspect", "snapshot", "--file", snapshotPath, "--json"], cap.io), 0);
  assert.equal(await runCli(["inspect", "audit", "--file", auditFile, "--json"], cap.io), 0);
  assert.equal(await runCli(["inspect", "envelope", "--file", envelopePath, "--json"], cap.io), 0);
  assert.equal(await runCli(["auth", "inspect", "--file", authPath, "--json"], cap.io), 0);

  const verifyAllCode = await runCli(
    ["verify", "all", "--state", stateFile, "--audit", auditFile, "--mode", "best-effort", "--json"],
    {
      ...cap.io,
      out: cap.io.out
    }
  );
  assert.equal(verifyAllCode, 1);
  const verifyAll = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(typeof verifyAll.snapshot.status, "string");
  assert.equal(typeof verifyAll.audit.status, "string");
  assert.equal(typeof verifyAll.envelope.status, "string");
});

// ── CLI trust UX: strict mode requires --trusted-keyset ───────────────────────

const MINIMAL_KEYSET = JSON.stringify({ issuer: "test-issuer", version: "1", keys: [] });

test("verify-envelope strict without --trusted-keyset fails with guidance message", async () => {
  const { policyFile, stateFile, auditFile, dir } = await setup();
  const cap = ioCapture(1_770_001_000);
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  const envelopePath = join(dir, "envelope.bin");
  await runCli(["make-envelope", "--out", envelopePath, "--state", stateFile, "--audit", auditFile], cap.io);

  const code = await runCli(["verify-envelope", envelopePath], cap.io);
  assert.equal(code, 1);
  assert.ok(cap.err.some((line) => line.includes("--trusted-keyset")));
  assert.ok(cap.err.some((line) => line.includes("best-effort")));
});

test("verify all strict without --trusted-keyset fails with guidance message", async () => {
  const { policyFile, stateFile, auditFile, dir } = await setup();
  const cap = ioCapture(1_770_001_100);
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  const snapshotPath = join(dir, "snapshot.bin");
  await runCli(["build", "snapshot", "--state", stateFile, "--out", snapshotPath], cap.io);
  const envelopePath = join(dir, "envelope.bin");
  await runCli(["make-envelope", "--out", envelopePath, "--state", stateFile, "--audit", auditFile], cap.io);

  const code = await runCli(["verify", "all", "--state", stateFile, "--audit", auditFile], cap.io);
  assert.equal(code, 1);
  assert.ok(cap.err.some((line) => line.includes("--trusted-keyset")));
  assert.ok(cap.err.some((line) => line.includes("best-effort")));
});

test("verify-envelope strict with --trusted-keyset proceeds past trust guard", async () => {
  const { policyFile, stateFile, auditFile, dir } = await setup();
  const cap = ioCapture(1_770_001_200);
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  const envelopePath = join(dir, "envelope.bin");
  await runCli(["make-envelope", "--out", envelopePath, "--state", stateFile, "--audit", auditFile], cap.io);
  const keysetPath = join(dir, "keyset.json");
  await writeFile(keysetPath, MINIMAL_KEYSET, "utf8");

  await runCli(["verify-envelope", envelopePath, "--trusted-keyset", keysetPath, "--json"], cap.io);
  // no trust-guard guidance — command ran past the guard and produced JSON output
  assert.ok(cap.err.every((line) => !line.includes("Strict verification requires")));
  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(typeof latest.status, "string");
  assert.ok(!latest.violations?.some((v: { code: string }) => v.code === "TRUSTED_KEYSETS_REQUIRED"));
});

test("verify all strict with --trusted-keyset proceeds past trust guard", async () => {
  const { policyFile, stateFile, auditFile, dir } = await setup();
  const cap = ioCapture(1_770_001_300);
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  const snapshotPath = join(dir, "snapshot.bin");
  await runCli(["build", "snapshot", "--state", stateFile, "--out", snapshotPath], cap.io);
  const envelopePath = join(dir, "envelope.bin");
  await runCli(["make-envelope", "--out", envelopePath, "--state", stateFile, "--audit", auditFile], cap.io);
  const keysetPath = join(dir, "keyset.json");
  await writeFile(keysetPath, MINIMAL_KEYSET, "utf8");

  await runCli(
    ["verify", "all", "--state", stateFile, "--audit", auditFile, "--trusted-keyset", keysetPath, "--json"],
    cap.io
  );
  // no trust-guard guidance — command ran past the guard and produced JSON output
  assert.ok(cap.err.every((line) => !line.includes("Strict verification requires")));
  const latest = JSON.parse(cap.out[cap.out.length - 1] ?? "{}");
  assert.equal(typeof latest.envelope, "object");
  assert.ok(!latest.envelope?.violations?.some((v: { code: string }) => v.code === "TRUSTED_KEYSETS_REQUIRED"));
});

test("verify --kind envelope strict without --trusted-keyset fails with guidance message", async () => {
  const { policyFile, stateFile, auditFile, dir } = await setup();
  const cap = ioCapture(1_770_002_000);
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  const envelopePath = join(dir, "envelope.bin");
  await runCli(["make-envelope", "--out", envelopePath, "--state", stateFile, "--audit", auditFile], cap.io);

  const code = await runCli(["verify", "--kind", "envelope", "--file", envelopePath], cap.io);
  assert.equal(code, 1);
  assert.ok(cap.err.some((line) => line.includes("--trusted-keyset")));
  assert.ok(cap.err.some((line) => line.includes("best-effort")));
});

test("verify --kind authorization strict without --trusted-keyset fails with guidance message", async () => {
  const { policyFile, stateFile, auditFile, dir } = await setup();
  const cap = ioCapture(1_770_002_100);
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  const authPath = join(dir, "authorization.json");
  await runCli(
    ["auth", "create", "PROVISION", "100", "us-east-1", "--agent", "agent-1", "--nonce", "99", "--state", stateFile, "--out", authPath],
    cap.io
  );

  const code = await runCli(["verify", "--kind", "authorization", "--file", authPath], cap.io);
  assert.equal(code, 1);
  assert.ok(cap.err.some((line) => line.includes("--trusted-keyset")));
  assert.ok(cap.err.some((line) => line.includes("best-effort")));
});

// ── CLI-1: strict authorization verification must require a verified signature ──

const CLI1_NOW = 1_770_003_000;
const CLI1_SECRET = "test-secret-must-be-at-least-32-chars!!";

async function cli1Keyset(dir: string) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  const keysetPath = join(dir, "keyset.json");
  await writeFile(
    keysetPath,
    JSON.stringify({ issuer: "oxdeai://cli1-issuer", version: "1", keys: [{ kid: "cli1-k1", alg: "Ed25519", public_key: publicKey, status: "active" }] }),
    "utf8"
  );
  return { keysetPath, privateKey };
}

async function cli1IssuedAuth() {
  const { policyFile, stateFile, auditFile, dir } = await setup();
  const cap = ioCapture(CLI1_NOW);
  await runCli(["init", "--file", policyFile, "--state", stateFile, "--audit", auditFile], cap.io);
  const authPath = join(dir, "authorization.json");
  const code = await runCli(
    ["auth", "create", "PROVISION", "100", "us-east-1", "--agent", "agent-1", "--nonce", "301", "--state", stateFile, "--out", authPath],
    cap.io
  );
  assert.equal(code, 0);
  return { dir, authPath };
}

function lastJson(out: string[]) {
  return JSON.parse(out[out.length - 1] ?? "{}");
}

test("CLI-1: strict (default) rejects a forged HMAC-SHA256 authorization", async () => {
  const { dir } = await setup();
  const { keysetPath } = await cli1Keyset(dir);
  const forgedPath = join(dir, "forged.json");
  await writeFile(
    forgedPath,
    JSON.stringify({
      version: "AuthorizationV1",
      auth_id: "forged-1",
      issuer: "oxdeai://cli1-issuer",
      audience: "rp://tool-gateway",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: "c".repeat(64),
      decision: "ALLOW",
      issued_at: CLI1_NOW - 10,
      expiry: CLI1_NOW + 365 * 86400,
      alg: "HMAC-SHA256",
      kid: "anything",
      signature: "Zm9yZ2VkLXNpZ25hdHVyZQ=="
    }),
    "utf8"
  );

  for (const extra of [[], ["--mode", "strict"]]) {
    const cap = ioCapture(CLI1_NOW);
    const code = await runCli(
      ["verify", "--kind", "authorization", "--file", forgedPath, "--trusted-keyset", keysetPath, ...extra, "--json"],
      cap.io
    );
    assert.equal(code, 1, `forged authorization must fail strict verification (${extra.join(" ") || "default"})`);
    const res = lastJson(cap.out);
    assert.equal(res.ok, false);
    assert.equal(res.signatureVerified, false);
    assert.equal(res.verificationMode, "strict");
    assert.ok(res.violations.some((v: { code: string }) => v.code === "AUTH_TRUST_MISSING"));
  }
});

test("CLI-1: strict rejects a tampered CLI-issued authorization, with or without the secret", async () => {
  const { dir, authPath } = await cli1IssuedAuth();
  const { keysetPath } = await cli1Keyset(dir);
  const auth = JSON.parse(await readFile(authPath, "utf8"));
  auth.audience = "rp://attacker";
  auth.expiry = CLI1_NOW + 365 * 86400;
  const tamperedPath = join(dir, "tampered.json");
  await writeFile(tamperedPath, JSON.stringify(auth), "utf8");

  const noSecret = ioCapture(CLI1_NOW);
  assert.equal(
    await runCli(["verify", "--kind", "authorization", "--file", tamperedPath, "--trusted-keyset", keysetPath, "--json"], noSecret.io),
    1
  );
  assert.equal(lastJson(noSecret.out).signatureVerified, false);

  const withSecret = ioCapture(CLI1_NOW);
  assert.equal(
    await runCli(
      ["verify", "--kind", "authorization", "--file", tamperedPath, "--trusted-keyset", keysetPath, "--legacy-hmac-secret", CLI1_SECRET, "--json"],
      withSecret.io
    ),
    1
  );
  assert.ok(lastJson(withSecret.out).violations.some((v: { code: string }) => v.code === "AUTH_SIGNATURE_INVALID"));
});

test("CLI-1: strict accepts a genuine CLI-issued HMAC authorization only with the secret", async () => {
  const { dir, authPath } = await cli1IssuedAuth();
  const { keysetPath } = await cli1Keyset(dir);
  const cap = ioCapture(CLI1_NOW);
  const code = await runCli(
    ["verify", "--kind", "authorization", "--file", authPath, "--trusted-keyset", keysetPath, "--legacy-hmac-secret", CLI1_SECRET, "--json"],
    cap.io
  );
  assert.equal(code, 0);
  const res = lastJson(cap.out);
  assert.equal(res.ok, true);
  assert.equal(res.signatureVerified, true);
  assert.equal(res.verificationMode, "strict");
});

test("CLI-1: strict accepts an Ed25519 authorization signed by a trusted key", async () => {
  const { dir } = await setup();
  const { keysetPath, privateKey } = await cli1Keyset(dir);
  const signed = signAuthorizationEd25519(
    {
      auth_id: "ed25519-ok-1",
      issuer: "oxdeai://cli1-issuer",
      audience: "rp://tool-gateway",
      intent_hash: "a".repeat(64),
      state_hash: "b".repeat(64),
      policy_id: "c".repeat(64),
      decision: "ALLOW",
      issued_at: CLI1_NOW - 10,
      expiry: CLI1_NOW + 60,
      kid: "cli1-k1"
    },
    privateKey
  );
  const authPath = join(dir, "ed25519.json");
  await writeFile(authPath, JSON.stringify(signed), "utf8");

  const ok = ioCapture(CLI1_NOW);
  assert.equal(
    await runCli(
      ["verify", "--kind", "authorization", "--file", authPath, "--trusted-keyset", keysetPath, "--expected-audience", "rp://tool-gateway", "--json"],
      ok.io
    ),
    0
  );
  assert.equal(lastJson(ok.out).signatureVerified, true);

  // Same artifact, one signed field changed: must fail.
  await writeFile(authPath, JSON.stringify({ ...signed, audience: "rp://attacker" }), "utf8");
  const bad = ioCapture(CLI1_NOW);
  assert.equal(await runCli(["verify", "--kind", "authorization", "--file", authPath, "--trusted-keyset", keysetPath, "--json"], bad.io), 1);
});
