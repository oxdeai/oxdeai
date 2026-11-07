// SPDX-License-Identifier: Apache-2.0
//
// F4-AUD-03 benchmark: delegation scope narrowing, former O(N x M) membership
// (`parent.tools.includes(t)` per child tool) vs the Set-based O(N + M) form.
//
// Informational only. NOT part of CI and not a pass/fail gate: timings depend
// on the machine. Synthetic data, no keys, no network.
//
//   node bench/scope-narrowing.f4-aud-03.mjs                # algorithm micro-benchmark
//   CORE_DIST=packages/core/dist node bench/scope-narrowing.f4-aud-03.mjs --e2e
//       # also time core verifyDelegationChain end to end on that build
//   SIZES=1000,10000,40000 node bench/scope-narrowing.f4-aud-03.mjs
//
// Shape (from the closure audit, S8): N child tools, M = 2N parent tools where
// the first N parent entries are disjoint and the last N are the child tools in
// reverse order — the worst case for a linear scan.
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";
import path from "node:path";

const sizes = (process.env.SIZES ?? "1000,5000,10000,20000,40000").split(",").map(Number);
const e2e = process.argv.includes("--e2e");

const formerNotAllowed = (child, parent) => child.filter((t) => !parent.includes(t));
const currentNotAllowed = (child, parent) => { const s = new Set(parent); return child.filter((t) => !s.has(t)); };

function shape(n) {
  const child = Array.from({ length: n }, (_, i) => `t${i}`);
  const parent = [...Array.from({ length: n }, (_, i) => `p${i}`), ...child.slice().reverse()];
  return { child, parent, kib: Math.round(Buffer.byteLength(JSON.stringify({ tools: child }) + JSON.stringify({ tools: parent })) / 1024) };
}

/** Run `fn` synchronously and report how long a 0 ms timer queued before it was delayed (event-loop blocking). */
async function timed(fn) {
  const queued = performance.now();
  const lag = new Promise((resolve) => setTimeout(() => resolve(performance.now() - queued), 0));
  const t0 = performance.now(); const out = fn(); const ms = performance.now() - t0;
  return { ms, blockedMs: await lag, out };
}

const rows = [];
for (const n of sizes) {
  const { child, parent, kib } = shape(n);
  const before = await timed(() => formerNotAllowed(child, parent));
  const after = await timed(() => currentNotAllowed(child, parent));
  if (JSON.stringify(before.out) !== JSON.stringify(after.out)) throw new Error(`results differ at N=${n}`);
  rows.push({ N: n, M: parent.length, payloadKiB: kib, formerMs: +before.ms.toFixed(1), currentMs: +after.ms.toFixed(2), speedup: +(before.ms / after.ms).toFixed(0), formerLoopBlockedMs: +before.blockedMs.toFixed(1), currentLoopBlockedMs: +after.blockedMs.toFixed(1) });
}
console.log(JSON.stringify({ node: process.version, platform: `${process.platform}/${process.arch}`, kind: "algorithm", rows }, null, 1));

if (e2e) {
  const dist = path.resolve(process.env.CORE_DIST ?? "packages/core/dist");
  const core = await import(pathToFileURL(path.join(dist, "index.js")).href);
  const { generateKeyPairSync } = await import("node:crypto");
  const k = () => generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
  const pdp = k(), agent = k(); const now = Math.floor(Date.now() / 1000);
  const parentAuth = core.signAuthorizationEd25519({ auth_id: "b".repeat(64), issuer: "pdp", audience: "agent-A", intent_hash: "a".repeat(64), state_hash: "c".repeat(64), policy_id: "P", decision: "ALLOW", issued_at: now - 10, expiry: now + 600, kid: "k1" }, pdp.privateKey);
  const trustedKeySets = [{ issuer: "agent-A", version: "1", keys: [{ kid: "a1", alg: "Ed25519", public_key: agent.publicKey }] }];
  const e2eRows = [];
  for (const n of sizes) {
    const { child, parent, kib } = shape(n);
    const d = { ...core.createDelegation(parentAuth, { delegatee: "agent-B", issuer: "agent-A", kid: "a1", scope: { tools: ["t0"] }, expiry: now + 300 }, agent.privateKey), scope: { tools: child, max_amount: 1n } };
    const r = await timed(() => core.verifyDelegationChain(d, parentAuth, { now, trustedKeySets, requireSignatureVerification: true, parentScope: { tools: parent } }));
    e2eRows.push({ N: n, M: parent.length, payloadKiB: kib, verifyDelegationChainMs: +r.ms.toFixed(1), loopBlockedMs: +r.blockedMs.toFixed(1), ok: r.out.ok });
  }
  console.log(JSON.stringify({ node: process.version, kind: "e2e verifyDelegationChain", coreDist: dist, rows: e2eRows }, null, 1));
}
