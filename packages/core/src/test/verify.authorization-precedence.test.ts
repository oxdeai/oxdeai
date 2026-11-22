// SPDX-License-Identifier: Apache-2.0
// AuthorizationV1 verification precedence (verification-v1.md §5, §9.1).
//
// The committed corpus (docs/spec/test-vectors/authorization-precedence-v1.json)
// fixes the determining code of overlapping-defect cases by step order. It
// must be byte-identical to the output of its independent generator.
//
// The reference verifier collects violations. With `reportPrimaryReasonCode`
// it identifies the determining code in a dedicated field
// (`primaryReasonCode`), as verification-v1.md §9.1 allows; `violations` keeps
// its historical order. Every corpus case must report the determining code,
// so REPORT_ORDER_PENDING is empty and the final test pins it at zero.
import assert from "node:assert/strict";
import test from "node:test";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyAuthorization } from "../verification/verifyAuthorization.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "../../../..");
const generator = resolve(repoRoot, "scripts/repro/authorization-precedence-fixtures.mjs");
const corpusPath = resolve(repoRoot, "docs/spec/test-vectors/authorization-precedence-v1.json");
const committed = readFileSync(corpusPath, "utf8");
const fixtures = JSON.parse(committed);

const REPORT_ORDER_PENDING: string[] = [];

function optionsFor(v: { options: Record<string, unknown> }) {
  const o: Record<string, unknown> = { ...fixtures.verifier_options };
  for (const [k, x] of Object.entries(v.options)) {
    if (x === null) delete o[k];
    else o[k] = x;
  }
  return o;
}

test("precedence corpus is byte-identical to its independent generator", () => {
  const regenerated = execFileSync(process.execPath, [generator], { encoding: "utf8" });
  assert.equal(regenerated, committed, "run: node scripts/repro/authorization-precedence-fixtures.mjs --write");
});

const notDetermined: string[] = [];
for (const v of fixtures.vectors) {
  test(`precedence ${v.id}: ${v.description}`, () => {
    const r = verifyAuthorization(structuredClone(v.artifact), { ...optionsFor(v), reportPrimaryReasonCode: true } as never);
    assert.equal(r.status, v.expected.status, JSON.stringify(r.violations));
    const codes = r.violations.map((x: { code: string }) => x.code);
    assert.ok(codes.includes(v.expected.determining_code), `${v.id}: determining code ${v.expected.determining_code} missing from ${codes.join(",")}`);
    if (r.primaryReasonCode !== v.expected.determining_code) notDetermined.push(v.id);
  });
}

test("reference verifier identifies the determining code in every corpus case (REPORT_ORDER_PENDING is empty)", () => {
  assert.deepEqual([...notDetermined].sort(), [...REPORT_ORDER_PENDING].sort());
  assert.equal(REPORT_ORDER_PENDING.length, 0);
});
