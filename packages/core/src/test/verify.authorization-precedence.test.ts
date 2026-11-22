// SPDX-License-Identifier: Apache-2.0
// AuthorizationV1 verification precedence (verification-v1.md §5, §9.1).
//
// The committed corpus (docs/spec/test-vectors/authorization-precedence-v1.json)
// fixes the determining code of overlapping-defect cases by step order. It
// must be byte-identical to the output of its independent generator.
//
// The reference verifier collects violations. What it is required to do today,
// and is asserted here, is to return the same verdict and to include the
// determining code. Presenting the determining code FIRST (or in a dedicated
// field) is what verification-v1.md §9.1 requires of a multi-code report; the
// reference verifier does not do that yet. The cases where it does not are
// pinned EXACTLY in REPORT_ORDER_PENDING, so a fix (or a regression) changes
// this test and cannot pass unnoticed. Follow-up: order the reference report
// per §9.1.
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

const REPORT_ORDER_PENDING = ["p-005", "p-006", "p-007", "p-008", "p-009", "p-010", "p-011", "p-012", "p-013"];

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

const notFirst: string[] = [];
for (const v of fixtures.vectors) {
  test(`precedence ${v.id}: ${v.description}`, () => {
    const r = verifyAuthorization(structuredClone(v.artifact), optionsFor(v) as never);
    assert.equal(r.status, v.expected.status, JSON.stringify(r.violations));
    const codes = r.violations.map((x: { code: string }) => x.code);
    assert.ok(codes.includes(v.expected.determining_code), `${v.id}: determining code ${v.expected.determining_code} missing from ${codes.join(",")}`);
    if (codes[0] !== v.expected.determining_code) notFirst.push(v.id);
  });
}

test("reference report order: pending cases are exactly the pinned set", () => {
  assert.deepEqual([...notFirst].sort(), [...REPORT_ORDER_PENDING].sort());
});
