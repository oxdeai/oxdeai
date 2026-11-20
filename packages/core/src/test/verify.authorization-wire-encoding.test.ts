// SPDX-License-Identifier: Apache-2.0
// AuthorizationV1 wire-encoding separation (authorization-v1.md §5, §13).
//
// The declared alg selects exactly one (preimage, alphabet) pair:
//   "Ed25519" -> "OXDEAI_AUTH_V1\n" || canonicalJson, standard base64
//   "ed25519" -> canonicalJson (no prefix), nested signature, base64url
// No cross-encoding fallback; top-level alg/kid beside a nested signature must
// match signature.alg/kid.
//
// The committed corpus (docs/spec/test-vectors/authorization-wire-encoding-v1.json)
// is the conformance artifact third parties consume. It must be byte-identical
// to the output of its independent generator (node:crypto only), and
// `expected.codes` is the EXACT set of distinct violation codes.
import assert from "node:assert/strict";
import test from "node:test";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyAuthorization } from "../verification/verifyAuthorization.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "../../../..");
const generator = resolve(repoRoot, "scripts/repro/authorization-wire-encoding-fixtures.mjs");
const corpusPath = resolve(repoRoot, "docs/spec/test-vectors/authorization-wire-encoding-v1.json");
const committed = readFileSync(corpusPath, "utf8");
const fixtures = JSON.parse(committed);

test("wire-encoding corpus is byte-identical to its independent generator", () => {
  const regenerated = execFileSync(process.execPath, [generator], { encoding: "utf8" });
  assert.equal(regenerated, committed, "run: node scripts/repro/authorization-wire-encoding-fixtures.mjs --write");
});

for (const v of fixtures.vectors) {
  test(`wire-encoding ${v.id}: ${v.description}`, () => {
    const r = verifyAuthorization(structuredClone(v.artifact), fixtures.verifier_options);
    assert.equal(r.status, v.expected.status, JSON.stringify(r.violations));
    if (v.expected.status === "ok") {
      assert.equal(r.signatureVerified, true);
      assert.deepEqual(r.violations, []);
    } else {
      const codes = [...new Set(r.violations.map((x) => x.code))].sort();
      assert.deepEqual(codes, [...v.expected.codes].sort(), `${v.id}: violation codes`);
    }
  });
}
