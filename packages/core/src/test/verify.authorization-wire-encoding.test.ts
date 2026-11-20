// SPDX-License-Identifier: Apache-2.0
// AuthorizationV1 wire-encoding separation (authorization-v1.md §5, §13).
//
// The declared alg selects exactly one (preimage, alphabet) pair:
//   "Ed25519" -> "OXDEAI_AUTH_V1\n" || canonicalJson, standard base64
//   "ed25519" -> canonicalJson (no prefix), nested signature, base64url
// No cross-encoding fallback; top-level alg/kid beside a nested signature must
// match signature.alg/kid. Fixtures come from an independent generator
// (node:crypto only) so they are reproducible outside this package.
import assert from "node:assert/strict";
import test from "node:test";
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyAuthorization } from "../verification/verifyAuthorization.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const generator = resolve(__dirname, "../../../../scripts/repro/authorization-wire-encoding-fixtures.mjs");
const fixtures = JSON.parse(execFileSync(process.execPath, [generator], { encoding: "utf8" }));

for (const v of fixtures.vectors) {
  test(`wire-encoding ${v.id}: ${v.description}`, () => {
    const r = verifyAuthorization(structuredClone(v.artifact), fixtures.verifier_options);
    assert.equal(r.status, v.expected.status, JSON.stringify(r.violations));
    if (v.expected.status === "ok") {
      assert.equal(r.signatureVerified, true);
    } else {
      const codes = r.violations.map((x) => x.code);
      for (const code of v.expected.codes) assert.ok(codes.includes(code), `${v.id}: missing ${code} in ${codes}`);
    }
  });
}
