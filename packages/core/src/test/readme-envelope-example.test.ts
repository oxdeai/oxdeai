// SPDX-License-Identifier: Apache-2.0
/**
 * The README's verifyEnvelope example must not present structural verification
 * as signature verification. Envelope signatures are optional, so an unsigned
 * envelope returns "ok" unless requireSignatureVerification is set. This pins
 * the documented call to the options that make "ok" mean "signed by a trusted
 * key", and to a fail-closed branch.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

test("README verifyEnvelope examples require signature verification and fail closed", () => {
  const readme = readFileSync(fileURLToPath(new URL("../../README.md", import.meta.url)), "utf8");
  const calls = [...readme.matchAll(/verifyEnvelope\(envelopeBytes(?:, \{([\s\S]*?)\})?\);/g)];
  assert.ok(calls.length > 0, "README no longer contains a verifyEnvelope(envelopeBytes...) example");

  for (const call of calls) {
    const opts = call[1] ?? "";
    assert.match(opts, /requireSignatureVerification: true/, `unsafe README example: ${call[0].slice(0, 60)}`);
    assert.match(opts, /trustedKeySets:/);
    const after = readme.slice(call.index! + call[0].length, call.index! + call[0].length + 200);
    assert.match(after, /if \(result\.status !== "ok"\) \{\s*throw/);
  }
  assert.doesNotMatch(readme, /console\.log\("artifact verified"\)/);
});
