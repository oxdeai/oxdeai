// SPDX-License-Identifier: Apache-2.0
//
// S3-MNT-1: Sift's small-order table (src/smallOrderEd25519.ts) is a deliberate
// copy of @oxdeai/core's (packages/core/src/crypto/signatures.ts). This asserts
// the two copies are the same set, so one cannot drift from the other. Core's
// table is read from source text, not imported, so @oxdeai/sift gains no
// dependency on @oxdeai/core. Fails (never skips) if core's table is not found.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { SMALL_ORDER_ED25519, isSmallOrderEd25519Key } from "../src/smallOrderEd25519.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CORE_SIGNATURES = resolve(__dirname, "../../../core/src/crypto/signatures.ts");

function coreSmallOrderTable(): string[] {
  const src = readFileSync(CORE_SIGNATURES, "utf-8");
  const m = src.match(/const SMALL_ORDER_ED25519\b[^=]*=\s*new Set\(\[([\s\S]*?)\]\)/);
  assert.ok(m, `SMALL_ORDER_ED25519 table not found in ${CORE_SIGNATURES}`);
  return [...m[1].matchAll(/"([0-9a-f]{64})"/g)].map((x) => x[1]);
}

test("S3-MNT-1: Sift small-order table equals @oxdeai/core's table", () => {
  const core = coreSmallOrderTable();
  assert.equal(core.length, 14, "core table has 14 entries");
  assert.equal(new Set(core).size, core.length, "core table has no duplicates");
  assert.deepEqual([...SMALL_ORDER_ED25519].sort(), [...core].sort());
});

test("S3-MNT-1: every core table entry is rejected by Sift's guard", () => {
  const spki = Buffer.from("302a300506032b6570032100", "hex");
  for (const hex of coreSmallOrderTable()) {
    const key = createPublicKey({ key: Buffer.concat([spki, Buffer.from(hex, "hex")]), format: "der", type: "spki" });
    assert.equal(isSmallOrderEd25519Key(key), true, hex);
  }
});
