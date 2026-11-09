// SPDX-License-Identifier: Apache-2.0
// test-evidence test-evidence reporter for node:test.
//
// Records one evidence file per test-runner process so that a later gate
// (scripts/ci/verify-test-evidence.mjs) can prove which tests actually executed.
// Exit codes and summary counters are not evidence: on Node 22 a skipped
// describe() reports "tests 0, skipped 0" and an empty discovery exits 0.
//
// Attach through the environment (no package.json changes needed):
//   OXDEAI_TEST_EVIDENCE_DIR   directory for evidence files (required; the reporter throws if unset)
//   OXDEAI_TEST_EVIDENCE_ROOT  repository root; recorded file paths are relative to it
//   NODE_OPTIONS="--test-reporter=spec --test-reporter-destination=stdout
//                 --test-reporter=<abs path>/test-evidence-reporter.mjs --test-reporter-destination=stderr"
//
// Record format (NDJSON): run-start, then one record per finished test/suite
// {run, kind, file, name: "suite > ... > test", status, skip, todo}, then run-end.
// A missing run-end means the runner did not finish and the gate rejects the file.
import { appendFileSync, mkdirSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { join, relative, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";

export default async function* testEvidenceReporter(source) {
  const dir = process.env.OXDEAI_TEST_EVIDENCE_DIR;
  if (!dir) throw new Error("OXDEAI_TEST_EVIDENCE_DIR is not set");
  const root = process.env.OXDEAI_TEST_EVIDENCE_ROOT ?? process.cwd();
  mkdirSync(dir, { recursive: true });
  const run = randomUUID();
  const out = join(dir, `${process.pid}-${run}.ndjson`);
  const write = (rec) => appendFileSync(out, JSON.stringify({ run, ...rec }) + "\n");
  const rel = (f) => {
    if (typeof f !== "string") return null;
    const p = f.startsWith("file:") ? fileURLToPath(f) : f;
    return isAbsolute(p) ? relative(root, p).split("\\").join("/") : p;
  };
  write({ kind: "run-start", node: process.version, cwd: rel(process.cwd()) });
  const stacks = new Map();
  for await (const { type, data } of source) {
    if (type === "test:start") {
      const s = stacks.get(data.file) ?? [];
      s[data.nesting] = data.name;
      s.length = data.nesting + 1;
      stacks.set(data.file, s);
    } else if (type === "test:pass" || type === "test:fail") {
      const s = stacks.get(data.file) ?? [];
      write({
        kind: data.details?.type === "suite" ? "suite" : "test",
        file: rel(data.file),
        name: [...s.slice(0, data.nesting), data.name].join(" > "),
        status: type === "test:pass" ? "pass" : "fail",
        skip: data.skip !== undefined && data.skip !== false,
        todo: data.todo !== undefined && data.todo !== false,
      });
    }
  }
  write({ kind: "run-end" });
}
