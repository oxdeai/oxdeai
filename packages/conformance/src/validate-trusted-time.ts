// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runTrustedTimeConformance, trustedTimeExitCode } from "./trustedTimeConformance.js";

const here = fileURLToPath(new URL(".", import.meta.url));
const raw = JSON.parse(readFileSync(resolve(here, "../../vectors/trusted-time.json"), "utf8"));
const jsonOutput = process.argv.includes("--json");
const summary = runTrustedTimeConformance(raw, jsonOutput ? () => {} : console.log);
console.log(JSON.stringify({ result: trustedTimeExitCode(summary) ? "FAIL" : "PASS", ...summary }));
if (!jsonOutput) console.log(`Trusted-time summary: active=${summary.active} passed=${summary.passed} failed=${summary.failed} pending=${summary.pending}`);
process.exitCode = trustedTimeExitCode(summary);
