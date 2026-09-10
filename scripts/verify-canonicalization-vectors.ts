import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

type OkVector = {
  id: string;
  description: string;
  status: "ok";
  input: unknown;
  expected_canonical_json: string;
  expected_sha256: string;
};

type ErrorVector = {
  id: string;
  description: string;
  status: "error";
  input: unknown;
  expected_error: string;
};

type Vector = OkVector | ErrorVector;

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function normalizeString(value: string): string {
  return value.normalize("NFC");
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Object.prototype.toString.call(value) === "[object Object]";
}

function canonicalize(input: unknown): Uint8Array {
  return Buffer.from(canonicalizeToJson(input), "utf8");
}

function sortUtf8Lex(keys: string[]): string[] {
  return [...keys].sort((a, b) =>
    Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"))
  );
}

function canonicalizeToJson(value: unknown): string {
  if (value === null) {
    return "null";
  }

  if (typeof value === "string") {
    return JSON.stringify(normalizeString(value));
  }

  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }

  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new Error("FLOAT_NOT_ALLOWED");
    }
    if (!Number.isSafeInteger(value)) {
      throw new Error("UNSAFE_INTEGER_NUMBER");
    }
    return String(value);
  }

  if (typeof value === "bigint") {
    return JSON.stringify(String(value));
  }

  if (
    typeof value === "undefined" ||
    typeof value === "function" ||
    typeof value === "symbol"
  ) {
    throw new Error("UNSUPPORTED_TYPE");
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeToJson(item)).join(",")}]`;
  }

  if (isPlainObject(value)) {
    const normalizedEntries = Object.entries(value).map(([k, v]) => {
      return [normalizeString(k), v] as const;
    });

    // Detect post-normalization collisions, e.g. two keys that normalize to same NFC form.
    const seen = new Set<string>();
    for (const [k] of normalizedEntries) {
      if (seen.has(k)) {
        throw new Error("DUPLICATE_KEY");
      }
      seen.add(k);
    }

    const sortedKeys = sortUtf8Lex(normalizedEntries.map(([k]) => k));

    const parts = sortedKeys.map((key) => {
      const entry = normalizedEntries.find(([k]) => k === key);
      if (!entry) {
        throw new Error("KEY_RESOLUTION_FAILED");
      }

      const [, child] = entry;

      // Profile-specific rule retained from your current code:
      // "ts" must be an integer timestamp, not a string / float.
      if (key === "ts") {
        if (typeof child !== "number" || !Number.isInteger(child) || !Number.isSafeInteger(child)) {
          throw new Error("INVALID_TIMESTAMP");
        }
      }

      return `${JSON.stringify(key)}:${canonicalizeToJson(child)}`;
    });

    return `{${parts.join(",")}}`;
  }

  throw new Error("UNSUPPORTED_TYPE");
}

function loadVectors(): Vector[] {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);

  const file = resolve(
    __dirname,
    "../docs/spec/test-vectors/canonicalization-v1.json"
  );

  return JSON.parse(readFileSync(file, "utf8")) as Vector[];
}

function main(): void {
  const vectors = loadVectors();
  let failed = 0;

  for (const vector of vectors) {
    try {
      const bytes = canonicalize(vector.input);
      const canonicalJson = Buffer.from(bytes).toString("utf8");
      const hash = sha256Hex(bytes);

      if (vector.status === "error") {
        failed++;
        console.error(
          `FAIL ${vector.id}: expected error ${vector.expected_error}, got success`
        );
        continue;
      }

      if (canonicalJson !== vector.expected_canonical_json) {
        failed++;
        console.error(`FAIL ${vector.id}: canonical JSON mismatch`);
        console.error(`  expected: ${vector.expected_canonical_json}`);
        console.error(`  actual:   ${canonicalJson}`);
        continue;
      }

      if (vector.expected_sha256 !== "" && hash !== vector.expected_sha256) {
        failed++;
        console.error(`FAIL ${vector.id}: SHA-256 mismatch`);
        console.error(`  expected: ${vector.expected_sha256}`);
        console.error(`  actual:   ${hash}`);
        continue;
      }

      console.log(`PASS ${vector.id}`);
    } catch (err) {
      const actual = err instanceof Error ? err.message : "UNKNOWN_ERROR";

      if (vector.status === "ok") {
        failed++;
        console.error(`FAIL ${vector.id}: unexpected error ${actual}`);
        continue;
      }

      if (actual !== vector.expected_error) {
        failed++;
        console.error(`FAIL ${vector.id}: wrong error`);
        console.error(`  expected: ${vector.expected_error}`);
        console.error(`  actual:   ${actual}`);
        continue;
      }

      console.log(`PASS ${vector.id}`);
    }
  }

  if (failed > 0) {
    console.error(`\n${failed} vector(s) failed`);
    process.exit(1);
  }

  console.log(`\nAll ${vectors.length} vector(s) passed (diagnostic only; scoped report: pnpm test:vectors:ts)`);
}

main();