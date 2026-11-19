// SPDX-License-Identifier: Apache-2.0
// Test helper: builds a minimal npm-pack-shaped tarball (gzip + ustar) in memory.
// Entries are [name, content, type] with type "0" (file, default) or any other
// typeflag for negative tests.
import { gzipSync } from "node:zlib";

function header(name, size, type) {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, "utf8");
  h.write("0000644\0", 100, "ascii");
  h.write("0000000\0", 108, "ascii");
  h.write("0000000\0", 116, "ascii");
  h.write(size.toString(8).padStart(11, "0") + "\0", 124, "ascii");
  h.write("00000000000\0", 136, "ascii");
  h.write("        ", 148, "ascii");
  h.write(type, 156, "ascii");
  h.write("ustar\0", 257, "ascii");
  h.write("00", 263, "ascii");
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, "ascii");
  return h;
}

export function makeTarball(entries) {
  const parts = [];
  for (const [name, content, type = "0"] of entries) {
    const body = Buffer.from(content);
    parts.push(header(name, body.length, type), body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  parts.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(parts));
}

export function makePackedTarball(packageJson) {
  return makeTarball([
    ["package/README.md", "# fixture\n"],
    ["package/package.json", JSON.stringify(packageJson)],
  ]);
}
