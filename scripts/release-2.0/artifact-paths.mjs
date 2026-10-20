// SPDX-License-Identifier: Apache-2.0
import fs from "node:fs";
import path from "node:path";

function unsafe(detail) {
  throw Object.assign(new Error(`unsafe artifact path: ${detail}`), { code: "UNSAFE_TARBALL_PATH" });
}

// Reject symlink components, including dangling links and an aliased release
// directory. This is a point-in-time check, not protection against a hostile
// concurrent filesystem writer (the release process has no interprocess lock).
export function artifactDirectory(dir) {
  if (typeof dir !== "string" || !dir || /[\\\x00-\x1f\x7f]/.test(dir)) unsafe("invalid directory");
  const absolute = path.resolve(dir);
  const parsed = path.parse(absolute);
  let current = parsed.root;
  for (const part of absolute.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    try {
      const stat = fs.lstatSync(current);
      if (stat.isSymbolicLink() || !stat.isDirectory()) unsafe(`directory component ${current}`);
    } catch (error) { if (error.code !== "ENOENT") throw error; }
  }
  return absolute;
}

// Reject linked output entries; regular archives may coexist, but must only be
// installed through packWithoutOverwrite(), never overwritten by pnpm directly.
export function packDestination(dir) {
  const absolute = artifactDirectory(dir);
  if (fs.existsSync(absolute)) {
    for (const entry of fs.readdirSync(absolute, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) unsafe(`linked output ${entry.name}`);
      if (entry.isDirectory()) packDestination(path.join(absolute, entry.name));
    }
  }
  return absolute;
}

export function containedTarball(directory, output) {
  const base = artifactDirectory(directory);
  if (typeof output !== "string" || !output || /[\\:\x00-\x1f\x7f]/.test(output) ||
      output.split("/").some(part => part === "..")) unsafe("invalid tarball output");
  const absolute = path.resolve(base, output);
  const relative = path.relative(base, absolute);
  if (!relative || relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative) ||
      !absolute.endsWith(".tgz")) unsafe("tarball outside authorized directory");
  artifactDirectory(path.dirname(absolute));
  const stat = fs.lstatSync(absolute);
  if (stat.isSymbolicLink() || !stat.isFile()) unsafe("tarball must be a regular file, not a symlink");
  return absolute;
}

export function manifestTarball(releaseDir, relative) {
  if (typeof relative !== "string" || path.isAbsolute(relative) || path.win32.isAbsolute(relative) ||
      relative.split("/").some(part => !part || part === "." || part === "..") || !relative.startsWith("tarballs/")) {
    unsafe("manifest tarball must be a contained relative tarballs/ path");
  }
  return containedTarball(path.join(artifactDirectory(releaseDir), "tarballs"), relative.slice("tarballs/".length));
}

// pnpm sees a fresh private directory, never retained archive bytes. linkSync
// installs the finished file atomically with no replacement (EEXIST includes
// dangling symlinks). Staging is on the same filesystem as the destination.
export function packWithoutOverwrite(dir, runPack) {
  const destination = packDestination(dir);
  fs.mkdirSync(destination, { recursive: true });
  const staging = fs.mkdtempSync(path.join(destination, ".pack-"));
  try {
    const archive = containedTarball(staging, runPack(staging));
    packDestination(destination);
    const target = path.join(destination, path.basename(archive));
    try { fs.linkSync(archive, target); }
    catch (error) {
      if (error.code !== "EEXIST") throw error;
      throw Object.assign(new Error(`existing archive must not be overwritten: ${target}`),
        { code: "ARTIFACT_ALREADY_EXISTS", cause: error });
    }
    return target;
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
}
