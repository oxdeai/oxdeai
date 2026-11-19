// SPDX-License-Identifier: Apache-2.0
// `latest` promotion floor (R3 reconciliation).
//
// promoteLatest() calls assertLatestPromotionAllowed() after consent validation
// and before any effect. It refuses, even with an explicit promotion consent:
//   - a candidate whose version, read from the frozen tarball that was
//     published, differs from the manifest or from POLICY;
//   - a prerelease candidate for `latest`;
//   - a candidate that is not strictly greater (SemVer precedence, never string
//     order) than the version `latest` points to at the moment of promotion.
// The current `latest` is observed by the caller immediately before this check;
// an observation that is missing, malformed or not a SemVer version fails
// closed. Nothing is changed or persisted when the check fails.
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { POLICY } from "../verify-packed-artifacts.mjs";
import { manifestTarball } from "./artifact-paths.mjs";
import { compareVersions } from "./published-baseline.mjs";

const PRERELEASE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)-/;
const STRICT_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const MAX_UNPACKED = 64 * 1024 * 1024;

export class PromotionFloorError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PromotionFloorError";
    this.code = code;
  }
}
const refuse = (code, message) => { throw new PromotionFloorError(code, message); };

const field = (block, start, length) => {
  const raw = block.subarray(start, start + length);
  const end = raw.indexOf(0);
  return raw.subarray(0, end === -1 ? length : end).toString("utf8");
};

// Reads `package/package.json` from an npm/pnpm pack tarball (gzip + ustar).
// Only regular files and directories are accepted; anything else (links, PAX
// or GNU long-name records, a duplicated or missing package.json, a truncated
// archive) fails closed rather than guessing which entry a client would use.
export function readPackedPackageJson(bytes) {
  let tar;
  try { tar = gunzipSync(bytes, { maxOutputLength: MAX_UNPACKED }); }
  catch (error) { refuse("TARBALL_UNREADABLE", `tarball is not a readable gzip archive: ${error.message}`); }
  let offset = 0, found;
  while (true) {
    if (offset + 512 > tar.length) refuse("TARBALL_UNREADABLE", "tarball is truncated");
    const header = tar.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) break;
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : header[i];
    if (Number.parseInt(field(header, 148, 8).trim(), 8) !== sum) refuse("TARBALL_UNREADABLE", "tar header checksum mismatch");
    const type = String.fromCharCode(header[156] || 48);
    const prefix = field(header, 345, 155);
    const name = prefix ? `${prefix}/${field(header, 0, 100)}` : field(header, 0, 100);
    const sizeField = field(header, 124, 12).trim();
    if (!/^[0-7]+$/.test(sizeField)) refuse("TARBALL_UNREADABLE", `invalid size for ${name}`);
    const size = Number.parseInt(sizeField, 8);
    if (type !== "0" && type !== "5") refuse("TARBALL_UNSUPPORTED_ENTRY", `unsupported tar entry type ${JSON.stringify(type)} for ${name}`);
    const start = offset + 512;
    if (start + size > tar.length) refuse("TARBALL_UNREADABLE", `tarball is truncated in ${name}`);
    if (type === "0" && name === "package/package.json") {
      if (found !== undefined) refuse("TARBALL_UNSUPPORTED_ENTRY", "tarball contains package/package.json more than once");
      found = tar.subarray(start, start + size).toString("utf8");
    }
    offset = start + Math.ceil(size / 512) * 512;
  }
  if (found === undefined) refuse("TARBALL_UNREADABLE", "tarball has no package/package.json");
  try { return JSON.parse(found); }
  catch { refuse("TARBALL_UNREADABLE", "package/package.json is not valid JSON"); }
}

// Throws PromotionFloorError, or returns { candidate, current }.
// `p` is the manifest entry selected for publication; `current` is the version
// `latest` was just observed to point to (null when the tag is absent).
// `readTarball(p)` returns the frozen tarball bytes and `integrityOf(bytes)` their
// npm SRI string; both are injected so the caller's existing tarball containment
// and integrity helpers are the only way bytes are read.
export function assertLatestPromotionAllowed({ p, current, releaseDir, readTarball, integrityOf, policy = POLICY }) {
  const meta = policy[p.package];
  if (!meta) refuse("PROMOTION_POLICY_MISSING", `${p.package} is not in the release POLICY`);
  let bytes;
  try { bytes = readTarball(releaseDir, p); }
  catch (error) { refuse("TARBALL_UNREADABLE", `${p.package}: frozen tarball unavailable: ${error.message}`); }
  if (integrityOf(bytes) !== p.integrity) {
    refuse("TARBALL_INTEGRITY_MISMATCH", `${p.package}: tarball bytes do not match the manifest integrity ${p.integrity}`);
  }
  const packed = readPackedPackageJson(bytes);
  if (packed?.name !== p.package) refuse("TARBALL_VERSION_MISMATCH", `${p.package}: tarball declares package ${JSON.stringify(packed?.name)}`);
  const candidate = packed.version;
  if (typeof candidate !== "string" || !STRICT_VERSION.test(candidate)) {
    refuse("TARBALL_VERSION_MISMATCH", `${p.package}: tarball version ${JSON.stringify(candidate)} is not a SemVer version`);
  }
  if (candidate !== p.version || candidate !== meta.version) {
    refuse("TARBALL_VERSION_MISMATCH",
      `${p.package}: tarball version ${candidate}, manifest ${p.version}, POLICY ${meta.version}; all three must be equal`);
  }
  if (PRERELEASE.test(candidate)) refuse("LATEST_PRERELEASE_REFUSED", `${p.package}@${candidate} is a prerelease and cannot be tagged latest`);
  if (current !== null) {
    if (typeof current !== "string" || !STRICT_VERSION.test(current)) {
      refuse("DIST_TAG_STATE_UNDETERMINED", `${p.package}: latest points to ${JSON.stringify(current)}, which is not a SemVer version`);
    }
    // `latest` already on this exact name@version (for example after a resumed
    // run whose effect landed): no promotion is performed, nothing to refuse.
    if (current === candidate) return { candidate, current, alreadyCurrent: true };
    if (compareVersions(candidate, current) <= 0) {
      refuse("LATEST_NOT_ADVANCING", `${p.package}: candidate ${candidate} is not greater than the current latest ${current}`);
    }
  }
  return { candidate, current, alreadyCurrent: false };
}

export function readFrozenTarball(releaseDir, p) {
  return readFileSync(manifestTarball(releaseDir, p.tarball));
}
