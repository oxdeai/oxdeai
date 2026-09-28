// SPDX-License-Identifier: Apache-2.0
// Site identity drift check for index.html. No dependencies: node:test only.
//
// Canonical identity (evidence: the GitHub repository homepage and the oxdeai
// organization website are both https://www.oxdeai.dev/, which serves this page):
//   website  https://www.oxdeai.dev/
//   source   https://github.com/oxdeai/oxdeai
//   npm      https://www.npmjs.com/package/@oxdeai/*
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const SITE = "https://www.oxdeai.dev/";
const REPO = "https://github.com/oxdeai/oxdeai";
const ORG = "https://github.com/oxdeai";

const root = fileURLToPath(new URL(".", import.meta.url));
const html = readFileSync(root + "index.html", "utf8");

function tag(attr, name) {
  const re = new RegExp(`<(?:meta|link)\\s[^>]*${attr}="${name}"[^>]*>`, "g");
  return [...html.matchAll(re)].map((m) => m[0].replace(/\s+/g, " "));
}
function value(el, key) {
  return el.match(new RegExp(`${key}="([^"]*)"`))?.[1];
}
function one(attr, name, key) {
  const els = tag(attr, name);
  assert.equal(els.length, 1, `expected exactly one ${attr}="${name}"`);
  return value(els[0], key);
}
/** Map an absolute URL on the canonical site to the file that serves it. */
function localFile(url) {
  assert.ok(url.startsWith(SITE), `${url} is not hosted on ${SITE}`);
  return root + url.slice(SITE.length);
}
function pngSize(file) {
  const b = readFileSync(file);
  assert.equal(b.toString("latin1", 1, 4), "PNG", `${file} is not a PNG`);
  return [b.readUInt32BE(16), b.readUInt32BE(20)];
}
function jsonLdNodes() {
  const blocks = [...html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)];
  assert.equal(blocks.length, 1, "expected exactly one JSON-LD block");
  const doc = JSON.parse(blocks[0][1]);
  return doc["@graph"] ?? [doc];
}

test("canonical and og:url identify the official website", () => {
  assert.equal(one("rel", "canonical", "href"), SITE);
  assert.equal(one("property", "og:url", "content"), SITE);
});

test("social preview images are hosted on the website and exist", () => {
  const og = one("property", "og:image", "content");
  assert.equal(one("name", "twitter:image", "content"), og);
  const [w, h] = pngSize(localFile(og));
  assert.equal(String(w), one("property", "og:image:width", "content"));
  assert.equal(String(h), one("property", "og:image:height", "content"));
});

test("icon declarations use the canonical mark and resolve to files", () => {
  const icons = tag("rel", "icon").map((el) => value(el, "href"));
  assert.deepEqual(icons.sort(), ["assets/logo-mark.png", "assets/logo-mark.svg"]);
  for (const href of icons) assert.ok(existsSync(root + href), `missing icon ${href}`);
});

test("JSON-LD separates the website from the source repository", () => {
  const nodes = jsonLdNodes();
  const byType = (t) => {
    const found = nodes.filter((n) => n["@type"] === t);
    assert.equal(found.length, 1, `expected one ${t} node`);
    return found[0];
  };
  assert.equal(byType("WebSite").url, SITE);

  const org = byType("Organization");
  assert.equal(org.url, SITE);
  assert.ok(existsSync(localFile(org.logo)), `missing logo ${org.logo}`);
  assert.deepEqual(org.sameAs, [ORG]);

  assert.equal(byType("SoftwareSourceCode").codeRepository, REPO);

  // GitHub is source identity only: never a node's url.
  for (const n of nodes) {
    assert.ok(!String(n.url ?? "").includes("github.com"), `${n["@type"]}.url points at GitHub`);
  }
});

test("head metadata does not hotlink raw.githubusercontent.com", () => {
  const head = html.slice(0, html.indexOf("</head>"));
  assert.doesNotMatch(head, /raw\.githubusercontent\.com/);
});

test("GitHub and npm links target the OxDeAI repository, organization and packages", () => {
  const urls = [...html.matchAll(/https?:\/\/[^"'<>\s]+/g)].map((m) => m[0]);
  const github = urls.filter((u) => u.includes("github.com"));
  const npm = urls.filter((u) => u.includes("npmjs."));
  assert.ok(github.length > 0 && npm.length > 0);
  for (const u of github) {
    assert.ok(u === ORG || u === REPO || u.startsWith(REPO + "/"), `unexpected GitHub URL ${u}`);
  }
  for (const u of npm) {
    assert.match(u, /^https:\/\/www\.npmjs\.com\/package\/@oxdeai\/[a-z0-9-]+$/, `unexpected npm URL ${u}`);
  }
});
