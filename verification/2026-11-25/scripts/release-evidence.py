"""Host-side evidence handler for reproduce-oxdeai-release.sh.

Actions: fetch RUN | compare RUN | summary RUN | sanitize
Build output is untrusted: it is never extracted to disk, executed, or printed
without removing terminal control characters first.
"""
import base64
import csv
import difflib
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import unicodedata
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, build_opener

MAX_PACKAGE = 32 * 1024 * 1024      # compressed .tgz
MAX_UNPACKED = 64 * 1024 * 1024     # all entries of one .tgz, uncompressed
MAX_ENTRIES = 5000
MAX_LINE = 65536
FIELDS = ["package", "version", "tag", "directory", "sha256", "integrity"]


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise ValueError("Unexpected registry redirect")


def clean(text):
    """Drop control and format characters (ANSI escapes, C1, bidi overrides), keep tabs."""
    return "".join(ch for ch in text if ch == "\t" or unicodedata.category(ch) not in ("Cc", "Cf"))


def download(url, limit):
    parts = urlsplit(url)
    if (parts.scheme, parts.netloc) != ("https", "registry.npmjs.org"):
        raise ValueError("Unexpected registry origin")
    with build_opener(NoRedirect).open(url, timeout=45) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Response exceeded size limit")
    return data


def hashes(data):
    return (hashlib.sha256(data).hexdigest(),
            "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode())


def filename(row):
    return row["package"][1:].replace("/", "-") + "-" + row["version"] + ".tgz"


def fetch(run, rows):
    published = run / "published"
    published.mkdir()
    for row in rows:
        name, version = row["package"], row["version"]
        raw = download("https://registry.npmjs.org/" + quote(name, safe="") + "/" + version, 1024**2)
        info = json.loads(raw)
        if (info["name"], info["version"]) != (name, version):
            raise ValueError(f"Registry metadata mismatch for {name}")
        data = download(info["dist"]["tarball"], MAX_PACKAGE)
        sha, sri = hashes(data)
        if (sha, sri) != (row["sha256"], row["integrity"]) or sri != info["dist"]["integrity"]:
            raise ValueError(f"Registry integrity mismatch for {name}")
        path = published / filename(row)
        path.write_bytes(data)
        path.with_suffix(".json").write_bytes(raw)
        print(f"[OK] {name} {version}: registry sha512 and supplied sha256 match ({sha})")


def entries(data):
    """Bounded in-memory read of a .tgz: {name: (type, mode, mtime, uid, gid, linkname, bytes)}."""
    raw = gzip.GzipFile(fileobj=io.BytesIO(data)).read(MAX_UNPACKED + 1)
    if len(raw) > MAX_UNPACKED:
        raise ValueError("Package exceeds unpacked size limit")
    out = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for count, member in enumerate(archive):
            if count >= MAX_ENTRIES:
                raise ValueError("Package has too many entries")
            body = archive.extractfile(member).read() if member.isreg() else b""
            out[member.name] = (member.type, member.mode, member.mtime, member.uid,
                                member.gid, member.linkname, body)
        order = archive.getnames()
    return out, order


def explain(published, rebuilt, diff_path):
    """Return human-readable lines naming what differs; write a text diff to diff_path."""
    a, order_a = entries(published)
    b, order_b = entries(rebuilt)
    notes, diff_text = [], []
    for name in sorted(set(a) | set(b)):
        if name not in b:
            notes.append(f"only in published: {name}")
        elif name not in a:
            notes.append(f"only in rebuilt: {name}")
        elif a[name] != b[name]:
            meta = [k for k, i in (("type", 0), ("mode", 1), ("mtime", 2), ("uid", 3),
                                   ("gid", 4), ("link", 5), ("content", 6)) if a[name][i] != b[name][i]]
            notes.append(f"differs ({', '.join(meta)}): {name}")
            if "content" in meta:
                left = a[name][6].decode("utf-8", "replace").splitlines()
                right = b[name][6].decode("utf-8", "replace").splitlines()
                diff_text += difflib.unified_diff(left, right, "published/" + name,
                                                  "rebuilt/" + name, lineterm="", n=1)
    if set(a) == set(b) and order_a != order_b:
        notes.append("entry order differs")
    if not notes:
        notes.append("all entries identical; gzip or tar header bytes differ")
    if diff_text:
        diff_path.write_text("\n".join(diff_text) + "\n")
    return notes, len(a), diff_text


def compare(run, rows):
    expected = {}
    for row in rows:
        for attempt in (1, 2):
            slug = row["package"].split("/")[1]
            expected[f"{attempt}/{slug}/{filename(row)}"] = (row["package"], attempt)
    observed = {}
    seen = set()
    # Never extract paths or follow links from the build output stream.
    with tarfile.open(run / "output.tar", mode="r|") as stream:
        for entry in stream:
            if entry.isdir():
                continue
            if (entry.name not in expected or entry.name in seen or
                    entry.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or
                    entry.sparse is not None or entry.size > MAX_PACKAGE or entry.size < 0):
                raise ValueError(f"Invalid build output member {clean(entry.name[:120])!r}")
            seen.add(entry.name)
            data = stream.extractfile(entry).read()
            dest = run / "rebuilt" / entry.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            observed[expected[entry.name]] = dest
    print()
    print("=" * 54)
    print("ARTIFACT COMPARISON (byte for byte, published npm tarball vs rebuilt pack)")
    print("=" * 54)
    results = []
    for row in rows:
        name = row["package"]
        reference = (run / "published" / filename(row)).read_bytes()
        if hashes(reference) != (row["sha256"], row["integrity"]):
            raise ValueError(f"Saved reference failed verification for {name}")
        packs = [observed.get((name, attempt)) for attempt in (1, 2)]
        values = [path.read_bytes() if path else None for path in packs]
        status = ("INCOMPLETE" if None in values else
                  "MATCH" if all(value == reference for value in values) else "DIFF")
        rebuilt = [hashes(v)[0] if v is not None else None for v in values]
        result = dict(package=name, version=row["version"], verdict=status,
                      packs_agree=None if None in values else values[0] == values[1],
                      published_sha256=row["sha256"], rebuilt_sha256=rebuilt, notes=[])
        print(f"{name} {row['version']}")
        print(f"  published {row['sha256']}")
        print(f"  rebuilt   {rebuilt[0] or 'missing'} (pack 1)")
        print(f"            {rebuilt[1] or 'missing'} (pack 2)")
        if status == "MATCH":
            print("  [OK] byte-for-byte IDENTICAL")
        elif status == "INCOMPLETE":
            print("  [ERROR] pack missing from build output")
        else:
            diff_path = run / "diffs" / (name.split("/")[1] + ".diff")
            diff_path.parent.mkdir(exist_ok=True)
            notes, total, diff_text = explain(reference, values[0], diff_path)
            result["notes"] = notes
            result["entries"] = total
            print(f"  [WARNING] differs: {len(notes)} of {total} entries")
            for note in notes[:10]:
                print("    " + clean(note))
            if diff_text:
                print(f"  First differences, {len(diff_text)} lines in total:")
                for line in diff_text[:8]:
                    print("    " + clean(line)[:200])
                print(f"  Full diff: {diff_path}")
        results.append(result)
    (run / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    if any(row["verdict"] == "INCOMPLETE" for row in results):
        return 2
    return int(any(row["verdict"] == "DIFF" for row in results))


def summary(run, rows):
    """Print the WalletScrutiny-style summary from results.json and the host facts file."""
    facts = dict(line.split("=", 1) for line in (run / "facts.txt").read_text().splitlines() if "=" in line)
    path = run / "results.json"
    results = json.loads(path.read_text()) if path.exists() else []
    verdicts = [r["verdict"] for r in results]
    if not results or "INCOMPLETE" in verdicts:
        verdict = "incomplete"
    elif all(v == "MATCH" for v in verdicts):
        verdict = "reproducible"
    else:
        verdict = "not_reproducible"
    same = sum(v == "MATCH" for v in verdicts)
    print()
    print("HASH LEGEND")
    print("  published   sha256 of the tarball the npm registry serves (also checked against Ange's list).")
    print("  rebuilt     sha256 of the tarball `pnpm pack` produced in this build.")
    print("  scriptHash  sha256 of reproduce-oxdeai-release.sh; helperHash of release-evidence.py.")
    print()
    print("===== Begin Results =====")
    for key, value in (("project:", "oxdeai (https://github.com/oxdeai/oxdeai)"),
                       ("packages:", f"{len(rows)} @oxdeai packages, {same} identical"),
                       ("verdict:", verdict), ("commit:", facts["commit"]),
                       ("scriptHash:", facts["script_sha256"]),
                       ("helperHash:", facts["helper_sha256"])):
        print(f"{key:<15} {value}")
    print()
    print("Diff:")
    for r in results:
        if r["verdict"] == "MATCH":
            print(f"{r['package']} {r['version']}: identical ({r['published_sha256']})")
        else:
            print(f"{r['package']} {r['version']}: published {r['published_sha256']}, "
                  f"rebuilt {r['rebuilt_sha256'][0] or 'N/A'}")
            for note in r.get("notes", [])[:10]:
                print("  " + clean(note))
    print()
    print("Revision, tags (and their signatures):")
    print(f"commit:         {facts['commit']}")
    print(f"tags:           {facts['tags']}")
    print()
    print("Signature Summary:")
    print(facts["commit_signature"])
    print("[WARNING] Tags are annotated but not signed; only the commit signature is checked")
    print()
    print("Published packages:")
    print(f"[OK] {len(rows)} of {len(rows)} registry tarballs match the supplied sha256 "
          "and the registry's sha512 integrity")
    print()
    print("Keys used:")
    print(f"Commit signed with: {facts['signer']} (key supplied by Ange)")
    print("===== End Results =====")
    print()
    print("Build environment:")
    print(f"image:          {facts['image_tag']} {facts['image']}")
    print(f"                base {facts['base_image']} (eclipse-temurin:17-jre, Ubuntu 26.04) + git from Ubuntu's apt")
    print(f"node:           v22.23.4, sha256 {facts['node_sha256']}")
    print(f"pnpm:           10.34.5, package tree sha256 {facts['pnpm_sha256']}")
    print(f"lockfile:       pnpm-lock.yaml sha256 {facts['lockfile_sha256']}")
    print(f"store:          {facts['store']}")
    print("container:      rootless Podman, no network, read-only root, uid 65534, no capabilities,")
    print("                no-new-privileges, 3 GB memory, 2 CPUs, 160 processes, 10-minute limit,")
    print("                no writable host mount (packs return as a size-limited tar stream)")
    print(f"elapsed:        {facts['elapsed']}")
    print()
    print("Limitations:")
    print("- Node and pnpm are the npm packages node-linux-x64 and pnpm in OXDEAI_TOOLS; the script checks")
    print("  their versions and prints their hashes, but does not verify them against upstream signatures.")
    print("- Dependencies come from the npm registry via stage-oxdeai-store.sh, checked by pnpm against the")
    print("  sha512 values in the signed commit's lockfile. Dependency install scripts did not run.")
    print("- Built once on Linux x64 under Ubuntu 26.04; the release machine's environment is not recorded.")
    print("- Both packs come from the same build, so matching packs show pack stability, not build stability.")
    print()
    return {"reproducible": 0, "not_reproducible": 1}.get(verdict, 2)


def sanitize():
    """Copy stdin to stdout line by line, removing terminal control characters."""
    source, sink = sys.stdin.buffer, sys.stdout
    while True:
        line = source.readline(MAX_LINE)
        if not line:
            return 0
        sink.write(clean(line.decode("utf-8", "replace")) + "\n")
        sink.flush()


def read_rows(directory):
    with (directory / "selected.tsv").open() as file:
        return list(csv.DictReader(file, delimiter="\t", fieldnames=FIELDS))


if __name__ == "__main__":
    if sys.argv[1:] == ["sanitize"]:
        sys.exit(sanitize())
    action, path = sys.argv[1:]
    directory = Path(path)
    actions = {"fetch": fetch, "compare": compare, "summary": summary}
    if action not in actions:
        sys.exit("Unknown operation")
    sys.exit(actions[action](directory, read_rows(directory)))
