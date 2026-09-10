#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import math
import sys
import unicodedata
from pathlib import Path
from typing import Any, Iterable, List, Tuple

SAFE_MIN = -9007199254740991
SAFE_MAX = 9007199254740991


class CanonicalError(Exception):
    pass


class CanonicalObject(dict):
    """Preserves pair order to detect duplicates after NFC normalization."""

    def __init__(self, pairs: Iterable[Tuple[str, Any]]):
        super().__init__()
        self._pairs: List[Tuple[str, Any]] = list(pairs)
        for k, v in self._pairs:
            super().__setitem__(k, v)


def normalize_string(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def to_integer(value: Any) -> int:
    if isinstance(value, bool):
        raise CanonicalError("UNSUPPORTED_TYPE")
    if isinstance(value, int):
        if value < SAFE_MIN or value > SAFE_MAX:
            raise CanonicalError("UNSAFE_INTEGER_NUMBER")
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value) or not value.is_integer():
            raise CanonicalError("FLOAT_NOT_ALLOWED")
        iv = int(value)
        if iv < SAFE_MIN or iv > SAFE_MAX:
            raise CanonicalError("UNSAFE_INTEGER_NUMBER")
        return iv
    raise CanonicalError("UNSUPPORTED_TYPE")


def canonicalize_timestamp(value: Any) -> str:
    try:
        iv = to_integer(value)
    except CanonicalError:
        raise CanonicalError("INVALID_TIMESTAMP")
    return str(iv)


def canonicalize(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(normalize_string(value), ensure_ascii=False)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(to_integer(value))
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        return canonicalize_object(value)
    raise CanonicalError("UNSUPPORTED_TYPE")


def canonicalize_object(obj: dict) -> str:
    pairs = obj._pairs if isinstance(obj, CanonicalObject) else list(obj.items())

    normalized_pairs: List[Tuple[str, Any]] = []
    seen = set()

    for key, val in pairs:
        if not isinstance(key, str):
            raise CanonicalError("UNSUPPORTED_TYPE")
        nkey = normalize_string(key)
        if nkey in seen:
            raise CanonicalError("DUPLICATE_KEY")
        seen.add(nkey)
        normalized_pairs.append((nkey, val))

    normalized_pairs.sort(key=lambda kv: kv[0].encode("utf-8"))

    parts = []
    for key, val in normalized_pairs:
        if key == "ts":
            vjson = canonicalize_timestamp(val)
        else:
            vjson = canonicalize(val)
        parts.append(f"{json.dumps(key, ensure_ascii=False)}:{vjson}")

    return "{" + ",".join(parts) + "}"


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def load_vectors() -> list[dict[str, Any]]:
    vectors_path = (
        Path(__file__).resolve().parent.parent
        / "docs"
        / "spec"
        / "test-vectors"
        / "canonicalization-v1.json"
    )
    with vectors_path.open("r", encoding="utf-8") as f:
        return json.load(f, object_pairs_hook=CanonicalObject)


def main() -> int:
    vectors = load_vectors()
    failed = 0

    for vector in vectors:
        vid = vector["id"]
        status = vector["status"]
        expected_err = vector.get("expected_error", "")
        try:
            canonical_json = canonicalize(vector["input"])
            digest = sha256_hex(canonical_json)

            if status == "error":
                failed += 1
                print(f"FAIL {vid}: expected error {expected_err}, got success", file=sys.stderr)
                continue

            if canonical_json != vector.get("expected_canonical_json", ""):
                failed += 1
                print(f"FAIL {vid}: canonical JSON mismatch", file=sys.stderr)
                print(f"  expected: {vector.get('expected_canonical_json','')}", file=sys.stderr)
                print(f"  actual:   {canonical_json}", file=sys.stderr)
                continue

            if vector.get("expected_sha256") and digest != vector["expected_sha256"]:
                failed += 1
                print(f"FAIL {vid}: SHA-256 mismatch", file=sys.stderr)
                print(f"  expected: {vector['expected_sha256']}", file=sys.stderr)
                print(f"  actual:   {digest}", file=sys.stderr)
                continue

            print(f"PASS {vid}")
        except CanonicalError as err:
            if status == "ok":
                failed += 1
                print(f"FAIL {vid}: unexpected error {err}", file=sys.stderr)
                continue
            if str(err) != expected_err:
                failed += 1
                print(f"FAIL {vid}: wrong error", file=sys.stderr)
                print(f"  expected: {expected_err}", file=sys.stderr)
                print(f"  actual:   {err}", file=sys.stderr)
                continue
            print(f"PASS {vid}")

    if failed:
        print(f"\n{failed} vector(s) failed", file=sys.stderr)
        return 1

    print(f"\nAll {len(vectors)} vector(s) passed (diagnostic only; scoped report: pnpm test:vectors:py)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
