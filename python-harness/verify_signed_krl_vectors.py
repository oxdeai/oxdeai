#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
SignedKRLV1 cross-language conformance verifier.

Reads docs/spec/test-vectors/signed-krl-v1.json and independently
reconstructs each signing preimage, verifies Ed25519 signatures via
ctypes + libcrypto (OpenSSL), and checks all 9 portable vectors against
expected reason-code verdicts.

Reuses the canonicalization-v1 implementation from verify_canonicalization_vectors.py.
"""
from __future__ import annotations

import base64
import json
import sys
from enum import Enum
from pathlib import Path
from typing import Any

# Reuse canonical JSON from the existing canonicalization harness.
# main() in that module is guarded by __name__, so it will not run on import.
from verify_canonicalization_vectors import canonicalize  # noqa: E402

# Shared Ed25519 / OpenSSL utilities (extracted to avoid duplication with
# verify_profile_c_vectors.py which also needs Encoding B verification).
from ed25519_utils import (  # noqa: E402
    InfrastructureError as _InfrastructureError,
    parse_ed25519_pem as _parse_ed25519_pem,
    ed25519_verify as _ed25519_verify,
)


# ── KRL reason-code constants ─────────────────────────────────────────────────

# KRL verification status strings — module constants so no inline literals.
_STATUS_OK      = "ok"
_STATUS_INVALID = "invalid"


class KrlReasonCode(str, Enum):
    MALFORMED              = "KRL_MALFORMED"
    SIG_INVALID            = "KRL_SIG_INVALID"
    EXPIRED                = "KRL_EXPIRED"
    UNSUPPORTED_ALG        = "KRL_UNSUPPORTED_ALG"
    UNKNOWN_SIGNING_KID    = "KRL_UNKNOWN_SIGNING_KID"
    SIGNING_KEY_INACTIVE   = "KRL_SIGNING_KEY_INACTIVE"
    VERSION_REGRESSION     = "KRL_VERSION_REGRESSION"


def _find_krl_key(
    trusted_key_sets: list[dict[str, Any]],
    issuer: str,
    kid: str,
) -> dict[str, Any] | None:
    """Return the first key entry matching issuer, kid, and alg=='Ed25519'."""
    for ks in trusted_key_sets:
        if ks.get("issuer") != issuer:
            continue
        for key in ks.get("keys", []):
            if key.get("kid") == kid and key.get("alg") == "Ed25519":
                return key
    return None


def _key_is_active_at(key: dict[str, Any], now_sec: int) -> bool:
    """Mirror keyIsActiveAt from @oxdeai/core.

    - status == "revoked" → False
    - not_before present && now < not_before → False
    - not_after  present && now > not_after  → False
    - otherwise → True
    """
    if key.get("status") == "revoked":
        return False
    not_before = key.get("not_before")
    if not_before is not None and now_sec < not_before:
        return False
    not_after = key.get("not_after")
    if not_after is not None and now_sec > not_after:
        return False
    return True


# ── Signing payload ───────────────────────────────────────────────────────────

def _build_krl_signing_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct signedKrlSigningPayload from a full SignedKRLV1 envelope.

    Includes all normative fields except signature.sig:
    version, issuer, krl_version, issued_at, not_after, revoked_kids,
    nonce (when present), signature.alg, signature.kid.
    """
    sig = envelope["signature"]
    payload: dict[str, Any] = {
        "version":      envelope["version"],
        "issuer":       envelope["issuer"],
        "krl_version":  envelope["krl_version"],
        "issued_at":    envelope["issued_at"],
        "not_after":    envelope["not_after"],
        "revoked_kids": envelope["revoked_kids"],
        "signature": {
            "alg": sig["alg"],
            "kid": sig["kid"],
            # sig.sig intentionally excluded
        },
    }
    if "nonce" in envelope:
        payload["nonce"] = envelope["nonce"]
    return payload


# ── Verifier ──────────────────────────────────────────────────────────────────

def _invalid(code: KrlReasonCode) -> tuple[str, list[dict[str, str]]]:
    return _STATUS_INVALID, [{"code": code.value}]


def _verify_signed_krl(
    envelope: dict[str, Any],
    now_sec: int,
    trusted_key_sets: list[dict[str, Any]],
    prev_versions: dict[str, int] | None,
) -> tuple[str, list[dict[str, str]]]:
    """Verify a SignedKRLV1 envelope.

    Returns (status, violations) where status is _STATUS_OK or _STATUS_INVALID.
    Raises _InfrastructureError on infrastructure failure (PEM parse, etc.).

    Check order (mirrors @oxdeai/core verifySignedKrl and Go signed_krl_verify.go):
      1. structural / malformed  → KRL_MALFORMED
      2. unsupported alg         → KRL_UNSUPPORTED_ALG
      3. kid lookup              → KRL_UNKNOWN_SIGNING_KID
      4. key activity            → KRL_SIGNING_KEY_INACTIVE
      5. expiry                  → KRL_EXPIRED
      6. version regression      → KRL_VERSION_REGRESSION
      7. signature               → KRL_SIG_INVALID
    """
    # ── 1. Structural checks (early return on first violation) ────────────

    # version
    if envelope.get("version") != "SignedKRLV1":
        return _invalid(KrlReasonCode.MALFORMED)

    # issuer
    issuer = envelope.get("issuer")
    if not isinstance(issuer, str) or not issuer:
        return _invalid(KrlReasonCode.MALFORMED)

    # krl_version (non-negative integer)
    krl_version = envelope.get("krl_version")
    if not isinstance(krl_version, int) or isinstance(krl_version, bool) or krl_version < 0:
        return _invalid(KrlReasonCode.MALFORMED)

    # issued_at (integer — informational only)
    if not isinstance(envelope.get("issued_at"), int) or isinstance(envelope.get("issued_at"), bool):
        return _invalid(KrlReasonCode.MALFORMED)

    # not_after (integer)
    not_after = envelope.get("not_after")
    if not isinstance(not_after, int) or isinstance(not_after, bool):
        return _invalid(KrlReasonCode.MALFORMED)

    # revoked_kids: array of strings, no duplicates
    revoked_kids = envelope.get("revoked_kids")
    if not isinstance(revoked_kids, list):
        return _invalid(KrlReasonCode.MALFORMED)
    seen_kids: set[str] = set()
    for k in revoked_kids:
        if not isinstance(k, str):
            return _invalid(KrlReasonCode.MALFORMED)
        if k in seen_kids:
            return _invalid(KrlReasonCode.MALFORMED)
        seen_kids.add(k)

    # signature object
    sig = envelope.get("signature")
    if not isinstance(sig, dict):
        return _invalid(KrlReasonCode.MALFORMED)

    # ── 2. Unsupported algorithm ──────────────────────────────────────────
    alg = sig.get("alg")
    if not isinstance(alg, str) or not alg:
        return _invalid(KrlReasonCode.MALFORMED)
    if alg != "Ed25519":
        return _invalid(KrlReasonCode.UNSUPPORTED_ALG)

    # signature.kid and signature.sig structural presence
    kid = sig.get("kid")
    if not isinstance(kid, str) or not kid:
        return _invalid(KrlReasonCode.MALFORMED)
    sig_str = sig.get("sig")
    if not isinstance(sig_str, str) or not sig_str:
        return _invalid(KrlReasonCode.MALFORMED)

    # ── 3. Kid lookup ─────────────────────────────────────────────────────
    key_entry = _find_krl_key(trusted_key_sets, issuer, kid)
    if key_entry is None:
        return _invalid(KrlReasonCode.UNKNOWN_SIGNING_KID)

    # ── 4. Key activity ───────────────────────────────────────────────────
    if not _key_is_active_at(key_entry, now_sec):
        return _invalid(KrlReasonCode.SIGNING_KEY_INACTIVE)

    # ── 5. Expiry (strict zero-tolerance: now >= not_after → KRL_EXPIRED) ─
    if now_sec >= not_after:
        return _invalid(KrlReasonCode.EXPIRED)

    # ── 6. Version regression ─────────────────────────────────────────────
    if prev_versions:
        prev = prev_versions.get(issuer)
        if prev is not None and krl_version < prev:
            return _invalid(KrlReasonCode.VERSION_REGRESSION)

    # ── 7. Signature verification ─────────────────────────────────────────

    # PEM parse failure is an infrastructure error, not a test outcome.
    pub_key_pem: str = key_entry.get("public_key", "")
    raw_pub = _parse_ed25519_pem(pub_key_pem)  # raises _InfrastructureError on failure

    # Reconstruct signing payload and build domain-prefixed preimage.
    signing_payload = _build_krl_signing_payload(envelope)
    canonical = canonicalize(signing_payload)
    preimage = b"OXDEAI_KRL_V1\n" + canonical.encode("utf-8")

    # Decode base64 signature (standard base64 as committed in the vector file).
    try:
        sig_bytes = base64.b64decode(sig_str)
    except Exception:
        return _invalid(KrlReasonCode.SIG_INVALID)

    if not _ed25519_verify(raw_pub, preimage, sig_bytes):
        return _invalid(KrlReasonCode.SIG_INVALID)

    return _STATUS_OK, []


# ── Vector loading ────────────────────────────────────────────────────────────

def _load_vectors() -> list[dict[str, Any]]:
    path = (
        Path(__file__).resolve().parent.parent
        / "docs" / "spec" / "test-vectors"
        / "signed-krl-v1.json"
    )
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data["vectors"]


# ── Runner ────────────────────────────────────────────────────────────────────

def main() -> int:
    vectors = _load_vectors()
    failed = 0

    for vector in vectors:
        vid: str = vector["id"]
        inp = vector["input"]
        envelope: dict[str, Any] = inp["envelope"]
        opts: dict[str, Any] = inp["opts"]
        expected: dict[str, Any] = vector["expected"]

        now_sec: int = opts["now"]
        trusted_key_sets: list[dict[str, Any]] = opts["trustedKeySets"]
        prev_versions: dict[str, int] | None = opts.get("previousKrlVersionByIssuer")

        try:
            status, violations = _verify_signed_krl(
                envelope, now_sec, trusted_key_sets, prev_versions
            )
        except _InfrastructureError as exc:
            print(f"FATAL [{vid}]: infrastructure error: {exc}", file=sys.stderr)
            sys.exit(1)

        expected_status: str = expected["status"]
        expected_violations: list[dict[str, Any]] = expected["violations"]

        # Compare status
        if status != expected_status:
            failed += 1
            print(f"FAIL {vid}: status mismatch", file=sys.stderr)
            print(f"  expected: {expected_status}", file=sys.stderr)
            print(f"  actual:   {status}", file=sys.stderr)
            continue

        # Compare violations
        if len(violations) != len(expected_violations):
            failed += 1
            print(
                f"FAIL {vid}: violations count mismatch "
                f"(expected {len(expected_violations)}, got {len(violations)})",
                file=sys.stderr,
            )
            continue

        mismatch = False
        for i, ev in enumerate(expected_violations):
            expected_code: str = ev["code"]
            actual_code: str = violations[i]["code"] if i < len(violations) else "(missing)"
            if actual_code != expected_code:
                mismatch = True
                print(f"FAIL {vid}: violation[{i}] code mismatch", file=sys.stderr)
                print(f"  expected: {expected_code}", file=sys.stderr)
                print(f"  actual:   {actual_code}", file=sys.stderr)
                break

        if mismatch:
            failed += 1
            continue

        print(f"PASS {vid}")

    if failed:
        print(f"\n{failed} SignedKRL vector(s) failed", file=sys.stderr)
        return 1

    print(f"\nAll {len(vectors)} SignedKRL vector(s) passed (diagnostic only; scoped report: pnpm test:vectors:py)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
