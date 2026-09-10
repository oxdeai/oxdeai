#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Profile C state-hash semantics cross-language conformance verifier.

Validates all 8 modes from docs/spec/test-vectors/profile-c-state-verification.json:
  - Modes 001–005: canonicalization-v1 + SHA-256 only
  - Modes 006–008: additionally require Encoding B AuthorizationV1 signature
    verification (alg='ed25519', expires_at, base64url signature, NO domain prefix)

Independent verification model:
  - Modes 001–005: compute state hashes from raw state_input JSON, compare outcomes
  - Modes 006–008: (1) independently verify Encoding B signature using canonical
    signing payload, (2) compute committedHash from state_input, cross-check with
    auth.state_hash as byte-equivalence proof, (3) compare with liveHash

Reuses canonicalization-v1 from verify_canonicalization_vectors.py.
Reuses Ed25519 utilities from ed25519_utils.py.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from enum import Enum
from pathlib import Path
from typing import Any, Callable

# Reuse canonical JSON and SHA-256 from the existing canonicalization harness.
# main() in that module is guarded by __name__, so it will not run on import.
from verify_canonicalization_vectors import canonicalize, sha256_hex, CanonicalError  # noqa: E402

# Shared Ed25519 / OpenSSL utilities (also used by verify_signed_krl_vectors.py).
from ed25519_utils import (  # noqa: E402
    InfrastructureError as _InfrastructureError,
    parse_ed25519_pem as _parse_ed25519_pem,
    ed25519_verify as _ed25519_verify,
    decode_base64url as _decode_base64url,
)


# ── Typed outcome constants ───────────────────────────────────────────────────

class ProfileCOutcome(str, Enum):
    OK                  = "ok"
    STATE_HASH_MISMATCH = "state-hash-mismatch"
    COMPUTE_ERROR       = "compute-error"


# ── Hash strategies ───────────────────────────────────────────────────────────

def _compute_core_hash(state: Any) -> str:
    """SHA-256(canonicalJson(state)) — standard OxDeAI state hash."""
    return sha256_hex(canonicalize(state))


def _compute_provider_hash(state: Any) -> str:
    """SHA-256('PROVIDER:' + canonicalJson(state)) — external provider hash."""
    return sha256_hex("PROVIDER:" + canonicalize(state))


def _compute_throws_hash(_state: Any) -> str:
    """Simulates a computeStateHash failure (compute-error outcome)."""
    raise RuntimeError("hash backend unavailable")


def _get_hash_fn(strategy: str) -> Callable[[Any], str] | None:
    return {
        "core":     _compute_core_hash,
        "provider": _compute_provider_hash,
        "throws":   _compute_throws_hash,
    }.get(strategy)


# ── Encoding B AuthorizationV1 verification ───────────────────────────────────

def _build_encoding_b_signing_payload(auth: dict[str, Any]) -> dict[str, Any]:
    """Build Encoding B signing payload from committed auth artifact.

    Includes all auth fields EXCEPT signature.sig.
    signature becomes { alg, kid } with sig excluded.

    Preimage: canonicalJson(result) — NO domain prefix.
    This is the Sift-compatible Encoding B wire format. Different from:
      - Encoding A: uses 'OXDEAI_AUTH_V1\\n' domain prefix
      - SignedKRLV1: uses 'OXDEAI_KRL_V1\\n' domain prefix
    """
    sig = auth["signature"]
    payload = {k: v for k, v in auth.items() if k != "signature"}
    payload["signature"] = {"alg": sig["alg"], "kid": sig["kid"]}
    return payload


def _verify_encoding_b_auth(auth: dict[str, Any], trusted_key_pem: str, vid: str) -> bool:
    """Verify Encoding B AuthorizationV1 artifact.

    Preimage: canonicalJson(signingPayload) — NO domain prefix.
    Signature: base64url Ed25519 (RFC 4648 §5, no padding).

    Raises _InfrastructureError on PEM parse failure.
    Returns True on valid signature, False otherwise.
    """
    sig_str: str = auth["signature"]["sig"]

    # Decode base64url signature (no padding).
    sig_bytes = _decode_base64url(sig_str)

    # Parse public key from SPKI PEM.
    raw_pub = _parse_ed25519_pem(trusted_key_pem)

    # Build signing payload and canonicalize — NO domain prefix.
    signing_payload = _build_encoding_b_signing_payload(auth)
    canonical = canonicalize(signing_payload)
    preimage = canonical.encode("utf-8")

    return _ed25519_verify(raw_pub, preimage, sig_bytes)


# ── Outcome computation ───────────────────────────────────────────────────────

def _compute_outcome(vector: dict[str, Any]) -> ProfileCOutcome:
    mode: str = vector.get("mode", "")

    # compute-throws: directly simulate computeStateHash failure.
    if mode == "compute-throws":
        return ProfileCOutcome.COMPUTE_ERROR

    # Encoding B modes: verify signature first, then compare state hashes.
    if mode.startswith("encoding-b-"):
        return _compute_encoding_b_outcome(vector)

    # Modes 001–005: pure state-hash comparison, no signature work.
    return _compute_state_hash_outcome(vector)


def _compute_state_hash_outcome(vector: dict[str, Any]) -> ProfileCOutcome:
    """Handles modes 001–005 (no signature)."""
    hash_strategy: str = vector.get("hash_strategy", "core")
    signing_strategy: str = vector.get("signing_strategy", hash_strategy)
    verify_strategy: str  = vector.get("verify_strategy",  hash_strategy)

    signing_fn = _get_hash_fn(signing_strategy)
    verify_fn  = _get_hash_fn(verify_strategy)
    if signing_fn is None or verify_fn is None:
        return ProfileCOutcome.COMPUTE_ERROR

    state_input = vector.get("state_input")
    try:
        committed_hash = signing_fn(state_input)
    except Exception:
        return ProfileCOutcome.COMPUTE_ERROR

    live_state = vector.get("live_state_input", state_input)

    try:
        live_hash = verify_fn(live_state)
    except Exception:
        return ProfileCOutcome.COMPUTE_ERROR

    if live_hash == committed_hash:
        return ProfileCOutcome.OK
    return ProfileCOutcome.STATE_HASH_MISMATCH


def _compute_encoding_b_outcome(vector: dict[str, Any]) -> ProfileCOutcome:
    """Handles modes 006–008 (Encoding B).

    Step 1: Verify Encoding B signature independently (fatal on failure — harness bug).
    Step 2: Independently compute committedHash from state_input.
    Step 3: Cross-check committedHash against auth.state_hash (byte-equivalence proof).
    Step 4: Compute liveHash using verify strategy.
    Step 5: Compare liveHash vs committedHash.
    """
    vid: str = vector.get("id", "?")
    auth: dict[str, Any] = vector["auth"]
    opts: dict[str, Any] = vector["opts"]
    trusted_key_pem: str = opts["trustedKey"]["public_key"]

    # Step 1: Verify Encoding B signature independently.
    try:
        sig_valid = _verify_encoding_b_auth(auth, trusted_key_pem, vid)
    except _InfrastructureError as exc:
        print(f"FATAL [{vid}]: Encoding B infrastructure error: {exc}", file=sys.stderr)
        sys.exit(1)

    if not sig_valid:
        print(
            f"FATAL [{vid}]: Encoding B signature verification failed — harness bug "
            f"(wrong preimage or key?)",
            file=sys.stderr,
        )
        sys.exit(1)

    # Step 2: Independently compute committedHash from state_input.
    hash_strategy: str = vector.get("hash_strategy", "provider")
    signing_strategy: str = vector.get("signing_strategy", hash_strategy)
    verify_strategy: str  = vector.get("verify_strategy",  hash_strategy)

    signing_fn = _get_hash_fn(signing_strategy)
    verify_fn  = _get_hash_fn(verify_strategy)
    if signing_fn is None or verify_fn is None:
        return ProfileCOutcome.COMPUTE_ERROR

    state_input = vector.get("state_input")
    try:
        committed_hash = signing_fn(state_input)
    except Exception:
        return ProfileCOutcome.COMPUTE_ERROR

    # Step 3: Cross-check committedHash against committed auth.state_hash.
    # If they differ, canonicalization or hash strategy in this harness is wrong.
    auth_state_hash: str = auth["state_hash"]
    if committed_hash != auth_state_hash:
        print(
            f"FATAL [{vid}]: independently-computed committedHash {committed_hash!r} "
            f"does not match committed auth.state_hash {auth_state_hash!r}\n"
            f"  This indicates a canonicalization or hash-strategy bug in the Python harness.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Step 4: Compute liveHash using verify strategy.
    live_state = vector.get("live_state_input", state_input)
    try:
        live_hash = verify_fn(live_state)
    except Exception:
        return ProfileCOutcome.COMPUTE_ERROR

    # Step 5: Compare liveHash vs committedHash.
    if live_hash == committed_hash:
        return ProfileCOutcome.OK
    return ProfileCOutcome.STATE_HASH_MISMATCH


# ── Vector loading ────────────────────────────────────────────────────────────

def _load_vectors() -> list[dict[str, Any]]:
    path = (
        Path(__file__).resolve().parent.parent
        / "docs" / "spec" / "test-vectors"
        / "profile-c-state-verification.json"
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
        expected_outcome: str = vector["expected"]["outcome"]

        computed = _compute_outcome(vector)

        if computed.value != expected_outcome:
            failed += 1
            print(f"FAIL {vid}: outcome mismatch", file=sys.stderr)
            print(f"  expected: {expected_outcome}", file=sys.stderr)
            print(f"  actual:   {computed.value}", file=sys.stderr)
            continue

        print(f"PASS {vid}")

    if failed:
        print(f"\n{failed} Profile C vector(s) failed", file=sys.stderr)
        return 1

    print(f"\nAll {len(vectors)} Profile C vector(s) passed (diagnostic only; scoped report: pnpm test:vectors:py)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
