# OxDeAI Canonicalization Test Vectors v1

**Version:** aligned with `canonicalization-v1.md`
**Status:** normative (machine-readable vectors) + illustrative examples

---

## 1. Purpose

This document defines canonical test vectors used to validate canonicalization implementations.

A conforming implementation **MUST**:

* produce identical canonical bytes for valid inputs
* produce identical SHA-256 hashes (lowercase hex)
* reject invalid inputs deterministically

---

## 2. Source of Truth (Normative)

The authoritative test vectors are defined in:

```
docs/spec/test-vectors/canonicalization-v1.json
```

This JSON file is the **single source of truth**.

All implementations **MUST** validate against it.

This Markdown document is **non-normative** and provided for readability only.

---

## 3.1 Scope Note

Locked, normative vectors currently published:
- canonicalization: `canonicalization-v1.json`
- authorization: `authorization-v1.json`
- PEP gateway: `pep-vectors-v1.json`
- authorization wire encoding: `authorization-wire-encoding-v1.json`
- authorization verification precedence: `authorization-precedence-v1.json`

Delegation vectors are not yet published; conformance for Delegation remains harness-based until vectors are added.

---

## 3. Hash Function

All hashes are defined as:

```
SHA-256(canonical_bytes) → lowercase hexadecimal string
```

The hash **MUST** be computed over the exact UTF-8 byte sequence returned by canonicalization.

---

## 4. Example Valid Vectors (Illustrative)

### V1 - Object Key Ordering

**Input**

```json
{"b":1,"a":2}
```

**Expected canonical**

```json
{"a":2,"b":1}
```

**Expected hash**

```
d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772
```

---

### V4 - Unicode NFC Normalization

**Input**

```json
{"text":"e\u0301"}
```

**Expected canonical**

```json
{"text":"é"}
```

---

### V8 - Realistic Intent Example

**Input**

```json
{
  "type": "EXECUTE",
  "tool": "payments.charge",
  "params": {
    "amount": "500",
    "currency": "USD"
  }
}
```

**Expected canonical**

```json
{"params":{"amount":"500","currency":"USD"},"tool":"payments.charge","type":"EXECUTE"}
```

**Expected hash**

```
b75c8d1d9952254b2386f4e412f8fd0b8ac7361ddb54e50c22b19ffc1a3c8c2d
```

---

## 5. Example Invalid Vectors (Illustrative)

### Float Rejection

**Input**

```json
{"value":1.5}
```

**Expected**

```
ERROR: FLOAT_NOT_ALLOWED
```

---

### String Timestamp Rejection

**Input**

```json
{"ts":"2026-04-03T12:00:00Z"}
```

**Expected**

```
ERROR: INVALID_TIMESTAMP
```

---

### Float Timestamp Rejection

**Input**

```json
{"ts":1712448000.5}
```

**Expected**

```
ERROR: INVALID_TIMESTAMP
```

---

## 6. Determinism Requirement

Implementations **MUST** satisfy:

```
canonicalize(input) == constant
hash(input) == constant
```

No variation is permitted across runs.

---

## 7. Cross-Language Conformance

All implementations **MUST** satisfy:

```
C_TS(input) == C_Go(input) == C_Python(input)
hash_TS(input) == hash_Go(input) == hash_Python(input)
```

Comparison **MUST** be byte-for-byte identical.

---

## 8. Replay Integrity Constraint

If:

```
intent_hash != SHA256(C(input))
```

Then:

```
authorization MUST be rejected
```

---

## 9. Conformance Execution

Recommended commands:

```
pnpm test:vectors:ts
pnpm test:vectors:go
pnpm test:vectors:py
pnpm test:vectors:all
```

All implementations **MUST** pass all locked vectors.

---

## 10. Invariant

```
No canonicalization
→ no stable bytes
→ no stable hash
→ no deterministic decision
→ no verifiable authorization
→ no execution
```
