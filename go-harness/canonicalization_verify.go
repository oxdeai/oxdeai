package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"runtime"

	"golang.org/x/text/unicode/norm"
)

const (
	safeMinInt = -9007199254740991
	safeMaxInt = 9007199254740991
)

type vector struct {
	ID                   string          `json:"id"`
	Description          string          `json:"description"`
	Status               string          `json:"status"`
	Input                interface{}     `json:"input"`
	ExpectedCanonical    string          `json:"expected_canonical_json"`
	ExpectedSHA256       string          `json:"expected_sha256"`
	ExpectedError        string          `json:"expected_error"`
}

type canonicalError string

func (e canonicalError) Error() string { return string(e) }

func normalizeString(s string) (string, error) {
	return norm.NFC.String(s), nil
}

func canonicalize(value interface{}) (string, error) {
	switch v := value.(type) {
	case nil:
		return "null", nil
	case bool:
		if v {
			return "true", nil
		}
		return "false", nil
	case string:
		norm, err := normalizeString(v)
		if err != nil {
			return "", err
		}
		return quoteString(norm), nil
	case json.Number:
		return canonicalizeJSONNumber(v)
	case float64:
		return canonicalizeFloat(v)
	case float32:
		return canonicalizeFloat(float64(v))
	case int:
		return canonicalizeInt(int64(v))
	case int64:
		return canonicalizeInt(v)
	case int32:
		return canonicalizeInt(int64(v))
	case int16:
		return canonicalizeInt(int64(v))
	case int8:
		return canonicalizeInt(int64(v))
	case uint:
		return canonicalizeUint(uint64(v))
	case uint64:
		return canonicalizeUint(v)
	case uint32:
		return canonicalizeUint(uint64(v))
	case uint16:
		return canonicalizeUint(uint64(v))
	case uint8:
		return canonicalizeUint(uint64(v))
	case []interface{}:
		return canonicalizeArray(v)
	case map[string]interface{}:
		return canonicalizeObject(v)
	default:
		return "", canonicalError("UNSUPPORTED_TYPE")
	}
}

func canonicalizeArray(arr []interface{}) (string, error) {
	parts := make([]string, len(arr))
	for i, item := range arr {
		c, err := canonicalize(item)
		if err != nil {
			return "", err
		}
		parts[i] = c
	}
	return "[" + join(parts, ",") + "]", nil
}

type entry struct {
	key   string
	value interface{}
}

func canonicalizeObject(obj map[string]interface{}) (string, error) {
	entries := make([]entry, 0, len(obj))
	seen := make(map[string]struct{}, len(obj))

	for k, v := range obj {
		normalized, err := normalizeString(k)
		if err != nil {
			return "", err
		}
		if _, exists := seen[normalized]; exists {
			return "", canonicalError("DUPLICATE_KEY")
		}
		seen[normalized] = struct{}{}
		entries = append(entries, entry{key: normalized, value: v})
	}

	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare([]byte(entries[i].key), []byte(entries[j].key)) < 0
	})

	parts := make([]string, len(entries))
	for i, ent := range entries {
		var val string
		var err error

		if ent.key == "ts" {
			val, err = canonicalizeTimestamp(ent.value)
		} else {
			val, err = canonicalize(ent.value)
		}
		if err != nil {
			return "", err
		}
		parts[i] = fmt.Sprintf("%s:%s", quoteString(ent.key), val)
	}

	return "{" + join(parts, ",") + "}", nil
}

func canonicalizeTimestamp(v interface{}) (string, error) {
	val, err := canonicalizeNumber(v)
	if err != nil {
		return "", canonicalError("INVALID_TIMESTAMP")
	}
	return val, nil
}

func canonicalizeJSONNumber(num json.Number) (string, error) {
	r := new(big.Rat)
	if _, ok := r.SetString(num.String()); !ok {
		return "", canonicalError("UNSUPPORTED_TYPE")
	}
	if !r.IsInt() {
		return "", canonicalError("FLOAT_NOT_ALLOWED")
	}
	i := r.Num()
	if err := ensureSafeInt(i); err != nil {
		return "", err
	}
	return i.String(), nil
}

func canonicalizeNumber(v interface{}) (string, error) {
	switch n := v.(type) {
	case json.Number:
		return canonicalizeJSONNumber(n)
	case float64:
		return canonicalizeFloat(n)
	case float32:
		return canonicalizeFloat(float64(n))
	case int, int8, int16, int32, int64:
		return canonicalizeInt(reflectInt64(n))
	case uint, uint8, uint16, uint32, uint64:
		return canonicalizeUint(reflectUint64(n))
	default:
		return "", canonicalError("UNSUPPORTED_TYPE")
	}
}

func canonicalizeFloat(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", canonicalError("FLOAT_NOT_ALLOWED")
	}
	if math.Trunc(f) != f {
		return "", canonicalError("FLOAT_NOT_ALLOWED")
	}
	if f < safeMinInt || f > safeMaxInt {
		return "", canonicalError("UNSAFE_INTEGER_NUMBER")
	}
	return strconv.FormatInt(int64(f), 10), nil
}

func canonicalizeInt(i int64) (string, error) {
	if i < safeMinInt || i > safeMaxInt {
		return "", canonicalError("UNSAFE_INTEGER_NUMBER")
	}
	return strconv.FormatInt(i, 10), nil
}

func canonicalizeUint(u uint64) (string, error) {
	if u > math.MaxInt64 {
		return "", canonicalError("UNSAFE_INTEGER_NUMBER")
	}
	return canonicalizeInt(int64(u))
}

func ensureSafeInt(i *big.Int) error {
	safeMin := big.NewInt(safeMinInt)
	safeMax := big.NewInt(safeMaxInt)
	if i.Cmp(safeMin) < 0 || i.Cmp(safeMax) > 0 {
		return canonicalError("UNSAFE_INTEGER_NUMBER")
	}
	return nil
}

func quoteString(s string) string {
	return strconv.Quote(s)
}

func join(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	size := len(sep) * (len(parts) - 1)
	for _, p := range parts {
		size += len(p)
	}
	var b bytes.Buffer
	b.Grow(size)
	for i, p := range parts {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(p)
	}
	return b.String()
}

// testVectorsDir returns the absolute path to docs/spec/test-vectors/ relative
// to this source file, so go run . works regardless of working directory.
func testVectorsDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "docs", "spec", "test-vectors"))
}

func loadVectors() ([]vector, error) {
	dir := testVectorsDir()
	if dir == "" {
		return nil, fmt.Errorf("unable to resolve caller path")
	}
	path := filepath.Join(dir, "canonicalization-v1.json")

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var vectors []vector
	dec := json.NewDecoder(f)
	dec.UseNumber()
	if err := dec.Decode(&vectors); err != nil {
		return nil, err
	}
	return vectors, nil
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:])
}

func main() {
	// ── 1. Canonicalization vectors ──────────────────────────────────────────
	vectors, err := loadVectors()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load canonicalization vectors: %v\n", err)
		os.Exit(1)
	}

	var canFailed int

	for _, v := range vectors {
		switch v.Status {
		case "ok":
			canon, err := canonicalize(v.Input)
			if err != nil {
				canFailed++
				fmt.Fprintf(os.Stderr, "FAIL %s: unexpected error %s\n", v.ID, err.Error())
				continue
			}
			if canon != v.ExpectedCanonical {
				canFailed++
				fmt.Fprintf(os.Stderr, "FAIL %s: canonical JSON mismatch\n", v.ID)
				fmt.Fprintf(os.Stderr, "  expected: %s\n", v.ExpectedCanonical)
				fmt.Fprintf(os.Stderr, "  actual:   %s\n", canon)
				continue
			}
			hash := sha256Hex([]byte(canon))
			if v.ExpectedSHA256 != "" && hash != v.ExpectedSHA256 {
				canFailed++
				fmt.Fprintf(os.Stderr, "FAIL %s: SHA-256 mismatch\n", v.ID)
				fmt.Fprintf(os.Stderr, "  expected: %s\n", v.ExpectedSHA256)
				fmt.Fprintf(os.Stderr, "  actual:   %s\n", hash)
				continue
			}
			fmt.Printf("PASS %s\n", v.ID)
		case "error":
			_, err := canonicalize(v.Input)
			if err == nil {
				canFailed++
				fmt.Fprintf(os.Stderr, "FAIL %s: expected error %s, got success\n", v.ID, v.ExpectedError)
				continue
			}
			if err.Error() != v.ExpectedError {
				canFailed++
				fmt.Fprintf(os.Stderr, "FAIL %s: wrong error\n", v.ID)
				fmt.Fprintf(os.Stderr, "  expected: %s\n", v.ExpectedError)
				fmt.Fprintf(os.Stderr, "  actual:   %s\n", err.Error())
				continue
			}
			fmt.Printf("PASS %s\n", v.ID)
		default:
			canFailed++
			fmt.Fprintf(os.Stderr, "FAIL %s: unsupported status %s\n", v.ID, v.Status)
		}
	}

	if canFailed > 0 {
		fmt.Fprintf(os.Stderr, "\n%d canonicalization vector(s) failed\n", canFailed)
	} else {
		fmt.Printf("\nAll %d canonicalization vector(s) passed (diagnostic only; scoped report: pnpm test:vectors:go)\n", len(vectors))
	}

	// ── 2. Profile C state-hash semantics (modes 001–005) ────────────────────
	profCPassed, profCFailed := verifyProfileCVectors()
	if profCFailed > 0 {
		fmt.Fprintf(os.Stderr, "\n%d Profile C vector(s) failed\n", profCFailed)
	} else {
		fmt.Printf("\nAll %d Profile C vector(s) passed (diagnostic only; scoped report: pnpm test:vectors:go)\n", profCPassed)
	}

	// ── 3. SignedKRLV1 verification (9 vectors) ───────────────────────────────
	krlPassed, krlFailed := verifySignedKrlVectors()
	if krlFailed > 0 {
		fmt.Fprintf(os.Stderr, "\n%d SignedKRL vector(s) failed\n", krlFailed)
	} else {
		fmt.Printf("\nAll %d SignedKRL vector(s) passed (diagnostic only; scoped report: pnpm test:vectors:go)\n", krlPassed)
	}

	// ── Final exit code ───────────────────────────────────────────────────────
	if canFailed+profCFailed+krlFailed > 0 {
		os.Exit(1)
	}
}

func reflectInt64(v interface{}) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int8:
		return int64(n)
	case int16:
		return int64(n)
	case int32:
		return int64(n)
	case int64:
		return n
	default:
		return 0
	}
}

func reflectUint64(v interface{}) uint64 {
	switch n := v.(type) {
	case uint:
		return uint64(n)
	case uint8:
		return uint64(n)
	case uint16:
		return uint64(n)
	case uint32:
		return uint64(n)
	case uint64:
		return n
	default:
		return 0
	}
}
