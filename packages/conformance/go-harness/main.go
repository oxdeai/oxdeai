package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
)

type violation struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Index   *int   `json:"index,omitempty"`
}

type verifyResult struct {
	Status       string      `json:"status"`
	PolicyID     string      `json:"policyId,omitempty"`
	StateHash    string      `json:"stateHash,omitempty"`
	AuditHead    string      `json:"auditHeadHash,omitempty"`
	Violations   []violation `json:"violations"`
}

type adapterRequest struct {
	Op    string      `json:"op"`
	Input interface{} `json:"input,omitempty"`
}

type adapterResponse struct {
	OK     bool                   `json:"ok"`
	Error  string                 `json:"error,omitempty"`
	Output map[string]interface{} `json:"output,omitempty"`
}

type vectorFile struct {
	Version string                   `json:"version"`
	Vectors []map[string]interface{} `json:"vectors"`
}

type assertionCtx struct {
	Passed   int
	Failures []string
}

type adapterClient struct {
	bin  string
	args []string
}

type strSlice []string

func (s *strSlice) String() string { return fmt.Sprint([]string(*s)) }
func (s *strSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func main() {
	var vectorsDir string
	var adapterBin string
	var adapterArgs strSlice

	flag.StringVar(&vectorsDir, "vectors", "../vectors", "Path to conformance vectors directory")
	flag.StringVar(&adapterBin, "adapter-bin", "", "Adapter executable implementing harness op protocol")
	flag.Var(&adapterArgs, "adapter-arg", "Adapter argument (repeatable)")
	flag.Parse()

	if adapterBin == "" {
		fmt.Fprintln(os.Stderr, "missing required --adapter-bin")
		fmt.Fprintln(os.Stderr, "example: go run ./main.go --adapter-bin ./your-adapter --vectors ../vectors")
		os.Exit(2)
	}

	cwd := must(os.Getwd())
	absVectors := vectorsDir
	if !filepath.IsAbs(absVectors) {
		absVectors = filepath.Clean(filepath.Join(cwd, absVectors))
	}

	adapter := adapterClient{bin: adapterBin, args: adapterArgs}
	ctx := &assertionCtx{}

	fmt.Println("Running Go conformance harness")
	fmt.Printf("Vectors: %s\n", absVectors)
	fmt.Printf("Adapter: %s %v\n", adapter.bin, adapter.args)

	runIntentHash(ctx, adapter, absVectors)
	runAuthorizationPayload(ctx, adapter, absVectors)
	runSnapshotHash(ctx, adapter, absVectors)
	runAuditChain(ctx, adapter, absVectors)
	runAuthorizationVerification(ctx, adapter, absVectors)
	runAuditVerification(ctx, adapter, absVectors)
	runEnvelopeVerification(ctx, adapter, absVectors)
	runAuthorizationSignatureVerification(ctx, adapter, absVectors)
	runEnvelopeSignatureVerification(ctx, adapter, absVectors)
	runDelegationParentHash(ctx, adapter, absVectors)
	runDelegationVerification(ctx, adapter, absVectors)
	runDelegationChainVerification(ctx, adapter, absVectors)
	runDelegationSignatureVerification(ctx, adapter, absVectors)

	if len(ctx.Failures) > 0 {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintf(os.Stderr, "Conformance failed: %d failures\n", len(ctx.Failures))
		for _, f := range ctx.Failures {
			fmt.Fprintf(os.Stderr, "- %s\n", f)
		}
		os.Exit(1)
	}

	fmt.Printf("\nDiagnostic checks passed: %d assertions (adapter protocol only; no scoped conformance claim)\n", ctx.Passed)
}

func runIntentHash(ctx *assertionCtx, adapter adapterClient, vectorsDir string) {
	vf := loadVectorFile(vectorsDir, "intent-hash.json")
	seen := map[string]string{}
	for _, v := range vf.Vectors {
		id := getString(v, "id")
		input := getMap(v, "input")
		resp, err := adapter.call("intent_hash", map[string]interface{}{"intent": input})
		if err != nil {
			fail(ctx, fmt.Sprintf("%s hash call failed: %v", id, err))
			continue
		}
		hash := getString(resp, "hash")
		eq(ctx, id+" hash", hash, getString(getMap(v, "expected"), "hash"))
		seen[id] = hash
		if inv, ok := v["invariant"].(string); ok && inv != "" {
			if refID, ok := parseInvariantEquals(inv); ok {
				if refHash, found := seen[refID]; found {
					eq(ctx, id+" invariant", hash, refHash)
				}
			}
		}
	}
}

func runAuthorizationPayload(ctx *assertionCtx, adapter adapterClient, vectorsDir string) {
	vf := loadVectorFile(vectorsDir, "authorization-payload.json")
	for _, v := range vf.Vectors {
		id := getString(v, "id")
		input := getMap(v, "input")
		resp, err := adapter.call("evaluate_authorization", map[string]interface{}{"intent": input})
		if err != nil {
			fail(ctx, fmt.Sprintf("%s evaluate_authorization failed: %v", id, err))
			continue
		}
		auth := getMap(resp, "authorization")
		exp := getMap(v, "expected")

		for _, field := range []string{"intent_hash", "state_hash", "expires_at", "signature"} {
			if _, ok := exp[field]; ok {
				eq(ctx, id+" "+field, fmt.Sprint(auth[field]), fmt.Sprint(exp[field]))
			}
		}
		if _, ok := exp["canonical_signing_payload"]; ok {
			eq(ctx, id+" canonical_signing_payload", getString(resp, "canonical_signing_payload"), fmt.Sprint(exp["canonical_signing_payload"]))
		}
	}
}

func runSnapshotHash(ctx *assertionCtx, adapter adapterClient, vectorsDir string) {
	vf := loadVectorFile(vectorsDir, "snapshot-hash.json")
	for _, v := range vf.Vectors {
		id := getString(v, "id")
		exp := getMap(v, "expected")

		if inState, ok := v["input_state"].(map[string]interface{}); ok {
			resp, err := adapter.call("encode_snapshot", map[string]interface{}{"state": inState})
			if err != nil {
				fail(ctx, fmt.Sprintf("%s encode_snapshot failed: %v", id, err))
				continue
			}
			snapB64 := getString(resp, "snapshot_base64")
			policyID := getString(resp, "policy_id")
			if expectedB64, ok := exp["snapshot_base64"]; ok {
				eq(ctx, id+" snapshot_base64", snapB64, fmt.Sprint(expectedB64))
			}
			vr, err := adapter.call("verify_snapshot", map[string]interface{}{"snapshot_base64": snapB64, "expected_policy_id": policyID})
			if err != nil {
				fail(ctx, fmt.Sprintf("%s verify_snapshot failed: %v", id, err))
				continue
			}
			eq(ctx, id+" state_hash", getString(vr, "stateHash"), getString(exp, "state_hash"))
			continue
		}

		if inB64, ok := v["input_snapshot_base64"].(string); ok {
			vr, err := adapter.call("verify_snapshot", map[string]interface{}{"snapshot_base64": inB64})
			if err != nil {
				fail(ctx, fmt.Sprintf("%s verify_snapshot(base64) failed: %v", id, err))
				continue
			}
			eq(ctx, id+" state_hash", getString(vr, "stateHash"), getString(exp, "state_hash"))
		}
	}
}

func runAuditChain(ctx *assertionCtx, adapter adapterClient, vectorsDir string) {
	vf := loadVectorFile(vectorsDir, "audit-chain.json")
	for _, v := range vf.Vectors {
		id := getString(v, "id")
		exp := getMap(v, "expected")

		switch id {
		case "audit-chain-001":
			in := fmt.Sprint(v["input"])
			eq(ctx, id+" genesis", sha256Hex(in), getString(exp, "genesis_hex"))
		case "audit-chain-002":
			input := getMap(v, "input")
			head0 := getString(input, "head_0")
			canon := getString(input, "canonical_event_0")
			head1 := sha256Hex(head0 + "\n" + canon)
			eq(ctx, id+" head_1", head1, getString(exp, "head_1"))
		case "audit-chain-003":
			input := getMap(v, "input")
			head := getString(input, "genesis")
			events := getSlice(input, "events")
			for idx, ev := range events {
				canonResp, err := adapter.call("canonical_json", map[string]interface{}{"value": ev})
				if err != nil {
					fail(ctx, fmt.Sprintf("%s canonical_json event[%d] failed: %v", id, idx, err))
					break
				}
				head = sha256Hex(head + "\n" + getString(canonResp, "canonical"))
				eq(ctx, fmt.Sprintf("%s head_%d", id, idx+1), head, getString(exp, fmt.Sprintf("head_%d", idx+1)))
			}
		case "audit-chain-004":
			input := getMap(v, "input")
			head0 := getString(input, "head_0")
			origResp, err := adapter.call("canonical_json", map[string]interface{}{"value": getMap(input, "original_event_0")})
			if err != nil {
				fail(ctx, fmt.Sprintf("%s canonical_json original failed: %v", id, err))
				continue
			}
			mutResp, err := adapter.call("canonical_json", map[string]interface{}{"value": getMap(input, "mutated_event_0")})
			if err != nil {
				fail(ctx, fmt.Sprintf("%s canonical_json mutated failed: %v", id, err))
				continue
			}
			orig := sha256Hex(head0 + "\n" + getString(origResp, "canonical"))
			mut := sha256Hex(head0 + "\n" + getString(mutResp, "canonical"))
			eq(ctx, id+" original_head_1", orig, getString(exp, "original_head_1"))
			eq(ctx, id+" mutated_head_1", mut, getString(exp, "mutated_head_1"))
			if orig == mut {
				fail(ctx, id+" must differ")
			} else {
				pass(ctx, id+" must differ")
			}
		}
	}
}

func runAuthorizationVerification(ctx *assertionCtx, adapter adapterClient, vectorsDir string) {
	vf := loadVectorFile(vectorsDir, "authorization-verification.json")
	for _, v := range vf.Vectors {
		id := getString(v, "id")
		input := getMap(v, "input")
		exp := getMap(v, "expected")
		resp, err := adapter.call("verify_authorization", input)
		if err != nil {
			fail(ctx, fmt.Sprintf("%s verify_authorization failed: %v", id, err))
			continue
		}
		eq(ctx, id+" status", getString(resp, "status"), getString(exp, "status"))
		eq(ctx, id+" violations", normalizeJSON(resp["violations"]), normalizeJSON(exp["violations"]))
	}
}

func runAuditVerification(ctx *assertionCtx, adapter adapterClient, vectorsDir string) {
	vf := loadVectorFile(vectorsDir, "audit-verification.json")
	for _, v := range vf.Vectors {
		id := getString(v, "id")
		exp := getMap(v, "expected")
		resp, err := adapter.call("verify_audit_case", map[string]interface{}{"id": id})
		if err != nil {
			fail(ctx, fmt.Sprintf("%s verify_audit_case failed: %v", id, err))
			continue
		}
		eq(ctx, id+" status", getString(resp, "status"), getString(exp, "status"))
		eq(ctx, id+" violations", normalizeJSON(resp["violations"]), normalizeJSON(exp["violations"]))
	}
}

func runEnvelopeVerification(ctx *assertionCtx, adapter adapterClient, vectorsDir string) {
	vf := loadVectorFile(vectorsDir, "envelope-verification.json")
	for _, v := range vf.Vectors {
		id := getString(v, "id")
		exp := getMap(v, "expected")
		resp, err := adapter.call("verify_envelope_case", map[string]interface{}{"id": id})
		if err != nil {
			fail(ctx, fmt.Sprintf("%s verify_envelope_case failed: %v", id, err))
			continue
		}
		eq(ctx, id+" status", getString(resp, "status"), getString(exp, "status"))
		for _, f := range []string{"policyId", "stateHash", "auditHeadHash"} {
			if expected, ok := exp[f]; ok {
				eq(ctx, id+" "+f, fmt.Sprint(resp[f]), fmt.Sprint(expected))
			}
		}
		eq(ctx, id+" violations", normalizeJSON(resp["violations"]), normalizeJSON(exp["violations"]))
	}
}

func runAuthorizationSignatureVerification(ctx *assertionCtx, adapter adapterClient, vectorsDir string) {
	vf := loadVectorFile(vectorsDir, "authorization-signature-verification.json")
	for _, v := range vf.Vectors {
		id := getString(v, "id")
		mode := getString(v, "mode")
		exp := getMap(v, "expected")
		resp, err := adapter.call("verify_authorization_signature_case", map[string]interface{}{"id": id, "mode": mode})
		if err != nil {
			fail(ctx, fmt.Sprintf("%s verify_authorization_signature_case failed: %v", id, err))
			continue
		}
		eq(ctx, id+" status", getString(resp, "status"), getString(exp, "status"))
		eq(ctx, id+" violations", normalizeJSON(resp["violations"]), normalizeJSON(exp["violations"]))
	}
}

func runEnvelopeSignatureVerification(ctx *assertionCtx, adapter adapterClient, vectorsDir string) {
	vf := loadVectorFile(vectorsDir, "envelope-signature-verification.json")
	for _, v := range vf.Vectors {
		id := getString(v, "id")
		mode := getString(v, "mode")
		exp := getMap(v, "expected")
		resp, err := adapter.call("verify_envelope_signature_case", map[string]interface{}{"id": id, "mode": mode})
		if err != nil {
			fail(ctx, fmt.Sprintf("%s verify_envelope_signature_case failed: %v", id, err))
			continue
		}
		eq(ctx, id+" status", getString(resp, "status"), getString(exp, "status"))
		eq(ctx, id+" violations", normalizeJSON(resp["violations"]), normalizeJSON(exp["violations"]))
	}
}

func runDelegationParentHash(ctx *assertionCtx, adapter adapterClient, vectorsDir string) {
	vf := loadVectorFile(vectorsDir, "delegation-parent-hash.json")
	seen := map[string]string{}
	for _, v := range vf.Vectors {
		id := getString(v, "id")
		input := getMap(v, "input")
		resp, err := adapter.call("delegation_parent_hash", input)
		if err != nil {
			fail(ctx, fmt.Sprintf("%s delegation_parent_hash failed: %v", id, err))
			continue
		}
		hash := getString(resp, "parent_auth_hash")
		eq(ctx, id+" parent_auth_hash", hash, getString(getMap(v, "expected"), "parent_auth_hash"))
		seen[id] = hash
		if inv, ok := v["invariant"].(string); ok && inv != "" {
			if refID, ok := parseInvariantEquals(inv); ok {
				if refHash, found := seen[refID]; found {
					eq(ctx, id+" invariant", hash, refHash)
				}
			}
		}
	}
}

func runDelegationVerification(ctx *assertionCtx, adapter adapterClient, vectorsDir string) {
	vf := loadVectorFile(vectorsDir, "delegation-verification.json")
	for _, v := range vf.Vectors {
		id := getString(v, "id")
		input := getMap(v, "input")
		exp := getMap(v, "expected")
		resp, err := adapter.call("verify_delegation", input)
		if err != nil {
			fail(ctx, fmt.Sprintf("%s verify_delegation failed: %v", id, err))
			continue
		}
		eq(ctx, id+" status", getString(resp, "status"), getString(exp, "status"))
		eq(ctx, id+" violations", normalizeJSON(resp["violations"]), normalizeJSON(exp["violations"]))
	}
}

func runDelegationChainVerification(ctx *assertionCtx, adapter adapterClient, vectorsDir string) {
	vf := loadVectorFile(vectorsDir, "delegation-chain-verification.json")
	for _, v := range vf.Vectors {
		id := getString(v, "id")
		exp := getMap(v, "expected")
		input := getMap(v, "input")
		resp, err := adapter.call("verify_delegation_chain", input)
		if err != nil {
			fail(ctx, fmt.Sprintf("%s verify_delegation_chain failed: %v", id, err))
			continue
		}
		eq(ctx, id+" status", getString(resp, "status"), getString(exp, "status"))
		eq(ctx, id+" violations", normalizeJSON(resp["violations"]), normalizeJSON(exp["violations"]))
	}
}

func runDelegationSignatureVerification(ctx *assertionCtx, adapter adapterClient, vectorsDir string) {
	vf := loadVectorFile(vectorsDir, "delegation-signature-verification.json")
	for _, v := range vf.Vectors {
		id := getString(v, "id")
		exp := getMap(v, "expected")
		input := getMap(v, "input")
		resp, err := adapter.call("verify_delegation_signature", input)
		if err != nil {
			fail(ctx, fmt.Sprintf("%s verify_delegation_signature failed: %v", id, err))
			continue
		}
		eq(ctx, id+" status", getString(resp, "status"), getString(exp, "status"))
		eq(ctx, id+" violations", normalizeJSON(resp["violations"]), normalizeJSON(exp["violations"]))
	}
}

func (a adapterClient) call(op string, input interface{}) (map[string]interface{}, error) {
	req := adapterRequest{Op: op, Input: input}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(a.bin, a.args...)
	cmd.Stdin = bytes.NewReader(body)
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("adapter command failed: %w; stderr=%s", err, errOut.String())
	}
	var resp adapterResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("adapter returned non-json output: %w; raw=%s", err, out.String())
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "unknown adapter error"
		}
		return nil, errors.New(resp.Error)
	}
	if resp.Output == nil {
		resp.Output = map[string]interface{}{}
	}
	return resp.Output, nil
}

func loadVectorFile(vectorsDir, name string) vectorFile {
	path := filepath.Join(vectorsDir, name)
	raw := must(os.ReadFile(path))
	var vf vectorFile
	must(vf, json.Unmarshal(raw, &vf))
	return vf
}

func getMap(m map[string]interface{}, key string) map[string]interface{} {
	v, ok := m[key].(map[string]interface{})
	if !ok {
		panic(fmt.Sprintf("expected map at key=%s", key))
	}
	return v
}

func getSlice(m map[string]interface{}, key string) []map[string]interface{} {
	raw, ok := m[key].([]interface{})
	if !ok {
		panic(fmt.Sprintf("expected array at key=%s", key))
	}
	out := make([]map[string]interface{}, 0, len(raw))
	for _, item := range raw {
		o, ok := item.(map[string]interface{})
		if !ok {
			panic(fmt.Sprintf("expected object in array key=%s", key))
		}
		out = append(out, o)
	}
	return out
}

func getString(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		panic(fmt.Sprintf("missing key=%s", key))
	}
	s, ok := v.(string)
	if !ok {
		panic(fmt.Sprintf("expected string at key=%s", key))
	}
	return s
}

func parseInvariantEquals(v string) (string, bool) {
	const p = "equals "
	if len(v) <= len(p) || v[:len(p)] != p {
		return "", false
	}
	return v[len(p):], true
}

func normalizeJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	var x interface{}
	if err := json.Unmarshal(b, &x); err != nil {
		return string(b)
	}
	return canonicalizeAny(x)
}

func canonicalizeAny(v interface{}) string {
	switch t := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf := bytes.NewBufferString("{")
		for i, k := range keys {
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			buf.WriteString(canonicalizeAny(t[k]))
			if i < len(keys)-1 {
				buf.WriteByte(',')
			}
		}
		buf.WriteByte('}')
		return buf.String()
	case []interface{}:
		buf := bytes.NewBufferString("[")
		for i, item := range t {
			buf.WriteString(canonicalizeAny(item))
			if i < len(t)-1 {
				buf.WriteByte(',')
			}
		}
		buf.WriteByte(']')
		return buf.String()
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func pass(ctx *assertionCtx, msg string) {
	ctx.Passed++
	fmt.Printf("PASS %s\n", msg)
}

func fail(ctx *assertionCtx, msg string) {
	ctx.Failures = append(ctx.Failures, msg)
	fmt.Printf("FAIL %s\n", msg)
}

func eq(ctx *assertionCtx, label string, actual interface{}, expected interface{}) {
	if fmt.Sprint(actual) != fmt.Sprint(expected) {
		fail(ctx, fmt.Sprintf("%s expected=%v actual=%v", label, expected, actual))
		return
	}
	pass(ctx, label)
}

func decodeB64(s string) []byte {
	return must(base64.StdEncoding.DecodeString(s))
}

func init() {
	_ = decodeB64
	_ = verifyResult{}
}
