package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/blashkar/portcullis/internal/audit"
	"github.com/blashkar/portcullis/internal/policy"
)

func compilePolicy(t *testing.T, s policy.Spec) *policy.Policy {
	t.Helper()
	p, err := policy.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// countingServer has a read_file tool that counts how often it runs.
func countingServer(calls *atomic.Int64) *mcp.Server {
	s := newUpstream("files")
	mcp.AddTool(s, &mcp.Tool{Name: "read_file"}, func(_ context.Context, _ *mcp.CallToolRequest, in pathArgs) (*mcp.CallToolResult, any, error) {
		calls.Add(1)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "read " + in.Path}}}, nil, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "write_file"}, func(_ context.Context, _ *mcp.CallToolRequest, in pathArgs) (*mcp.CallToolResult, any, error) {
		calls.Add(1)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "wrote " + in.Path}}}, nil, nil
	})
	return s
}

func blockedBy(t *testing.T, err error) map[string]string {
	t.Helper()
	var werr *jsonrpc.Error
	if !errors.As(err, &werr) || werr.Code != CodePolicyBlocked {
		t.Fatalf("err = %v, want a policy error", err)
	}
	var data map[string]string
	if err := json.Unmarshal(werr.Data, &data); err != nil {
		t.Fatalf("error data %s: %v", werr.Data, err)
	}
	return data
}

func TestPolicyBlocksCalls(t *testing.T) {
	var calls atomic.Int64
	pol := compilePolicy(t, policy.Spec{Rules: []policy.RuleSpec{
		{Name: "budget", Tool: policy.Patterns{"fs__read_file"}, RateLimit: "3/hour"},
		{Name: "workspace-only", Tool: policy.Patterns{"fs__*"}, When: `!under(args.path, "/workspace")`, Action: policy.Deny, Reason: "outside /workspace"},
		{Name: "confirm-writes", Tool: policy.Patterns{"fs__write_file"}, Action: policy.RequireApproval},
	}})
	h := startWithPolicy(t, map[string]*mcp.Server{"fs": countingServer(&calls)}, pol)

	res, err := h.call("fs__read_file", map[string]any{"path": "/workspace/a"})
	if err != nil || text(res) != "read /workspace/a" {
		t.Fatalf("allowed call: %v, %v", res, err)
	}

	_, err = h.call("fs__read_file", map[string]any{"path": "/workspace/../etc/passwd"})
	if d := blockedBy(t, err); d["decision"] != "deny" || d["rule"] != "workspace-only" {
		t.Errorf("deny data = %v", d)
	}
	if !strings.Contains(err.Error(), `the policy does not allow fs__read_file (rule "workspace-only"): outside /workspace`) {
		t.Errorf("deny message = %v", err)
	}

	_, err = h.call("fs__write_file", map[string]any{"path": "/workspace/a"})
	if d := blockedBy(t, err); d["decision"] != "require_approval" || !strings.Contains(err.Error(), "needs a person's approval") {
		t.Errorf("approval: %v, %v", d, err)
	}

	if _, err := h.call("fs__read_file", map[string]any{"path": "/workspace/b"}); err != nil {
		t.Fatal(err)
	}
	_, err = h.call("fs__read_file", map[string]any{"path": "/workspace/c"})
	if d := blockedBy(t, err); d["decision"] != "rate_limit" || d["rule"] != "budget" {
		t.Errorf("rate limit data = %v", d)
	}

	if n := calls.Load(); n != 2 {
		t.Errorf("the upstream ran %d calls, want only the 2 allowed ones", n)
	}

	e, ok := h.rec.find(func(e audit.Event) bool { return e.Decision == "deny" })
	if !ok || e.Rule != "workspace-only" || e.Reason != "outside /workspace" || !e.IsError || e.Tool != "fs__read_file" || e.Upstream != "fs" {
		t.Errorf("audit event for the denied call: %+v", e)
	}
	if e, ok := h.rec.find(func(e audit.Event) bool { return e.Decision == "allow" }); !ok || e.Rule != "" || e.IsError {
		t.Errorf("audit event for the allowed call: %+v", e)
	}
	if _, ok := h.rec.find(func(e audit.Event) bool { return e.Decision == "rate_limit" }); !ok {
		t.Error("the rate-limited call wasn't recorded")
	}
	if e, ok := h.rec.find(func(e audit.Event) bool { return e.Method == "tools/list" }); ok && e.Decision != "" {
		t.Errorf("tools/list got a decision: %+v", e)
	}
}

func TestLogOnlyRulesDontBlock(t *testing.T) {
	var calls atomic.Int64
	pol := compilePolicy(t, policy.Spec{Rules: []policy.RuleSpec{
		{Name: "trial", Tool: policy.Patterns{"fs__write_file"}, Action: policy.Deny, LogOnly: true},
	}})
	h := startWithPolicy(t, map[string]*mcp.Server{"fs": countingServer(&calls)}, pol)
	if _, err := h.call("fs__write_file", map[string]any{"path": "/workspace/a"}); err != nil {
		t.Fatal(err)
	}
	e, ok := h.rec.find(func(e audit.Event) bool { return e.Tool == "fs__write_file" })
	if !ok || e.Decision != "allow" || e.WouldDecision != "deny" || e.WouldRule != "trial" || calls.Load() != 1 {
		t.Errorf("event = %+v, upstream calls = %d", e, calls.Load())
	}
}

func TestNoPolicyRecordsNoDecision(t *testing.T) {
	h := start(t, twoServers())
	if _, err := h.call("fs__read_file", map[string]any{"path": "/w/a"}); err != nil {
		t.Fatal(err)
	}
	if e, _ := h.rec.find(func(e audit.Event) bool { return e.Tool == "fs__read_file" }); e.Decision != "" {
		t.Errorf("decision without a policy: %q", e.Decision)
	}
}

func TestPolicyRejectsMalformedArguments(t *testing.T) {
	var calls atomic.Int64
	pol := compilePolicy(t, policy.Spec{})
	h := startWithPolicy(t, map[string]*mcp.Server{"fs": countingServer(&calls)}, pol)
	_, err := h.client.CallTool(h.ctx, &mcp.CallToolParams{Name: "fs__read_file", Arguments: json.RawMessage(`["/etc/passwd"]`)})
	var werr *jsonrpc.Error
	if !errors.As(err, &werr) || werr.Code != jsonrpc.CodeInvalidParams || calls.Load() != 0 {
		t.Errorf("err = %v, upstream calls = %d", err, calls.Load())
	}
}

func TestDecodeArgs(t *testing.T) {
	tests := []struct {
		name, in, forward string
		check             func(map[string]any) bool
	}{
		{"empty", ``, ``, func(m map[string]any) bool { return len(m) == 0 }},
		{"null", `null`, ``, func(m map[string]any) bool { return len(m) == 0 }},
		{
			// The policy and the server must see the same value; the
			// duplicate isn't forwarded.
			"duplicate key", `{"path":"/workspace/a","path":"/etc/passwd"}`, `{"path":"/etc/passwd"}`,
			func(m map[string]any) bool { return m["path"] == "/etc/passwd" },
		},
		{
			"numbers", `{"big":12345678901234567890,"n":3,"f":1.5}`, `{"big":12345678901234567890,"f":1.5,"n":3}`,
			func(m map[string]any) bool {
				return m["n"] == int64(3) && m["f"] == 1.5 && m["big"] == 12345678901234567890.0
			},
		},
		{
			"nested", `{"edits":[{"old":"<a>","new":"&"}]}`, `{"edits":[{"new":"&","old":"<a>"}]}`,
			func(m map[string]any) bool { return m["edits"].([]any)[0].(map[string]any)["old"] == "<a>" },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args, forward, err := decodeArgs(json.RawMessage(tt.in))
			if err != nil {
				t.Fatal(err)
			}
			if string(forward) != tt.forward || !tt.check(args) {
				t.Errorf("forward %s, args %#v", forward, args)
			}
		})
	}
	for _, bad := range []string{`[1]`, `"x"`, `{"a":1} {"b":2}`, `{"a":`, `{} x`} {
		if _, _, err := decodeArgs(json.RawMessage(bad)); err == nil {
			t.Errorf("decodeArgs(%s) succeeded", bad)
		}
	}
}

// The arguments forwarded to the server must decode to exactly what the
// policy checked.
func FuzzDecodeArgs(f *testing.F) {
	for _, s := range []string{`{}`, `null`, `{"path":"/a","path":"/b"}`, `{"n":1e400}`, `{"a":[1,{"b":"\u0000"}]}`, `{"x":"\xff"}`, `[]`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		args, forward, err := decodeArgs(raw)
		if err != nil {
			return
		}
		if forward == nil {
			if len(args) != 0 {
				t.Fatalf("nothing forwarded for %q, but the policy saw %v", raw, args)
			}
			return
		}
		again, forward2, err := decodeArgs(forward)
		if err != nil {
			t.Fatalf("forwarded %s doesn't decode: %v", forward, err)
		}
		if !reflect.DeepEqual(args, again) || !bytes.Equal(forward, forward2) {
			t.Fatalf("%q: the policy saw %#v, the server would see %#v", raw, args, again)
		}
	})
}
