package replay

import (
	"errors"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/blashkar/portcullis/internal/audit"
	"github.com/blashkar/portcullis/internal/policy"
)

func compile(t *testing.T, src string) *policy.Policy {
	t.Helper()
	var s policy.Spec
	if err := yaml.Unmarshal([]byte(src), &s); err != nil {
		t.Fatal(err)
	}
	p, err := policy.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var start = time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)

func call(sec int, tool, decision, params string) audit.Event {
	server, _, _ := strings.Cut(tool, "__")
	return audit.Event{
		Time: start.Add(time.Duration(sec) * time.Second), Direction: audit.ClientToServer, Method: "tools/call",
		Tool: tool, Upstream: server, Decision: decision, Params: params,
	}
}

func TestCheck(t *testing.T) {
	events := []audit.Event{
		call(0, "fs__read_file", "allow", `{"name":"fs__read_file","arguments":{"path":"/workspace/a"}}`),
		call(1, "fs__read_file", "allow", `{"name":"fs__read_file","arguments":{"path":"/etc/passwd"}}`),
		{Time: start, Direction: audit.ServerToClient, Method: "notifications/tools/list_changed"},
		call(2, "git__git_reset", "deny", `{"name":"git__git_reset","arguments":{"mode":"hard"}}`),
		call(3, "fs__write_file", audit.DecisionApproved, `{"name":"fs__write_file","arguments":{"path":"/workspace/b","content":"x"}}`),
		call(4, "fs__write_file", "require_approval", `{"name":"fs__write_file","arguments":{"path":"/workspace/c","content":"x"}}`),
		call(5, "evil__steal", audit.DecisionHeld, `{"name":"evil__steal","arguments":{}}`),
		call(6, "fs__read_file", "", `{"name":"fs__read_file","arguments":{"path":"/workspace/very-long`+"…[truncated]"),
		call(7, "web__fetch", "", `{"name":"web__fetch","arguments":{"url":"https://example.com/","max_length":5000}}`),
		call(8, "web__fetch", "", `{"name":"web__fetch","arguments":{"url":"https://example.com/2","max_length":5000}}`),
	}
	p := compile(t, `
rules:
  - name: fs-workspace-only
    tool: "fs__*"
    when: 'has(args.path) && !under(args.path, "/workspace")'
    action: deny
  - name: writes
    tool: fs__write_file
    action: require_approval
  - name: no-big-fetches
    tool: web__fetch
    when: args.max_length > 1000
    rate_limit: 1/min
`)
	results := Check(events, p)
	type row struct {
		tool, before, after string
		changed             bool
	}
	want := []row{
		{"fs__read_file", "allow", "allow", false},
		{"fs__read_file", "allow", "deny", true},
		{"git__git_reset", "deny", "allow", true},
		{"fs__write_file", "require_approval", "require_approval", false},
		{"fs__write_file", "require_approval", "require_approval", false},
		{"evil__steal", "held", "allow", false},
		{"fs__read_file", "allow", "", false},
		// Arguments are numbers as the gateway decodes them, and the rate
		// limit counts calls by when they were made.
		{"web__fetch", "allow", "allow", false},
		{"web__fetch", "allow", "rate_limit", true},
	}
	if len(results) != len(want) {
		t.Fatalf("%d results, want %d: %+v", len(results), len(want), results)
	}
	for i, w := range want {
		r := results[i]
		after := ""
		if r.Err == nil {
			after = r.After.Outcome()
		}
		if r.Event.Tool != w.tool || r.Before != w.before || after != w.after || r.Changed() != w.changed {
			t.Errorf("%d: got %s %s -> %s (changed %v, err %v), want %+v", i, r.Event.Tool, r.Before, after, r.Changed(), r.Err, w)
		}
	}
	if r := results[1]; !r.NowBlocked() || r.NowAllowed() || r.After.Rule != "fs-workspace-only" {
		t.Errorf("/etc/passwd: %+v", r)
	}
	if r := results[2]; r.NowBlocked() || !r.NowAllowed() {
		t.Errorf("git reset: %+v", r)
	}
	if !errors.Is(results[6].Err, ErrTruncated) {
		t.Errorf("truncated call: %v", results[6].Err)
	}
}

// A log_only rule is replayed as it would run: not enforced, but reported.
func TestCheckLogOnly(t *testing.T) {
	p := compile(t, `
rules:
  - name: try-me
    tool: "*"
    action: deny
    log_only: true
`)
	r := Check([]audit.Event{call(0, "fs__read_file", "", `{"name":"fs__read_file"}`)}, p)
	if len(r) != 1 || r[0].Changed() || r[0].After.Would == nil || r[0].After.Would.Rule != "try-me" {
		t.Errorf("%+v", r)
	}
}
