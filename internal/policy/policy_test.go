package policy

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func mustCompile(t *testing.T, src string) *Policy {
	t.Helper()
	var s Spec
	dec := yaml.NewDecoder(strings.NewReader(src))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		t.Fatal(err)
	}
	p, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const workspacePolicy = `
default: allow
rules:
  - name: fs-workspace-only
    tool: "fs__*"
    when: 'values(args, ["path", "paths", "source", "destination"]).exists(p, !under(p, "/workspace"))'
    action: deny
    reason: the filesystem tools only work under /workspace
  - name: no-reset
    tool: [git__git_reset, git__git_checkout]
    action: deny
  - name: confirm-commits
    tool: git__git_commit
    action: require_approval
  - name: git-allowed
    tool: "git__*"
    action: allow
  - name: everything-off
    tool: "everything__*"
    action: deny
`

func TestCheck(t *testing.T) {
	p := mustCompile(t, workspacePolicy)
	tests := []struct {
		name   string
		call   Call
		action Action
		rule   string
	}{
		{"inside the workspace", Call{Tool: "fs__read_file", Args: map[string]any{"path": "/workspace/notes.txt"}}, Allow, ""},
		{"the workspace itself", Call{Tool: "fs__list_directory", Args: map[string]any{"path": "/workspace"}}, Allow, ""},
		{"outside", Call{Tool: "fs__read_file", Args: map[string]any{"path": "/etc/passwd"}}, Deny, "fs-workspace-only"},
		{"dot-dot", Call{Tool: "fs__read_file", Args: map[string]any{"path": "/workspace/../etc/passwd"}}, Deny, "fs-workspace-only"},
		{"prefix but not inside", Call{Tool: "fs__read_file", Args: map[string]any{"path": "/workspace-evil/x"}}, Deny, "fs-workspace-only"},
		{"relative", Call{Tool: "fs__read_file", Args: map[string]any{"path": "notes.txt"}}, Deny, "fs-workspace-only"},
		{"home", Call{Tool: "fs__read_file", Args: map[string]any{"path": "~/.ssh/id_ed25519"}}, Deny, "fs-workspace-only"},
		{"one of several paths", Call{Tool: "fs__read_multiple_files", Args: map[string]any{"paths": []any{"/workspace/a", "/etc/shadow"}}}, Deny, "fs-workspace-only"},
		{"move out", Call{Tool: "fs__move_file", Args: map[string]any{"source": "/workspace/a", "destination": "/tmp/a"}}, Deny, "fs-workspace-only"},
		{"move within", Call{Tool: "fs__move_file", Args: map[string]any{"source": "/workspace/a", "destination": "/workspace/b"}}, Allow, ""},
		{"no path argument", Call{Tool: "fs__list_allowed_directories"}, Allow, ""},
		{"a path that isn't a string fails closed", Call{Tool: "fs__read_file", Args: map[string]any{"path": 42.0}}, Deny, "fs-workspace-only"},
		{"listed tool", Call{Tool: "git__git_checkout", Args: map[string]any{"repo_path": "/workspace/repo"}}, Deny, "no-reset"},
		{"require approval", Call{Tool: "git__git_commit"}, RequireApproval, "confirm-commits"},
		{"allow rule", Call{Tool: "git__git_log"}, Allow, "git-allowed"},
		{"star matches anything", Call{Tool: "everything__get-env"}, Deny, "everything-off"},
		{"star matches slashes too", Call{Tool: "everything__a/b"}, Deny, "everything-off"},
		{"other servers fall through to the default", Call{Tool: "other__tool"}, Allow, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := p.Check(tt.call)
			if d.Action != tt.action || d.Rule != tt.rule {
				t.Errorf("got %s by %q (%s), want %s by %q", d.Action, d.Rule, d.Reason, tt.action, tt.rule)
			}
			if d.Would != nil {
				t.Errorf("unexpected log_only decision %+v", d.Would)
			}
		})
	}
	if d := p.Check(Call{Tool: "fs__read_file", Args: map[string]any{"path": "/etc/passwd"}}); d.Reason != "the filesystem tools only work under /workspace" {
		t.Errorf("reason = %q", d.Reason)
	}
}

func TestNilPolicyAllows(t *testing.T) {
	var p *Policy
	if d := p.Check(Call{Tool: "anything"}); d.Action != Allow || d.Blocked() {
		t.Errorf("nil policy: %+v", d)
	}
}

func TestDefaultDeny(t *testing.T) {
	p := mustCompile(t, `
default: deny
rules:
  - tool: fs__read_file
    action: allow
`)
	if d := p.Check(Call{Tool: "fs__read_file"}); d.Action != Allow || d.Rule != "rule 1" {
		t.Errorf("allowed tool: %+v", d)
	}
	if d := p.Check(Call{Tool: "fs__write_file"}); d.Action != Deny || d.Rule != "" || d.Reason != "no rule matched" {
		t.Errorf("other tool: %+v", d)
	}
}

func TestConditionErrorsFailClosed(t *testing.T) {
	p := mustCompile(t, `
rules:
  - name: careless
    tool: "*"
    when: 'args.path.startsWith("/tmp")'
    action: allow
`)
	d := p.Check(Call{Tool: "fs__list_allowed_directories"})
	if d.Action != Deny || d.Rule != "careless" || !strings.Contains(d.Reason, "no such key") {
		t.Errorf("got %+v, want a deny explaining the missing key", d)
	}
}

func TestVariables(t *testing.T) {
	p := mustCompile(t, `
rules:
  - tool: "*"
    when: 'server == "git" && tool.endsWith("_reset") && args.?repo_path.orValue("").lowerAscii().contains("prod")'
    action: deny
`)
	if d := p.Check(Call{Tool: "git__git_reset", Server: "git", Args: map[string]any{"repo_path": "/workspace/PROD"}}); d.Action != Deny {
		t.Errorf("got %+v", d)
	}
	if d := p.Check(Call{Tool: "git__git_reset", Server: "git", Args: map[string]any{"repo_path": "/workspace/dev"}}); d.Action != Allow {
		t.Errorf("got %+v", d)
	}
}

func TestRateLimit(t *testing.T) {
	p := mustCompile(t, `
rules:
  - name: budget
    tool: "fs__*"
    rate_limit: 2/min
  - name: no-writes
    tool: fs__write_file
    action: deny
`)
	read := Call{Tool: "fs__read_file"}
	for i := range 2 {
		if d := p.Check(read); d.Action != Allow {
			t.Fatalf("call %d: %+v", i+1, d)
		}
	}
	d := p.Check(read)
	if d.Action != Deny || !d.RateLimited || d.Outcome() != "rate_limit" || d.Rule != "budget" || d.Reason != "rate limit of 2/min exceeded" {
		t.Errorf("third call: %+v", d)
	}
	// Under the limit, a rate limit rule doesn't decide: later rules do.
	q := mustCompile(t, `
rules:
  - tool: "*"
    rate_limit: 5/s
  - name: no-writes
    tool: fs__write_file
    action: deny
`)
	if d := q.Check(Call{Tool: "fs__write_file"}); d.Rule != "no-writes" {
		t.Errorf("got %+v, want no-writes to decide", d)
	}
}

// Calls with a recorded time, as replay checks them, are rate-limited by
// that time rather than the clock.
func TestRateLimitCallTime(t *testing.T) {
	p := mustCompile(t, `
rules:
  - tool: "*"
    rate_limit: 2/min
`)
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	var got []string
	for _, offset := range []time.Duration{0, time.Second, 2 * time.Second, 61 * time.Second} {
		got = append(got, p.Check(Call{Tool: "fs__read", Time: start.Add(offset)}).Outcome())
	}
	if want := "allow allow rate_limit allow"; strings.Join(got, " ") != want {
		t.Errorf("got %v, want %s", got, want)
	}
}

func TestLimiterWindow(t *testing.T) {
	l, err := parseRateLimit("2/sec")
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(1000, 0)
	steps := []struct {
		at   time.Duration
		want bool
	}{
		{0, true},
		{100 * time.Millisecond, true},
		{500 * time.Millisecond, false}, // two in the last second
		{1000 * time.Millisecond, true}, // the first has left the window
		{1050 * time.Millisecond, false},
		{1100 * time.Millisecond, true},
	}
	for _, s := range steps {
		if got := l.allow(t0.Add(s.at)); got != s.want {
			t.Errorf("at %v: allow = %v, want %v", s.at, got, s.want)
		}
	}
}

func TestLogOnlyRule(t *testing.T) {
	p := mustCompile(t, `
rules:
  - name: trial
    tool: "fs__*"
    when: '!under(args.path, "/workspace")'
    action: deny
    log_only: true
`)
	d := p.Check(Call{Tool: "fs__read_file", Args: map[string]any{"path": "/etc/passwd"}})
	if d.Action != Allow || d.Would == nil || d.Would.Action != Deny || d.Would.Rule != "trial" {
		t.Errorf("got %+v (would %+v), want allow, would deny by trial", d, d.Would)
	}
	if d := p.Check(Call{Tool: "fs__read_file", Args: map[string]any{"path": "/workspace/a"}}); d.Action != Allow || d.Would != nil {
		t.Errorf("inside: %+v", d)
	}
}

func TestLogOnlyPolicy(t *testing.T) {
	p := mustCompile(t, `
default: deny
log_only: true
rules:
  - name: reads
    tool: fs__read_file
    action: allow
  - name: everything-else
    tool: "fs__*"
    action: deny
`)
	// An allow rule that matches first means enforcing would allow too, so
	// there's nothing to report, even though a later rule would deny.
	if d := p.Check(Call{Tool: "fs__read_file"}); d.Action != Allow || d.Would != nil {
		t.Errorf("read: %+v, would %+v", d, d.Would)
	}
	if d := p.Check(Call{Tool: "fs__write_file"}); d.Action != Allow || d.Would == nil || d.Would.Rule != "everything-else" {
		t.Errorf("write: %+v, would %+v", d, d.Would)
	}
	if d := p.Check(Call{Tool: "git__git_log"}); d.Action != Allow || d.Would == nil || d.Would.Action != Deny || d.Would.Rule != "" {
		t.Errorf("unmatched: %+v, would %+v", d, d.Would)
	}
}

func TestLogOnlyAllowBeforeDeny(t *testing.T) {
	// Trying out a looser rule: enforcement still denies, and the log shows
	// the rule would have allowed the call.
	p := mustCompile(t, `
rules:
  - name: loosen
    tool: fs__write_file
    action: allow
    log_only: true
  - name: no-writes
    tool: fs__write_file
    action: deny
`)
	d := p.Check(Call{Tool: "fs__write_file"})
	if d.Action != Deny || d.Rule != "no-writes" || d.Would == nil || d.Would.Action != Allow || d.Would.Rule != "loosen" {
		t.Errorf("got %+v, would %+v", d, d.Would)
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name, src, want string
	}{
		{"bad default", "default: maybe", "default must be allow or deny"},
		{"approval default", "default: require_approval", "default must be allow or deny"},
		{"no action", "rules: [{tool: x}]", "rule 1: no action or rate_limit"},
		{"both", "rules: [{tool: x, action: deny, rate_limit: 1/s}]", "not both"},
		{"bad action", "rules: [{tool: x, action: block}]", `not "block"`},
		{"bad rate", "rules: [{tool: x, rate_limit: 5/day}]", "such as 30/min"},
		{"zero rate", "rules: [{tool: x, rate_limit: 0/min}]", "positive"},
		{"syntax", `rules: [{name: oops, tool: x, action: deny, when: "args.path =="}]`, "oops: when:"},
		{"unknown function", `rules: [{tool: x, action: deny, when: "rm(args)"}]`, "undeclared reference"},
		{"not a bool", `rules: [{tool: x, action: deny, when: "args.path"}]`, "must be true or false"},
		{"duplicate names", "rules: [{name: a, action: deny}, {name: a, action: allow}]", `two rules are named "a"`},
		{"empty pattern", `rules: [{tool: [""], action: deny}]`, "empty tool pattern"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s Spec
			if err := yaml.Unmarshal([]byte(tt.src), &s); err != nil {
				t.Fatal(err)
			}
			_, err := Compile(s)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestUnused(t *testing.T) {
	p := mustCompile(t, workspacePolicy)
	got := p.Unused([]string{"fs__read_file", "git__git_log", "git__git_reset"})
	if strings.Join(got, ",") != "confirm-commits,everything-off" {
		t.Errorf("unused = %v", got)
	}
}

func TestUnder(t *testing.T) {
	tests := []struct {
		p, dir string
		want   bool
	}{
		{"/workspace/a/b", "/workspace", true},
		{"/workspace", "/workspace/", true},
		{"/workspace/./a/../b", "/workspace", true},
		{"/workspace/../workspace2", "/workspace", false},
		{"//workspace//a", "/workspace", true},
		{"/etc", "/", true},
		{"a", "/", false},
		{"/workspace/a\x00", "/workspace", false},
		{"/workspace/a", "workspace", false},
	}
	for _, tt := range tests {
		if got := under(tt.p, tt.dir); got != tt.want {
			t.Errorf("under(%q, %q) = %v, want %v", tt.p, tt.dir, got, tt.want)
		}
	}
}

func TestConcurrentChecks(t *testing.T) {
	p := mustCompile(t, `
rules:
  - tool: "*"
    rate_limit: 50/hour
  - tool: "*"
    when: 'under(args.path, "/workspace")'
    action: allow
`)
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for range 200 {
		wg.Go(func() {
			if !p.Check(Call{Tool: "fs__read_file", Args: map[string]any{"path": "/workspace/a"}}).Blocked() {
				allowed.Add(1)
			}
		})
	}
	wg.Wait()
	if allowed.Load() != 50 {
		t.Errorf("%d calls allowed, want 50", allowed.Load())
	}
}
