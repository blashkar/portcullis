package dashboard

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blashkar/portcullis/internal/approval"
	"github.com/blashkar/portcullis/internal/audit"
	"github.com/blashkar/portcullis/internal/gateway"
	"github.com/blashkar/portcullis/internal/policy"
	"github.com/blashkar/portcullis/internal/redact"
)

func TestSecurityPage(t *testing.T) {
	f := startDashboard(t)
	if _, body := f.get(f.url + "security"); !strings.Contains(body, "Nothing caught yet") {
		t.Error("empty security page")
	}
	ok := call("fs__read", `{"path":"/workspace/a"}`, textResult("fine"))
	f.feed.Observe(ok, gateway.Details{})
	denied := call("fs__read", `{"path":"/etc/passwd"}`, "")
	denied.Decision, denied.Rule, denied.Reason = "deny", "workspace-only", "outside /workspace"
	f.feed.Observe(denied, gateway.Details{})
	f.feed.Observe(call("cfg__read", `{}`, textResult("key: [REDACTED:aws_access_key]")), gateway.Details{Redacted: map[string]int{"aws_access_key": 1}})
	f.feed.Observe(audit.Event{
		Method: "tool/held", Direction: audit.Internal, Tool: "evil__notes", Reason: "its definition looks like tool poisoning",
		Findings: "high hidden-instructions in description: \"<IMPORTANT>\"",
	}, gateway.Details{})

	_, body := f.get(f.url + "security")
	for _, want := range []string{
		"Denied by policy", "policy: rule workspace-only", "denied; the server never saw it", `path=&#34;/etc/passwd&#34;`,
		"Secrets redacted", "secret redaction", "delivered without the secrets", "It was replaced",
		"Tool held back", "the tool-poisoning scanner", "tool hidden from the agent", "&lt;IMPORTANT&gt;",
		`href="./?event=2"`, `class="tab on" aria-current="page">Security events <span class="count bad">3</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("security page lacks %q", want)
		}
	}
	if strings.Contains(body, "/workspace/a") {
		t.Error("a call that went through is a security event")
	}
	if strings.Index(body, "evil__notes") > strings.Index(body, "/etc/passwd") {
		t.Error("not newest first")
	}
}

func TestServersPage(t *testing.T) {
	pol, err := policy.Compile(policy.Spec{Default: policy.Allow, Rules: []policy.RuleSpec{
		{Name: "budget", RateLimit: "120/min"},
		{Name: "workspace-only", Tool: policy.Patterns{"fs__*"}, When: `!args.path.startsWith("/workspace")`, Action: policy.Deny},
		{Name: "no-resets", Tool: policy.Patterns{"git__git_reset"}, Action: policy.Deny},
		{Name: "confirm-commits", Tool: policy.Patterns{"git__git_commit"}, Action: policy.RequireApproval},
		{Name: "trial", Tool: policy.Patterns{"git__git_log"}, Action: policy.Deny, LogOnly: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	f := startDashboardWith(t, func(s *Server) {
		s.o.Policy = pol
		s.o.Servers = func() []gateway.ServerInfo {
			return []gateway.ServerInfo{
				{Name: "fs", Connected: true, Tools: []string{"fs__read_file"}},
				{
					Name: "git", Connected: true, Tools: []string{"git__git_commit", "git__git_log", "git__git_reset"},
					Held: map[string]string{"git__git_push": "its definition changed since it was approved"},
				},
				{Name: "local", Connected: false, Tools: nil},
			}
		}
		s.o.Commands = map[string][]string{
			"fs": {"sandbox/run.sh", "filesystem"}, "git": {"../sandbox/run.sh", "git"}, "local": {"node", "server<x>.js"},
		}
	})
	_, body := f.get(f.url + "servers")
	section := func(name string) string {
		i := strings.Index(body, `<span class="tool big">`+name+`</span>`)
		if i < 0 {
			t.Fatalf("no card for %s", name)
		}
		rest := body[i:]
		if j := strings.Index(rest[1:], `<span class="tool big">`); j >= 0 {
			rest = rest[:j+1]
		}
		return rest
	}
	for name, wants := range map[string][]string{
		"fs": {
			"Docker sandbox", "sandbox/run.sh filesystem", "depends on arguments", "Some calls are denied",
			"budget: at most 120/min", "workspace-only: denied for some arguments", "otherwise the default: allowed",
		},
		"git": {
			"Docker sandbox", "1 held back", `git__git_commit</span><span class="stage info">needs approval`,
			`git__git_reset</span><span class="stage bad">denied`, `git__git_log</span><span class="stage ok">allowed`,
			"trial: denied (log only)", `git__git_push</span><span class="stage bad">held back`, "changed since it was approved",
		},
		"local": {"disconnected", "not sandboxed", "runs directly on this machine", "node server&lt;x&gt;.js"},
	} {
		sec := section(name)
		for _, want := range wants {
			if !strings.Contains(sec, want) {
				t.Errorf("%s card lacks %q", name, want)
			}
		}
	}
	if !strings.Contains(body, `Servers &amp; tools <span class="count bad">1</span>`) {
		t.Error("the tab doesn't count the held tool")
	}
}

func TestSandboxed(t *testing.T) {
	for cmd, want := range map[string]bool{
		"sandbox/run.sh": true, "../sandbox/run.sh": true, "/opt/portcullis/sandbox/run.sh": true,
		"run.sh": false, "sandbox/evil.sh": false, "npx": false, "notsandbox/run.sh": false,
	} {
		if got := sandboxed([]string{cmd, "x"}); got != want {
			t.Errorf("%s: %v", cmd, got)
		}
	}
	if sandboxed(nil) {
		t.Error("no command")
	}
}

// fakeAudit is an audit log with fixed sessions.
type fakeAudit struct {
	sessions []audit.Session
	events   map[string][]audit.Event
	err      error
}

func (a *fakeAudit) Sessions(context.Context, int) ([]audit.Session, error) {
	return a.sessions, a.err
}

func (a *fakeAudit) Events(_ context.Context, f audit.Filter) ([]audit.Event, error) {
	return a.events[f.SessionID], a.err
}

func TestSessionsPage(t *testing.T) {
	token := "ghp_" + strings.Repeat("a1B2", 9)
	start := time.Date(2026, 1, 2, 9, 0, 0, 0, time.UTC)
	denied := call("fs__read", `{"path":"/etc/passwd"}`, "")
	denied.ID, denied.Decision, denied.Rule, denied.IsError = 3, "deny", "workspace-only", true
	sent := call("web__post", `{"body":"TOKEN=`+token+`"}`, textResult("ok"))
	sent.ID = 4
	redacted := call("cfg__read", `{}`, textResult("key: [REDACTED:github_token]"))
	redacted.ID, redacted.Findings = 5, "redacted: github_token×2"
	logs := &fakeAudit{
		sessions: []audit.Session{
			{ID: "SESSION1", Started: start.Add(time.Hour), Client: "claude-code 2.0", Upstreams: "fs,git", ToolCallCount: 3, BlockedCalls: 1},
			{ID: "OLDSESSION", Started: start, Ended: start.Add(90 * time.Second), Client: "portcullis-agent", Upstreams: "fs", ToolCallCount: 2},
		},
		events: map[string][]audit.Event{"OLDSESSION": {
			{ID: 1, Method: "initialize", Direction: audit.ClientToServer},
			{ID: 2, Method: "tools/list", Direction: audit.ClientToServer},
			denied, sent, redacted,
		}},
	}
	f := startDashboardWith(t, func(s *Server) { s.o.Audit, s.o.Redactor = logs, redact.New() })

	_, body := f.get(f.url + "sessions")
	for _, want := range []string{"2026-01-02 10:00", "this one", "claude-code 2.0", "fs, git", "1m30s", "open", `href="sessions?id=OLDSESSION"`, "Select a session"} {
		if !strings.Contains(body, want) {
			t.Errorf("sessions lack %q", want)
		}
	}

	_, body = f.get(f.url + "sessions?id=OLDSESSION")
	for _, want := range []string{"Session OLDSESSION", "policy</span> denied", "checks</span> 2 secrets redacted", `href="sessions?event=3&amp;id=OLDSESSION"`, `class="selected"`} {
		if !strings.Contains(body, want) {
			t.Errorf("session timeline lacks %q", want)
		}
	}
	if strings.Contains(body, "tools/list") || strings.Contains(body, "initialize") {
		t.Error("housekeeping is in the timeline")
	}
	if strings.Contains(body, token) {
		t.Error("a secret the client sent is shown")
	}
	_, body = f.get(f.url + "sessions-main?id=OLDSESSION&event=4")
	if !strings.Contains(body, "[REDACTED:github_token]") || strings.Contains(body, token) {
		t.Error("the selected call's arguments aren't redacted")
	}
	_, body = f.get(f.url + "sessions?id=OLDSESSION&show=caught")
	if strings.Contains(body, "web__post") || !strings.Contains(body, "fs__read") {
		t.Error("the caught filter on a past session")
	}

	for q, want := range map[string]string{
		"id=NOSUCH":                     "isn't among the recent ones",
		"id=%3Cscript%3E":               "Select a session",
		"id=" + strings.Repeat("A", 65): "Select a session",
	} {
		if _, body := f.get(f.url + "sessions?" + q); !strings.Contains(body, want) || strings.Contains(body, "<script>") {
			t.Errorf("%s: lacks %q", q, want)
		}
	}

	logs.err = errors.New("disk on fire")
	if _, body := f.get(f.url + "sessions"); !strings.Contains(body, "couldn't be read") || strings.Contains(body, "disk on fire") {
		t.Error("a read error")
	}
	g := startDashboard(t)
	if _, body := g.get(g.url + "sessions"); !strings.Contains(body, "audit log is off") {
		t.Error("no audit log")
	}
}

func TestDetailsFromAudit(t *testing.T) {
	for _, c := range []struct {
		e    audit.Event
		want gateway.Details
	}{
		{
			audit.Event{Method: "tools/call", Findings: "redacted: aws_access_key, github_token×3"},
			gateway.Details{Redacted: map[string]int{"aws_access_key": 1, "github_token": 3}},
		},
		{
			audit.Event{Method: "tools/call", Findings: `prompt injection (override: "x"); high override: "x"`},
			gateway.Details{Injection: true},
		},
		{
			audit.Event{Method: "tools/call", Findings: `prompt injection (override: "x")`, Result: `{"content":[{"type":"text","text":"[portcullis] This tool result was withheld because it appears to contain a prompt injection."}]}`},
			gateway.Details{Injection: true, Withheld: true},
		},
		{
			audit.Event{Method: "tools/call", Findings: `medium override: "x"; the guard model found no injection`},
			gateway.Details{Suspicious: true},
		},
		{
			audit.Event{Method: "tools/call", Decision: "require_approval", Reason: "nobody answered in time"},
			gateway.Details{Approval: "expired"},
		},
		{audit.Event{Method: "tool/flagged", Findings: `medium secrets in description: "env"`}, gateway.Details{}},
	} {
		got := detailsFromAudit(c.e)
		if got.Injection != c.want.Injection || got.Withheld != c.want.Withheld || got.Suspicious != c.want.Suspicious ||
			got.Approval != c.want.Approval || len(got.Redacted) != len(c.want.Redacted) {
			t.Errorf("%+v:\n got %+v\nwant %+v", c.e.Findings, got, c.want)
		}
		for k, n := range c.want.Redacted {
			if got.Redacted[k] != n {
				t.Errorf("%s: %d", k, got.Redacted[k])
			}
		}
	}
}

// Every page has the tabs, says when calls are waiting, and refreshes from
// its own main section.
func TestPagesAndTabs(t *testing.T) {
	f := startDashboard(t)
	r, _ := f.ask(approval.Request{Tool: "git__git_push", Args: []byte(`{}`), Rule: "confirm-push"})
	defer func() { _ = f.broker.Decide(r.ID, false) }()
	for page, partial := range map[string]string{"": "main", "security": "security-main", "servers": "servers-main", "sessions": "sessions-main"} {
		res, body := f.get(f.url + page)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%q: %d", page, res.StatusCode)
		}
		for _, want := range []string{`data-partial="` + partial + `"`, `aria-label="Dashboard pages" data-pending="1"`, `Live <span class="count info">1</span>`} {
			if !strings.Contains(body, want) {
				t.Errorf("%q lacks %q", page, want)
			}
		}
		if banner := strings.Contains(body, "1 call is waiting for your approval"); banner != (page != "") {
			t.Errorf("%q: banner %v", page, banner)
		}
		if res, _ := f.get(f.url + partial); res.StatusCode != http.StatusOK {
			t.Errorf("%s: %d", partial, res.StatusCode)
		}
		if res, _ := f.get(f.base + "/wrongtoken/" + page); res.StatusCode != http.StatusNotFound {
			t.Errorf("wrong token on %q: %d", page, res.StatusCode)
		}
	}
}
