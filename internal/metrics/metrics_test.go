package metrics

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blashkar/portcullis/internal/audit"
	"github.com/blashkar/portcullis/internal/gateway"
)

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape = %d", rec.Code)
	}
	return rec.Body.String()
}

func wantLines(t *testing.T, body string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if !strings.Contains(body, "\n"+l+"\n") {
			t.Errorf("missing %q", l)
		}
	}
}

func call(tool, decision string, failed bool) audit.Event {
	server, _, _ := strings.Cut(tool, "__")
	return audit.Event{
		Direction: audit.ClientToServer, Method: "tools/call", Tool: tool, Upstream: server,
		Decision: decision, IsError: failed, Duration: 30 * time.Millisecond,
	}
}

func TestObserve(t *testing.T) {
	pending, held := 2, 1
	m := New(Options{Version: "v1.2.3", Pending: func() int { return pending }, Held: func() int { return held }})
	m.Observe(call("fs__read_file", "allow", false), gateway.Details{})
	m.Observe(call("fs__read_file", "allow", false), gateway.Details{Redacted: map[string]int{"github_token": 2}})
	m.Observe(call("fs__read_file", "allow", true), gateway.Details{})
	m.Observe(call("fs__write_file", "deny", true), gateway.Details{})
	m.Observe(call("fs__write_file", "require_approval", true), gateway.Details{Approval: "denied"})
	m.Observe(call("fs__write_file", audit.DecisionApproved, false), gateway.Details{Approval: "approved"})
	m.Observe(call("web__fetch", "", false), gateway.Details{Injection: true})
	m.Observe(call("web__fetch", "", false), gateway.Details{Suspicious: true})
	m.Observe(audit.Event{Direction: audit.ServerToClient, Method: "notifications/tools/list_changed"}, gateway.Details{})
	m.Observe(audit.Event{Direction: audit.ClientToServer, Method: "made/up"}, gateway.Details{})
	m.Observe(audit.Event{Direction: audit.Internal, Method: "tool/changed", Upstream: "fs", Tool: "fs__read_file"}, gateway.Details{})
	m.Observe(audit.Event{Direction: audit.Internal, Method: "tool/pinned", Upstream: "fs", Tool: "fs__read_file"}, gateway.Details{})
	m.Observe(audit.Event{Direction: audit.Internal, Method: "upstream/disconnected", Upstream: "web", IsError: true}, gateway.Details{})

	body := scrape(t, m)
	wantLines(t, body,
		`portcullis_tool_calls_total{decision="allow",outcome="ok",server="fs",tool="fs__read_file"} 2`,
		`portcullis_tool_calls_total{decision="allow",outcome="failed",server="fs",tool="fs__read_file"} 1`,
		`portcullis_tool_calls_total{decision="deny",outcome="blocked",server="fs",tool="fs__write_file"} 1`,
		`portcullis_tool_calls_total{decision="require_approval",outcome="blocked",server="fs",tool="fs__write_file"} 1`,
		`portcullis_tool_calls_total{decision="approved",outcome="ok",server="fs",tool="fs__write_file"} 1`,
		`portcullis_tool_calls_total{decision="none",outcome="ok",server="web",tool="web__fetch"} 2`,
		`portcullis_secrets_redacted_total{kind="github_token",server="fs"} 2`,
		`portcullis_injection_findings_total{server="web",verdict="injection"} 1`,
		`portcullis_injection_findings_total{server="web",verdict="suspicious"} 1`,
		`portcullis_approvals_total{outcome="approved"} 1`,
		`portcullis_approvals_total{outcome="denied"} 1`,
		`portcullis_messages_total{direction="client->server",method="tools/call"} 8`,
		`portcullis_messages_total{direction="client->server",method="other"} 1`,
		`portcullis_messages_total{direction="server->client",method="notifications/tools/list_changed"} 1`,
		`portcullis_tool_definitions_total{result="changed",server="fs"} 1`,
		`portcullis_tool_definitions_total{result="pinned",server="fs"} 1`,
		`portcullis_upstream_disconnects_total{server="web"} 1`,
		`portcullis_approvals_pending 2`,
		`portcullis_tools_held 1`,
		`portcullis_build_info{version="v1.2.3"} 1`,
		// Blocked calls never ran, so only the six that went ahead are timed.
		`portcullis_tool_call_duration_seconds_count{server="fs"} 4`,
		`portcullis_tool_call_duration_seconds_count{server="web"} 2`,
	)
	if strings.Contains(body, "portcullis_tools_offered") {
		t.Error("a gauge without a function was registered")
	}

	pending, held = 0, 3
	wantLines(t, scrape(t, m), `portcullis_approvals_pending 0`, `portcullis_tools_held 3`)
}

// A client can name any tool, so it can't make the metrics grow without
// bound.
func TestToolNamesAreCapped(t *testing.T) {
	m := New(Options{})
	for i := range maxNames + 50 {
		m.Observe(call(fmt.Sprintf("fs__tool%d", i), "allow", true), gateway.Details{})
	}
	body := scrape(t, m)
	if n := strings.Count(body, "portcullis_tool_calls_total{"); n != maxNames+1 {
		t.Errorf("%d series, want %d", n, maxNames+1)
	}
	wantLines(t, body, `portcullis_tool_calls_total{decision="allow",outcome="failed",server="fs",tool="other"} 50`)
}

func TestServe(t *testing.T) {
	m := New(Options{Version: "test"})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- m.Serve(ctx, ln, slog.New(slog.DiscardHandler)) }()

	get := func(host, path string) (int, string) {
		req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	for _, host := range []string{ln.Addr().String(), "localhost:" + port} {
		if code, body := get(host, "/metrics"); code != http.StatusOK || !strings.Contains(body, `portcullis_build_info{version="test"} 1`) {
			t.Errorf("Host %s: %d\n%.200s", host, code, body)
		}
	}
	// A page on another site, its name rebound to 127.0.0.1, can't read them.
	if code, _ := get("evil.example:"+port, "/metrics"); code != http.StatusForbidden {
		t.Errorf("wrong host: %d", code)
	}
	if code, _ := get(ln.Addr().String(), "/"); code != http.StatusNotFound {
		t.Errorf("/: %d", code)
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("Serve: %v", err)
	}
}

func TestServeRefusesNonLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	if err := New(Options{}).Serve(t.Context(), ln, slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Errorf("Serve on %v: %v", ln.Addr(), err)
	}
}
