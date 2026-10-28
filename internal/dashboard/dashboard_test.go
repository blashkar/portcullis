package dashboard

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/blashkar/portcullis/internal/approval"
	"github.com/blashkar/portcullis/internal/audit"
	"github.com/blashkar/portcullis/internal/pin"
)

type fixture struct {
	t      *testing.T
	ctx    context.Context
	base   string // http://127.0.0.1:port
	url    string // base + "/token/"
	hub    *Hub
	broker *approval.Broker
	feed   *Feed
	pins   *pin.Store
	heldMu sync.Mutex
	heldM  map[string]string
}

func startDashboard(t *testing.T) *fixture {
	t.Helper()
	return startDashboardWith(t, func(*Server) {})
}

func startDashboardWith(t *testing.T, configure func(*Server)) *fixture {
	t.Helper()
	f := &fixture{t: t, hub: NewHub(), heldM: map[string]string{}}
	f.broker = approval.NewBroker(time.Minute, f.hub.Notify)
	f.feed = NewFeed(100, f.hub.Notify)
	f.pins = pin.Open(filepath.Join(t.TempDir(), "pins.json"), true)
	s := New(Options{
		Hub: f.hub, Approvals: f.broker, Feed: f.feed, Pins: f.pins, Version: "test", SessionID: "SESSION1",
		Held: func() map[string]string {
			f.heldMu.Lock()
			defer f.heldMu.Unlock()
			out := map[string]string{}
			for k, v := range f.heldM {
				out[k] = v
			}
			return out
		},
	})
	configure(s)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	f.ctx = ctx
	f.base = "http://" + ln.Addr().String()
	f.url = s.URL(ln.Addr())
	return f
}

var client = &http.Client{
	Timeout: 10 * time.Second,
	// Redirects are part of what's tested.
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func (f *fixture) do(req *http.Request) (*http.Response, string) {
	f.t.Helper()
	res, err := client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res, string(body)
}

func (f *fixture) get(u string) (*http.Response, string) {
	f.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	return f.do(req)
}

func (f *fixture) post(path string, form url.Values, header map[string]string) (*http.Response, string) {
	f.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.url+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	return f.do(req)
}

// ask starts a call waiting for approval and returns its request and a
// channel with the outcome.
func (f *fixture) ask(req approval.Request) (approval.Request, <-chan approval.Outcome) {
	f.t.Helper()
	out := make(chan approval.Outcome, 1)
	before := len(f.broker.Pending())
	go func() { out <- f.broker.Ask(context.Background(), req) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p := f.broker.Pending(); len(p) > before {
			return p[len(p)-1], out
		}
		time.Sleep(time.Millisecond)
	}
	f.t.Fatal("the request never started waiting")
	return approval.Request{}, nil
}

func TestTokenIsRequired(t *testing.T) {
	f := startDashboard(t)
	for _, u := range []string{f.base + "/", f.base + "/wrong/", f.base + "/wrong/main", f.base + "/static/app.js"} {
		if res, _ := f.get(u); res.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", u, res.StatusCode)
		}
	}
	res, body := f.get(f.url)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "Waiting for approval") {
		t.Fatalf("GET with the token = %d\n%s", res.StatusCode, body)
	}
	// Without the trailing slash, relative links would break.
	if res, _ := f.get(strings.TrimSuffix(f.url, "/")); res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != res.Request.URL.Path+"/" {
		t.Errorf("GET without the slash = %d, Location %q", res.StatusCode, res.Header.Get("Location"))
	}
	for _, p := range []string{"static/app.js", "static/style.css"} {
		if res, _ := f.get(f.url + p); res.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d", p, res.StatusCode)
		}
	}
	if res, _ := f.get(f.url + "static/page.html"); res.StatusCode != http.StatusNotFound {
		t.Errorf("templates are served: %d", res.StatusCode)
	}
}

func TestSecurityHeaders(t *testing.T) {
	f := startDashboard(t)
	for _, u := range []string{f.url, f.base + "/nope"} {
		res, _ := f.get(u)
		csp := res.Header.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "form-action 'self'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP %q lacks %q", u, csp, want)
			}
		}
		for h, want := range map[string]string{"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin", "Cache-Control": "no-store"} {
			if got := res.Header.Get(h); got != want {
				t.Errorf("%s: %s = %q, want %q", u, h, got, want)
			}
		}
		if res.Header.Get("Set-Cookie") != "" {
			t.Errorf("%s set a cookie", u)
		}
	}
	// A meta tag overrides the header. Under no-referrer, browsers send
	// "Origin: null" on the page's own form posts, and they're refused.
	if _, body := f.get(f.url); !strings.Contains(body, `<meta name="referrer" content="same-origin">`) || strings.Contains(body, "no-referrer") {
		t.Error("the page doesn't set the same-origin referrer policy")
	}
}

// A web page whose domain resolves to 127.0.0.1 (DNS rebinding) sends its
// own name as the Host.
func TestWrongHostIsRefused(t *testing.T) {
	f := startDashboard(t)
	req, _ := http.NewRequest(http.MethodGet, f.url, nil)
	req.Host = "attacker.example:" + req.URL.Port()
	if res, _ := f.do(req); res.StatusCode != http.StatusForbidden {
		t.Errorf("rebinding host = %d, want 403", res.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodGet, f.url, nil)
	req.Host = "localhost:" + req.URL.Port()
	if res, _ := f.do(req); res.StatusCode != http.StatusOK {
		t.Errorf("localhost = %d, want 200", res.StatusCode)
	}
}

func TestApproveAndDenyCalls(t *testing.T) {
	f := startDashboard(t)
	write, wrote := f.ask(approval.Request{Tool: "fs__write_file", Server: "fs", Args: []byte(`{"path":"/workspace/a","content":"hi"}`), Rule: "confirm-writes", Reason: "writes change files"})
	push, pushed := f.ask(approval.Request{Tool: "git__git_push", Server: "git", Args: []byte(`{}`), Rule: "confirm-push"})

	_, body := f.get(f.url + "main")
	for _, want := range []string{"fs__write_file", "confirm-writes", "writes change files", `&#34;path&#34;: &#34;/workspace/a&#34;`, "git__git_push", `data-pending="2"`, write.ID} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}

	res, _ := f.post("approvals", url.Values{"id": {write.ID}, "decision": {"approve"}}, map[string]string{"Origin": f.base, "Sec-Fetch-Site": "same-origin"})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("approve = %d", res.StatusCode)
	}
	if o := <-wrote; o != approval.Approved {
		t.Errorf("write = %v, want approved", o)
	}
	if res, _ := f.post("approvals", url.Values{"id": {push.ID}, "decision": {"deny"}}, nil); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("deny = %d", res.StatusCode)
	}
	if o := <-pushed; o != approval.Denied {
		t.Errorf("push = %v, want denied", o)
	}
	// Too late: the call was already decided.
	if res, body := f.post("approvals", url.Values{"id": {write.ID}, "decision": {"approve"}}, nil); res.StatusCode != http.StatusConflict || !strings.Contains(body, "waiting any more") {
		t.Errorf("deciding again = %d\n%s", res.StatusCode, body)
	}
	if res, _ := f.post("approvals", url.Values{"id": {"x"}, "decision": {"maybe"}}, nil); res.StatusCode != http.StatusBadRequest {
		t.Errorf("bad decision = %d", res.StatusCode)
	}
}

// Another web page open in the browser can post a form to the dashboard,
// but the browser says where the post came from.
func TestCrossSitePostsAreRefused(t *testing.T) {
	f := startDashboard(t)
	r, out := f.ask(approval.Request{Tool: "git__git_push", Args: []byte(`{}`)})
	for _, h := range []map[string]string{
		{"Origin": "http://attacker.example"},
		{"Origin": "null"},
		{"Sec-Fetch-Site": "cross-site"},
		{"Sec-Fetch-Site": "same-site"},
	} {
		if res, _ := f.post("approvals", url.Values{"id": {r.ID}, "decision": {"approve"}}, h); res.StatusCode != http.StatusForbidden {
			t.Errorf("%v: %d, want 403", h, res.StatusCode)
		}
	}
	// The wrong token gets nothing, even with the right request ID.
	req, _ := http.NewRequest(http.MethodPost, f.base+"/wrong/approvals", strings.NewReader(url.Values{"id": {r.ID}, "decision": {"approve"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if res, _ := f.do(req); res.StatusCode != http.StatusNotFound {
		t.Errorf("wrong token: %d", res.StatusCode)
	}
	if len(f.broker.Pending()) != 1 {
		t.Fatal("a refused post decided the call")
	}
	if err := f.broker.Decide(r.ID, false); err != nil {
		t.Fatal(err)
	}
	<-out
}

func TestTooLongArgumentsCanOnlyBeDenied(t *testing.T) {
	f := startDashboard(t)
	big := `{"content":"` + strings.Repeat("a", maxShownArgs) + `"}`
	r, out := f.ask(approval.Request{Tool: "fs__write_file", Args: []byte(big)})
	_, body := f.get(f.url + "main")
	if strings.Contains(body, `value="approve"`) || !strings.Contains(body, "can only be denied") {
		t.Error("the page offers to approve arguments it can't show")
	}
	if res, _ := f.post("approvals", url.Values{"id": {r.ID}, "decision": {"approve"}}, nil); res.StatusCode != http.StatusForbidden {
		t.Errorf("approve = %d, want 403", res.StatusCode)
	}
	if res, _ := f.post("approvals", url.Values{"id": {r.ID}, "decision": {"deny"}}, nil); res.StatusCode != http.StatusSeeOther {
		t.Errorf("deny = %d", res.StatusCode)
	}
	if o := <-out; o != approval.Denied {
		t.Errorf("outcome = %v", o)
	}
}

func TestTextIsEscapedAndHiddenCharactersShown(t *testing.T) {
	f := startDashboard(t)
	rlo := string(rune(0x202E))
	zwsp := string(rune(0x200B))
	tag := string(rune(0xE0041))
	r, out := f.ask(approval.Request{
		Tool:   `fs__<script>alert(1)</script>`,
		Args:   []byte(`{"path":"/workspace/invoice` + rlo + `fdp.exe","note":"a` + zwsp + `b` + tag + `"}`),
		Rule:   `<img src=x onerror=alert(1)>`,
		Reason: "x\x1b[31m",
	})
	defer func() {
		_ = f.broker.Decide(r.ID, false)
		<-out
	}()
	_, body := f.get(f.url + "main")
	for _, bad := range []string{"<script>alert", "<img src=x", rlo, zwsp, tag, "\x1b"} {
		if strings.Contains(body, bad) {
			t.Errorf("page contains %q raw", bad)
		}
	}
	for _, want := range []string{"&lt;script&gt;", "U+202E", "U+200B", "U+E0041", "U+001B"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

func TestVisible(t *testing.T) {
	cases := map[string]string{
		"plain":                        "plain",
		"a<b>&\"'":                     "a&lt;b&gt;&amp;&#34;&#39;",
		"line\nnext\ttab":              "line\nnext\ttab",
		"x" + string(rune(0x202E)):     `x<span class="esc" title="hidden character">U+202E</span>`,
		"bad\xffutf8":                  `bad<span class="esc" title="hidden character">U+FFFD</span>utf8`,
		string(rune(0xFE0F)) + "emoji": `<span class="esc" title="hidden character">U+FE0F</span>emoji`,
		"日本語":                          "日本語",
	}
	for in, want := range cases {
		if got := string(visible(in)); got != want {
			t.Errorf("visible(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestApproveHeldTool(t *testing.T) {
	f := startDashboard(t)
	tool := &mcp.Tool{Name: "add", Description: "Adds numbers", InputSchema: map[string]any{"type": "object"}}
	if _, err := f.pins.Check(map[string]pin.Definition{"m__add": pin.FromTool(tool)}); err != nil {
		t.Fatal(err)
	}
	f.heldMu.Lock()
	f.heldM["m__add"] = "it is new and hasn't been approved"
	f.heldM["m__evil"] = "its definition looks like tool poisoning"
	f.heldMu.Unlock()

	_, body := f.get(f.url + "main")
	hash := pin.FromTool(tool).Hash()
	for _, want := range []string{"m__add", "new", "Adds numbers", `value="` + hash + `"`, "m__evil", "tool poisoning"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Count(body, "Approve this definition") != 1 {
		t.Error("a tool held for poisoning can be approved from the page")
	}

	if res, _ := f.post("approve-tool", url.Values{"tool": {"m__add"}, "hash": {"sha256:other"}}, nil); res.StatusCode != http.StatusConflict {
		t.Errorf("stale hash = %d, want 409", res.StatusCode)
	}
	if res, _ := f.post("approve-tool", url.Values{"tool": {""}, "hash": {""}}, nil); res.StatusCode != http.StatusConflict {
		t.Errorf("no tool = %d, want 409", res.StatusCode)
	}
	if res, _ := f.post("approve-tool", url.Values{"tool": {"m__add"}, "hash": {hash}}, nil); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("approve = %d", res.StatusCode)
	}
	e, _ := f.pins.Entries()
	if e["m__add"].Hash != hash || e["m__add"].Pending != nil {
		t.Errorf("entry = %+v", e["m__add"])
	}
}

func TestFeedKeepsOnlyWhatIsShown(t *testing.T) {
	f := NewFeed(2, nil)
	for i := range 3 {
		_ = f.Record(context.Background(), audit.Event{Method: "m", Tool: string(rune('a' + i)), Result: strings.Repeat("x", 1<<20)})
	}
	got := f.Events()
	if len(got) != 2 || got[0].Tool != "c" || got[1].Tool != "b" || got[0].ID != 3 {
		t.Fatalf("events = %d, newest %+v", len(got), got[0].Tool)
	}
	if n := len(got[0].Result); n > maxShownPayload+len("…") {
		t.Errorf("kept %d bytes of a result", n)
	}
}

func TestActivity(t *testing.T) {
	f := startDashboard(t)
	_ = f.feed.Record(f.ctx, audit.Event{
		Time: time.Now(), Direction: audit.ClientToServer, Method: "tools/call", Tool: "fs__read_file",
		Decision: "deny", Rule: "workspace-only", Reason: "outside /workspace", Params: `{"name":"fs__read_file"}`, IsError: true,
	})
	_ = f.feed.Record(f.ctx, audit.Event{
		Time: time.Now(), Direction: audit.ClientToServer, Method: "tools/call", Tool: "fs__read_text_file",
		Findings: "redacted: github_token", Result: `{"content":[]}`,
	})
	_, body := f.get(f.url + "main")
	for _, want := range []string{"fs__read_file", "workspace-only", "outside /workspace", "redacted: github_token", `id="event-1"`, `id="event-2"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// Newest first.
	if strings.Index(body, "fs__read_text_file") > strings.Index(body, "fs__read_file<") {
		t.Error("activity isn't newest first")
	}
}

func TestEventsStream(t *testing.T) {
	// A short read timeout, which bounds reading the request: the stream
	// must outlive it.
	f := startDashboardWith(t, func(s *Server) { s.readTimeout = 100 * time.Millisecond })
	req, _ := http.NewRequestWithContext(f.ctx, http.MethodGet, f.url+"events", nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if ct := res.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q", ct)
	}
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(res.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	if l := <-lines; l != ": connected" {
		t.Fatalf("first line %q", l)
	}
	time.Sleep(300 * time.Millisecond)
	_, out := f.ask(approval.Request{Tool: "x", Args: []byte(`{}`)})
	timeout := time.After(5 * time.Second)
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatal("stream ended")
			}
			if l == "event: change" {
				for _, r := range f.broker.Pending() {
					_ = f.broker.Decide(r.ID, false)
				}
				<-out
				return
			}
		case <-timeout:
			t.Fatal("no change event")
		}
	}
}

type fakeListener struct {
	net.Listener
	addr net.Addr
}

func (l fakeListener) Addr() net.Addr { return l.addr }

func TestServeRefusesNonLoopback(t *testing.T) {
	s := New(Options{})
	ln := fakeListener{addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 7878}}
	if err := s.Serve(context.Background(), ln); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Errorf("Serve on a LAN address: %v", err)
	}
}
