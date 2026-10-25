package gateway

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/blashkar/portcullis/internal/audit"
)

// fakeRecorder keeps audit events in memory.
type fakeRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *fakeRecorder) Record(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *fakeRecorder) find(match func(audit.Event) bool) (audit.Event, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.events {
		if match(e) {
			return e, true
		}
	}
	return audit.Event{}, false
}

type pathArgs struct {
	Path string `json:"path"`
}

// addReadFile adds a read_file tool that answers "<label>:<path>", or a tool
// error for paths under /secret.
func addReadFile(s *mcp.Server, label string) {
	mcp.AddTool(s, &mcp.Tool{Name: "read_file", Description: label + " reader"},
		func(_ context.Context, _ *mcp.CallToolRequest, in pathArgs) (*mcp.CallToolResult, any, error) {
			if strings.HasPrefix(in.Path, "/secret") {
				return nil, nil, errors.New("access denied")
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: label + ":" + in.Path}}}, nil, nil
		})
}

func newUpstream(name string) *mcp.Server {
	return mcp.NewServer(&mcp.Implementation{Name: name, Version: "1"}, nil)
}

type harness struct {
	t        *testing.T
	ctx      context.Context
	gw       *Gateway
	rec      *fakeRecorder
	client   *mcp.ClientSession
	upstream map[string]*mcp.ServerSession
	clientMu sync.Mutex
	changed  int // tools/list_changed notifications the client got
	info     string
}

// start connects the upstreams to a new gateway and a client to the gateway.
func start(t *testing.T, upstreams map[string]*mcp.Server) *harness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h := &harness{t: t, ctx: ctx, rec: &fakeRecorder{}, upstream: map[string]*mcp.ServerSession{}}
	h.gw = New(Options{
		Version: "test", SessionID: "sess-1", Recorder: h.rec,
		OnClientInfo: func(name, version string) {
			h.clientMu.Lock()
			h.info = name + " " + version
			h.clientMu.Unlock()
		},
	})
	t.Cleanup(func() { _ = h.gw.Close() })

	names := slices.Sorted(func(yield func(string) bool) {
		for n := range upstreams {
			if !yield(n) {
				return
			}
		}
	})
	for _, name := range names {
		st, ct := mcp.NewInMemoryTransports()
		ss, err := upstreams[name].Connect(ctx, st, nil)
		if err != nil {
			t.Fatal(err)
		}
		h.upstream[name] = ss
		if err := h.gw.Connect(ctx, name, ct); err != nil {
			t.Fatal(err)
		}
	}

	st, ct := mcp.NewInMemoryTransports()
	go func() { _ = h.gw.Serve(ctx, st) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "9.9"}, &mcp.ClientOptions{
		ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) {
			h.clientMu.Lock()
			h.changed++
			h.clientMu.Unlock()
		},
	})
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	h.client = cs
	return h
}

func (h *harness) toolNames() []string {
	h.t.Helper()
	var names []string
	for tool, err := range h.client.Tools(h.ctx, nil) {
		if err != nil {
			h.t.Fatal(err)
		}
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

func (h *harness) call(tool string, args map[string]any) (*mcp.CallToolResult, error) {
	return h.client.CallTool(h.ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
}

func text(res *mcp.CallToolResult) string {
	var parts []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, "")
}

// eventually retries cond until it's true or a few seconds have passed.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func twoServers() map[string]*mcp.Server {
	fs := newUpstream("files")
	addReadFile(fs, "fs")
	mcp.AddTool(fs, &mcp.Tool{Name: "write_file"}, func(context.Context, *mcp.CallToolRequest, pathArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "written"}}}, nil, nil
	})
	git := newUpstream("git")
	addReadFile(git, "git") // the same tool name as fs's
	mcp.AddTool(git, &mcp.Tool{Name: "git_log"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "abc123 Initial commit"}}}, nil, nil
	})
	return map[string]*mcp.Server{"fs": fs, "git": git}
}

func TestToolsAreNamespacedAndRouted(t *testing.T) {
	h := start(t, twoServers())

	want := []string{"fs__read_file", "fs__write_file", "git__git_log", "git__read_file"}
	if got := h.toolNames(); !slices.Equal(got, want) {
		t.Fatalf("tools = %v, want %v", got, want)
	}
	if got := h.gw.Tools(); !slices.Equal(got, want) {
		t.Errorf("Gateway.Tools = %v", got)
	}

	for tool, want := range map[string]string{"fs__read_file": "fs:/w/a.txt", "git__read_file": "git:/w/a.txt"} {
		res, err := h.call(tool, map[string]any{"path": "/w/a.txt"})
		if err != nil {
			t.Fatal(err)
		}
		if text(res) != want || res.IsError {
			t.Errorf("%s returned %q (error %v), want %q", tool, text(res), res.IsError, want)
		}
	}

	// Tool errors come back as results, not protocol errors.
	res, err := h.call("fs__read_file", map[string]any{"path": "/secret/key"})
	if err != nil || !res.IsError || !strings.Contains(text(res), "access denied") {
		t.Errorf("tool error: %+v, %v", res, err)
	}

	if _, err := h.call("nope__read_file", nil); err == nil {
		t.Error("calling an unknown tool succeeded")
	}
	if _, err := h.call("read_file", nil); err == nil {
		t.Error("calling a tool by its unprefixed name succeeded")
	}
}

func TestAuditEvents(t *testing.T) {
	h := start(t, twoServers())
	h.toolNames()
	if _, err := h.call("git__read_file", map[string]any{"path": "/repo/README"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.call("fs__read_file", map[string]any{"path": "/secret/x"}); err != nil {
		t.Fatal(err)
	}

	e, ok := h.rec.find(func(e audit.Event) bool { return e.Tool == "git__read_file" })
	if !ok {
		t.Fatalf("no audit event for the call; got %+v", h.rec.events)
	}
	if e.SessionID != "sess-1" || e.Direction != audit.ClientToServer || e.Method != "tools/call" || e.Upstream != "git" || e.IsError {
		t.Errorf("event = %+v", e)
	}
	if !strings.Contains(e.Params, `"path":"/repo/README"`) || !strings.Contains(e.Result, "git:/repo/README") || e.Duration <= 0 {
		t.Errorf("payloads: params %s, result %s, duration %v", e.Params, e.Result, e.Duration)
	}

	failed, ok := h.rec.find(func(e audit.Event) bool { return e.Tool == "fs__read_file" })
	if !ok || !failed.IsError || failed.Error != "" {
		t.Errorf("a tool error should be IsError without a protocol error: %+v", failed)
	}
	if _, ok := h.rec.find(func(e audit.Event) bool { return e.Method == "tools/list" }); !ok {
		t.Error("tools/list wasn't recorded")
	}
	h.clientMu.Lock()
	info := h.info
	h.clientMu.Unlock()
	if info != "test-client 9.9" {
		t.Errorf("OnClientInfo got %q", info)
	}
}

func TestToolListChanges(t *testing.T) {
	servers := twoServers()
	h := start(t, servers)

	// The upstream adds a tool while connected; the client is told and sees it.
	mcp.AddTool(servers["git"], &mcp.Tool{Name: "git_status"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "clean"}}}, nil, nil
	})
	eventually(t, "git__git_status to appear", func() bool { return slices.Contains(h.toolNames(), "git__git_status") })
	res, err := h.call("git__git_status", nil)
	if err != nil || text(res) != "clean" {
		t.Fatalf("new tool: %+v, %v", res, err)
	}
	h.clientMu.Lock()
	changed := h.changed
	h.clientMu.Unlock()
	if changed == 0 {
		t.Error("the client got no tools/list_changed notification")
	}

	// And removes one.
	servers["git"].RemoveTools("git_log")
	eventually(t, "git__git_log to disappear", func() bool { return !slices.Contains(h.toolNames(), "git__git_log") })
	if !slices.Contains(h.toolNames(), "fs__read_file") {
		t.Error("another server's tools went away too")
	}
}

func TestUpstreamExit(t *testing.T) {
	h := start(t, twoServers())

	_ = h.upstream["git"].Close() // the git server goes away
	eventually(t, "git's tools to disappear", func() bool {
		return !slices.ContainsFunc(h.toolNames(), func(n string) bool { return strings.HasPrefix(n, "git__") })
	})

	if _, err := h.call("git__read_file", map[string]any{"path": "/x"}); err == nil {
		t.Error("calling a tool of an exited server succeeded")
	}
	res, err := h.call("fs__read_file", map[string]any{"path": "/still/works"})
	if err != nil || text(res) != "fs:/still/works" {
		t.Errorf("the other server stopped working: %+v, %v", res, err)
	}
	eventually(t, "the disconnect to be audited", func() bool {
		_, ok := h.rec.find(func(e audit.Event) bool {
			return e.Method == "upstream/disconnected" && e.Upstream == "git" && e.Direction == audit.Internal
		})
		return ok
	})
}

func TestPromptsAndResources(t *testing.T) {
	fs := newUpstream("files")
	fs.AddPrompt(&mcp.Prompt{Name: "summarize", Description: "Summarize a file"},
		func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{
				{Role: "user", Content: &mcp.TextContent{Text: "summarize " + req.Params.Arguments["file"]}},
			}}, nil
		})
	readme := func(label string) mcp.ResourceHandler {
		return func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, Text: label + " readme"}}}, nil
		}
	}
	fs.AddResource(&mcp.Resource{URI: "file:///w/README.md", Name: "readme"}, readme("fs"))
	git := newUpstream("git")
	// The same URI from a second server: the first one keeps it.
	git.AddResource(&mcp.Resource{URI: "file:///w/README.md", Name: "readme"}, readme("git"))
	git.AddResource(&mcp.Resource{URI: "git://repo/HEAD", Name: "head"}, readme("git head"))
	h := start(t, map[string]*mcp.Server{"fs": fs, "git": git})

	prompts, err := h.client.ListPrompts(h.ctx, nil)
	if err != nil || len(prompts.Prompts) != 1 || prompts.Prompts[0].Name != "fs__summarize" {
		t.Fatalf("prompts = %+v, %v", prompts, err)
	}
	got, err := h.client.GetPrompt(h.ctx, &mcp.GetPromptParams{Name: "fs__summarize", Arguments: map[string]string{"file": "a.txt"}})
	if err != nil || got.Messages[0].Content.(*mcp.TextContent).Text != "summarize a.txt" {
		t.Fatalf("GetPrompt = %+v, %v", got, err)
	}

	resources, err := h.client.ListResources(h.ctx, nil)
	if err != nil || len(resources.Resources) != 2 {
		t.Fatalf("resources = %+v, %v", resources, err)
	}
	for uri, want := range map[string]string{"file:///w/README.md": "fs readme", "git://repo/HEAD": "git head readme"} {
		r, err := h.client.ReadResource(h.ctx, &mcp.ReadResourceParams{URI: uri})
		if err != nil || r.Contents[0].Text != want {
			t.Errorf("ReadResource(%s) = %+v, %v; want %q", uri, r, err, want)
		}
	}
	e, ok := h.rec.find(func(e audit.Event) bool {
		return e.Method == "resources/read" && strings.Contains(e.Params, "git://repo/HEAD")
	})
	if !ok || e.Upstream != "git" {
		t.Errorf("resource read audited as %+v", e)
	}
}

func TestConnectRejectsDuplicateNames(t *testing.T) {
	ctx := context.Background()
	g := New(Options{})
	defer g.Close()
	for i := range 2 {
		st, ct := mcp.NewInMemoryTransports()
		if _, err := newUpstream("x").Connect(ctx, st, nil); err != nil {
			t.Fatal(err)
		}
		err := g.Connect(ctx, "fs", ct)
		if i == 1 && (err == nil || !strings.Contains(err.Error(), "already connected")) {
			t.Errorf("second Connect: %v", err)
		}
	}
}

func TestValidObjectSchema(t *testing.T) {
	for _, tt := range []struct {
		s    any
		want bool
	}{
		{map[string]any{"type": "object"}, true},
		{map[string]any{"type": "string"}, false},
		{nil, false},
		{"object", false},
	} {
		if got := validObjectSchema(tt.s); got != tt.want {
			t.Errorf("validObjectSchema(%v) = %v", tt.s, got)
		}
	}
}

func TestUnprefixedCallHasNoUpstream(t *testing.T) {
	h := start(t, twoServers())
	if _, err := h.call("read_file", nil); err == nil {
		t.Fatal("an unprefixed call succeeded")
	}
	e, ok := h.rec.find(func(e audit.Event) bool { return e.Tool == "read_file" })
	if !ok || e.Upstream != "" || !e.IsError || e.Error == "" {
		t.Errorf("event = %+v", e)
	}
}

func TestCloseIsNotAFailure(t *testing.T) {
	h := start(t, twoServers())
	if err := h.gw.Close(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "both upstreams to be recorded as closed", func() bool {
		n := 0
		for _, name := range []string{"fs", "git"} {
			if _, ok := h.rec.find(func(e audit.Event) bool { return e.Method == "upstream/closed" && e.Upstream == name && !e.IsError }); ok {
				n++
			}
		}
		return n == 2
	})
	if _, ok := h.rec.find(func(e audit.Event) bool { return e.Method == "upstream/disconnected" }); ok {
		t.Error("a clean shutdown was recorded as a disconnect")
	}
}

// A client cancelling a call cancels it on the upstream too.
func TestCancellationReachesUpstream(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	slow := newUpstream("slow")
	mcp.AddTool(slow, &mcp.Tool{Name: "wait"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		return nil, nil, ctx.Err()
	})
	h := start(t, map[string]*mcp.Server{"slow": slow})

	ctx, cancel := context.WithCancel(h.ctx)
	errc := make(chan error, 1)
	go func() {
		_, err := h.client.CallTool(ctx, &mcp.CallToolParams{Name: "slow__wait"})
		errc <- err
	}()
	<-started
	cancel()
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream handler wasn't cancelled")
	}
	if err := <-errc; err == nil {
		t.Error("the cancelled call succeeded")
	}
}

// Progress notifications from an upstream reach the client with the
// client's own progress token.
func TestProgressReachesClient(t *testing.T) {
	worker := newUpstream("worker")
	mcp.AddTool(worker, &mcp.Tool{Name: "work"}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		for i := 1; i <= 3; i++ {
			err := req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
				ProgressToken: req.Params.GetProgressToken(), Progress: float64(i), Total: 3,
			})
			if err != nil {
				return nil, nil, err
			}
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "done"}}}, nil, nil
	})

	ctx := context.Background()
	g := New(Options{})
	defer g.Close()
	st, ct := mcp.NewInMemoryTransports()
	if _, err := worker.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	if err := g.Connect(ctx, "w", ct); err != nil {
		t.Fatal(err)
	}
	gst, gct := mcp.NewInMemoryTransports()
	go func() { _ = g.Serve(ctx, gst) }()

	var mu sync.Mutex
	var got []string
	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "1"}, &mcp.ClientOptions{
		ProgressNotificationHandler: func(_ context.Context, r *mcp.ProgressNotificationClientRequest) {
			mu.Lock()
			got = append(got, fmt.Sprintf("%v:%v/%v", r.Params.ProgressToken, r.Params.Progress, r.Params.Total))
			mu.Unlock()
		},
	})
	cs, err := client.Connect(ctx, gct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	params := &mcp.CallToolParams{Name: "w__work"}
	params.SetProgressToken("tok-7")
	if _, err := cs.CallTool(ctx, params); err != nil {
		t.Fatal(err)
	}
	eventually(t, "three progress notifications", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) == 3
	})
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(got, " ") != "tok-7:1/3 tok-7:2/3 tok-7:3/3" {
		t.Errorf("progress = %v", got)
	}
}
