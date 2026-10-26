package gateway

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/blashkar/portcullis/internal/approval"
	"github.com/blashkar/portcullis/internal/audit"
	"github.com/blashkar/portcullis/internal/inject"
	"github.com/blashkar/portcullis/internal/policy"
	"github.com/blashkar/portcullis/internal/redact"
)

type observed struct {
	e audit.Event
	d Details
}

// observer keeps what it is told.
type observer struct {
	mu  sync.Mutex
	got []observed
}

func (o *observer) Observe(e audit.Event, d Details) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.got = append(o.got, observed{e, d})
}

// details returns the details of the first tools/call event for tool.
func (o *observer) details(t *testing.T, tool string) Details {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, x := range o.got {
		if x.e.Tool == tool && x.e.Method == "tools/call" {
			return x.d
		}
	}
	t.Fatalf("no event for %s", tool)
	return Details{}
}

func TestObserverRedactionsAndInjections(t *testing.T) {
	token := "ghp_" + strings.Repeat("a1B2", 9)
	s := webServer()
	mcp.AddTool(s, &mcp.Tool{Name: "env"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "A=" + token + " B=" + token + " C=" + token + "x"}}}, nil, nil
	})
	o := &observer{}
	h := startWith(t, map[string]*mcp.Server{"web": s}, func(opts *Options) {
		opts.Observer = o
		opts.Redactor = redact.New()
		opts.Inject = InjectOptions{Detector: &inject.Detector{}, Action: InjectWarn}
	})
	for _, tool := range []string{"web__env", "web__fetch_evil", "web__fetch_clean"} {
		if _, err := h.call(tool, nil); err != nil {
			t.Fatal(err)
		}
	}
	// Two distinct tokens, one of them twice.
	if d := o.details(t, "web__env"); d.Redacted["github_token"] != 2 || d.Injection {
		t.Errorf("env: %+v", d)
	}
	if d := o.details(t, "web__fetch_evil"); !d.Injection || d.Suspicious {
		t.Errorf("evil: %+v", d)
	}
	if d := o.details(t, "web__fetch_clean"); d.Injection || d.Suspicious || d.Redacted != nil {
		t.Errorf("clean: %+v", d)
	}
}

func TestObserverApprovals(t *testing.T) {
	var calls atomic.Int64
	b := approval.NewBroker(time.Minute, nil)
	pol := compilePolicy(t, policy.Spec{Rules: []policy.RuleSpec{
		{Tool: policy.Patterns{"fs__write_file"}, Action: policy.RequireApproval},
	}})
	o := &observer{}
	h := startWith(t, map[string]*mcp.Server{"fs": countingServer(&calls)}, func(opts *Options) {
		opts.Policy, opts.Approver, opts.Observer = pol, b, o
	})
	seen := make(chan approval.Request, 1)
	defer decideAll(b, false, seen)()
	if _, err := h.call("fs__write_file", map[string]any{"path": "/workspace/a"}); err == nil {
		t.Fatal("a denied call went ahead")
	}
	if d := o.details(t, "fs__write_file"); d.Approval != "denied" {
		t.Errorf("details = %+v", d)
	}
}
