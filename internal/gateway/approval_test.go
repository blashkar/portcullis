package gateway

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/blashkar/portcullis/internal/approval"
	"github.com/blashkar/portcullis/internal/audit"
	"github.com/blashkar/portcullis/internal/policy"
)

// startWithApprover runs fs (a countingServer) behind a policy that wants
// writes approved.
func startWithApprover(t *testing.T, calls *atomic.Int64, a Approver) *harness {
	t.Helper()
	pol := compilePolicy(t, policy.Spec{Rules: []policy.RuleSpec{
		{Name: "confirm-writes", Tool: policy.Patterns{"fs__write_file"}, Action: policy.RequireApproval, Reason: "writes change the workspace"},
	}})
	return startWith(t, map[string]*mcp.Server{"fs": countingServer(calls)}, func(o *Options) {
		o.Policy = pol
		o.Approver = a
	})
}

// decideAll decides every request as it arrives, recording what it saw.
func decideAll(b *approval.Broker, approve bool, seen chan<- approval.Request) func() {
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
			for _, r := range b.Pending() {
				if b.Decide(r.ID, approve) == nil {
					seen <- r
				}
			}
		}
	}()
	return func() { close(stop) }
}

func TestApprovedCallGoesAhead(t *testing.T) {
	var calls atomic.Int64
	b := approval.NewBroker(time.Minute, nil)
	h := startWithApprover(t, &calls, b)
	seen := make(chan approval.Request, 1)
	defer decideAll(b, true, seen)()

	res, err := h.call("fs__write_file", map[string]any{"path": "/workspace/a"})
	if err != nil || text(res) != "wrote /workspace/a" {
		t.Fatalf("approved call: %v, %v", res, err)
	}
	r := <-seen
	if r.Tool != "fs__write_file" || r.Server != "fs" || r.Rule != "confirm-writes" || r.Reason != "writes change the workspace" {
		t.Errorf("request = %+v", r)
	}
	// The person sees the arguments exactly as they are sent.
	if string(r.Args) != `{"path":"/workspace/a"}` {
		t.Errorf("args shown = %s", r.Args)
	}
	e, ok := h.rec.find(func(e audit.Event) bool { return e.Tool == "fs__write_file" })
	if !ok || e.Decision != audit.DecisionApproved || e.Rule != "confirm-writes" || e.Reason != "approved in the dashboard" || e.IsError {
		t.Errorf("audit event: %+v", e)
	}
	// Calls the policy allows don't wait.
	if _, err := h.call("fs__read_file", map[string]any{"path": "/workspace/a"}); err != nil {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("upstream ran %d calls, want 2", n)
	}
}

func TestDeniedCallIsBlocked(t *testing.T) {
	var calls atomic.Int64
	b := approval.NewBroker(time.Minute, nil)
	h := startWithApprover(t, &calls, b)
	seen := make(chan approval.Request, 1)
	defer decideAll(b, false, seen)()

	_, err := h.call("fs__write_file", map[string]any{"path": "/workspace/a"})
	d := blockedBy(t, err)
	if d["decision"] != "require_approval" || d["approval"] != "denied" || !strings.Contains(err.Error(), `a person denied fs__write_file (rule "confirm-writes")`) {
		t.Errorf("error: %v, data %v", err, d)
	}
	if calls.Load() != 0 {
		t.Error("the denied call reached the server")
	}
	e, ok := h.rec.find(func(e audit.Event) bool { return e.Tool == "fs__write_file" })
	if !ok || e.Decision != "require_approval" || e.Reason != "denied in the dashboard" || !e.IsError {
		t.Errorf("audit event: %+v", e)
	}
}

func TestUnansweredCallExpires(t *testing.T) {
	var calls atomic.Int64
	h := startWithApprover(t, &calls, approval.NewBroker(50*time.Millisecond, nil))
	_, err := h.call("fs__write_file", map[string]any{"path": "/workspace/a"})
	if d := blockedBy(t, err); d["approval"] != "expired" || !strings.Contains(err.Error(), "nobody answered within 50ms") {
		t.Errorf("error: %v, data %v", err, d)
	}
	if calls.Load() != 0 {
		t.Error("the expired call reached the server")
	}
	e, _ := h.rec.find(func(e audit.Event) bool { return e.Tool == "fs__write_file" })
	if e.Decision != "require_approval" || e.Reason != "nobody answered in time" {
		t.Errorf("audit event: %+v", e)
	}
}

func TestCancelledCallStopsWaiting(t *testing.T) {
	var calls atomic.Int64
	b := approval.NewBroker(time.Minute, nil)
	h := startWithApprover(t, &calls, b)
	ctx, cancel := context.WithCancel(h.ctx)
	done := make(chan error, 1)
	go func() {
		_, err := h.client.CallTool(ctx, &mcp.CallToolParams{Name: "fs__write_file", Arguments: map[string]any{"path": "/workspace/a"}})
		done <- err
	}()
	eventually(t, "a request waiting", func() bool { return len(b.Pending()) == 1 })
	cancel()
	if err := <-done; err == nil {
		t.Fatal("the cancelled call succeeded")
	}
	eventually(t, "the request to go away", func() bool { return len(b.Pending()) == 0 })
	if calls.Load() != 0 {
		t.Error("the cancelled call reached the server")
	}
}
