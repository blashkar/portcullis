package gateway

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/blashkar/portcullis/internal/audit"
	"github.com/blashkar/portcullis/internal/pin"
)

// observerFunc is an Observer made from a function.
type observerFunc func(audit.Event, Details)

func (f observerFunc) Observe(e audit.Event, d Details) { f(e, d) }

// An upstream that exits while a refresh is between listing its tools and
// adding them: the refresh must not add them back once the exit has
// removed them.
func TestExitDuringARefreshLeavesNothingBehind(t *testing.T) {
	m := newUpstream("math")
	addTextTool(m, "add", "Adds two numbers.", "4")
	var h *harness
	var once sync.Once
	h = startWith(t, map[string]*mcp.Server{"m": m}, func(o *Options) {
		o.Pins = pin.Open(filepath.Join(t.TempDir(), "pins.json"), pin.TrustNew)
		o.Observer = observerFunc(func(e audit.Event, _ Details) {
			// Checking the new tool comes after the listing and before it
			// is added: exit the upstream here.
			if e.Method == "tool/pinned" && e.Tool == "m__late" {
				once.Do(func() {
					_ = h.upstream["m"].Close()
					time.Sleep(50 * time.Millisecond) // time for the exit to be handled
				})
			}
		})
	})
	addTextTool(m, "late", "Added later.", "1")
	eventually(t, "the exit to be recorded", func() bool {
		_, ok := h.rec.find(func(e audit.Event) bool { return e.Method == "upstream/disconnected" })
		return ok
	})
	time.Sleep(50 * time.Millisecond)
	if got := h.toolNames(); len(got) != 0 {
		t.Errorf("tools = %v after the upstream exited", got)
	}
}

// failingLists answers every list with an error, as a broken server can.
func failingLists(method string) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, m string, req mcp.Request) (mcp.Result, error) {
			if m == method {
				return nil, errors.New("listing broke")
			}
			return next(ctx, m, req)
		}
	}
}

// A first listing that fails partway leaves no upstream behind: nothing it
// added stays offered, its session is closed, and the name is free.
func TestFailedConnectIsCleanedUp(t *testing.T) {
	m := newUpstream("docs")
	addTextTool(m, "search", "Searches the docs.", "ok")
	addTextPrompt(m, &mcp.Prompt{Name: "summarize"}, "Summarize it.")
	m.AddReceivingMiddleware(failingLists("prompts/list"))

	h := startWith(t, map[string]*mcp.Server{}, func(*Options) {})
	st, ct := mcp.NewInMemoryTransports()
	ss, err := m.Connect(h.ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = h.gw.Connect(h.ctx, "d", ct)
	if err == nil || !strings.Contains(err.Error(), "listing broke") {
		t.Fatalf("Connect = %v", err)
	}
	if got := h.toolNames(); len(got) != 0 {
		t.Errorf("tools = %v; want none from a failed upstream", got)
	}
	if got := h.gw.Tools(); len(got) != 0 {
		t.Errorf("Tools = %v", got)
	}
	if sv := h.gw.Servers(); len(sv) != 0 {
		t.Errorf("Servers = %+v", sv)
	}
	done := make(chan struct{})
	go func() { _ = ss.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("the upstream's session is still open")
	}

	// The name can be used again.
	m2 := newUpstream("docs")
	addTextTool(m2, "search", "Searches the docs.", "ok")
	st, ct = mcp.NewInMemoryTransports()
	if _, err := m2.Connect(h.ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.gw.Connect(h.ctx, "d", ct); err != nil {
		t.Fatalf("connecting again: %v", err)
	}
	eventually(t, "the tool to be offered", func() bool { return slices.Equal(h.toolNames(), []string{"d__search"}) })
}
