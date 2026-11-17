package gateway

import (
	"context"
	"os"
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

func holdAfterFirst(pins string) func(*Options) {
	return func(o *Options) { o.Pins = pin.Open(pins, pin.HoldAfterFirst) }
}

// The default: what a server offers on its first run is pinned, tools,
// prompts and resources alike; what it adds later is held, whether
// mid-session or on a later run.
func TestHoldAfterFirstRun(t *testing.T) {
	pins := filepath.Join(t.TempDir(), "pins.json")
	m := newUpstream("docs")
	addTextTool(m, "search", "Searches the docs.", "ok")
	addTextPrompt(m, &mcp.Prompt{Name: "summarize"}, "Summarize it.")
	addTextResource(m, &mcp.Resource{URI: "notes://meeting", Name: "meeting"}, "10am")

	h := startWith(t, map[string]*mcp.Server{"d": m}, holdAfterFirst(pins))
	if got := h.toolNames(); !slices.Equal(got, []string{"d__search"}) {
		t.Errorf("tools = %v", got)
	}
	if p, r := h.promptNames(), h.resourceURIs(); len(p) != 1 || len(r) != 1 {
		t.Errorf("prompts = %v, resources = %v; want the first run's pinned", p, r)
	}
	if n := h.rec.count(func(e audit.Event) bool { return e.Method == "definition/pinned" }); n != 3 {
		t.Errorf("%d pinned events, want 3", n)
	}

	// Added mid-session: held.
	addTextTool(m, "export", "Exports the docs.", "ok")
	eventually(t, "the new tool to be held", func() bool { return h.gw.Held()["d__export"] != "" })
	if got := h.toolNames(); !slices.Equal(got, []string{"d__search"}) {
		t.Errorf("tools = %v", got)
	}
	_, err := h.call("d__export", nil)
	if msg := heldError(t, err); !strings.Contains(msg, "is new and hasn't been approved") {
		t.Errorf("message = %s", msg)
	}

	// Added before a later run: held too, and what was pinned still works.
	addTextPrompt(m, &mcp.Prompt{Name: "translate"}, "Translate it.")
	h2 := startWith(t, map[string]*mcp.Server{"d": m}, holdAfterFirst(pins))
	if got := h2.toolNames(); !slices.Equal(got, []string{"d__search"}) {
		t.Errorf("second run's tools = %v", got)
	}
	if got := h2.promptNames(); !slices.Equal(got, []string{"d__summarize|"}) {
		t.Errorf("second run's prompts = %v", got)
	}
	if held := h2.gw.Held(); held["d__export"] == "" || held["prompt:d__translate"] == "" {
		t.Errorf("Held = %v", held)
	}
	if _, err := h2.call("d__search", nil); err != nil {
		t.Errorf("a pinned tool: %v", err)
	}

	// Approving brings it in.
	if _, err := pin.Open(pins, pin.HoldAfterFirst).Approve([]string{"d__export"}); err != nil {
		t.Fatal(err)
	}
	h3 := startWith(t, map[string]*mcp.Server{"d": m}, holdAfterFirst(pins))
	if got := h3.toolNames(); !slices.Equal(got, []string{"d__export", "d__search"}) {
		t.Errorf("after approval: %v", got)
	}
}

// Each server has its own first run: one the pin file already knows
// doesn't make another's first run suspect, or the other way round.
func TestHoldAfterFirstIsPerServer(t *testing.T) {
	pins := filepath.Join(t.TempDir(), "pins.json")
	a := newUpstream("a")
	addTextTool(a, "one", "One.", "1")
	startWith(t, map[string]*mcp.Server{"a": a}, holdAfterFirst(pins))

	addTextTool(a, "two", "Two.", "2")
	b := newUpstream("b")
	addTextTool(b, "three", "Three.", "3")
	h := startWith(t, map[string]*mcp.Server{"a": a, "b": b}, holdAfterFirst(pins))
	if got := h.toolNames(); !slices.Equal(got, []string{"a__one", "b__three"}) {
		t.Errorf("tools = %v; want a's new tool held and b's first run pinned", got)
	}
}

// A pin file from before servers were recorded: its tools and prompts are
// attributed by name, so the server's later additions are held.
func TestHoldAfterFirstWithAnOldPinFile(t *testing.T) {
	pins := filepath.Join(t.TempDir(), "pins.json")
	m := newUpstream("math")
	addTextTool(m, "add", "Adds two numbers.", "4")
	startWith(t, map[string]*mcp.Server{"m": m}, func(o *Options) {
		o.Pins = pin.Open(pins, pin.TrustNew)
		o.PinPoll = time.Hour // its watcher would give the entry its server back
	})
	data, err := os.ReadFile(pins)
	if err != nil {
		t.Fatal(err)
	}
	old := strings.Replace(string(data), `"server": "m",`, "", 1)
	if old == string(data) {
		t.Fatalf("pin file has no server field:\n%s", data)
	}
	if err := os.WriteFile(pins, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}

	// A fresh server: the first gateway is still connected to m and would
	// see a tool added to it.
	m2 := newUpstream("math")
	addTextTool(m2, "add", "Adds two numbers.", "4")
	addTextTool(m2, "sub", "Subtracts two numbers.", "0")
	h := startWith(t, map[string]*mcp.Server{"m": m2}, holdAfterFirst(pins))
	if got := h.toolNames(); !slices.Equal(got, []string{"m__add"}) {
		t.Errorf("tools = %v; want the new one held", got)
	}
	entries, err := pin.Open(pins, pin.HoldAfterFirst).Entries()
	if err != nil || entries["m__add"].Server != "m" {
		t.Errorf("the old entry wasn't given its server: %+v, %v", entries["m__add"], err)
	}
}

// A server that adds to its lists while the first run is being listed:
// the refresh this sets off can list it before the first run's own
// listing does, and must not leave the first run's definitions held.
func TestFirstRunWithAListChangeDuringIt(t *testing.T) {
	m := newUpstream("docs")
	addTextTool(m, "search", "Searches the docs.", "ok")
	addTextPrompt(m, &mcp.Prompt{Name: "summarize"}, "Summarize it.")
	addTextResource(m, &mcp.Resource{URI: "notes://meeting", Name: "meeting"}, "10am")
	var once sync.Once
	m.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "tools/list" {
				once.Do(func() {
					addTextPrompt(m, &mcp.Prompt{Name: "translate"}, "Translate it.")
					addTextResource(m, &mcp.Resource{URI: "notes://todo", Name: "todo"}, "milk")
					// A real server's listing is slower than the SDK's
					// delay before it sends list_changed.
					time.Sleep(30 * time.Millisecond)
				})
			}
			return next(ctx, method, req)
		}
	})
	h := startWith(t, map[string]*mcp.Server{"d": m}, holdAfterFirst(filepath.Join(t.TempDir(), "pins.json")))
	time.Sleep(50 * time.Millisecond) // let the refreshes finish
	if held := h.gw.Held(); len(held) != 0 {
		t.Errorf("Held = %v; want the first run pinned", held)
	}
	if p, r := h.promptNames(), h.resourceURIs(); len(p) != 2 || len(r) != 2 {
		t.Errorf("prompts = %v, resources = %v", p, r)
	}
}
