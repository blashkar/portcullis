package gateway

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// endless yields n items of size bytes each, or forever if n < 0.
func endless(n, size int) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		for i := 0; n < 0 || i < n; i++ {
			if !yield(strings.Repeat("x", size), nil) {
				return
			}
		}
	}
}

func TestCollectStops(t *testing.T) {
	items, full, err := collect(endless(-1, 10))
	if err != nil || full || len(items) != maxListed {
		t.Errorf("endless list: %d items, full %v, %v", len(items), full, err)
	}
	items, full, err = collect(endless(-1, 1<<20))
	if err != nil || full || len(items) != maxListBytes>>20-1 {
		t.Errorf("large items: %d items, full %v, %v", len(items), full, err)
	}
	items, full, err = collect(endless(3, 10))
	if err != nil || !full || len(items) != 3 {
		t.Errorf("short list: %d items, full %v, %v", len(items), full, err)
	}
	fail := func(yield func(string, error) bool) { yield("", errors.New("boom")) }
	if _, _, err := collect(iter.Seq2[string, error](fail)); err == nil {
		t.Error("error not returned")
	}
}

// A flood of calls runs f at most twice, never two at once.
func TestCoalesce(t *testing.T) {
	var runs, running atomic.Int64
	release := make(chan struct{})
	f := coalesce(func() {
		if running.Add(1) > 1 {
			t.Error("two runs at once")
		}
		runs.Add(1)
		<-release
		running.Add(-1)
	})
	var wg sync.WaitGroup
	for range 1000 {
		wg.Go(f)
	}
	wg.Wait()
	close(release)
	eventually(t, "the runs to finish", func() bool { return running.Load() == 0 && runs.Load() >= 1 })
	time.Sleep(50 * time.Millisecond)
	if n := runs.Load(); n > 2 {
		t.Errorf("%d runs for 1000 calls", n)
	}
}

// A server listing too many tools gets only some of them offered.
func TestUpstreamListLimits(t *testing.T) {
	big := newUpstream("big")
	for i := range maxListed + 20 {
		mcp.AddTool(big, &mcp.Tool{Name: fmt.Sprintf("t%04d", i)}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{}, nil, nil
		})
	}
	h := start(t, map[string]*mcp.Server{"big": big})
	if n := len(h.gw.Tools()); n != maxListed {
		t.Errorf("%d tools offered, want %d", n, maxListed)
	}
}
