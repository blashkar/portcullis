package gateway

import (
	"encoding/json"
	"iter"
	"sync"
	"time"
)

// Limits on what one upstream can make portcullis hold or do. A server
// could otherwise list tools without end, or send notifications without end.
const (
	// maxListed caps the tools, prompts or resources taken from one list.
	maxListed = 1000
	// maxListBytes caps their total size, as JSON.
	maxListBytes = 8 << 20
	// refreshTimeout bounds fetching a list again after a server says it
	// changed.
	refreshTimeout = 30 * time.Second
)

// collect reads a list from an upstream, stopping at maxListed items or
// maxListBytes, whichever comes first. Leaving the rest out is safe: the
// client is offered less. full is false when it stopped early.
func collect[T any](seq iter.Seq2[T, error]) (items []T, full bool, err error) {
	size := 0
	for x, err := range seq {
		if err != nil {
			return nil, false, err
		}
		b, err := json.Marshal(x)
		if err != nil {
			return nil, false, err
		}
		if len(items) == maxListed || size+len(b) > maxListBytes {
			return items, false, nil
		}
		size += len(b)
		items = append(items, x)
	}
	return items, true, nil
}

// tooLong warns that a server's list was cut short.
func (g *Gateway) tooLong(upstream, what string) {
	g.log.Warn("the server's list is too long; offering only part of it", "upstream", upstream, "list", what,
		"max_items", maxListed, "max_bytes", maxListBytes)
}

// coalesce returns a function that runs f in the background, one run at a
// time. Calls while it runs cause at most one more run, after it.
func coalesce(f func()) func() {
	var mu sync.Mutex
	running, again := false, false
	return func() {
		mu.Lock()
		defer mu.Unlock()
		if running {
			again = true
			return
		}
		running = true
		go func() {
			for {
				f()
				mu.Lock()
				if !again {
					running = false
					mu.Unlock()
					return
				}
				again = false
				mu.Unlock()
			}
		}()
	}
}
