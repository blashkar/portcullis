package dashboard

import (
	"context"
	"sync"

	"github.com/blashkar/portcullis/internal/audit"
)

// Feed keeps the most recent audit events in memory for the dashboard. It
// implements gateway.Recorder.
type Feed struct {
	n        int
	onChange func()

	mu     sync.Mutex
	events []audit.Event // oldest first
	next   int64         // numbers the events, so the page can tell them apart
}

// NewFeed returns a Feed that keeps the last n events and calls onChange,
// if it isn't nil, after each one.
func NewFeed(n int, onChange func()) *Feed {
	if onChange == nil {
		onChange = func() {}
	}
	return &Feed{n: n, onChange: onChange}
}

// Record adds an event.
func (f *Feed) Record(_ context.Context, e audit.Event) error {
	// Only the start of each payload is shown; don't keep the rest.
	e.Params, e.Result = shorten(e.Params, maxShownPayload), shorten(e.Result, maxShownPayload)
	f.mu.Lock()
	f.next++
	e.ID = f.next
	f.events = append(f.events, e)
	if len(f.events) > f.n {
		f.events = append(f.events[:0], f.events[len(f.events)-f.n:]...)
	}
	f.mu.Unlock()
	f.onChange()
	return nil
}

// Events returns the events, newest first.
func (f *Feed) Events() []audit.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]audit.Event, len(f.events))
	for i, e := range f.events {
		out[len(out)-1-i] = e
	}
	return out
}

// Hub tells open dashboards that something changed, so they refresh.
type Hub struct {
	mu   sync.Mutex
	subs map[chan struct{}]struct{}
}

// maxSubscribers caps the open live connections. Each is a goroutine, and a
// few browser tabs need a handful.
const maxSubscribers = 16

// NewHub returns a Hub with no subscribers.
func NewHub() *Hub {
	return &Hub{subs: map[chan struct{}]struct{}{}}
}

// Notify wakes every subscriber. It never blocks: a subscriber that hasn't
// caught up yet already has a wake-up waiting.
func (h *Hub) Notify() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// subscribe returns a channel that receives after each change, and a
// function that ends the subscription. ok is false if there are too many.
func (h *Hub) subscribe() (ch chan struct{}, cancel func(), ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subs) >= maxSubscribers {
		return nil, nil, false
	}
	ch = make(chan struct{}, 1)
	h.subs[ch] = struct{}{}
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}, true
}
