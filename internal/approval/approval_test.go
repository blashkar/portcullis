package approval

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitPending waits until n requests are waiting and returns them.
func waitPending(t *testing.T, b *Broker, n int) []Request {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p := b.Pending(); len(p) == n {
			return p
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%d requests waiting, want %d", len(b.Pending()), n)
	return nil
}

func ask(ctx context.Context, b *Broker, req Request) <-chan Outcome {
	out := make(chan Outcome, 1)
	go func() { out <- b.Ask(ctx, req) }()
	return out
}

func TestApproveAndDeny(t *testing.T) {
	var changes atomic.Int64
	b := NewBroker(time.Minute, func() { changes.Add(1) })
	ctx := context.Background()

	first := ask(ctx, b, Request{Tool: "fs__write_file", Server: "fs", Args: []byte(`{"path":"/workspace/a"}`), Rule: "confirm-writes"})
	waitPending(t, b, 1)
	second := ask(ctx, b, Request{Tool: "git__git_push"})
	p := waitPending(t, b, 2)

	r := p[0]
	if r.Tool != "fs__write_file" || r.Server != "fs" || string(r.Args) != `{"path":"/workspace/a"}` || r.Rule != "confirm-writes" {
		t.Errorf("oldest request = %+v", r)
	}
	if len(r.ID) < 20 || r.Expires.Sub(r.Time) != time.Minute {
		t.Errorf("ID %q, expires after %v", r.ID, r.Expires.Sub(r.Time))
	}
	if got, ok := b.Get(r.ID); !ok || got.Tool != r.Tool {
		t.Errorf("Get = %+v, %v", got, ok)
	}

	if err := b.Decide(r.ID, true); err != nil {
		t.Fatal(err)
	}
	if o := <-first; o != Approved {
		t.Errorf("first = %v, want approved", o)
	}
	// A request is decided once.
	if err := b.Decide(r.ID, false); !errors.Is(err, ErrNotWaiting) {
		t.Errorf("deciding twice: %v", err)
	}
	if err := b.Decide(p[1].ID, false); err != nil {
		t.Fatal(err)
	}
	if o := <-second; o != Denied {
		t.Errorf("second = %v, want denied", o)
	}
	waitPending(t, b, 0)
	if changes.Load() < 4 {
		t.Errorf("%d change notifications, want at least 4", changes.Load())
	}
	if err := b.Decide("made-up", true); !errors.Is(err, ErrNotWaiting) {
		t.Errorf("unknown ID: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	b := NewBroker(20*time.Millisecond, nil)
	if o := b.Ask(context.Background(), Request{Tool: "x"}); o != Expired {
		t.Errorf("outcome = %v, want expired", o)
	}
	if n := len(b.Pending()); n != 0 {
		t.Errorf("%d still waiting", n)
	}
}

func TestCancel(t *testing.T) {
	b := NewBroker(time.Minute, nil)
	ctx, cancel := context.WithCancel(context.Background())
	out := ask(ctx, b, Request{Tool: "x"})
	id := waitPending(t, b, 1)[0].ID
	cancel()
	if o := <-out; o != Cancelled {
		t.Errorf("outcome = %v, want cancelled", o)
	}
	// Approving a call the client gave up on does nothing.
	if err := b.Decide(id, true); !errors.Is(err, ErrNotWaiting) {
		t.Errorf("deciding a cancelled request: %v", err)
	}
}

func TestTooManyWaiting(t *testing.T) {
	b := NewBroker(time.Minute, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	for range MaxPending {
		wg.Go(func() { b.Ask(ctx, Request{Tool: "x"}) })
	}
	waitPending(t, b, MaxPending)
	if o := b.Ask(ctx, Request{Tool: "x"}); o != Refused {
		t.Errorf("outcome = %v, want refused", o)
	}
	cancel()
	wg.Wait()
}

// A decision racing the timeout is either taken or rejected, never lost:
// Decide succeeding means Ask returns that decision.
func TestDecisionRacingTimeout(t *testing.T) {
	for range 200 {
		b := NewBroker(time.Millisecond, nil)
		var decided atomic.Bool
		stop, done := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, r := range b.Pending() {
					if b.Decide(r.ID, true) == nil {
						decided.Store(true)
					}
				}
			}
		}()
		o := b.Ask(context.Background(), Request{Tool: "x"})
		close(stop)
		<-done
		if decided.Load() && o != Approved {
			t.Fatalf("Decide succeeded but Ask returned %v", o)
		}
		if !decided.Load() && o != Expired {
			t.Fatalf("no decision but Ask returned %v", o)
		}
	}
}
