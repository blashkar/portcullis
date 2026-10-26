// Package approval holds tool calls that need a person's OK until someone
// approves or denies them, or the wait runs out.
//
// The call waits in the gateway with its arguments already encoded, and a
// decision answers that one call: what was shown is exactly what is sent,
// and approving it doesn't approve the next call, even an identical one.
package approval

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"
)

// Request is a tool call waiting for a decision.
type Request struct {
	ID      string
	Time    time.Time // when it started waiting
	Expires time.Time
	Tool    string          // the name the client used: fs__write_file
	Server  string          // the upstream server it goes to
	Args    json.RawMessage // exactly what will be sent if it's approved
	Rule    string          // the policy rule that asked for approval
	Reason  string          // the rule's reason, if it has one
}

// Outcome is how a request ended.
type Outcome int

// Outcomes.
const (
	Approved  Outcome = iota + 1
	Denied            // a person said no
	Expired           // nobody answered in time
	Cancelled         // the client gave up on the call
	Refused           // too many calls were already waiting
)

func (o Outcome) String() string {
	switch o {
	case Approved:
		return "approved"
	case Denied:
		return "denied"
	case Expired:
		return "expired"
	case Cancelled:
		return "cancelled"
	case Refused:
		return "refused"
	}
	return "unknown"
}

// DefaultTimeout is how long a call waits for a decision by default.
const DefaultTimeout = 2 * time.Minute

// MaxPending caps the calls waiting at once. More are refused, so a client
// stuck in a loop can't pile up calls and memory.
const MaxPending = 32

// ErrNotWaiting means the request was already decided, expired, or never
// existed.
var ErrNotWaiting = errors.New("approval: no such request is waiting")

// Broker keeps the waiting requests. It is safe for concurrent use.
type Broker struct {
	timeout  time.Duration
	onChange func()

	mu      sync.Mutex
	pending map[string]*waiting
}

type waiting struct {
	req      Request
	decision chan Outcome // buffered: Decide never blocks
}

// NewBroker returns a Broker whose requests wait up to timeout (0 means
// DefaultTimeout). onChange, if not nil, is called whenever the set of
// waiting requests changes.
func NewBroker(timeout time.Duration, onChange func()) *Broker {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if onChange == nil {
		onChange = func() {}
	}
	return &Broker{timeout: timeout, onChange: onChange, pending: map[string]*waiting{}}
}

// Timeout returns how long a request waits for a decision.
func (b *Broker) Timeout() time.Duration {
	return b.timeout
}

// Ask waits until req is approved or denied, the wait times out, or ctx is
// done. It fills in req's ID, Time and Expires.
func (b *Broker) Ask(ctx context.Context, req Request) Outcome {
	req.ID = rand.Text()
	req.Time = time.Now()
	req.Expires = req.Time.Add(b.timeout)
	w := &waiting{req: req, decision: make(chan Outcome, 1)}

	b.mu.Lock()
	if len(b.pending) >= MaxPending {
		b.mu.Unlock()
		return Refused
	}
	b.pending[req.ID] = w
	b.mu.Unlock()
	b.onChange()
	defer func() {
		b.mu.Lock()
		delete(b.pending, req.ID)
		b.mu.Unlock()
		b.onChange()
	}()

	timer := time.NewTimer(b.timeout)
	defer timer.Stop()
	select {
	case o := <-w.decision:
		return o
	case <-timer.C:
	case <-ctx.Done():
	}
	// A decision may have arrived at the same moment. Take it out of the
	// map first, so no decision can arrive after this check.
	b.mu.Lock()
	delete(b.pending, req.ID)
	b.mu.Unlock()
	select {
	case o := <-w.decision:
		return o
	default:
	}
	if ctx.Err() != nil {
		return Cancelled
	}
	return Expired
}

// Decide approves or denies a waiting request.
func (b *Broker) Decide(id string, approve bool) error {
	o := Denied
	if approve {
		o = Approved
	}
	b.mu.Lock()
	w, ok := b.pending[id]
	if ok {
		// Removed here, so a request can be decided only once. The decision
		// is sent before unlocking: Ask, after a timeout, takes the lock and
		// then looks for a decision, so it can't miss one that got this far.
		// The channel is buffered and only one Decide gets here, so the send
		// doesn't block.
		delete(b.pending, id)
		w.decision <- o
	}
	b.mu.Unlock()
	if !ok {
		return ErrNotWaiting
	}
	if afterDecide != nil {
		afterDecide()
	}
	b.onChange()
	return nil
}

// afterDecide, if set, runs once Decide has decided a request; a test uses
// it to make Ask time out at that moment.
var afterDecide func()

// Get returns a waiting request.
func (b *Broker) Get(id string) (Request, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	w, ok := b.pending[id]
	if !ok {
		return Request{}, false
	}
	return w.req, true
}

// Pending returns the waiting requests, oldest first.
func (b *Broker) Pending() []Request {
	b.mu.Lock()
	out := make([]Request, 0, len(b.pending))
	for _, w := range b.pending {
		out = append(out, w.req)
	}
	b.mu.Unlock()
	slices.SortFunc(out, func(a, b Request) int { return a.Time.Compare(b.Time) })
	return out
}
