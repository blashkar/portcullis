package dashboard

import (
	"bytes"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/blashkar/portcullis/internal/audit"
	"github.com/blashkar/portcullis/internal/gateway"
	"github.com/blashkar/portcullis/internal/redact"
)

// Feed keeps what the dashboard shows: the most recent calls and what
// portcullis did about them, and totals for the whole session. It
// implements gateway.Observer.
type Feed struct {
	n        int
	redactor *redact.Redactor
	onChange func()

	mu     sync.Mutex
	events []Event // oldest first
	next   int64   // numbers the events, so the page can tell them apart
	totals Totals
}

// Event is an audit event with what the gateway did to the message. Its
// Params and Result are dropped for the readable forms below.
type Event struct {
	audit.Event
	Details gateway.Details

	// Input is what the client sent, such as a tool call's arguments, or
	// a tool's definition: redacted, indented and shortened. Summary is
	// the arguments on one line.
	Input, Summary string
	// Output is what the client got back: the text of a result, or the
	// JSON if it has none; shortened.
	Output string
}

// Totals count what happened in the session, including events the feed no
// longer keeps.
type Totals struct {
	Calls int // tool calls
	// How the tool calls were decided. A call that needed approval and
	// didn't get it was denied, expired, cancelled or refused.
	Allowed, Approved, NotApproved, Denied, RateLimited, Held int

	Redacted   int // secrets, in results and prompts
	Injections int // results judged a prompt injection
	Withheld   int // of those, results withheld
}

// Blocked is how many tool calls didn't go ahead.
func (t Totals) Blocked() int {
	return t.NotApproved + t.Denied + t.RateLimited + t.Held
}

// NewFeed returns a Feed that keeps the last n events worth showing and
// calls onChange, if it isn't nil, after each one. Secrets in what the
// client sends are redacted with r, if it isn't nil, before they're kept:
// unlike results, the gateway doesn't redact them.
func NewFeed(n int, r *redact.Redactor, onChange func()) *Feed {
	if onChange == nil {
		onChange = func() {}
	}
	return &Feed{n: n, redactor: r, onChange: onChange}
}

// Observe adds an event.
func (f *Feed) Observe(e audit.Event, d gateway.Details) {
	var ev Event
	keep := shown(e)
	if keep {
		ev = f.readable(e)
		ev.Details = d
	}
	f.mu.Lock()
	f.count(e, d)
	if keep {
		f.next++
		ev.ID = f.next
		f.events = append(f.events, ev)
		if len(f.events) > f.n {
			f.events = append(f.events[:0], f.events[len(f.events)-f.n:]...)
		}
	}
	f.mu.Unlock()
	f.onChange()
}

// redactWindow is how much of what the client sent is redacted and shown
// in part. It's far more than is shown, so a secret cut off at its end
// can't reach the part that is.
const redactWindow = 64 << 10

// summaryLen caps the one-line form of a call's arguments.
const summaryLen = 120

// readable makes e's payloads readable and drops the raw ones. What the
// client sent is redacted: unlike results, the gateway doesn't redact it.
func (f *Feed) readable(e audit.Event) Event {
	params, result := e.Params, e.Result
	e.Params, e.Result = "", ""
	ev := Event{Event: e}

	var in any
	parsed := params != "" && len(params) <= redactWindow && json.Unmarshal([]byte(params), &in) == nil
	key := map[string]string{"tools/call": "arguments", "prompts/get": "arguments", "resources/read": "uri"}[e.Method]
	switch {
	case parsed && key != "":
		if in = field(in, key); in != nil {
			if f.redactor != nil {
				in = f.redactor.Value(in, redact.Counts{})
			}
			ev.Input = shorten(indent(in), maxShownPayload)
			ev.Summary = shorten(oneLine(in), summaryLen)
		}
	case parsed:
		// A tool's definition, which portcullis reports.
		ev.Input = shorten(indent(in), maxShownPayload)
	case params != "":
		p := shorten(params, redactWindow)
		if f.redactor != nil {
			p, _ = f.redactor.String(p)
		}
		ev.Input = shorten(p, maxShownPayload)
	}
	ev.Output = shorten(resultText(result), maxShownPayload)
	return ev
}

// field returns v's key, if v is an object.
func field(v any, key string) any {
	m, _ := v.(map[string]any)
	return m[key]
}

// resultText is the text in a result: a tool call's content, a resource's
// contents or a prompt's messages. A result with no text is shown as JSON.
func resultText(raw string) string {
	var v any
	if raw == "" || json.Unmarshal([]byte(raw), &v) != nil {
		return raw
	}
	var texts []string
	for _, key := range []string{"content", "contents", "messages"} {
		collectText(field(v, key), &texts)
	}
	if len(texts) == 0 {
		return prettyJSON([]byte(raw))
	}
	return strings.Join(texts, "\n")
}

// collectText appends every "text" string in v, in order.
func collectText(v any, texts *[]string) {
	switch v := v.(type) {
	case []any:
		for _, x := range v {
			collectText(x, texts)
		}
	case map[string]any:
		if t, ok := v["text"].(string); ok {
			*texts = append(*texts, t)
		}
		for _, k := range slices.Sorted(maps.Keys(v)) {
			if k != "text" {
				collectText(v[k], texts)
			}
		}
	}
}

// indent is v as indented JSON, with <, > and & kept as they are: the page
// escapes them.
func indent(v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return ""
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// oneLine is v on one line: an object's fields as key=value, in key order.
func oneLine(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return compact(v)
	}
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		parts = append(parts, k+"="+compact(m[k]))
	}
	return strings.Join(parts, " ")
}

func compact(v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return ""
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// shown reports whether the timeline shows e: calls and what portcullis
// did about tools and servers, not the protocol's housekeeping.
func shown(e audit.Event) bool {
	switch e.Method {
	case "tools/call", "prompts/get", "resources/read":
		return e.Direction == audit.ClientToServer
	case "tool/held", "tool/changed", "tool/flagged", "upstream/disconnected":
		return true
	}
	return false
}

func (f *Feed) count(e audit.Event, d gateway.Details) {
	t := &f.totals
	for _, n := range d.Redacted {
		t.Redacted += n
	}
	if d.Injection {
		t.Injections++
	}
	if d.Withheld {
		t.Withheld++
	}
	if e.Method != "tools/call" || e.Direction != audit.ClientToServer {
		return
	}
	t.Calls++
	switch e.Decision {
	case audit.DecisionHeld:
		t.Held++
	case "deny":
		t.Denied++
	case "rate_limit":
		t.RateLimited++
	case audit.DecisionApproved:
		t.Approved++
	case "require_approval":
		t.NotApproved++
	default:
		t.Allowed++
	}
}

// Events returns the events, newest first.
func (f *Feed) Events() []Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Event, len(f.events))
	for i, e := range f.events {
		out[len(out)-1-i] = e
	}
	return out
}

// Totals returns the session's totals.
func (f *Feed) Totals() Totals {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.totals
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
