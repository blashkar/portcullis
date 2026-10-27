package gateway

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/blashkar/portcullis/internal/inject"
)

// Progress notifications are text a server can send at any time, outside
// any result, so they get their own checks: only a request waiting on that
// server gets them, at a bounded rate, and their message is redacted and
// dropped if it looks like an injection.
const (
	// maxProgressPerSecond caps the notifications passed on from one
	// upstream, so a server can't flood the client or the audit log.
	maxProgressPerSecond = 10
	// maxProgressMessage caps a message's length, in characters.
	maxProgressMessage = 200
)

// progressGrace is how long a request's token stays valid after the
// request ends: a notification the server sent before its response can be
// handled after it.
var progressGrace = 2 * time.Second

// rateWindow counts the notifications passed on in the current second.
type rateWindow struct {
	start time.Time
	n     int
}

func progressKey(token any) string {
	return fmt.Sprintf("%T:%v", token, token)
}

// expectProgress notes that a request with this progress token is waiting
// on upstream, until progressGrace after the returned function is called.
// A request without a token gets no progress notifications.
func (g *Gateway) expectProgress(upstream string, token any) (done func()) {
	if token == nil {
		return func() {}
	}
	k := progressKey(token)
	g.mu.Lock()
	if g.inFlight[upstream] == nil {
		g.inFlight[upstream] = map[string]int{}
	}
	g.inFlight[upstream][k]++
	g.mu.Unlock()
	return func() {
		time.AfterFunc(progressGrace, func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			if g.inFlight[upstream][k]--; g.inFlight[upstream][k] <= 0 {
				delete(g.inFlight[upstream], k)
			}
		})
	}
}

// waitingOn reports whether a request with this token is waiting on upstream.
func (g *Gateway) waitingOn(upstream string, token any) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.inFlight[upstream][progressKey(token)] > 0
}

// progress passes on a progress notification from upstream if a request
// with its token is waiting on that upstream and the rate limit allows.
func (g *Gateway) progress(ctx context.Context, upstream string, p *mcp.ProgressNotificationParams) {
	if p == nil {
		return
	}
	now := time.Now()
	g.mu.Lock()
	waiting := g.inFlight[upstream][progressKey(p.ProgressToken)] > 0
	allowed := false
	if waiting {
		w := g.progressRate[upstream]
		if w == nil || now.Sub(w.start) >= time.Second {
			w = &rateWindow{start: now}
			g.progressRate[upstream] = w
		}
		w.n++
		allowed = w.n <= maxProgressPerSecond
	}
	g.mu.Unlock()
	switch {
	case !waiting:
		g.log.Debug("dropping progress for no waiting request", "upstream", upstream)
		return
	case !allowed:
		g.log.Debug("dropping progress over the rate limit", "upstream", upstream)
		return
	}
	// A new value rather than the server's: its _meta isn't passed on.
	out := &mcp.ProgressNotificationParams{
		ProgressToken: p.ProgressToken,
		Progress:      p.Progress,
		Total:         p.Total,
		Message:       g.progressMessage(upstream, p.Message),
	}
	if ss := g.clientSession(); ss != nil {
		_ = ss.NotifyProgress(ctx, out)
	}
}

// progressMessage returns a progress message fit to pass on: shortened,
// redacted, and empty if it looks like an injection.
func (g *Gateway) progressMessage(upstream, msg string) string {
	if msg == "" {
		return ""
	}
	// Redact and check the whole message before shortening it: cut first,
	// a secret could lose the part its pattern needs and get through.
	if g.opts.Redactor != nil {
		msg, _ = g.opts.Redactor.String(msg)
	}
	if fs := inject.Heuristics(msg); len(fs) > 0 {
		g.log.Warn("dropping a progress message that looks like an injection", "upstream", upstream, "finding", fs[0].Check)
		return ""
	}
	if r := []rune(msg); len(r) > maxProgressMessage {
		msg = string(r[:maxProgressMessage]) + "…"
	}
	return msg
}
