package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/blashkar/portcullis/internal/audit"
	"github.com/blashkar/portcullis/internal/glob"
	"github.com/blashkar/portcullis/internal/pin"
	"github.com/blashkar/portcullis/internal/policy"
	"github.com/blashkar/portcullis/internal/redact"
	"github.com/blashkar/portcullis/internal/scan"
)

// CodeToolHeld is the JSON-RPC error code for a call to a tool portcullis
// is holding back: one whose definition changed, that hasn't been approved,
// or that looks poisoned.
const CodeToolHeld = -32031

// ScanOptions configure the tool-poisoning scanner.
type ScanOptions struct {
	Enabled bool
	// Hide holds back tools with a high-severity finding; otherwise
	// findings are only logged and recorded.
	Hide bool
	// Ignore lists tools that aren't scanned.
	Ignore glob.Patterns
}

// DefaultPinPoll is how often the gateway checks the pin file for tools
// approved by "portcullis pin approve".
const DefaultPinPoll = 2 * time.Second

// callNote collects what the gateway did to a request, for its audit event.
// The observe middleware puts one in the context; handlers fill it in.
type callNote struct {
	decision *policy.Decision
	held     string // why the tool is held, if it is
	redacted redact.Counts
	// injection summarizes what the injection checks found, if anything.
	injection string
}

type noteKey struct{}

func noteFrom(ctx context.Context) *callNote {
	n, _ := ctx.Value(noteKey{}).(*callNote)
	return n
}

// toolCheck is the outcome of checking one tool's definition.
type toolCheck struct {
	status   pin.Status // 0 without pinning
	findings []scan.Finding
	held     string // why the tool is held back; "" if it's offered
}

// checkTools pins and scans the tools an upstream offers, keyed by their
// client-facing names. others are the other upstreams' tool names.
func (g *Gateway) checkTools(upstream string, tools map[string]*mcp.Tool, others []string) (map[string]toolCheck, error) {
	out := make(map[string]toolCheck, len(tools))
	var statuses map[string]pin.Status
	if g.opts.Pins != nil {
		defs := make(map[string]pin.Definition, len(tools))
		for name, t := range tools {
			defs[name] = pin.FromTool(t)
		}
		var err error
		if statuses, err = g.opts.Pins.Check(defs); err != nil {
			return nil, err
		}
	}
	sc := g.opts.Scan
	for name, t := range tools {
		c := toolCheck{status: statuses[name]}
		if sc.Enabled && !sc.Ignore.Match(name) {
			c.findings = scan.Tool(t, others)
		}
		switch {
		case c.status == pin.Changed:
			c.held = "its definition changed since it was approved; review it with `portcullis pin diff " + name + "` and approve it with `portcullis pin approve " + name + "`"
		case c.status == pin.New:
			c.held = "it is new and hasn't been approved; review it with `portcullis pin diff " + name + "` and approve it with `portcullis pin approve " + name + "`"
		case sc.Hide && scan.Max(c.findings) == scan.High:
			c.held = "its definition looks like tool poisoning (" + firstHigh(c.findings).String() + "); if you trust it, add it to scan.ignore in the config"
		}
		g.reportTool(upstream, name, pin.FromTool(t), c)
		out[name] = c
	}
	return out, nil
}

func firstHigh(fs []scan.Finding) scan.Finding {
	for _, f := range fs {
		if f.Severity == scan.High {
			return f
		}
	}
	return scan.Finding{}
}

// reportTool logs and records what checking a tool found, once per
// definition: a server re-listing its tools doesn't repeat the report.
func (g *Gateway) reportTool(upstream, name string, def pin.Definition, c toolCheck) {
	var method string
	switch {
	case c.status == pin.Changed:
		method = "tool/changed"
	case c.held != "":
		method = "tool/held"
	case len(c.findings) > 0:
		method = "tool/flagged"
	case c.status == pin.Pinned:
		method = "tool/pinned"
	default:
		return
	}
	key := method + "|" + name + "|" + def.Hash()
	g.mu.Lock()
	seen := g.reported[key]
	g.reported[key] = true
	g.mu.Unlock()
	if seen {
		return
	}

	var findings []string
	for _, f := range c.findings {
		findings = append(findings, f.String())
	}
	e := audit.Event{
		Time: time.Now(), Direction: audit.Internal, Upstream: upstream, Method: method, Tool: name,
		Reason: c.held, Findings: strings.Join(findings, "; "), IsError: c.held != "",
	}
	if method != "tool/pinned" && g.opts.Recorder != nil {
		e.Params = marshal(def)
	}
	attrs := []any{"upstream", upstream, "tool", name}
	if c.held != "" {
		attrs = append(attrs, "reason", c.held)
	}
	if len(findings) > 0 {
		attrs = append(attrs, "findings", e.Findings)
	}
	switch {
	case c.held != "":
		g.log.Warn("tool held back", attrs...)
	case method == "tool/flagged":
		g.log.Warn("tool definition flagged", attrs...)
	default:
		g.log.Info("tool pinned", attrs...)
	}
	g.record(context.Background(), e)
}

// guard is receiving middleware that refuses calls to held tools, with an
// error saying why, rather than the SDK's bare "unknown tool".
func (g *Gateway) guard(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if p, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok && method == "tools/call" {
			if reason := g.heldReason(p.Name); reason != "" {
				if n := noteFrom(ctx); n != nil {
					n.held = reason
				}
				data, _ := json.Marshal(map[string]string{"reason": reason})
				return nil, &jsonrpc.Error{
					Code:    CodeToolHeld,
					Message: fmt.Sprintf("portcullis: %s is held back: %s", p.Name, reason),
					Data:    data,
				}
			}
		}
		return next(ctx, method, req)
	}
}

func (g *Gateway) heldReason(name string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, u := range g.upstreams {
		if r, ok := u.held[name]; ok {
			return r
		}
	}
	return ""
}

// Held returns the tools being held back, with the reasons.
func (g *Gateway) Held() map[string]string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := map[string]string{}
	for _, u := range g.upstreams {
		for name, r := range u.held {
			out[name] = r
		}
	}
	return out
}

// otherToolNames returns the tool names of every upstream but one, both
// client-facing and as the servers name them, for the cross-tool check.
func (g *Gateway) otherToolNames(upstream string) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []string
	for name, u := range g.upstreams {
		if name == upstream {
			continue
		}
		for _, n := range u.names {
			out = append(out, n, prefixed(name, n))
		}
	}
	return out
}

// Resync fetches every upstream's tools again and rechecks them. serve calls
// it once all upstreams are connected, so the cross-tool check sees them all.
func (g *Gateway) Resync(ctx context.Context) {
	g.mu.Lock()
	var us []*upstream
	for _, u := range g.upstreams {
		us = append(us, u)
	}
	g.mu.Unlock()
	for _, u := range us {
		if err := g.syncTools(ctx, u); err != nil {
			g.log.Warn("refreshing upstream tools", "upstream", u.name, "err", err)
		}
	}
}

// watchPins resyncs when the pin file changes, so a tool approved with
// "portcullis pin approve" while serve runs is offered without a restart.
func (g *Gateway) watchPins(ctx context.Context) {
	if g.opts.Pins == nil {
		return
	}
	every := g.opts.PinPoll
	if every <= 0 {
		every = DefaultPinPoll
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if g.opts.Pins.Modified() {
				g.log.Info("pin file changed; rechecking tools", "path", g.opts.Pins.Path())
				g.Resync(ctx)
			}
		}
	}
}

// redactContent redacts secrets in content the model will read.
func (g *Gateway) redactContent(content []mcp.Content, counts redact.Counts) {
	for _, c := range content {
		switch c := c.(type) {
		case *mcp.TextContent:
			c.Text = g.redactString(c.Text, counts)
		case *mcp.EmbeddedResource:
			if c.Resource != nil {
				c.Resource.Text = g.redactString(c.Resource.Text, counts)
			}
		}
	}
}

func (g *Gateway) redactString(s string, counts redact.Counts) string {
	out, c := g.opts.Redactor.String(s)
	counts.Add(c)
	return out
}

func (g *Gateway) redactToolResult(ctx context.Context, res *mcp.CallToolResult) {
	if g.opts.Redactor == nil || res == nil {
		return
	}
	counts := redact.Counts{}
	g.redactContent(res.Content, counts)
	if res.StructuredContent != nil {
		res.StructuredContent = g.opts.Redactor.Value(res.StructuredContent, counts)
	}
	g.noteRedactions(ctx, counts)
}

func (g *Gateway) redactResource(ctx context.Context, res *mcp.ReadResourceResult) {
	if g.opts.Redactor == nil || res == nil {
		return
	}
	counts := redact.Counts{}
	for _, c := range res.Contents {
		if c != nil {
			c.Text = g.redactString(c.Text, counts)
		}
	}
	g.noteRedactions(ctx, counts)
}

func (g *Gateway) redactPrompt(ctx context.Context, res *mcp.GetPromptResult) {
	if g.opts.Redactor == nil || res == nil {
		return
	}
	counts := redact.Counts{}
	for _, m := range res.Messages {
		if m != nil {
			g.redactContent([]mcp.Content{m.Content}, counts)
		}
	}
	g.noteRedactions(ctx, counts)
}

func (g *Gateway) noteRedactions(ctx context.Context, counts redact.Counts) {
	if len(counts) == 0 {
		return
	}
	if n := noteFrom(ctx); n != nil {
		n.redacted = counts
	}
	g.log.Warn("redacted secrets", "redacted", counts.String())
}
