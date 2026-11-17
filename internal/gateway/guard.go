package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/blashkar/portcullis/internal/approval"
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
	// injection summarizes what the injection checks found, if anything,
	// and injected is whether they judged it an injection.
	injection string
	injected  bool
	withheld  bool // the result was withheld as an injection
	// withheldText is what was withheld, redacted, for the audit log.
	withheldText string
	// approval is how a call that needed a person's approval ended.
	approval approval.Outcome
}

type noteKey struct{}

func noteFrom(ctx context.Context) *callNote {
	n, _ := ctx.Value(noteKey{}).(*callNote)
	return n
}

// toolCheck is the outcome of checking one tool's, prompt's or resource's
// definition.
type toolCheck struct {
	status   pin.Status // 0 without pinning
	findings []scan.Finding
	held     string // why it is held back; "" if it's offered
}

// offering is a tool, prompt or resource an upstream offers, to check.
type offering struct {
	def  pin.Definition        // as the client will see it
	scan func() []scan.Finding // the scanner's findings
}

// firstRunKey marks the context of the first listing of a server the pin
// file has nothing from, whose definitions HoldAfterFirst pins.
type firstRunKey struct{}

// check pins and scans what an upstream offers, keyed by pin key, and says
// which of it to hold back.
func (g *Gateway) check(ctx context.Context, u *upstream, offered map[string]offering) (map[string]toolCheck, error) {
	out := make(map[string]toolCheck, len(offered))
	var statuses map[string]pin.Status
	if g.opts.Pins != nil {
		defs := make(map[string]pin.Definition, len(offered))
		for key, o := range offered {
			defs[key] = o.def
		}
		var err error
		if statuses, err = g.opts.Pins.Check(u.name, ctx.Value(firstRunKey{}) == true, defs); err != nil {
			return nil, err
		}
	}
	sc := g.opts.Scan
	for key, o := range offered {
		c := toolCheck{status: statuses[key]}
		if sc.Enabled && !sc.Ignore.Match(key) {
			c.findings = o.scan()
		}
		review := "review it with `portcullis pin diff " + key + "` and approve it with `portcullis pin approve " + key + "`"
		switch {
		case c.status == pin.Changed:
			c.held = "its definition changed since it was approved; " + review
		case c.status == pin.New:
			c.held = "it is new and hasn't been approved; " + review
		case sc.Hide && scan.Max(c.findings) == scan.High:
			c.held = "its definition looks like tool poisoning (" + firstHigh(c.findings).String() + "); if you trust it, add it to scan.ignore in the config"
		}
		g.report(u, key, o.def, c)
		out[key] = c
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

// maxReports is how many reports the gateway remembers per definition
// name, so a server flipping between versions isn't reported each time.
const maxReports = 4

// report logs and records what checking a tool, prompt or resource found,
// once per version of its definition: a server re-listing it doesn't
// repeat the report.
func (g *Gateway) report(u *upstream, name string, def pin.Definition, c toolCheck) {
	var method string
	switch {
	case c.status == pin.Changed:
		method = audit.DefinitionChanged
	case c.held != "":
		method = audit.DefinitionHeld
	case len(c.findings) > 0:
		method = audit.DefinitionFlagged
	case c.status == pin.Pinned:
		method = audit.DefinitionPinned
	default:
		return
	}
	if g.reportedBefore(u, name, method+"|"+def.Hash()) {
		return
	}

	var findings []string
	for _, f := range c.findings {
		findings = append(findings, f.String())
	}
	e := audit.Event{
		Time: time.Now(), Direction: audit.Internal, Upstream: u.name, Method: method, Tool: name,
		Reason: c.held, Findings: strings.Join(findings, "; "), IsError: c.held != "",
	}
	if method != audit.DefinitionPinned && (g.opts.Recorder != nil || g.opts.Observer != nil) {
		e.Params = marshal(def)
	}
	attrs := []any{"upstream", u.name, pin.KindOf(name), name}
	if c.held != "" {
		attrs = append(attrs, "reason", c.held)
	}
	if len(findings) > 0 {
		attrs = append(attrs, "findings", e.Findings)
	}
	switch {
	case c.held != "":
		g.log.Warn(pin.KindOf(name)+" held back", attrs...)
	case method == audit.DefinitionFlagged:
		g.log.Warn(pin.KindOf(name)+" definition flagged", attrs...)
	default:
		g.log.Info(pin.KindOf(name)+" pinned", attrs...)
	}
	g.record(context.Background(), e, Details{})
}

// reportedBefore reports whether report was already made for name, and
// remembers it if not. It keeps the last maxReports reports per name.
func (g *Gateway) reportedBefore(u *upstream, name, report string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	past := u.reported[name]
	if slices.Contains(past, report) {
		return true
	}
	if len(past) == maxReports {
		past = past[1:]
	}
	if u.reported == nil {
		u.reported = map[string][]string{}
	}
	u.reported[name] = append(slices.Clip(past), report)
	return false
}

// forgetReports forgets the reports about definitions of kind the upstream
// no longer lists, so what is remembered is bounded by what it lists now.
// g.mu must be held.
func (g *Gateway) forgetReports(u *upstream, kind string, listed map[string]offering) {
	for name := range u.reported {
		if _, ok := listed[name]; !ok && pin.KindOf(name) == kind {
			delete(u.reported, name)
		}
	}
}

// guard is receiving middleware that refuses to call held tools, get held
// prompts and read held resources, with an error saying why, rather than
// the SDK's bare "unknown tool".
func (g *Gateway) guard(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		var key string
		switch p := req.GetParams().(type) {
		case *mcp.CallToolParamsRaw:
			if method == "tools/call" {
				key = p.Name
			}
		case *mcp.GetPromptParams:
			if method == "prompts/get" {
				key = pin.FromPrompt(&mcp.Prompt{Name: p.Name}).Key()
			}
		case *mcp.ReadResourceParams:
			if method == "resources/read" {
				key = pin.FromResource(&mcp.Resource{URI: p.URI}).Key()
			}
		}
		if reason := g.heldReason(key); key != "" && reason != "" {
			if n := noteFrom(ctx); n != nil {
				n.held = reason
			}
			data, _ := json.Marshal(map[string]string{"reason": reason})
			return nil, &jsonrpc.Error{
				Code:    CodeToolHeld,
				Message: fmt.Sprintf("portcullis: %s is held back: %s", key, reason),
				Data:    data,
			}
		}
		return next(ctx, method, req)
	}
}

// heldReason says why the tool, prompt or resource with pin key name is
// held back, or returns "" if it isn't.
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

// Held returns the tools, prompts and resources being held back, by pin
// key, with the reasons.
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

// Resync fetches every upstream's tools, prompts and resources again and
// rechecks them. serve calls it once all upstreams are connected, so the
// cross-tool check sees them all.
func (g *Gateway) Resync(ctx context.Context) {
	g.mu.Lock()
	var us []*upstream
	for _, u := range g.upstreams {
		us = append(us, u)
	}
	g.mu.Unlock()
	for _, u := range us {
		if err := errors.Join(g.syncTools(ctx, u), g.syncPrompts(ctx, u), g.syncResources(ctx, u)); err != nil {
			g.log.Warn("refreshing upstream lists", "upstream", u.name, "err", err)
		}
	}
}

// watchPins resyncs when the pin file changes, so anything approved with
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
			g.redactResourceContents(c.Resource, counts)
		case *mcp.ResourceLink:
			c.URI = g.redactString(c.URI, counts)
			c.Name = g.redactString(c.Name, counts)
			c.Title = g.redactString(c.Title, counts)
			c.Description = g.redactString(c.Description, counts)
		}
	}
}

// redactResourceContents redacts a resource's text, and its blob if that
// is text too.
func (g *Gateway) redactResourceContents(r *mcp.ResourceContents, counts redact.Counts) {
	if r == nil {
		return
	}
	r.Text = g.redactString(r.Text, counts)
	if b, ok := blobText(r.Blob); ok {
		if out := g.redactString(b, counts); out != b {
			r.Blob = []byte(out)
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
		g.redactResourceContents(c, counts)
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
