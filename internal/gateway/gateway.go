// Package gateway puts several upstream MCP servers behind one MCP server.
//
// The client sees a single server. Each upstream's tools and prompts appear
// with the upstream's name as a prefix (fs__read_file), so two servers can
// both have a read_file tool. Resources keep their URIs and are routed by
// them. Calls are forwarded to the upstream that owns the name, and every
// message is logged and, if a Recorder is set, written to the audit log.
// Before a tool call is forwarded, the policy, if there is one, decides
// whether it may go ahead.
//
// Tools are checked before they are offered: a tool whose definition
// changed since it was pinned, or that looks poisoned, is held back. Secrets
// in tool results, resources and prompts are redacted on the way back, and
// results are checked for prompt injection.
//
// When an upstream's tool, prompt or resource list changes, the gateway
// picks up the new list and the client is told; when an upstream exits,
// its tools disappear and the others keep working.
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/blashkar/portcullis/internal/approval"
	"github.com/blashkar/portcullis/internal/audit"
	"github.com/blashkar/portcullis/internal/config"
	"github.com/blashkar/portcullis/internal/pin"
	"github.com/blashkar/portcullis/internal/policy"
	"github.com/blashkar/portcullis/internal/redact"
)

// CodePolicyBlocked is the JSON-RPC error code for a tool call the policy
// stopped. The error's data says which rule and why.
const CodePolicyBlocked = -32030

// Recorder stores audit events. *audit.Store implements it.
type Recorder interface {
	Record(ctx context.Context, e audit.Event) error
}

// Options configure a Gateway.
type Options struct {
	Version   string
	SessionID string
	Logger    *slog.Logger
	Recorder  Recorder // nil disables the audit log
	// Observer, if set, is told about every event too, such as for metrics
	// or the dashboard, with the same payloads as the Recorder.
	Observer Observer
	Policy   *policy.Policy // nil allows every call
	// Approver asks a person about calls the policy says need approval.
	// Without one, those calls are blocked.
	Approver Approver

	Pins     *pin.Store    // nil turns tool pinning off
	PinPoll  time.Duration // how often to look for approvals; 0 means DefaultPinPoll
	Scan     ScanOptions
	Redactor *redact.Redactor // nil turns redaction off
	Inject   InjectOptions

	// OnClientInfo is called once the client has said who it is.
	OnClientInfo func(name, version string)
}

// Gateway is the aggregating MCP server.
type Gateway struct {
	opts   Options
	log    *slog.Logger
	server *mcp.Server

	mu        sync.Mutex
	upstreams map[string]*upstream
	// resources maps each resource URI to the upstream that owns it.
	resources map[string]string
	client    *mcp.ServerSession
	gotClient bool
	closing   bool // Close was called, so upstreams exiting is expected
	// reported holds the tool reports already made, so each is made once.
	reported map[string]bool
	// inFlight counts, per upstream, the progress tokens of requests
	// waiting on it; progress notifications for others are dropped.
	inFlight     map[string]map[string]int
	progressRate map[string]*rateWindow
}

type upstream struct {
	name    string
	session *mcp.ClientSession // nil once the upstream has exited
	caps    *mcp.ServerCapabilities

	// syncMu serializes refreshes of this upstream's lists.
	syncMu    sync.Mutex
	tools     map[string]bool   // client-facing names of the tools offered
	held      map[string]string // tools held back, with the reason
	names     []string          // every tool's name as the server gives it
	prompts   map[string]bool
	resources map[string]bool // URIs
}

// New returns a Gateway with no upstreams.
func New(opts Options) *Gateway {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	g := &Gateway{
		opts:      opts,
		log:       opts.Logger,
		upstreams: map[string]*upstream{},
		resources: map[string]string{},
		reported:  map[string]bool{},

		inFlight:     map[string]map[string]int{},
		progressRate: map[string]*rateWindow{},
	}
	g.server = mcp.NewServer(&mcp.Implementation{Name: "portcullis", Version: opts.Version}, &mcp.ServerOptions{
		Capabilities: &mcp.ServerCapabilities{
			Tools:     &mcp.ToolCapabilities{ListChanged: true},
			Prompts:   &mcp.PromptCapabilities{ListChanged: true},
			Resources: &mcp.ResourceCapabilities{ListChanged: true},
		},
	})
	g.server.AddReceivingMiddleware(g.observe(audit.ClientToServer), g.guard)
	g.server.AddSendingMiddleware(g.observe(audit.ServerToClient))
	return g
}

// Connect connects to an upstream server over t, which for a child process
// is an *mcp.CommandTransport, and adds its tools, prompts and resources.
func (g *Gateway) Connect(ctx context.Context, name string, t mcp.Transport) error {
	u := &upstream{name: name, tools: map[string]bool{}, prompts: map[string]bool{}, resources: map[string]bool{}}
	// Each list is fetched again outside the notification handler, which
	// runs on the session's read loop. A server can send notifications
	// without end, so refreshes are coalesced and time-limited.
	refresher := func(sync func(context.Context, *upstream) error) func() {
		return coalesce(func() {
			ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
			defer cancel()
			if err := sync(ctx, u); err != nil {
				g.log.Warn("refreshing upstream lists", "upstream", name, "err", err)
			}
		})
	}
	refreshTools, refreshPrompts, refreshResources := refresher(g.syncTools), refresher(g.syncPrompts), refresher(g.syncResources)
	client := mcp.NewClient(&mcp.Implementation{Name: "portcullis", Version: g.opts.Version}, &mcp.ClientOptions{
		// No roots: portcullis doesn't expose the client's filesystem to upstreams.
		Capabilities:               &mcp.ClientCapabilities{},
		ToolListChangedHandler:     func(context.Context, *mcp.ToolListChangedRequest) { refreshTools() },
		PromptListChangedHandler:   func(context.Context, *mcp.PromptListChangedRequest) { refreshPrompts() },
		ResourceListChangedHandler: func(context.Context, *mcp.ResourceListChangedRequest) { refreshResources() },
		ProgressNotificationHandler: func(ctx context.Context, r *mcp.ProgressNotificationClientRequest) {
			// Progress tokens are chosen by the client and passed through
			// unchanged, so the notification can go back with the same one.
			g.progress(ctx, name, r.Params)
		},
	})
	session, err := client.Connect(ctx, t, nil)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", name, err)
	}
	u.session = session
	if res := session.InitializeResult(); res != nil {
		u.caps = res.Capabilities
	}

	g.mu.Lock()
	if _, dup := g.upstreams[name]; dup {
		g.mu.Unlock()
		_ = session.Close()
		return fmt.Errorf("upstream %s is already connected", name)
	}
	g.upstreams[name] = u
	g.mu.Unlock()

	if err := errors.Join(g.syncTools(ctx, u), g.syncPrompts(ctx, u), g.syncResources(ctx, u)); err != nil {
		return fmt.Errorf("listing %s's features: %w", name, err)
	}
	go func() {
		err := session.Wait()
		g.upstreamExited(u, err)
	}()
	g.log.Info("upstream connected", "upstream", name, "tools", len(u.tools), "prompts", len(u.prompts), "resources", len(u.resources))
	return nil
}

// Serve serves one client over t until it disconnects or ctx is cancelled.
func (g *Gateway) Serve(ctx context.Context, t mcp.Transport) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go g.watchPins(ctx)
	return g.server.Run(ctx, t)
}

// Close disconnects from every upstream, which stops their processes.
func (g *Gateway) Close() error {
	g.mu.Lock()
	g.closing = true
	var sessions []*mcp.ClientSession
	for _, u := range g.upstreams {
		if u.session != nil {
			sessions = append(sessions, u.session)
		}
	}
	g.mu.Unlock()

	var wg sync.WaitGroup
	errs := make([]error, len(sessions))
	for i, s := range sessions {
		wg.Go(func() { errs[i] = s.Close() })
	}
	wg.Wait()
	return errors.Join(errs...)
}

// Tools returns the client-facing tool names, sorted.
func (g *Gateway) Tools() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var names []string
	for _, u := range g.upstreams {
		names = append(names, slices.Collect(maps.Keys(u.tools))...)
	}
	slices.Sort(names)
	return names
}

// session returns the upstream's session, or an error if it has exited.
func (g *Gateway) session(name string) (*mcp.ClientSession, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	u := g.upstreams[name]
	if u == nil || u.session == nil {
		return nil, fmt.Errorf("server %s is not available", name)
	}
	return u.session, nil
}

func (g *Gateway) clientSession() *mcp.ServerSession {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.client
}

// prefixed returns the client-facing name of an upstream's tool or prompt.
func prefixed(upstream, name string) string {
	return upstream + config.Separator + name
}

// splitName splits a client-facing name into upstream and original name.
// ok is false, and upstream "", if the name has no prefix.
func splitName(name string) (upstream, original string, ok bool) {
	upstream, original, ok = strings.Cut(name, config.Separator)
	if !ok {
		return "", name, false
	}
	return upstream, original, true
}

func (g *Gateway) syncTools(ctx context.Context, u *upstream) error {
	if u.caps == nil || u.caps.Tools == nil {
		return nil
	}
	u.syncMu.Lock()
	defer u.syncMu.Unlock()
	s, err := g.session(u.name)
	if err != nil {
		return nil // it exited; upstreamExited cleans up
	}

	tools, full, err := collect(s.Tools(ctx, nil))
	if err != nil {
		return err
	}
	if !full {
		g.tooLong(u.name, "tools")
	}

	offered := map[string]*mcp.Tool{}
	var names []string
	for _, t := range tools {
		names = append(names, t.Name)
		if !validObjectSchema(t.InputSchema) {
			g.log.Warn("skipping tool with an invalid input schema", "upstream", u.name, "tool", t.Name)
			continue
		}
		ft := *t
		ft.Name = prefixed(u.name, t.Name)
		offered[ft.Name] = &ft
	}
	g.mu.Lock()
	u.names = names
	g.mu.Unlock()

	checks, err := g.checkTools(u.name, offered, g.otherToolNames(u.name))
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	held := map[string]string{}
	for name, ft := range offered {
		if r := checks[name].held; r != "" {
			held[name] = r
			continue
		}
		g.server.AddTool(ft, g.toolHandler(u.name, strings.TrimPrefix(name, u.name+config.Separator)))
		seen[name] = true
	}
	g.server.RemoveTools(stale(u.tools, seen)...)
	g.mu.Lock()
	u.tools, u.held = seen, held
	g.mu.Unlock()
	return nil
}

func (g *Gateway) toolHandler(upstream, tool string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, forward, err := decodeArgs(req.Params.Arguments)
		if err != nil {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: err.Error()}
		}
		if g.opts.Policy != nil {
			d := g.opts.Policy.Check(policy.Call{Tool: req.Params.Name, Server: upstream, Args: args})
			g.noteDecision(ctx, req.Params.Name, d)
			switch {
			case g.needsApproval(d):
				if err := g.askApproval(ctx, req.Params.Name, upstream, forward, d); err != nil {
					return nil, err
				}
			case d.Blocked():
				return nil, blockedError(req.Params.Name, d)
			}
		}
		s, err := g.session(upstream)
		if err != nil {
			return nil, err
		}
		defer g.expectProgress(upstream, req.Params.GetProgressToken())()
		res, err := s.CallTool(ctx, &mcp.CallToolParams{
			Meta:           req.Params.Meta,
			Name:           tool,
			Arguments:      forward,
			InputResponses: req.Params.InputResponses,
			RequestState:   req.Params.RequestState,
		})
		g.redactToolResult(ctx, res)
		return g.checkToolResult(ctx, req.Params.Name, res), err
	}
}

// decodeArgs decodes a tool call's arguments for the policy to check, and
// encodes them again for the upstream. Forwarding the re-encoded arguments
// means the server gets exactly what the policy saw: if the client sent a
// key twice, say, the server can't read the copy the policy didn't.
func decodeArgs(raw json.RawMessage) (map[string]any, json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return map[string]any{}, nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep large integers exact
	var args map[string]any
	if err := dec.Decode(&args); err != nil || args == nil {
		return nil, nil, errors.New("tool arguments must be a JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, nil, errors.New("tool arguments must be a single JSON object")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(args); err != nil {
		return nil, nil, err
	}
	forward := json.RawMessage(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	return celValue(args).(map[string]any), forward, nil
}

// PolicyArgs decodes a tool call's arguments as the gateway does before the
// policy checks them, for checking recorded calls again.
func PolicyArgs(raw json.RawMessage) (map[string]any, error) {
	args, _, err := decodeArgs(raw)
	return args, err
}

// celValue turns the json.Numbers in a decoded value into int64 or float64,
// which CEL understands.
func celValue(v any) any {
	switch v := v.(type) {
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i
		}
		f, _ := v.Float64()
		return f
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, x := range v {
			out[k] = celValue(x)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = celValue(x)
		}
		return out
	default:
		return v
	}
}

// blockedError is the error a blocked call gets.
func blockedError(tool string, d policy.Decision) error {
	rule := "the default policy"
	if d.Rule != "" {
		rule = "rule " + strconv.Quote(d.Rule)
	}
	var msg string
	switch {
	case d.RateLimited:
		msg = fmt.Sprintf("portcullis: %s is rate limited (%s): %s", tool, rule, d.Reason)
	case d.Action == policy.RequireApproval:
		msg = fmt.Sprintf("portcullis: %s needs a person's approval (%s), and no approver is configured", tool, rule)
	default:
		msg = fmt.Sprintf("portcullis: the policy does not allow %s (%s)", tool, rule)
		if d.Reason != "" && d.Reason != "no rule matched" {
			msg += ": " + d.Reason
		}
	}
	data, _ := json.Marshal(map[string]string{"decision": d.Outcome(), "rule": d.Rule, "reason": d.Reason})
	return &jsonrpc.Error{Code: CodePolicyBlocked, Message: msg, Data: data}
}

func (g *Gateway) noteDecision(ctx context.Context, tool string, d policy.Decision) {
	if n := noteFrom(ctx); n != nil {
		n.decision = &d
	}
	attrs := []any{"tool", tool, "decision", d.Outcome(), "rule", d.Rule, "reason", d.Reason}
	if d.Blocked() && !g.needsApproval(d) {
		g.log.Warn("call blocked by policy", attrs...)
	}
	if w := d.Would; w != nil {
		g.log.Warn("log_only policy would decide differently", "tool", tool, "decision", d.Outcome(), "would", w.Outcome(), "rule", w.Rule, "reason", w.Reason)
	}
}

// needsApproval reports whether a call waits for a person's decision.
func (g *Gateway) needsApproval(d policy.Decision) bool {
	return d.Action == policy.RequireApproval && !d.RateLimited && g.opts.Approver != nil
}

func (g *Gateway) syncPrompts(ctx context.Context, u *upstream) error {
	if u.caps == nil || u.caps.Prompts == nil {
		return nil
	}
	u.syncMu.Lock()
	defer u.syncMu.Unlock()
	s, err := g.session(u.name)
	if err != nil {
		return nil // it exited; upstreamExited cleans up
	}

	prompts, full, err := collect(s.Prompts(ctx, nil))
	if err != nil {
		return err
	}
	if !full {
		g.tooLong(u.name, "prompts")
	}
	seen := map[string]bool{}
	for _, p := range prompts {
		name := prefixed(u.name, p.Name)
		fp := *p
		fp.Name = name
		original := p.Name
		g.server.AddPrompt(&fp, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			s, err := g.session(u.name)
			if err != nil {
				return nil, err
			}
			defer g.expectProgress(u.name, req.Params.GetProgressToken())()
			res, err := s.GetPrompt(ctx, &mcp.GetPromptParams{Meta: req.Params.Meta, Name: original, Arguments: req.Params.Arguments})
			g.redactPrompt(ctx, res)
			return res, err
		})
		seen[name] = true
	}
	g.server.RemovePrompts(stale(u.prompts, seen)...)
	g.mu.Lock()
	u.prompts = seen
	g.mu.Unlock()
	return nil
}

func (g *Gateway) syncResources(ctx context.Context, u *upstream) error {
	if u.caps == nil || u.caps.Resources == nil {
		return nil
	}
	u.syncMu.Lock()
	defer u.syncMu.Unlock()
	s, err := g.session(u.name)
	if err != nil {
		return nil // it exited; upstreamExited cleans up
	}

	resources, full, err := collect(s.Resources(ctx, nil))
	if err != nil {
		return err
	}
	if !full {
		g.tooLong(u.name, "resources")
	}
	seen := map[string]bool{}
	for _, r := range resources {
		g.mu.Lock()
		owner, taken := g.resources[r.URI]
		if !taken {
			g.resources[r.URI] = u.name
		}
		g.mu.Unlock()
		if taken && owner != u.name {
			// URIs aren't namespaced, so the first server to offer one keeps it.
			g.log.Warn("skipping resource another server already offers", "upstream", u.name, "uri", r.URI, "owner", owner)
			continue
		}
		if err := addResource(g.server, r, g.resourceHandler(u.name)); err != nil {
			g.log.Warn("skipping resource", "upstream", u.name, "uri", r.URI, "err", err)
			continue
		}
		seen[r.URI] = true
	}
	gone := stale(u.resources, seen)
	g.server.RemoveResources(gone...)
	g.mu.Lock()
	for _, uri := range gone {
		delete(g.resources, uri)
	}
	u.resources = seen
	g.mu.Unlock()
	return nil
}

func (g *Gateway) resourceHandler(upstream string) mcp.ResourceHandler {
	return func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		s, err := g.session(upstream)
		if err != nil {
			return nil, err
		}
		defer g.expectProgress(upstream, req.Params.GetProgressToken())()
		res, err := s.ReadResource(ctx, &mcp.ReadResourceParams{Meta: req.Params.Meta, URI: req.Params.URI})
		g.redactResource(ctx, res)
		if err == nil {
			if berr := g.checkResource(ctx, req.Params.URI, res); berr != nil {
				return nil, berr
			}
		}
		return res, err
	}
}

// addResource adds r, turning the SDK's panic on an invalid URI into an error.
func addResource(s *mcp.Server, r *mcp.Resource, h mcp.ResourceHandler) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("invalid resource: %v", p)
		}
	}()
	s.AddResource(r, h)
	return nil
}

// upstreamExited removes an upstream's features once its session has ended.
func (g *Gateway) upstreamExited(u *upstream, err error) {
	g.mu.Lock()
	u.session = nil
	tools := slices.Collect(maps.Keys(u.tools))
	prompts := slices.Collect(maps.Keys(u.prompts))
	uris := slices.Collect(maps.Keys(u.resources))
	for _, uri := range uris {
		delete(g.resources, uri)
	}
	u.tools, u.prompts, u.resources = map[string]bool{}, map[string]bool{}, map[string]bool{}
	u.held, u.names = nil, nil

	closing := g.closing
	g.mu.Unlock()

	g.server.RemoveTools(tools...)
	g.server.RemovePrompts(prompts...)
	g.server.RemoveResources(uris...)
	if closing {
		g.log.Info("upstream closed", "upstream", u.name)
		g.record(context.Background(), audit.Event{Time: time.Now(), Direction: audit.Internal, Upstream: u.name, Method: "upstream/closed"}, Details{})
		return
	}
	g.log.Warn("upstream disconnected", "upstream", u.name, "err", err, "tools_removed", len(tools))
	g.record(context.Background(), audit.Event{
		Time: time.Now(), Direction: audit.Internal, Upstream: u.name, Method: "upstream/disconnected",
		Error: errString(err), IsError: true,
	}, Details{})
}

// stale returns the names in old that aren't in current.
func stale(old, current map[string]bool) []string {
	var out []string
	for name := range old {
		if !current[name] {
			out = append(out, name)
		}
	}
	return out
}

// validObjectSchema reports whether s is a JSON Schema for an object, which
// the SDK requires of every tool's input.
func validObjectSchema(s any) bool {
	m, ok := s.(map[string]any)
	return ok && m["type"] == "object"
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// observe returns middleware that logs every message going in dir and
// records it in the audit log.
func (g *Gateway) observe(dir string) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if dir == audit.ClientToServer {
				g.noteClient(req)
			}
			var note callNote
			if dir == audit.ClientToServer {
				ctx = context.WithValue(ctx, noteKey{}, &note)
			}
			start := time.Now()
			res, err := next(ctx, method, req)
			e := audit.Event{Time: start, Direction: dir, Method: method, Duration: time.Since(start), Error: errString(err), IsError: err != nil}
			g.describe(&e, req.GetParams(), res)
			if d := note.decision; d != nil {
				e.Decision, e.Rule, e.Reason = d.Outcome(), d.Rule, d.Reason
				if d.Would != nil {
					e.WouldDecision, e.WouldRule = d.Would.Outcome(), d.Would.Rule
				}
			}
			if note.approval != 0 {
				e.Reason = approvalReason(note.approval)
				if note.approval == approval.Approved {
					e.Decision = audit.DecisionApproved
				}
			}
			if note.held != "" {
				e.Decision, e.Reason = audit.DecisionHeld, note.held
			}
			var findings []string
			if len(note.redacted) > 0 {
				findings = append(findings, "redacted: "+note.redacted.String())
			}
			if note.injection != "" {
				findings = append(findings, note.injection)
			}
			e.Findings = strings.Join(findings, "; ")
			g.logEvent(e)
			g.record(context.WithoutCancel(ctx), e, note.details())
			return res, err
		}
	}
}

// describe fills in an event's tool, upstream and payloads.
func (g *Gateway) describe(e *audit.Event, params mcp.Params, res mcp.Result) {
	switch p := params.(type) {
	case *mcp.CallToolParamsRaw:
		e.Tool = p.Name
		e.Upstream, _, _ = splitName(p.Name)
	case *mcp.GetPromptParams:
		e.Upstream, _, _ = splitName(p.Name)
	case *mcp.ReadResourceParams:
		g.mu.Lock()
		e.Upstream = g.resources[p.URI]
		g.mu.Unlock()
	}
	if r, ok := res.(*mcp.CallToolResult); ok && r != nil && r.IsError {
		e.IsError = true
	}
	if g.opts.Recorder != nil || g.opts.Observer != nil {
		e.Params = marshal(params)
		e.Result = marshal(res)
	}
}

func marshal(v any) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil || string(b) == "null" {
		return ""
	}
	return string(b)
}

func (g *Gateway) logEvent(e audit.Event) {
	attrs := []any{"dir", e.Direction, "method", e.Method, "duration", e.Duration}
	if e.Tool != "" {
		attrs = append(attrs, "tool", e.Tool)
	}
	if e.Upstream != "" {
		attrs = append(attrs, "upstream", e.Upstream)
	}
	if e.Decision != "" {
		attrs = append(attrs, "decision", e.Decision)
	}
	if e.IsError {
		attrs = append(attrs, "failed", true)
	}
	if e.Error != "" {
		attrs = append(attrs, "error", e.Error)
	}
	g.log.Info("message", attrs...)
}

func (g *Gateway) record(ctx context.Context, e audit.Event, d Details) {
	e.SessionID = g.opts.SessionID
	if g.opts.Observer != nil {
		g.opts.Observer.Observe(e, d)
	}
	if g.opts.Recorder == nil {
		return
	}
	if err := g.opts.Recorder.Record(ctx, e); err != nil {
		g.log.Error("writing the audit log", "err", err)
	}
}

// noteClient remembers the client's session, for forwarding notifications,
// and reports who the client is the first time it says so.
func (g *Gateway) noteClient(req mcp.Request) {
	ss, _ := req.GetSession().(*mcp.ServerSession)
	g.mu.Lock()
	if ss != nil {
		g.client = ss
	}
	known := g.gotClient
	g.mu.Unlock()
	if known || g.opts.OnClientInfo == nil {
		return
	}

	// The initialize request carries clientInfo; newer protocol revisions
	// send it with other requests' params, so look for it in any of them.
	var info struct {
		ClientInfo *mcp.Implementation `json:"clientInfo"`
	}
	if b, err := json.Marshal(req.GetParams()); err == nil {
		_ = json.Unmarshal(b, &info)
	}
	if info.ClientInfo == nil && ss != nil {
		if p := ss.InitializeParams(); p != nil {
			info.ClientInfo = p.ClientInfo
		}
	}
	if info.ClientInfo == nil || info.ClientInfo.Name == "" {
		return
	}
	// Requests are handled concurrently: report the client only once.
	g.mu.Lock()
	first := !g.gotClient
	g.gotClient = true
	g.mu.Unlock()
	if first {
		g.opts.OnClientInfo(info.ClientInfo.Name, info.ClientInfo.Version)
	}
}
