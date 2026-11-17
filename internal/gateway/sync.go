package gateway

import (
	"context"
	"iter"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/blashkar/portcullis/internal/config"
	"github.com/blashkar/portcullis/internal/pin"
	"github.com/blashkar/portcullis/internal/scan"
)

// feature describes one list an upstream offers (its tools, prompts or
// resources) for syncFeature.
type feature[T any] struct {
	list    string // "tools", "prompts" or "resources", for logs
	kind    string // what pin.KindOf says of its pin keys
	enabled func(*mcp.ServerCapabilities) bool
	fetch   func(context.Context, *mcp.ClientSession) iter.Seq2[*T, error]
	// offer picks what to offer from what the server listed, by the name
	// the client will know it by. It is called with u.syncMu held.
	offer func(u *upstream, items []*T) map[string]*T
	def   func(*T) pin.Definition
	scan  func(x *T, others []string) []scan.Finding
	// add offers x to the client under name, and reports whether it did.
	add    func(u *upstream, name string, x *T) bool
	remove func(names ...string)
	// offered is the upstream's set of names now offered. g.mu must be
	// held.
	offered func(u *upstream) *map[string]bool
	// withdrawn, if set, is told the names no longer offered. g.mu is
	// held.
	withdrawn func(u *upstream, names []string)
}

// syncFeature lists one of an upstream's features, checks each definition
// and offers the ones that pass, withdrawing the ones no longer listed.
func syncFeature[T any](ctx context.Context, g *Gateway, u *upstream, f feature[T]) error {
	if u.caps == nil || !f.enabled(u.caps) {
		return nil
	}
	u.syncMu.Lock()
	defer u.syncMu.Unlock()
	s, err := g.session(u.name)
	if err != nil {
		return nil // it exited; upstreamExited cleans up
	}

	items, full, err := collect(f.fetch(ctx, s))
	if err != nil {
		return err
	}
	if !full {
		g.tooLong(u.name, f.list)
	}
	offered := f.offer(u, items)

	others := g.otherToolNames(u.name)
	keys := make(map[string]string, len(offered)) // name → pin key
	toCheck := make(map[string]offering, len(offered))
	for name, x := range offered {
		def := f.def(x)
		keys[name] = def.Key()
		toCheck[def.Key()] = offering{def: def, scan: func() []scan.Finding { return f.scan(x, others) }}
	}
	checks, err := g.check(ctx, u, toCheck)
	if err != nil {
		return err
	}

	seen := map[string]bool{}
	held := map[string]string{}
	for name, x := range offered {
		key := keys[name]
		if r := checks[key].held; r != "" {
			held[key] = r
			continue
		}
		if f.add(u, name, x) {
			seen[name] = true
		}
	}
	g.mu.Lock()
	gone := stale(*f.offered(u), seen)
	g.mu.Unlock()
	f.remove(gone...)

	g.mu.Lock()
	defer g.mu.Unlock()
	if f.withdrawn != nil {
		f.withdrawn(u, gone)
	}
	*f.offered(u) = seen
	g.setHeld(u, f.kind, held)
	g.forgetReports(u, f.kind, toCheck)
	return nil
}

func (g *Gateway) syncTools(ctx context.Context, u *upstream) error {
	return syncFeature(ctx, g, u, feature[mcp.Tool]{
		list:    "tools",
		kind:    "tool",
		enabled: func(c *mcp.ServerCapabilities) bool { return c.Tools != nil },
		fetch: func(ctx context.Context, s *mcp.ClientSession) iter.Seq2[*mcp.Tool, error] {
			return s.Tools(ctx, nil)
		},
		offer: func(u *upstream, tools []*mcp.Tool) map[string]*mcp.Tool {
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
			return offered
		},
		def:  pin.FromTool,
		scan: scan.Tool,
		add: func(u *upstream, name string, t *mcp.Tool) bool {
			g.server.AddTool(t, g.toolHandler(u.name, strings.TrimPrefix(name, u.name+config.Separator)))
			return true
		},
		remove:  g.server.RemoveTools,
		offered: func(u *upstream) *map[string]bool { return &u.tools },
	})
}

func (g *Gateway) syncPrompts(ctx context.Context, u *upstream) error {
	return syncFeature(ctx, g, u, feature[mcp.Prompt]{
		list:    "prompts",
		kind:    pin.KindPrompt,
		enabled: func(c *mcp.ServerCapabilities) bool { return c.Prompts != nil },
		fetch: func(ctx context.Context, s *mcp.ClientSession) iter.Seq2[*mcp.Prompt, error] {
			return s.Prompts(ctx, nil)
		},
		offer: func(u *upstream, prompts []*mcp.Prompt) map[string]*mcp.Prompt {
			offered := map[string]*mcp.Prompt{}
			for _, p := range prompts {
				fp := *p
				fp.Name = prefixed(u.name, p.Name)
				offered[fp.Name] = &fp
			}
			return offered
		},
		def:  pin.FromPrompt,
		scan: scan.Prompt,
		add: func(u *upstream, name string, p *mcp.Prompt) bool {
			g.server.AddPrompt(p, g.promptHandler(u.name, name, strings.TrimPrefix(name, u.name+config.Separator)))
			return true
		},
		remove:  g.server.RemovePrompts,
		offered: func(u *upstream) *map[string]bool { return &u.prompts },
	})
}

func (g *Gateway) promptHandler(upstream, name, original string) mcp.PromptHandler {
	return func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		s, err := g.session(upstream)
		if err != nil {
			return nil, err
		}
		defer g.expectProgress(upstream, req.Params.GetProgressToken())()
		res, err := s.GetPrompt(ctx, &mcp.GetPromptParams{Meta: req.Params.Meta, Name: original, Arguments: req.Params.Arguments})
		g.redactPrompt(ctx, res)
		if err != nil {
			return nil, g.checkError(ctx, name, err)
		}
		if berr := g.checkPrompt(ctx, name, res); berr != nil {
			return nil, berr
		}
		return res, nil
	}
}

func (g *Gateway) syncResources(ctx context.Context, u *upstream) error {
	return syncFeature(ctx, g, u, feature[mcp.Resource]{
		list:    "resources",
		kind:    pin.KindResource,
		enabled: func(c *mcp.ServerCapabilities) bool { return c.Resources != nil },
		fetch: func(ctx context.Context, s *mcp.ClientSession) iter.Seq2[*mcp.Resource, error] {
			return s.Resources(ctx, nil)
		},
		// URIs aren't namespaced, so the first server to offer one keeps it.
		offer: func(u *upstream, resources []*mcp.Resource) map[string]*mcp.Resource {
			offered := map[string]*mcp.Resource{}
			for _, r := range resources {
				g.mu.Lock()
				owner, taken := g.resources[r.URI]
				g.mu.Unlock()
				if taken && owner != u.name {
					g.log.Warn("skipping resource another server already offers", "upstream", u.name, "uri", r.URI, "owner", owner)
					continue
				}
				offered[r.URI] = r
			}
			return offered
		},
		def:  pin.FromResource,
		scan: scan.Resource,
		add: func(u *upstream, uri string, r *mcp.Resource) bool {
			g.mu.Lock()
			owner, taken := g.resources[uri]
			if !taken {
				g.resources[uri] = u.name
			}
			g.mu.Unlock()
			if taken && owner != u.name {
				g.log.Warn("skipping resource another server already offers", "upstream", u.name, "uri", uri, "owner", owner)
				return false
			}
			if err := addResource(g.server, r, g.resourceHandler(u.name)); err != nil {
				g.log.Warn("skipping resource", "upstream", u.name, "uri", uri, "err", err)
				if !taken {
					g.mu.Lock()
					delete(g.resources, uri)
					g.mu.Unlock()
				}
				return false
			}
			return true
		},
		remove:  g.server.RemoveResources,
		offered: func(u *upstream) *map[string]bool { return &u.resources },
		withdrawn: func(u *upstream, uris []string) {
			for _, uri := range uris {
				if g.resources[uri] == u.name {
					delete(g.resources, uri)
				}
			}
		},
	})
}
