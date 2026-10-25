package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/blashkar/portcullis/internal/audit"
	"github.com/blashkar/portcullis/internal/config"
	"github.com/blashkar/portcullis/internal/gateway"
	"github.com/blashkar/portcullis/internal/inject"
	"github.com/blashkar/portcullis/internal/ollama"
	"github.com/blashkar/portcullis/internal/pin"
)

type serveOptions struct {
	configPath     string
	logFile        string
	logLevel       string
	connectTimeout time.Duration
	grace          time.Duration
}

func newServeCmd() *cobra.Command {
	var opts serveOptions
	cmd := &cobra.Command{
		Use:   "serve [flags]",
		Short: "Serve several MCP servers as one, with an audit log",
		Long: `serve starts every server in the config file and offers them to the client
as a single MCP server on portcullis's stdin and stdout. Each server's tools
and prompts get its name as a prefix (fs__read_file), so names can't
collide, and each call goes to the server it belongs to.

Before a tool call is forwarded, the policy in the config file decides
whether it may go ahead. Tools are pinned and scanned before they are
offered: one whose definition changed since it was approved, or that looks
poisoned, is held back ("portcullis pin" reviews and approves changes).
Secrets in what servers send back are redacted, and results are checked
for prompt injection, optionally with a local guard model through Ollama.
Every message, with the
policy's decision, is logged and recorded in a SQLite audit log, which
"portcullis audit" searches.`,
		Example: `  portcullis serve --config portcullis.yaml
  claude mcp add portcullis -- /home/user/portcullis/bin/portcullis serve --config /home/user/portcullis/portcullis.yaml`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), opts)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&opts.configPath, "config", "c", "portcullis.yaml", "config file")
	f.StringVar(&opts.logFile, "log-file", "", "append JSON logs to this file instead of writing text logs to stderr")
	f.StringVar(&opts.logLevel, "log-level", "info", "debug, info, warn or error")
	f.DurationVar(&opts.connectTimeout, "connect-timeout", time.Minute, "how long each server gets to start")
	f.DurationVar(&opts.grace, "shutdown-grace", 5*time.Second, "how long each server gets to exit after its stdin closes, before SIGTERM")
	return cmd
}

func runServe(ctx context.Context, opts serveOptions) error {
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	logger, closeLog, err := newLogger(opts.logFile, opts.logLevel)
	if err != nil {
		return err
	}
	defer closeLog()
	sessionID := rand.Text()[:12]
	log := logger.With("session", sessionID)
	names := cfg.ServerNames()

	pol, err := cfg.CompilePolicy()
	if err != nil {
		return err
	}
	redactor, err := cfg.Redactor()
	if err != nil {
		return err
	}
	gwOpts := gateway.Options{Version: version, SessionID: sessionID, Logger: log, Policy: pol, Redactor: redactor}
	if path := cfg.PinsPath(); path != "" {
		gwOpts.Pins = pin.Open(path, cfg.HoldNewTools())
		log.Info("pinning tool definitions", "path", path)
	} else {
		log.Warn("tool pinning is off: changed tool definitions won't be caught")
	}
	switch cfg.Scan.Tools {
	case "", "hide":
		gwOpts.Scan = gateway.ScanOptions{Enabled: true, Hide: true, Ignore: cfg.ScanIgnore()}
	case "log":
		gwOpts.Scan = gateway.ScanOptions{Enabled: true, Ignore: cfg.ScanIgnore()}
	}
	if redactor == nil {
		log.Warn("secret redaction is off")
	}
	if cfg.Inject.Action != "off" {
		gwOpts.Inject = gateway.InjectOptions{
			Detector: &inject.Detector{GuardAll: cfg.Inject.Guard.Check != "suspicious"},
			Action:   gateway.InjectAction(cmp.Or(cfg.Inject.Action, string(gateway.InjectWarn))),
		}
		if g := cfg.Inject.Guard; g.Enabled {
			guard, err := newGuard(ctx, g, log)
			if err != nil {
				return err
			}
			gwOpts.Inject.Detector.Guard = guard
		}
	}
	if path := cfg.AuditPath(); path != "" {
		store, err := audit.Open(path, cfg.MaxPayload())
		if err != nil {
			return err
		}
		defer store.Close()
		started := time.Now()
		if err := store.StartSession(ctx, audit.Session{ID: sessionID, Started: started, Version: version, Upstreams: strings.Join(names, ",")}); err != nil {
			return fmt.Errorf("audit: %w", err)
		}
		defer func() {
			if err := store.EndSession(context.WithoutCancel(ctx), sessionID, time.Now()); err != nil {
				log.Error("audit: ending the session", "err", err)
			}
		}()
		gwOpts.Recorder = store
		gwOpts.OnClientInfo = func(name, ver string) {
			log.Info("client identified", "client", name, "client_version", ver)
			if err := store.SetClient(context.WithoutCancel(ctx), sessionID, strings.TrimSpace(name+" "+ver)); err != nil {
				log.Error("audit: recording the client", "err", err)
			}
		}
		log.Info("audit log", "path", path)
	}

	gw := gateway.New(gwOpts)
	defer func() {
		if err := gw.Close(); err != nil {
			log.Debug("closing upstreams", "err", err)
		}
	}()

	if err := connectAll(ctx, gw, cfg, names, opts); err != nil {
		return err
	}
	// Check every server's tools again now that all are known, for the
	// scanner's cross-tool check.
	gw.Resync(ctx)
	for name, reason := range gw.Held() {
		log.Warn("holding back tool", "tool", name, "reason", reason)
	}
	if pol == nil {
		log.Info("no policy: every tool call is allowed")
	} else if unused := pol.Unused(gw.Tools()); len(unused) > 0 {
		log.Warn("policy rules that match no tool", "rules", strings.Join(unused, ", "))
	}
	log.Info("serving", "version", version, "servers", strings.Join(names, ","), "tools", len(gw.Tools()))

	err = gw.Serve(ctx, &mcp.StdioTransport{})
	log.Info("session ended")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// newGuard sets up the guard model. Whether the model is there is checked in
// the background: until it answers, and whenever it fails, results are
// checked with the patterns alone.
func newGuard(ctx context.Context, g config.Guard, log *slog.Logger) (*inject.Guard, error) {
	client, err := ollama.NewClient(cmp.Or(g.Host, os.Getenv("OLLAMA_HOST")), nil)
	if err != nil {
		return nil, fmt.Errorf("inject.guard.host: %w", err)
	}
	guard := inject.NewGuard(client, inject.GuardOptions{Model: g.Model, Timeout: g.Timeout})
	if !isLoopback(client.Host()) {
		log.Warn("the guard model's Ollama isn't on this machine: tool results will be sent to it", "host", client.Host())
	}
	go func() {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if _, err := client.Show(ctx, guard.Model()); err != nil {
			log.Error("the guard model isn't available; checking results with patterns only",
				"model", guard.Model(), "err", err, "hint", "ollama pull "+guard.Model())
			return
		}
		log.Info("guard model ready", "model", guard.Model(), "host", client.Host())
	}()
	return guard, nil
}

// isLoopback reports whether a URL's host is this machine.
func isLoopback(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.Hostname() == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(u.Hostname())
	return err == nil && ip.IsLoopback()
}

// connectAll starts the upstream servers in parallel. If any fails, serve
// fails: a half-working set of tools would be confusing.
func connectAll(ctx context.Context, gw *gateway.Gateway, cfg *config.Config, names []string, opts serveOptions) error {
	errs := make([]error, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Go(func() {
			argv := cfg.CommandFor(name)
			// Upstream logs go to stderr, each line tagged with the server's name.
			stderr := &prefixWriter{w: os.Stderr, prefix: "[" + name + "] "}
			cmd := exec.Command(argv[0], argv[1:]...)
			cmd.Stderr = stderr
			connectCtx, cancel := context.WithTimeout(ctx, opts.connectTimeout)
			defer cancel()
			err := gw.Connect(connectCtx, name, &mcp.CommandTransport{Command: cmd, TerminateDuration: opts.grace})
			if err != nil {
				errs[i] = fmt.Errorf("starting server %s (%s): %w", name, strings.Join(argv, " "), err)
			}
		})
	}
	wg.Wait()
	return errors.Join(errs...)
}

// prefixWriter writes each line with a prefix. Partial lines are held until
// they're complete.
type prefixWriter struct {
	mu     sync.Mutex
	w      io.Writer
	prefix string
	buf    []byte
}

// stderrMu keeps lines from different servers from interleaving.
var stderrMu sync.Mutex

func (p *prefixWriter) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.buf = append(p.buf, b...)
	for {
		i := bytes.IndexByte(p.buf, '\n')
		if i < 0 {
			break
		}
		stderrMu.Lock()
		_, err := fmt.Fprintf(p.w, "%s%s\n", p.prefix, p.buf[:i])
		stderrMu.Unlock()
		p.buf = p.buf[i+1:]
		if err != nil {
			return len(b), err
		}
	}
	return len(b), nil
}
