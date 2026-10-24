package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/blashkar/portcullis/internal/jsonrpc"
	"github.com/blashkar/portcullis/internal/proxy"
	"github.com/blashkar/portcullis/internal/transport"
)

type wrapOptions struct {
	logFile        string
	logLevel       string
	logPayloads    int
	maxMessageSize int
	grace          time.Duration
}

func newWrapCmd() *cobra.Command {
	var opts wrapOptions
	cmd := &cobra.Command{
		Use:   "wrap [flags] -- <command> [args...]",
		Short: "Run a stdio MCP server behind portcullis",
		Long: `wrap starts an MCP server as a child process and relays the messages
between it and the client on portcullis's own stdin and stdout.

Point your MCP client at portcullis instead of the server, and put the
server's command after "--".`,
		Example: `  portcullis wrap -- npx -y @modelcontextprotocol/server-filesystem /home/user/project
  portcullis wrap --log-file portcullis.log -- ./my-server --verbose`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWrap(cmd.Context(), opts, args)
		},
	}
	// Stop parsing flags at the server command, so its flags stay its own.
	cmd.Flags().SetInterspersed(false)

	f := cmd.Flags()
	f.StringVar(&opts.logFile, "log-file", "", "append JSON logs to this file instead of writing text logs to stderr")
	f.StringVar(&opts.logLevel, "log-level", "info", "debug, info, warn or error")
	f.IntVar(&opts.logPayloads, "log-payloads", 0, "log up to this many bytes of each message body (may include secrets)")
	f.IntVar(&opts.maxMessageSize, "max-message-size", jsonrpc.DefaultMaxMessageSize, "largest message in bytes; bigger ones are dropped")
	f.DurationVar(&opts.grace, "shutdown-grace", 5*time.Second, "how long the server gets to exit before each escalation (close stdin, SIGTERM, SIGKILL)")
	return cmd
}

func runWrap(ctx context.Context, opts wrapOptions, args []string) error {
	logger, closeLog, err := newLogger(opts.logFile, opts.logLevel)
	if err != nil {
		return err
	}
	defer closeLog()
	log := logger.With("session", rand.Text()[:12])

	// Cancelling serverCtx sends the server SIGTERM, then SIGKILL after the grace period.
	serverCtx, stopServer := context.WithCancel(ctx)
	defer stopServer()
	server, err := transport.StartProcess(serverCtx, args[0], args[1:], os.Stderr, opts.grace)
	if err != nil {
		return err
	}
	log.Info("session started", "version", version, "server", args[0], "pid", server.PID())

	var clientClosed, stopping atomic.Bool
	p := &proxy.Proxy{
		Logger:         log,
		MaxMessageSize: opts.maxMessageSize,
		PayloadLimit:   opts.logPayloads,
		// The client hung up and the server's stdin is closed. Most servers exit
		// right away; give the stragglers a grace period, then terminate them.
		OnClientClose: func() {
			clientClosed.Store(true)
			log.Debug("client closed the connection; waiting for the server to exit")
			time.AfterFunc(opts.grace, func() {
				stopping.Store(true)
				stopServer()
			})
		},
	}

	start := time.Now()
	stats, relayErr := p.Run(proxy.Endpoints{
		ClientIn:  os.Stdin,
		ClientOut: os.Stdout,
		ServerIn:  server.Stdin,
		ServerOut: server.Stdout,
	})
	if relayErr != nil {
		stopServer() // the client can't hear us any more
	}
	waitErr := server.Wait()
	code := server.ExitCode()

	var reason string
	var result error
	switch {
	case relayErr != nil:
		reason, result = "relay error", fmt.Errorf("relaying to the client: %w", relayErr)
	case ctx.Err() != nil:
		reason, result = "signal", ctx.Err()
	case stopping.Load():
		reason = "terminated after client closed"
		log.Warn("server didn't exit after its stdin closed, so it was terminated")
	case clientClosed.Load():
		reason = "client closed"
	default:
		reason = "server exited"
	}
	if result == nil && !stopping.Load() {
		if code > 0 {
			result = exitCodeError{code}
		} else if waitErr != nil {
			result = fmt.Errorf("server: %w", waitErr) // e.g. "server: signal: killed"
		}
	}

	log.Info("session ended",
		"reason", reason,
		"duration", time.Since(start).Round(time.Millisecond),
		"client_to_server", stats.ClientToServer,
		"server_to_client", stats.ServerToClient,
		"invalid", stats.Invalid,
		"dropped", stats.Dropped,
		"exit_code", code,
	)
	return result
}

// newLogger logs text to stderr, or JSON to path when it's set. MCP clients
// read the proxy's stdout as protocol messages, so logs must never go there.
func newLogger(path, level string) (*slog.Logger, func(), error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, nil, fmt.Errorf("--log-level: %w", err)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if path == "" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts)), func() {}, nil
	}
	// 0600: the log can contain tool arguments and results.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("opening log file: %w", err)
	}
	return slog.New(slog.NewJSONHandler(f, opts)), func() { _ = f.Close() }, nil
}
