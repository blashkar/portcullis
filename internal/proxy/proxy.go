// Package proxy relays JSON-RPC messages between an MCP client and one
// upstream MCP server, inspecting each message on the way through.
//
// For now every message is forwarded unchanged and logged. Policy checks and
// scanners will hook in where inspect is called.
package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blashkar/portcullis/internal/jsonrpc"
)

// Direction is which way a message travels through the proxy.
type Direction int

// Messages flow both ways: the server can send requests to the client too
// (sampling, roots/list, elicitation).
const (
	ClientToServer Direction = iota
	ServerToClient
)

func (d Direction) String() string {
	if d == ClientToServer {
		return "client->server"
	}
	return "server->client"
}

func (d Direction) opposite() Direction {
	return 1 - d
}

// Endpoints are the two streams on each side of the proxy.
type Endpoints struct {
	ClientIn  io.Reader      // messages from the client (the proxy's stdin)
	ClientOut io.Writer      // messages to the client (the proxy's stdout)
	ServerIn  io.WriteCloser // messages to the server (its stdin)
	ServerOut io.Reader      // messages from the server (its stdout)
}

// Proxy relays messages between a client and a server. The zero value is
// ready to use and logs nothing.
type Proxy struct {
	Logger *slog.Logger

	// MaxMessageSize caps a single message; 0 means jsonrpc.DefaultMaxMessageSize.
	MaxMessageSize int

	// PayloadLimit is how many bytes of each message body to log. 0 logs no
	// bodies, since tool arguments and results can contain secrets.
	PayloadLimit int

	// OnClientClose is called once the client's stream has ended and the
	// server's stdin has been closed, which asks the server to exit.
	OnClientClose func()

	pending sync.Map // pendingKey -> pendingRequest
}

// Stats counts what passed through a session.
type Stats struct {
	ClientToServer int64
	ServerToClient int64
	Invalid        int64 // malformed messages (forwarded anyway, for now)
	Dropped        int64 // oversized messages that couldn't be forwarded
}

type pendingKey struct {
	dir Direction // direction the request traveled
	id  string
}

type pendingRequest struct {
	method string
	tool   string
	start  time.Time
}

type counters struct {
	sent    [2]atomic.Int64
	invalid atomic.Int64
	dropped atomic.Int64
}

// Run relays messages until the server closes its stdout, which happens when
// it exits. A failure writing to the client ends the session early.
func (p *Proxy) Run(e Endpoints) (Stats, error) {
	var c counters

	// The client side can block on a read from the proxy's stdin long after the
	// server is gone, so Run waits only for the server side; the caller exits
	// the process once Run returns.
	go func() {
		err := p.pump(ClientToServer, e.ClientIn, e.ServerIn, &c)
		if err != nil {
			p.logger().Error("relay to server stopped", "err", err)
		}
		if err := e.ServerIn.Close(); err != nil {
			p.logger().Debug("closing server stdin", "err", err)
		}
		if p.OnClientClose != nil {
			p.OnClientClose()
		}
	}()

	err := p.pump(ServerToClient, e.ServerOut, e.ClientOut, &c)
	stats := Stats{
		ClientToServer: c.sent[ClientToServer].Load(),
		ServerToClient: c.sent[ServerToClient].Load(),
		Invalid:        c.invalid.Load(),
		Dropped:        c.dropped.Load(),
	}
	return stats, err
}

// pump copies messages from src to dst until src ends. It returns nil at EOF.
func (p *Proxy) pump(dir Direction, src io.Reader, dst io.Writer, c *counters) error {
	r := jsonrpc.NewReader(src, p.MaxMessageSize)
	w := jsonrpc.NewWriter(dst)
	for {
		raw, err := r.Read()
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case errors.Is(err, jsonrpc.ErrMessageTooLarge):
			// The reader skipped the line, so the stream is still usable. The
			// peer gets no reply and will time out on its side.
			c.dropped.Add(1)
			p.logger().Warn("dropped oversized message", "dir", dir.String(), "err", err)
			continue
		case err != nil:
			return err
		}

		if !p.inspect(dir, raw) {
			c.invalid.Add(1)
		}
		if err := w.Write(raw); err != nil {
			return err
		}
		c.sent[dir].Add(1)
	}
}

// inspect logs a message and tracks requests so their responses can be
// matched up. It reports whether the message was valid JSON-RPC.
func (p *Proxy) inspect(dir Direction, raw []byte) bool {
	log := p.logger()
	attrs := []any{"dir", dir.String(), "bytes", len(raw)}
	if p.PayloadLimit > 0 {
		attrs = append(attrs, "payload", truncate(raw, p.PayloadLimit))
	}

	msg, err := jsonrpc.Parse(raw)
	if err != nil {
		log.Warn("invalid message", append(attrs, "err", err)...)
		return false
	}
	attrs = append(attrs, "kind", msg.Kind().String())
	if id := msg.IDString(); id != "" {
		attrs = append(attrs, "id", id)
	}

	switch msg.Kind() {
	case jsonrpc.KindRequest:
		req := pendingRequest{method: msg.Method, tool: toolName(msg), start: time.Now()}
		p.pending.Store(pendingKey{dir, msg.IDString()}, req)
		attrs = append(attrs, "method", msg.Method)
		if req.tool != "" {
			attrs = append(attrs, "tool", req.tool)
		}
	case jsonrpc.KindNotification:
		attrs = append(attrs, "method", msg.Method)
	case jsonrpc.KindResponse:
		if v, ok := p.pending.LoadAndDelete(pendingKey{dir.opposite(), msg.IDString()}); ok {
			req := v.(pendingRequest)
			attrs = append(attrs, "method", req.method, "duration", time.Since(req.start))
			if req.tool != "" {
				attrs = append(attrs, "tool", req.tool)
			}
		}
		if msg.Error != nil {
			attrs = append(attrs, "error_code", msg.Error.Code, "error", msg.Error.Message)
		}
	}
	log.Info("message", attrs...)
	return true
}

func (p *Proxy) logger() *slog.Logger {
	if p.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return p.Logger
}

// toolName returns the tool a tools/call request invokes, or "".
func toolName(msg *jsonrpc.Message) string {
	if msg.Method != "tools/call" {
		return ""
	}
	var params struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return ""
	}
	return params.Name
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
