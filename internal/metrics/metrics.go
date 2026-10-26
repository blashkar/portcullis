// Package metrics exposes what portcullis sees as Prometheus metrics: tool
// calls and the policy's decisions, how long calls take, secrets redacted,
// prompt injections caught, approvals, and tools held back.
//
// Metrics are served on a loopback address only, like the dashboard. They
// hold no arguments or results, but tool names and counts still say what an
// agent is doing.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/blashkar/portcullis/internal/audit"
	"github.com/blashkar/portcullis/internal/gateway"
)

// Options configure Metrics. The functions report current state when the
// metrics are scraped; nil ones are left out.
type Options struct {
	Version string
	// Pending returns how many calls are waiting for approval.
	Pending func() int
	// Held returns how many tools are being held back.
	Held func() int
	// Tools returns how many tools are offered to the client.
	Tools func() int
}

// Metrics counts what the gateway does. It implements gateway.Observer and
// is safe for concurrent use.
type Metrics struct {
	reg *prometheus.Registry

	messages    *prometheus.CounterVec
	calls       *prometheus.CounterVec
	duration    *prometheus.HistogramVec
	redactions  *prometheus.CounterVec
	injections  *prometheus.CounterVec
	approvals   *prometheus.CounterVec
	toolEvents  *prometheus.CounterVec
	disconnects *prometheus.CounterVec

	// Tool and server names come from the client and the servers, so the
	// number of distinct ones kept as labels is capped.
	tools, servers *capped
}

// maxNames caps the distinct tool and server names kept as labels; any
// beyond are counted as "other".
const maxNames = 500

var _ gateway.Observer = (*Metrics)(nil)

// New returns Metrics with every metric registered.
func New(o Options) *Metrics {
	m := &Metrics{
		reg:     prometheus.NewRegistry(),
		tools:   newCapped(maxNames),
		servers: newCapped(maxNames),
	}
	f := func(c prometheus.Collector) { m.reg.MustRegister(c) }
	m.messages = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_messages_total",
		Help: "MCP messages handled, by direction and method.",
	}, []string{"direction", "method"})
	m.calls = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_tool_calls_total",
		Help: "Tool calls, by server, tool, policy decision and outcome (ok, failed or blocked).",
	}, []string{"server", "tool", "decision", "outcome"})
	m.duration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "portcullis_tool_call_duration_seconds",
		Help:    "How long tool calls that went ahead took, including any wait for approval.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120},
	}, []string{"server"})
	m.redactions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_secrets_redacted_total",
		Help: "Distinct secrets redacted from what servers sent back, by kind.",
	}, []string{"server", "kind"})
	m.injections = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_injection_findings_total",
		Help: "Results the prompt-injection checks judged an injection, or only noticed something in (suspicious).",
	}, []string{"server", "verdict"})
	m.approvals = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_approvals_total",
		Help: "Calls that needed a person's approval, by how they ended.",
	}, []string{"outcome"})
	m.toolEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_tool_definitions_total",
		Help: "Tool definitions checked, by result: pinned, changed, held or flagged.",
	}, []string{"server", "result"})
	m.disconnects = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_upstream_disconnects_total",
		Help: "Servers that exited unexpectedly.",
	}, []string{"server"})
	for _, c := range []prometheus.Collector{m.messages, m.calls, m.duration, m.redactions, m.injections, m.approvals, m.toolEvents, m.disconnects} {
		f(c)
	}

	f(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name:        "portcullis_build_info",
		Help:        "Always 1; the version is a label.",
		ConstLabels: prometheus.Labels{"version": o.Version},
	}, func() float64 { return 1 }))
	gauge := func(name, help string, fn func() int) {
		if fn != nil {
			f(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: name, Help: help}, func() float64 { return float64(fn()) }))
		}
	}
	gauge("portcullis_approvals_pending", "Calls waiting for a person's approval.", o.Pending)
	gauge("portcullis_tools_held", "Tools held back because their definition changed, wasn't approved or looks poisoned.", o.Held)
	gauge("portcullis_tools_offered", "Tools offered to the client.", o.Tools)
	f(collectors.NewGoCollector())
	f(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// Observe counts an event.
func (m *Metrics) Observe(e audit.Event, d gateway.Details) {
	server := m.servers.get(e.Upstream)
	if e.Direction == audit.Internal {
		if result, ok := strings.CutPrefix(e.Method, "tool/"); ok {
			m.toolEvents.WithLabelValues(server, result).Inc()
		} else if e.Method == "upstream/disconnected" {
			m.disconnects.WithLabelValues(server).Inc()
		}
		return
	}
	m.messages.WithLabelValues(e.Direction, method(e.Method)).Inc()

	for kind, n := range d.Redacted {
		m.redactions.WithLabelValues(server, kind).Add(float64(n))
	}
	switch {
	case d.Injection:
		m.injections.WithLabelValues(server, "injection").Inc()
	case d.Suspicious:
		m.injections.WithLabelValues(server, "suspicious").Inc()
	}
	if d.Approval != "" {
		m.approvals.WithLabelValues(d.Approval).Inc()
	}

	if e.Method != "tools/call" || e.Direction != audit.ClientToServer {
		return
	}
	decision := e.Decision
	if decision == "" {
		decision = "none" // no policy
	}
	outcome := "ok"
	switch {
	case decision != "none" && decision != "allow" && decision != audit.DecisionApproved:
		outcome = "blocked"
	case e.IsError:
		outcome = "failed"
	}
	m.calls.WithLabelValues(server, m.tools.get(e.Tool), decision, outcome).Inc()
	if outcome != "blocked" {
		m.duration.WithLabelValues(server).Observe(e.Duration.Seconds())
	}
}

// knownMethods are the MCP methods counted by name; the client or a server
// could send any name, so others are counted as "other".
var knownMethods = map[string]bool{}

func init() {
	for _, m := range strings.Fields(`initialize ping tools/list tools/call prompts/list prompts/get
		resources/list resources/read resources/templates/list resources/subscribe resources/unsubscribe
		completion/complete logging/setLevel roots/list sampling/createMessage elicitation/create
		notifications/initialized notifications/cancelled notifications/progress notifications/message
		notifications/roots/list_changed notifications/tools/list_changed notifications/prompts/list_changed
		notifications/resources/list_changed notifications/resources/updated`) {
		knownMethods[m] = true
	}
}

func method(m string) string {
	if knownMethods[m] {
		return m
	}
	return "other"
}

// capped hands out label values, up to max distinct ones.
type capped struct {
	mu   sync.Mutex
	max  int
	seen map[string]bool
}

func newCapped(maxValues int) *capped {
	return &capped{max: maxValues, seen: map[string]bool{}}
}

func (c *capped) get(v string) string {
	if v == "" {
		return "-"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen[v] {
		return v
	}
	if len(c.seen) >= c.max {
		return "other"
	}
	c.seen[v] = true
	return v
}

// Handler serves the metrics in Prometheus's text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// Serve serves the metrics at /metrics on ln until ctx is done. The
// listener must be on a loopback address, and requests must name it in
// their Host header, so a web page can't read the metrics through DNS
// rebinding.
func (m *Metrics) Serve(ctx context.Context, ln net.Listener, log *slog.Logger) error {
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || !addr.IP.IsLoopback() {
		return fmt.Errorf("metrics: %v isn't a loopback address", ln.Addr())
	}
	port := strconv.Itoa(addr.Port)
	hosts := map[string]bool{ln.Addr().String(): true, "localhost:" + port: true}
	metrics := m.Handler()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		if !hosts[r.Host] {
			http.Error(w, "wrong host", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		metrics.ServeHTTP(w, r)
	})
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if srv.Shutdown(shutdown) != nil {
			_ = srv.Close()
		}
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
