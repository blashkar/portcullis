package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/blashkar/portcullis/internal/audit"
	"github.com/blashkar/portcullis/internal/config"
)

type auditOptions struct {
	db         string
	configPath string
	session    string
	tool       string
	upstream   string
	method     string
	failed     bool
	blocked    bool
	decision   string
	rule       string
	logOnly    bool
	flagged    bool
	since      time.Duration
	limit      int
	asJSON     bool
	payloads   bool
}

func newAuditCmd() *cobra.Command {
	var opts auditOptions
	cmd := &cobra.Command{
		Use:   "audit [flags]",
		Short: "Search the audit log",
		Long: `audit lists the messages "portcullis serve" recorded, oldest first. By default
it shows the most recent session; --session all searches every session.`,
		Example: `  portcullis audit                      # the last session
  portcullis audit --tool 'fs__*' --session all --since 24h
  portcullis audit --failed --payloads
  portcullis audit --blocked --session all
  portcullis audit --log-only        # what log_only rules would have changed
  portcullis audit --flagged --session all   # redactions, flagged and held tools
  portcullis audit sessions`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAudit(cmd, opts)
		},
	}
	pf := cmd.PersistentFlags()
	pf.StringVar(&opts.db, "db", "", "audit database (default: the one in the config file)")
	pf.StringVarP(&opts.configPath, "config", "c", "portcullis.yaml", "config file, used to find the database")
	pf.IntVarP(&opts.limit, "limit", "n", 100, "show at most this many of the newest entries (0 = all)")
	pf.BoolVar(&opts.asJSON, "json", false, "print JSON lines instead of a table")

	f := cmd.Flags()
	f.StringVarP(&opts.session, "session", "s", "last", `session ID, "last" or "all"`)
	f.StringVarP(&opts.tool, "tool", "t", "", `tool name, or a prefix ending in "*" ('fs__*')`)
	f.StringVarP(&opts.upstream, "server", "u", "", "only messages routed to this server")
	f.StringVarP(&opts.method, "method", "m", "", "only this method, such as tools/call")
	f.BoolVar(&opts.failed, "failed", false, "only failed calls")
	f.BoolVar(&opts.blocked, "blocked", false, "only calls the policy blocked")
	f.StringVar(&opts.decision, "decision", "", "only calls with this policy decision: allow, deny, require_approval or rate_limit")
	f.StringVar(&opts.rule, "rule", "", "only calls this policy rule decided, or would have")
	f.BoolVar(&opts.logOnly, "log-only", false, "only calls a log_only rule would have decided differently")
	f.BoolVar(&opts.flagged, "flagged", false, "only messages with findings: redacted secrets, flagged or held tools")
	f.DurationVar(&opts.since, "since", 0, "only messages from this long ago, such as 1h")
	f.BoolVarP(&opts.payloads, "payloads", "p", false, "show each message's params and result")

	cmd.AddCommand(&cobra.Command{
		Use:   "sessions",
		Short: "List recorded sessions, newest first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAuditSessions(cmd, opts)
		},
	})
	return cmd
}

// openAuditDB opens an existing audit database; it never creates one.
func openAuditDB(opts auditOptions) (*audit.Store, error) {
	path := opts.db
	if path == "" {
		cfg, err := config.Load(opts.configPath)
		if err != nil {
			return nil, fmt.Errorf("finding the audit log (or pass --db): %w", err)
		}
		if path = cfg.AuditPath(); path == "" {
			return nil, fmt.Errorf("%s turns the audit log off", opts.configPath)
		}
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("no audit log at %s: %w", path, err)
	}
	return audit.Open(path, 0)
}

func runAudit(cmd *cobra.Command, opts auditOptions) error {
	store, err := openAuditDB(opts)
	if err != nil {
		return err
	}
	defer store.Close()
	ctx := cmd.Context()

	f := audit.Filter{
		Tool: opts.tool, Upstream: opts.upstream, Method: opts.method, OnlyFails: opts.failed,
		Blocked: opts.blocked, Decision: opts.decision, Rule: opts.rule, LogOnly: opts.logOnly, Flagged: opts.flagged, Limit: opts.limit,
	}
	switch opts.session {
	case "all":
	case "last":
		if f.SessionID, err = store.LatestSession(ctx); err != nil {
			return err
		}
	default:
		f.SessionID = opts.session
	}
	if opts.since > 0 {
		f.Since = time.Now().Add(-opts.since)
	}
	events, err := store.Events(ctx, f)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if opts.asJSON {
		return writeJSONLines(out, events, eventJSON)
	}
	if len(events) == 0 {
		fmt.Fprintln(cmd.ErrOrStderr(), "no matching messages")
		return nil
	}
	if f.SessionID != "" {
		fmt.Fprintf(out, "session %s\n\n", f.SessionID)
	}
	// Align the rows first, then put each event's details under its row:
	// lines with fewer cells would break the table's alignment.
	var table bytes.Buffer
	tw := tabwriter.NewWriter(&table, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tDIRECTION\tSERVER\tMETHOD\tTOOL\tDURATION\tPOLICY\tSTATUS")
	details := make([][]string, len(events))
	for i, e := range events {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			e.Time.Local().Format("15:04:05.000"), e.Direction, clean(dash(e.Upstream)), clean(e.Method), clean(dash(e.Tool)),
			formatDuration(e.Duration), clean(policyText(e)), clean(status(e)))
		// Why a call was blocked, and what portcullis found, matter enough
		// to show without --payloads.
		if e.Reason != "" && (blocked(e) || e.Direction == audit.Internal) {
			details[i] = append(details[i], "reason: "+e.Reason)
		}
		if e.Findings != "" {
			details[i] = append(details[i], "findings: "+e.Findings)
		}
		if opts.payloads {
			if e.Params != "" {
				details[i] = append(details[i], "params: "+e.Params)
			}
			if e.Result != "" {
				details[i] = append(details[i], "result: "+e.Result)
			}
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	rows := strings.Split(strings.TrimSuffix(table.String(), "\n"), "\n")
	fmt.Fprintln(out, rows[0])
	for i, row := range rows[1:] {
		fmt.Fprintln(out, row)
		for _, d := range details[i] {
			fmt.Fprintln(out, "              "+clean(d))
		}
	}
	return nil
}

// clean escapes control characters in text that came from a server or
// client, so it can't move the cursor, rewrite earlier lines or change a
// terminal's settings with escape sequences when it's printed.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return '\uFFFD'
		}
		return r
	}, s)
}

func runAuditSessions(cmd *cobra.Command, opts auditOptions) error {
	store, err := openAuditDB(opts)
	if err != nil {
		return err
	}
	defer store.Close()
	sessions, err := store.Sessions(cmd.Context(), opts.limit)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if opts.asJSON {
		return writeJSONLines(out, sessions, func(s audit.Session) any { return s })
	}
	if len(sessions) == 0 {
		return audit.ErrNoSessions
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SESSION\tSTARTED\tDURATION\tCLIENT\tSERVERS\tMESSAGES\tTOOL CALLS\tBLOCKED\tFAILED")
	for _, s := range sessions {
		dur := "open"
		if !s.Ended.IsZero() {
			dur = s.Ended.Sub(s.Started).Round(time.Second).String()
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\n",
			s.ID, s.Started.Local().Format("2006-01-02 15:04"), dur, clean(dash(s.Client)), s.Upstreams, s.Events, s.ToolCallCount, s.BlockedCalls, s.FailedEvents)
	}
	return tw.Flush()
}

func writeJSONLines[T any](w io.Writer, items []T, conv func(T) any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false) // keep "client->server" readable
	for _, it := range items {
		if err := enc.Encode(conv(it)); err != nil {
			return err
		}
	}
	return nil
}

// eventJSON keeps params and results as JSON rather than escaped strings
// when they're intact.
func eventJSON(e audit.Event) any {
	raw := func(s string) any {
		if s == "" {
			return nil
		}
		if json.Valid([]byte(s)) {
			return json.RawMessage(s)
		}
		return s // truncated
	}
	return struct {
		ID        int64     `json:"id"`
		Session   string    `json:"session"`
		Time      time.Time `json:"time"`
		Direction string    `json:"direction"`
		Server    string    `json:"server,omitempty"`
		Method    string    `json:"method"`
		Tool      string    `json:"tool,omitempty"`
		Params    any       `json:"params,omitempty"`
		Result    any       `json:"result,omitempty"`
		Error     string    `json:"error,omitempty"`
		Failed    bool      `json:"failed"`
		Duration  float64   `json:"duration_ms"`
		Decision  string    `json:"decision,omitempty"`
		Rule      string    `json:"rule,omitempty"`
		Reason    string    `json:"reason,omitempty"`
		Would     string    `json:"log_only_decision,omitempty"`
		WouldRule string    `json:"log_only_rule,omitempty"`
		Findings  string    `json:"findings,omitempty"`
	}{
		e.ID, e.SessionID, e.Time, e.Direction, e.Upstream, e.Method, e.Tool, raw(e.Params), raw(e.Result),
		e.Error, e.IsError, float64(e.Duration.Microseconds()) / 1000,
		e.Decision, e.Rule, e.Reason, e.WouldDecision, e.WouldRule, e.Findings,
	}
}

func status(e audit.Event) string {
	switch {
	case e.Method == "tool/changed" || e.Method == "tool/held":
		return "held"
	case e.Method == "tool/flagged":
		return "flagged"
	case e.Method == "tool/pinned":
		return "pinned"
	case blocked(e):
		return "blocked"
	case e.Error != "":
		return "error: " + firstLine(e.Error)
	case e.IsError:
		return "failed"
	default:
		return "ok"
	}
}

func blocked(e audit.Event) bool {
	return e.Decision != "" && e.Decision != "allow"
}

// policyText shows a decision and the rule that made it, such as
// "deny fs-workspace-only", followed by what log_only rules would have done.
func policyText(e audit.Event) string {
	if e.Decision == "" {
		return "-"
	}
	out := strings.TrimSpace(e.Decision + " " + e.Rule)
	if e.WouldDecision != "" {
		out += " (log_only: " + strings.TrimSpace(e.WouldDecision+" "+e.WouldRule) + ")"
	}
	return out
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return d.Round(time.Microsecond).String()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}
