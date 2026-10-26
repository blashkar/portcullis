package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/blashkar/portcullis/internal/audit"
	"github.com/blashkar/portcullis/internal/config"
	"github.com/blashkar/portcullis/internal/replay"
)

type replayOptions struct {
	auditOptions
	policyPath string
	all        bool
}

func newReplayCmd() *cobra.Command {
	var opts replayOptions
	cmd := &cobra.Command{
		Use:   "replay [session] --policy FILE",
		Short: "Check recorded tool calls against a new policy",
		Long: `replay checks the tool calls an earlier session made against the policy in
FILE, and shows the ones it would decide differently: calls that went ahead
and would now be blocked, and calls that were blocked and would now go
ahead. Nothing is sent to any server; only the policy is checked.

FILE can be a whole config file or one with just a policy section. The
session is an ID from "portcullis audit sessions", "last" (the default) or
"all". Calls are checked in order, with the times they were made, so rate
limits count them as they did then.`,
		Example: `  portcullis replay --policy new-policy.yaml
  portcullis replay 3f9a1c2b7d4e --policy new-policy.yaml --all
  portcullis replay all --policy portcullis.yaml --json`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.session = "last"
			if len(args) == 1 {
				opts.session = args[0]
			}
			return runReplay(cmd, opts)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&opts.policyPath, "policy", "P", "", "the policy to check the calls against (required)")
	f.StringVar(&opts.db, "db", "", "audit database (default: the one in the config file)")
	f.StringVarP(&opts.configPath, "config", "c", "portcullis.yaml", "config file, used to find the database")
	f.BoolVarP(&opts.all, "all", "a", false, "show every call, not only the ones decided differently")
	f.BoolVar(&opts.asJSON, "json", false, "print JSON lines instead of a table")
	f.BoolVarP(&opts.payloads, "payloads", "p", false, "show each call's arguments")
	_ = cmd.MarkFlagRequired("policy")
	return cmd
}

func runReplay(cmd *cobra.Command, opts replayOptions) error {
	// Check the new policy before anything else: it's the likeliest mistake.
	if _, err := config.LoadPolicy(opts.policyPath); err != nil {
		return err
	}
	store, err := openAuditDB(opts.auditOptions)
	if err != nil {
		return err
	}
	defer store.Close()
	ctx := cmd.Context()

	f := audit.Filter{Method: "tools/call"}
	switch opts.session {
	case "all":
	case "last":
		if f.SessionID, err = store.LatestSession(ctx); err != nil {
			return err
		}
	default:
		f.SessionID = opts.session
	}
	events, err := store.Events(ctx, f)
	if err != nil {
		return err
	}

	// Each session had its own "portcullis serve", with its own rate
	// limits, so each gets a freshly compiled policy.
	var order []string
	bySession := map[string][]audit.Event{}
	for _, e := range events {
		if _, ok := bySession[e.SessionID]; !ok {
			order = append(order, e.SessionID)
		}
		bySession[e.SessionID] = append(bySession[e.SessionID], e)
	}
	var results []replay.Result
	for _, id := range order {
		pol, err := config.LoadPolicy(opts.policyPath)
		if err != nil {
			return err
		}
		results = append(results, replay.Check(bySession[id], pol)...)
	}

	out := cmd.OutOrStdout()
	if opts.asJSON {
		var shown []replay.Result
		for _, r := range results {
			if opts.all || r.Changed() {
				shown = append(shown, r)
			}
		}
		return writeJSONLines(out, shown, replayJSON)
	}
	if len(results) == 0 {
		fmt.Fprintln(cmd.ErrOrStderr(), "no tool calls to replay")
		return nil
	}
	if f.SessionID != "" {
		fmt.Fprintf(out, "session %s\n\n", f.SessionID)
	}
	if err := writeReplayTable(out, results, opts, f.SessionID == ""); err != nil {
		return err
	}
	fmt.Fprintln(out, replaySummary(results))
	return nil
}

func writeReplayTable(out io.Writer, results []replay.Result, opts replayOptions, showSession bool) error {
	var table bytes.Buffer
	tw := tabwriter.NewWriter(&table, 0, 0, 2, ' ', 0)
	header := "TIME\tTOOL\tBEFORE\tAFTER\t"
	if showSession {
		header = "SESSION\t" + header
	}
	fmt.Fprintln(tw, header)
	var details [][]string
	for _, r := range results {
		if !opts.all && !r.Changed() {
			continue
		}
		e := r.Event
		row := fmt.Sprintf("%s\t%s\t%s\t%s\t%s", e.Time.Local().Format("15:04:05.000"), clean(e.Tool),
			clean(policyText(audit.Event{Decision: e.Decision, Rule: e.Rule})), clean(afterText(r)), changeText(r))
		if showSession {
			row = e.SessionID + "\t" + row
		}
		fmt.Fprintln(tw, row)
		var d []string
		if r.Changed() && r.After.Reason != "" {
			d = append(d, "reason: "+r.After.Reason)
		}
		// Arguments are as the client sent them: redaction covers only
		// what servers send back.
		if opts.payloads && r.Err == nil {
			d = append(d, "args: "+shorten(argsText(e.Params), 160))
		}
		details = append(details, d)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	rows := strings.Split(strings.TrimSuffix(table.String(), "\n"), "\n")
	for i, row := range rows {
		fmt.Fprintln(out, strings.TrimRight(row, " "))
		if i == 0 {
			continue
		}
		for _, d := range details[i-1] {
			fmt.Fprintln(out, "              "+clean(d))
		}
	}
	if len(rows) == 1 {
		fmt.Fprintln(out, "(no call is decided differently; --all shows them all)")
	}
	fmt.Fprintln(out)
	return nil
}

func afterText(r replay.Result) string {
	if r.Err != nil {
		return "? " + r.Err.Error()
	}
	return policyText(audit.Event{
		Decision: r.After.Outcome(), Rule: r.After.Rule,
		WouldDecision: wouldOutcome(r), WouldRule: wouldRule(r),
	})
}

func changeText(r replay.Result) string {
	switch {
	case r.NowBlocked():
		return "now blocked"
	case r.NowAllowed():
		return "now allowed"
	case r.Changed():
		return "changed"
	case r.Before == replay.Held:
		return "(tool was held back)"
	}
	return ""
}

func wouldOutcome(r replay.Result) string {
	if r.After.Would == nil {
		return ""
	}
	return r.After.Would.Outcome()
}

func wouldRule(r replay.Result) string {
	if r.After.Would == nil {
		return ""
	}
	return r.After.Would.Rule
}

func replaySummary(results []replay.Result) string {
	var changed, blocked, allowed, held, unreadable int
	for _, r := range results {
		switch {
		case r.Err != nil:
			unreadable++
		case r.Before == replay.Held:
			held++
		case r.Changed():
			changed++
			if r.NowBlocked() {
				blocked++
			}
			if r.NowAllowed() {
				allowed++
			}
		}
	}
	s := fmt.Sprintf("%s replayed: %d decided differently (%d now blocked, %d now allowed)",
		plural(len(results), "tool call"), changed, blocked, allowed)
	if held > 0 {
		s += fmt.Sprintf("; %s to held-back tools, which the policy never saw", plural(held, "call"))
	}
	if unreadable > 0 {
		s += fmt.Sprintf("; %s not checked: the audit log truncated the arguments (audit.max_payload)", plural(unreadable, "call"))
	}
	return s
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}

// argsText returns a call's arguments from its recorded params, with
// characters such as < unescaped.
func argsText(params string) string {
	var p struct {
		Arguments json.RawMessage `json:"arguments"`
	}
	if json.Unmarshal([]byte(params), &p) != nil || len(p.Arguments) == 0 {
		return "{}"
	}
	dec := json.NewDecoder(bytes.NewReader(p.Arguments))
	dec.UseNumber() // keep numbers as they were sent
	var v any
	if dec.Decode(&v) != nil {
		return string(p.Arguments)
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) != nil {
		return string(p.Arguments)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func shorten(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func replayJSON(r replay.Result) any {
	type decision struct {
		Decision string `json:"decision"`
		Rule     string `json:"rule,omitempty"`
		Reason   string `json:"reason,omitempty"`
		Would    string `json:"log_only_decision,omitempty"`
	}
	out := struct {
		ID      int64     `json:"id"`
		Session string    `json:"session"`
		Time    time.Time `json:"time"`
		Tool    string    `json:"tool"`
		Before  decision  `json:"before"`
		After   *decision `json:"after,omitempty"`
		Changed bool      `json:"changed"`
		Error   string    `json:"error,omitempty"`
	}{
		ID: r.Event.ID, Session: r.Event.SessionID, Time: r.Event.Time, Tool: r.Event.Tool,
		Before:  decision{Decision: r.Before, Rule: r.Event.Rule},
		Changed: r.Changed(),
	}
	if r.Err != nil {
		out.Error = r.Err.Error()
	} else {
		out.After = &decision{Decision: r.After.Outcome(), Rule: r.After.Rule, Reason: r.After.Reason, Would: wouldOutcome(r)}
	}
	return out
}
