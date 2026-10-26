// Package replay checks recorded tool calls against a policy, to show what
// a policy change would do before it is made.
//
// Calls are checked in the order they were made, with the times they were
// made, so rate limits count them as they would have been counted. Only
// the policy is replayed: nothing is sent to any server.
package replay

import (
	"encoding/json"
	"errors"

	"github.com/blashkar/portcullis/internal/audit"
	"github.com/blashkar/portcullis/internal/gateway"
	"github.com/blashkar/portcullis/internal/policy"
)

// Result is one recorded call checked again.
type Result struct {
	Event audit.Event
	// Before is the policy's decision when the call was made: allow, deny,
	// require_approval or rate_limit, or held for a tool that was held back
	// before the policy saw the call. A call that needed approval counts as
	// require_approval, however the person decided.
	Before string
	// After is what the new policy decides.
	After policy.Decision
	// Err is set when the call's arguments can't be read back, which
	// happens when they were too long and the audit log truncated them.
	Err error
}

// Changed reports whether the new policy decides the call differently.
func (r Result) Changed() bool {
	return r.Err == nil && r.Before != Held && r.Before != r.After.Outcome()
}

// NowBlocked reports whether a call that went ahead would now be blocked.
func (r Result) NowBlocked() bool {
	return r.Changed() && r.Before == string(policy.Allow)
}

// NowAllowed reports whether a call that was blocked would now go ahead.
func (r Result) NowAllowed() bool {
	return r.Changed() && r.After.Outcome() == string(policy.Allow)
}

// Held is Before for calls to tools that were held back.
const Held = audit.DecisionHeld

// ErrTruncated means a call's arguments were cut short in the audit log.
var ErrTruncated = errors.New("the audit log truncated its arguments")

// Check checks the tool calls among events, which must be from one session
// and oldest first, against p. A policy keeps rate-limit state, so each
// session needs a freshly compiled one, as each "portcullis serve" had.
func Check(events []audit.Event, p *policy.Policy) []Result {
	var out []Result
	for _, e := range events {
		if e.Method != "tools/call" || e.Direction != audit.ClientToServer {
			continue
		}
		r := Result{Event: e, Before: before(e)}
		args, err := arguments(e.Params)
		if err != nil {
			r.Err = err
			out = append(out, r)
			continue
		}
		r.After = p.Check(policy.Call{Tool: e.Tool, Server: e.Upstream, Args: args, Time: e.Time})
		out = append(out, r)
	}
	return out
}

func before(e audit.Event) string {
	switch e.Decision {
	case "":
		return string(policy.Allow) // there was no policy
	case audit.DecisionApproved:
		return string(policy.RequireApproval)
	}
	return e.Decision
}

// arguments reads a call's arguments from its recorded params.
func arguments(params string) (map[string]any, error) {
	var p struct {
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal([]byte(params), &p); err != nil {
		return nil, ErrTruncated
	}
	return gateway.PolicyArgs(p.Arguments)
}
