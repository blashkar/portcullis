package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/blashkar/portcullis/internal/approval"
	"github.com/blashkar/portcullis/internal/policy"
)

// Approver asks a person whether a tool call may go ahead. *approval.Broker
// implements it.
type Approver interface {
	Ask(ctx context.Context, req approval.Request) approval.Outcome
	Timeout() time.Duration
}

// askApproval holds a call the policy wants approved until a person decides.
// It returns nil if the call may go ahead.
func (g *Gateway) askApproval(ctx context.Context, tool, upstream string, args json.RawMessage, d policy.Decision) error {
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	g.log.Warn("waiting for approval", "tool", tool, "rule", d.Rule)
	o := g.opts.Approver.Ask(ctx, approval.Request{Tool: tool, Server: upstream, Args: args, Rule: d.Rule, Reason: d.Reason})
	if n := noteFrom(ctx); n != nil {
		n.approval = o
	}
	if o == approval.Approved {
		g.log.Info("call approved", "tool", tool, "rule", d.Rule)
		return nil
	}
	g.log.Warn("call not approved", "tool", tool, "rule", d.Rule, "outcome", o)
	return approvalError(tool, d, o, g.opts.Approver.Timeout())
}

// approvalReason says what happened to a call that needed approval, for the
// audit log.
func approvalReason(o approval.Outcome) string {
	switch o {
	case approval.Approved:
		return "approved in the dashboard"
	case approval.Denied:
		return "denied in the dashboard"
	case approval.Expired:
		return "nobody answered in time"
	case approval.Cancelled:
		return "the client cancelled the call while it waited"
	case approval.Refused:
		return "too many calls were already waiting for approval"
	}
	return o.String()
}

func approvalError(tool string, d policy.Decision, o approval.Outcome, timeout time.Duration) error {
	rule := "the default policy"
	if d.Rule != "" {
		rule = "rule " + strconv.Quote(d.Rule)
	}
	var msg string
	switch o {
	case approval.Denied:
		msg = fmt.Sprintf("portcullis: a person denied %s (%s)", tool, rule)
	case approval.Expired:
		msg = fmt.Sprintf("portcullis: %s needs a person's approval (%s), and nobody answered within %v", tool, rule, timeout)
	default:
		msg = fmt.Sprintf("portcullis: %s needs a person's approval (%s): %s", tool, rule, approvalReason(o))
	}
	data, _ := json.Marshal(map[string]string{"decision": d.Outcome(), "rule": d.Rule, "reason": d.Reason, "approval": o.String()})
	return &jsonrpc.Error{Code: CodePolicyBlocked, Message: msg, Data: data}
}
