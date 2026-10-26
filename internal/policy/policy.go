// Package policy decides whether a tool call may go ahead.
//
// A policy is a list of rules, checked in order. Each rule names the tools it
// covers and, optionally, a CEL condition on the call's arguments. The first
// rule that matches decides:
//
//	policy:
//	  default: allow
//	  rules:
//	    - name: fs-workspace-only
//	      tool: "fs__*"
//	      when: 'values(args, ["path", "paths", "source", "destination"]).exists(p, !under(p, "/workspace"))'
//	      action: deny
//	    - name: no-reset
//	      tool: git__git_reset
//	      action: deny
//
// A rule with a rate_limit instead of an action only decides when its limit
// is exceeded; otherwise checking moves on to the next rule. A rule marked
// log_only, or every rule when the whole policy is, is checked but not
// enforced: the decision it would have made is reported alongside the real
// one, so a new rule can be tried out on real traffic first.
package policy

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"cel.dev/cel-go/cel"
	"go.yaml.in/yaml/v3"

	"github.com/blashkar/portcullis/internal/glob"
)

// Action is what a rule does with a call it matches.
type Action string

// Actions.
const (
	Allow           Action = "allow"
	Deny            Action = "deny"
	RequireApproval Action = "require_approval"
)

// Spec is the policy section of the config file.
type Spec struct {
	// Default is what happens to a call no rule decides: allow (the default)
	// or deny.
	Default Action `yaml:"default"`
	// LogOnly checks every rule but enforces none of them.
	LogOnly bool       `yaml:"log_only"`
	Rules   []RuleSpec `yaml:"rules"`
}

// RuleSpec is one rule as written in the config file.
type RuleSpec struct {
	// Name identifies the rule in logs, the audit log and errors sent to
	// the client. It defaults to "rule N".
	Name string `yaml:"name"`
	// Tool is the tools the rule covers: names as the client sees them
	// (fs__read_file), where "*" matches any run of characters. It defaults
	// to every tool.
	Tool Patterns `yaml:"tool"`
	// When is a CEL expression that must be true for the rule to match.
	When string `yaml:"when"`
	// Action is allow, deny or require_approval.
	Action Action `yaml:"action"`
	// RateLimit, such as "30/min", allows that many matching calls in any
	// such window. A rule has an action or a rate limit, not both.
	RateLimit string `yaml:"rate_limit"`
	// Reason is told to the client when the rule blocks a call.
	Reason string `yaml:"reason"`
	// LogOnly reports what the rule would do without doing it.
	LogOnly bool `yaml:"log_only"`
}

// Patterns is one tool pattern or a list of them.
type Patterns []string

// UnmarshalYAML accepts a single string as well as a list.
func (p *Patterns) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*p = Patterns{n.Value}
		return nil
	}
	var list []string
	if err := n.Decode(&list); err != nil {
		return err
	}
	*p = list
	return nil
}

// Call is a tool call to check.
type Call struct {
	Tool   string         // the name the client used: fs__read_file
	Server string         // the upstream server it goes to: fs
	Args   map[string]any // decoded JSON arguments
	// Time is when the call was made, for rate limits; zero means now.
	// Replaying recorded calls sets it, oldest first.
	Time time.Time
}

// Decision is the outcome of checking a call.
type Decision struct {
	Action      Action
	Rule        string // the rule that decided; "" for the default
	Reason      string
	RateLimited bool // a rate limit was exceeded

	// Would is the decision log_only rules would have made, if its outcome
	// differs.
	Would *Decision
}

// Outcome names the decision for logs and the audit log: allow, deny,
// require_approval or rate_limit.
func (d Decision) Outcome() string {
	if d.RateLimited {
		return "rate_limit"
	}
	return string(d.Action)
}

// Blocked reports whether the call must not go ahead.
func (d Decision) Blocked() bool {
	return d.Action != Allow
}

// Policy is a compiled policy. A nil *Policy allows everything.
type Policy struct {
	def     Action
	logOnly bool
	rules   []*rule
}

type rule struct {
	name    string
	tools   glob.Patterns
	when    cel.Program // nil: always
	action  Action
	limit   *limiter
	reason  string
	logOnly bool
}

// costLimit bounds the work one condition can do, so a rule can't stall
// every call. Ordinary conditions cost well under a thousand.
const costLimit = 1_000_000

// Compile checks a policy and compiles its conditions.
func Compile(s Spec) (*Policy, error) {
	p := &Policy{def: s.Default, logOnly: s.LogOnly}
	switch p.def {
	case "":
		p.def = Allow
	case Allow, Deny:
	default:
		return nil, fmt.Errorf("policy: default must be allow or deny, not %q", s.Default)
	}
	env, err := newEnv()
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	var errs []error
	for i, rs := range s.Rules {
		r, err := compileRule(env, rs, i)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if names[r.name] {
			errs = append(errs, fmt.Errorf("policy: two rules are named %q", r.name))
		}
		names[r.name] = true
		p.rules = append(p.rules, r)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return p, nil
}

func compileRule(env *cel.Env, rs RuleSpec, i int) (*rule, error) {
	r := &rule{name: rs.Name, action: rs.Action, reason: rs.Reason, logOnly: rs.LogOnly}
	if r.name == "" {
		r.name = fmt.Sprintf("rule %d", i+1)
	}
	fail := func(format string, args ...any) (*rule, error) {
		return nil, fmt.Errorf("policy: %s: %s", r.name, fmt.Sprintf(format, args...))
	}

	patterns := rs.Tool
	if len(patterns) == 0 {
		patterns = Patterns{"*"}
	}
	tools, err := glob.Compile(patterns)
	if err != nil {
		return fail("%v", err)
	}
	r.tools = tools

	switch {
	case rs.RateLimit != "" && rs.Action != "":
		return fail("a rule has an action or a rate_limit, not both")
	case rs.RateLimit != "":
		l, err := parseRateLimit(rs.RateLimit)
		if err != nil {
			return fail("%v", err)
		}
		r.limit = l
	case rs.Action == "":
		return fail("no action or rate_limit")
	case rs.Action != Allow && rs.Action != Deny && rs.Action != RequireApproval:
		return fail("action must be allow, deny or require_approval, not %q", rs.Action)
	}

	if strings.TrimSpace(rs.When) != "" {
		ast, iss := env.Compile(rs.When)
		if iss.Err() != nil {
			return fail("when: %v", iss.Err())
		}
		if ast.OutputType() != cel.BoolType {
			return fail("when must be true or false, but it is a %v", ast.OutputType())
		}
		prg, err := env.Program(ast, cel.CostLimit(costLimit))
		if err != nil {
			return fail("when: %v", err)
		}
		r.when = prg
	}
	return r, nil
}

// Check decides whether a call may go ahead. It is safe for concurrent use.
func (p *Policy) Check(c Call) Decision {
	if p == nil {
		return Decision{Action: Allow}
	}
	if c.Args == nil {
		c.Args = map[string]any{}
	}
	// Rules are checked in order until one decides. Two outcomes are
	// tracked: the enforced one, which skips log_only rules, and the one
	// that would result if they were enforced. The second is settled no
	// later than the first, so every rule this loop reaches would also be
	// reached without log_only rules, and rate limits count the same calls
	// either way.
	var enforced, would *Decision
	for _, r := range p.rules {
		if enforced != nil {
			break
		}
		d, ok := r.decide(c)
		if !ok {
			continue
		}
		if would == nil {
			would = &d
		}
		if !r.logOnly && !p.logOnly {
			enforced = &d
		}
	}

	def := Decision{Action: p.def, Reason: "no rule matched"}
	if enforced == nil {
		enforced = &def
		if p.logOnly {
			enforced = &Decision{Action: Allow, Reason: "the policy is log_only"}
		}
	}
	if would == nil {
		would = &def
	}
	out := *enforced
	if would.Outcome() != out.Outcome() {
		out.Would = would
	}
	return out
}

// decide reports the rule's decision, and false if the rule doesn't decide
// this call. A condition that fails to evaluate blocks the call: a rule
// that can't be checked mustn't let calls through.
func (r *rule) decide(c Call) (Decision, bool) {
	if !r.matchesTool(c.Tool) {
		return Decision{}, false
	}
	if r.when != nil {
		out, _, err := r.when.Eval(map[string]any{"tool": c.Tool, "server": c.Server, "args": c.Args})
		if err != nil {
			return Decision{Action: Deny, Rule: r.name, Reason: "checking the rule failed: " + err.Error()}, true
		}
		if out.Value() != true {
			return Decision{}, false
		}
	}
	if r.limit != nil {
		now := c.Time
		if now.IsZero() {
			now = time.Now()
		}
		if r.limit.allow(now) {
			return Decision{}, false
		}
		return Decision{Action: Deny, Rule: r.name, Reason: "rate limit of " + r.limit.String() + " exceeded", RateLimited: true}, true
	}
	return Decision{Action: r.action, Rule: r.name, Reason: r.reason}, true
}

func (r *rule) matchesTool(tool string) bool {
	return r.tools.Match(tool)
}

// NeedsApproval reports whether any enforced rule asks for a person's
// approval.
func (p *Policy) NeedsApproval() bool {
	if p == nil || p.logOnly {
		return false
	}
	for _, r := range p.rules {
		if r.action == RequireApproval && !r.logOnly {
			return true
		}
	}
	return false
}

// Unused returns the names of the rules whose tool patterns match none of
// the given tools, which usually means a typo.
func (p *Policy) Unused(tools []string) []string {
	if p == nil {
		return nil
	}
	var out []string
	for _, r := range p.rules {
		used := false
		for _, t := range tools {
			if r.matchesTool(t) {
				used = true
				break
			}
		}
		if !used {
			out = append(out, r.name)
		}
	}
	return out
}

// limiter allows n events in any window of length per.
type limiter struct {
	n    int
	per  time.Duration
	unit string

	mu    sync.Mutex
	times []time.Time // the allowed events still inside the window, oldest first
}

var rateLimitRE = regexp.MustCompile(`^\s*(\d+)\s*/\s*(s|sec|second|m|min|minute|h|hour)\s*$`)

func parseRateLimit(s string) (*limiter, error) {
	m := rateLimitRE.FindStringSubmatch(s)
	if m == nil {
		return nil, fmt.Errorf("rate_limit %q: want a count per second, minute or hour, such as 30/min", s)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n <= 0 {
		return nil, fmt.Errorf("rate_limit %q: the count must be positive", s)
	}
	l := &limiter{n: n}
	switch m[2] {
	case "s", "sec", "second":
		l.per, l.unit = time.Second, "sec"
	case "m", "min", "minute":
		l.per, l.unit = time.Minute, "min"
	default:
		l.per, l.unit = time.Hour, "hour"
	}
	return l, nil
}

func (l *limiter) String() string {
	return fmt.Sprintf("%d/%s", l.n, l.unit)
}

// allow records an event at now and reports whether it is within the limit.
// Events over the limit aren't recorded, so a client that keeps retrying
// gets through again once the window has moved on.
func (l *limiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-l.per)
	i := 0
	for i < len(l.times) && !l.times[i].After(cutoff) {
		i++
	}
	l.times = l.times[i:]
	if len(l.times) >= l.n {
		return false
	}
	l.times = append(l.times, now)
	return true
}
